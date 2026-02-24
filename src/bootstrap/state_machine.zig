const std = @import("std");
const abi_parser = @import("../parser/abi_parser.zig");
const parse_errors = @import("../parser/parse_errors.zig");
const validator = @import("../knx/validator.zig");
const mini_tuf = @import("../trust/mini_tuf.zig");
const kx_error = @import("../errors/kx_error.zig");
const toolchain_installer = @import("toolchain_installer.zig");

pub const State = enum {
    init,
    load_trust_metadata,
    verify_metadata_chain,
    parse_knxfile,
    resolve_toolchain,
    download_blob,
    verify_blob,
    unpack_staging,
    compute_tree_root,
    verify_tree_root,
    seal_cache_object,
    execute_build_graph,
    verify_outputs,
    atomic_publish,
    done,
    failed,
};

pub const RunResult = struct {
    trace: std.ArrayList(State),
    canonical_json: []u8,
    verify_mode: validator.VerifyMode,
    knx_digest_hex: [64]u8,
    trust: mini_tuf.VerificationSummary,
    final_state: State,

    pub fn deinit(self: *RunResult, allocator: std.mem.Allocator) void {
        self.trace.deinit(allocator);
        allocator.free(self.canonical_json);
        self.* = undefined;
    }
};

pub const RunFailure = struct {
    at: State,
    code: kx_error.Code,
    cause: anyerror,
};

pub const RunAttempt = union(enum) {
    success: RunResult,
    failure: RunFailure,
};

const max_knxfile_bytes: usize = 4 * 1024 * 1024;

pub fn runFromPath(allocator: std.mem.Allocator, path: []const u8) !RunResult {
    return runFromPathWithOptions(allocator, path, .{});
}

pub const RunOptions = struct {
    trust_metadata_dir: ?[]const u8 = "trust",
    trust_state_path: ?[]const u8 = ".kilnexus-trust-state.json",
};

pub fn runFromPathWithOptions(allocator: std.mem.Allocator, path: []const u8, options: RunOptions) !RunResult {
    const source = try std.fs.cwd().readFileAlloc(allocator, path, max_knxfile_bytes);
    defer allocator.free(source);
    var failed_at: State = .init;
    return runWithOptionsCore(allocator, source, options, &failed_at);
}

pub fn run(allocator: std.mem.Allocator, source: []const u8) !RunResult {
    return runWithOptions(allocator, source, .{
        .trust_metadata_dir = null,
        .trust_state_path = null,
    });
}

pub fn runWithOptions(allocator: std.mem.Allocator, source: []const u8, options: RunOptions) !RunResult {
    var failed_at: State = .init;
    return runWithOptionsCore(allocator, source, options, &failed_at);
}

pub fn attemptRunFromPathWithOptions(allocator: std.mem.Allocator, path: []const u8, options: RunOptions) RunAttempt {
    const source = std.fs.cwd().readFileAlloc(allocator, path, max_knxfile_bytes) catch |err| {
        const cause = kx_error.normalizeIo(err);
        return .{
            .failure = .{
                .at = .init,
                .code = kx_error.classifyIo(cause),
                .cause = cause,
            },
        };
    };
    defer allocator.free(source);
    return attemptRunWithOptions(allocator, source, options);
}

pub fn attemptRunWithOptions(allocator: std.mem.Allocator, source: []const u8, options: RunOptions) RunAttempt {
    var failed_at: State = .init;
    const result = runWithOptionsCore(allocator, source, options, &failed_at) catch |err| {
        const cause = normalizeCauseByState(failed_at, err);
        return .{
            .failure = .{
                .at = failed_at,
                .code = classifyByState(failed_at, cause),
                .cause = cause,
            },
        };
    };
    return .{ .success = result };
}

fn runWithOptionsCore(allocator: std.mem.Allocator, source: []const u8, options: RunOptions, failed_at: *State) !RunResult {
    var trace: std.ArrayList(State) = .empty;
    errdefer trace.deinit(allocator);
    failed_at.* = .init;

    try push(&trace, allocator, .init);
    try push(&trace, allocator, .load_trust_metadata);
    var trust_summary: mini_tuf.VerificationSummary = .{
        .root_version = 0,
        .timestamp_version = 0,
        .snapshot_version = 0,
        .targets_version = 0,
    };
    if (options.trust_metadata_dir) |trust_dir_path| {
        var bundle = mini_tuf.loadFromDirStrict(allocator, trust_dir_path) catch |err| {
            failed_at.* = .load_trust_metadata;
            push(&trace, allocator, .failed) catch {};
            return err;
        };
        defer bundle.deinit(allocator);

        try push(&trace, allocator, .verify_metadata_chain);
        trust_summary = mini_tuf.verifyStrict(allocator, &bundle, .{
            .state_path = options.trust_state_path,
        }) catch |err| {
            failed_at.* = .verify_metadata_chain;
            push(&trace, allocator, .failed) catch {};
            return err;
        };
    } else {
        try push(&trace, allocator, .verify_metadata_chain);
    }
    try push(&trace, allocator, .parse_knxfile);

    const parsed = abi_parser.parseLockfileStrict(allocator, source) catch |err| {
        failed_at.* = .parse_knxfile;
        push(&trace, allocator, .failed) catch {};
        return err;
    };
    errdefer allocator.free(parsed.canonical_json);
    const validation = validator.validateCanonicalJsonStrict(allocator, parsed.canonical_json) catch |err| {
        failed_at.* = .parse_knxfile;
        push(&trace, allocator, .failed) catch {};
        return err;
    };
    var toolchain_spec = validator.parseToolchainSpecStrict(allocator, parsed.canonical_json) catch |err| {
        failed_at.* = .parse_knxfile;
        push(&trace, allocator, .failed) catch {};
        return err;
    };
    defer toolchain_spec.deinit(allocator);
    const knx_digest_hex = validator.computeKnxDigestHex(parsed.canonical_json);

    var install_session: ?toolchain_installer.InstallSession = null;
    if (toolchain_spec.source != null) {
        install_session = toolchain_installer.InstallSession.init(allocator, &toolchain_spec, .{
            .cache_root = ".kilnexus-cache",
            .verify_mode = validation.verify_mode,
        }) catch |err| {
            failed_at.* = .resolve_toolchain;
            push(&trace, allocator, .failed) catch {};
            return err;
        };
    }
    defer if (install_session) |*session| session.deinit();

    try push(&trace, allocator, .resolve_toolchain);
    if (install_session) |*session| {
        session.resolveToolchain() catch |err| {
            failed_at.* = .resolve_toolchain;
            push(&trace, allocator, .failed) catch {};
            return err;
        };
    }

    try push(&trace, allocator, .download_blob);
    if (install_session) |*session| {
        session.downloadBlob() catch |err| {
            failed_at.* = .download_blob;
            push(&trace, allocator, .failed) catch {};
            return err;
        };
    }

    try push(&trace, allocator, .verify_blob);
    if (install_session) |*session| {
        session.verifyBlob() catch |err| {
            failed_at.* = .verify_blob;
            push(&trace, allocator, .failed) catch {};
            return err;
        };
    }

    try push(&trace, allocator, .unpack_staging);
    if (install_session) |*session| {
        session.unpackStaging() catch |err| {
            failed_at.* = .unpack_staging;
            push(&trace, allocator, .failed) catch {};
            return err;
        };
    }

    try push(&trace, allocator, .compute_tree_root);
    if (install_session) |*session| {
        session.computeTreeRoot() catch |err| {
            failed_at.* = .compute_tree_root;
            push(&trace, allocator, .failed) catch {};
            return err;
        };
    }

    try push(&trace, allocator, .verify_tree_root);
    if (install_session) |*session| {
        session.verifyTreeRoot() catch |err| {
            failed_at.* = .verify_tree_root;
            push(&trace, allocator, .failed) catch {};
            return err;
        };
    }

    try push(&trace, allocator, .seal_cache_object);
    if (install_session) |*session| {
        session.sealCacheObject() catch |err| {
            failed_at.* = .seal_cache_object;
            push(&trace, allocator, .failed) catch {};
            return err;
        };
    }

    try push(&trace, allocator, .execute_build_graph);
    try push(&trace, allocator, .verify_outputs);
    try push(&trace, allocator, .atomic_publish);
    try push(&trace, allocator, .done);

    return .{
        .trace = trace,
        .canonical_json = parsed.canonical_json,
        .verify_mode = validation.verify_mode,
        .knx_digest_hex = knx_digest_hex,
        .trust = trust_summary,
        .final_state = .done,
    };
}

fn classifyByState(state: State, err: anyerror) kx_error.Code {
    return switch (state) {
        .init => kx_error.classifyIo(err),
        .load_trust_metadata, .verify_metadata_chain => kx_error.classifyTrust(err),
        .parse_knxfile => kx_error.classifyParse(err),
        .resolve_toolchain, .download_blob, .unpack_staging, .seal_cache_object => kx_error.classifyIo(err),
        .verify_blob => kx_error.classifyIntegrity(err),
        .compute_tree_root, .verify_tree_root => kx_error.classifyIntegrity(err),
        .execute_build_graph => kx_error.classifyBuild(err),
        .verify_outputs, .atomic_publish => kx_error.classifyPublish(err),
        else => .KX_INTERNAL,
    };
}

fn normalizeCauseByState(state: State, err: anyerror) anyerror {
    return switch (state) {
        .init, .resolve_toolchain, .download_blob, .unpack_staging, .seal_cache_object => kx_error.normalizeIo(err),
        .load_trust_metadata, .verify_metadata_chain => mini_tuf.normalizeError(err),
        .parse_knxfile => parse_errors.normalize(err),
        .verify_blob, .compute_tree_root, .verify_tree_root => kx_error.normalizeIntegrity(err),
        .execute_build_graph => kx_error.normalizeBuild(err),
        .verify_outputs, .atomic_publish => kx_error.normalizePublish(err),
        else => err,
    };
}

fn push(trace: *std.ArrayList(State), allocator: std.mem.Allocator, state: State) !void {
    try trace.append(allocator, state);
}

test "run completes bootstrap happy path" {
    const allocator = std.testing.allocator;
    const source =
        \\{
        \\  "version": 1,
        \\  "target": "x86_64-unknown-linux-musl",
        \\  "toolchain": {
        \\    "id": "zigcc-0.14.0",
        \\    "blob_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\    "tree_root": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        \\    "size": 1
        \\  },
        \\  "policy": {
        \\    "network": "off",
        \\    "clock": "fixed"
        \\  },
        \\  "env": {
        \\    "TZ": "UTC",
        \\    "LANG": "C",
        \\    "SOURCE_DATE_EPOCH": "1735689600"
        \\  },
        \\  "outputs": [
        \\    { "path": "kilnexus-out/app", "mode": "0755" }
        \\  ]
        \\}
    ;

    var result = try run(allocator, source);
    defer result.deinit(allocator);

    try std.testing.expectEqual(State.done, result.final_state);
    try std.testing.expectEqual(@as(usize, 15), result.trace.items.len);
    try std.testing.expectEqual(State.parse_knxfile, result.trace.items[3]);
    try std.testing.expectEqual(State.done, result.trace.items[result.trace.items.len - 1]);
    try std.testing.expectEqual(validator.VerifyMode.strict, result.verify_mode);
    try std.testing.expectEqual(@as(usize, 64), result.knx_digest_hex.len);
}

test "run fails on malformed lockfile" {
    const allocator = std.testing.allocator;
    const source = "version=1";

    try std.testing.expectError(error.Syntax, run(allocator, source));
}

test "run fails on policy violation" {
    const allocator = std.testing.allocator;
    const source =
        \\{
        \\  "version": 1,
        \\  "target": "x86_64-unknown-linux-musl",
        \\  "toolchain": {
        \\    "id": "zigcc-0.14.0",
        \\    "blob_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\    "tree_root": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        \\    "size": 1
        \\  },
        \\  "policy": {
        \\    "network": "on",
        \\    "clock": "fixed",
        \\    "verify_mode": "strict"
        \\  },
        \\  "env": {
        \\    "TZ": "UTC",
        \\    "LANG": "C",
        \\    "SOURCE_DATE_EPOCH": "1735689600"
        \\  },
        \\  "outputs": [
        \\    { "path": "kilnexus-out/app", "mode": "0755" }
        \\  ]
        \\}
    ;
    try std.testing.expectError(error.ValueInvalid, run(allocator, source));
}

test "attemptRunWithOptions returns structured parse error" {
    const allocator = std.testing.allocator;
    const source = "version=1";

    const attempt = attemptRunWithOptions(allocator, source, .{
        .trust_metadata_dir = null,
        .trust_state_path = null,
    });

    switch (attempt) {
        .success => |*result| {
            defer result.deinit(allocator);
            return error.ExpectedFailure;
        },
        .failure => |failure| {
            try std.testing.expectEqual(State.parse_knxfile, failure.at);
            try std.testing.expectEqual(kx_error.Code.KX_PARSE_SYNTAX, failure.code);
            try std.testing.expectEqual(error.Syntax, failure.cause);
        },
    }
}

test "attemptRunWithOptions maps integrity failure by error kind" {
    const allocator = std.testing.allocator;
    const source = "{}";

    const mapped = classifyByState(.verify_blob, normalizeCauseByState(.verify_blob, error.BlobHashMismatch));
    try std.testing.expectEqual(kx_error.Code.KX_INTEGRITY_BLOB_MISMATCH, mapped);

    const mapped_tree = classifyByState(.verify_tree_root, normalizeCauseByState(.verify_tree_root, error.PathTraversalDetected));
    try std.testing.expectEqual(kx_error.Code.KX_INTEGRITY_PATH_TRAVERSAL, mapped_tree);

    _ = source;
    _ = allocator;
}

test "attemptRunWithOptions maps publish failure by error kind" {
    const mapped = classifyByState(.atomic_publish, normalizeCauseByState(.atomic_publish, error.FsyncFailed));
    try std.testing.expectEqual(kx_error.Code.KX_PUBLISH_FSYNC_FAILED, mapped);
}

test "attemptRunFromPathWithOptions returns canonical io cause for missing input" {
    const allocator = std.testing.allocator;
    const attempt = attemptRunFromPathWithOptions(allocator, "__knx_missing_input__.knx", .{
        .trust_metadata_dir = null,
        .trust_state_path = null,
    });

    switch (attempt) {
        .success => |*result| {
            defer result.deinit(allocator);
            return error.ExpectedFailure;
        },
        .failure => |failure| {
            try std.testing.expectEqual(State.init, failure.at);
            try std.testing.expectEqual(kx_error.Code.KX_IO_NOT_FOUND, failure.code);
            try std.testing.expectEqual(error.IoNotFound, failure.cause);
        },
    }
}

test "attemptRunWithOptions fails at download when source file is missing" {
    const allocator = std.testing.allocator;
    const source =
        \\{
        \\  "version": 1,
        \\  "target": "x86_64-unknown-linux-musl",
        \\  "toolchain": {
        \\    "id": "zigcc-0.14.0",
        \\    "source": "file://__missing_blob__.bin",
        \\    "blob_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\    "tree_root": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        \\    "size": 1
        \\  },
        \\  "policy": {
        \\    "network": "off",
        \\    "clock": "fixed"
        \\  },
        \\  "env": {
        \\    "TZ": "UTC",
        \\    "LANG": "C",
        \\    "SOURCE_DATE_EPOCH": "1735689600"
        \\  },
        \\  "outputs": [
        \\    { "path": "kilnexus-out/app", "mode": "0755" }
        \\  ]
        \\}
    ;

    const attempt = attemptRunWithOptions(allocator, source, .{
        .trust_metadata_dir = null,
        .trust_state_path = null,
    });

    switch (attempt) {
        .success => |*result| {
            defer result.deinit(allocator);
            return error.ExpectedFailure;
        },
        .failure => |failure| {
            try std.testing.expectEqual(State.download_blob, failure.at);
            try std.testing.expectEqual(kx_error.Code.KX_IO_NOT_FOUND, failure.code);
            try std.testing.expectEqual(error.IoNotFound, failure.cause);
        },
    }
}
