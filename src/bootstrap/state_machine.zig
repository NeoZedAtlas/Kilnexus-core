const std = @import("std");
const abi_parser = @import("../parser/abi_parser.zig");
const validator = @import("../knx/validator.zig");
const mini_tuf = @import("../trust/mini_tuf.zig");
const kx_error = @import("../errors/kx_error.zig");

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
        return .{
            .failure = .{
                .at = .init,
                .code = kx_error.classifyIo(err),
                .cause = err,
            },
        };
    };
    defer allocator.free(source);
    return attemptRunWithOptions(allocator, source, options);
}

pub fn attemptRunWithOptions(allocator: std.mem.Allocator, source: []const u8, options: RunOptions) RunAttempt {
    var failed_at: State = .init;
    const result = runWithOptionsCore(allocator, source, options, &failed_at) catch |err| {
        return .{
            .failure = .{
                .at = failed_at,
                .code = classifyByState(failed_at, err),
                .cause = err,
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
        var bundle = mini_tuf.loadFromDir(allocator, trust_dir_path) catch |err| {
            failed_at.* = .load_trust_metadata;
            push(&trace, allocator, .failed) catch {};
            return err;
        };
        defer bundle.deinit(allocator);

        try push(&trace, allocator, .verify_metadata_chain);
        trust_summary = mini_tuf.verify(allocator, &bundle, .{
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

    const parsed = abi_parser.parseLockfile(allocator, source) catch |err| {
        failed_at.* = .parse_knxfile;
        push(&trace, allocator, .failed) catch {};
        return err;
    };
    errdefer allocator.free(parsed.canonical_json);
    const validation = validator.validateCanonicalJson(allocator, parsed.canonical_json) catch |err| {
        failed_at.* = .parse_knxfile;
        push(&trace, allocator, .failed) catch {};
        return err;
    };
    const knx_digest_hex = validator.computeKnxDigestHex(parsed.canonical_json);

    try push(&trace, allocator, .resolve_toolchain);
    try push(&trace, allocator, .download_blob);
    try push(&trace, allocator, .verify_blob);
    try push(&trace, allocator, .unpack_staging);
    try push(&trace, allocator, .compute_tree_root);
    try push(&trace, allocator, .verify_tree_root);
    try push(&trace, allocator, .seal_cache_object);
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

    try std.testing.expectError(error.Schema, run(allocator, source));
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
    try std.testing.expectError(error.InvalidPolicyNetwork, run(allocator, source));
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
            try std.testing.expectEqual(error.Schema, failure.cause);
        },
    }
}

test "attemptRunWithOptions maps integrity failure by error kind" {
    const allocator = std.testing.allocator;
    const source = "{}";

    const mapped = classifyByState(.verify_blob, error.BlobHashMismatch);
    try std.testing.expectEqual(kx_error.Code.KX_INTEGRITY_BLOB_MISMATCH, mapped);

    const mapped_tree = classifyByState(.verify_tree_root, error.PathTraversalDetected);
    try std.testing.expectEqual(kx_error.Code.KX_INTEGRITY_PATH_TRAVERSAL, mapped_tree);

    _ = source;
    _ = allocator;
}

test "attemptRunWithOptions maps publish failure by error kind" {
    const mapped = classifyByState(.atomic_publish, error.FsyncFailed);
    try std.testing.expectEqual(kx_error.Code.KX_PUBLISH_FSYNC_FAILED, mapped);
}
