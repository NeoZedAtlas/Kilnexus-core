const std = @import("std");
const abi_parser = @import("../parser/abi_parser.zig");
const parse_errors = @import("../parser/parse_errors.zig");
const validator = @import("../knx/validator.zig");
const mini_tuf = @import("../trust/mini_tuf.zig");
const kx_error = @import("../errors/kx_error.zig");
const toolchain_installer = @import("toolchain_installer.zig");
const workspace_projector = @import("workspace_projector.zig");
const build_executor = @import("build_executor.zig");
const output_publisher = @import("output_publisher.zig");

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
    workspace_cwd: []u8,
    verify_mode: validator.VerifyMode,
    knx_digest_hex: [64]u8,
    trust: mini_tuf.VerificationSummary,
    final_state: State,

    pub fn deinit(self: *RunResult, allocator: std.mem.Allocator) void {
        self.trace.deinit(allocator);
        allocator.free(self.canonical_json);
        allocator.free(self.workspace_cwd);
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
    cache_root: []const u8 = ".kilnexus-cache",
    output_root: []const u8 = "kilnexus-out",
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
    const tree_hex = std.fmt.bytesToHex(toolchain_spec.tree_root, .lower);
    const toolchain_tree_path = try std.fs.path.join(allocator, &.{
        options.cache_root,
        "cas",
        "official",
        "tree",
        tree_hex[0..],
    });
    defer allocator.free(toolchain_tree_path);
    var workspace_spec = validator.parseWorkspaceSpecStrict(allocator, parsed.canonical_json) catch |err| {
        failed_at.* = .parse_knxfile;
        push(&trace, allocator, .failed) catch {};
        return err;
    };
    defer workspace_spec.deinit(allocator);
    var build_spec = validator.parseBuildSpecStrict(allocator, parsed.canonical_json) catch |err| {
        failed_at.* = .parse_knxfile;
        push(&trace, allocator, .failed) catch {};
        return err;
    };
    defer build_spec.deinit(allocator);
    var output_spec = validator.parseOutputSpecStrict(allocator, parsed.canonical_json) catch |err| {
        failed_at.* = .parse_knxfile;
        push(&trace, allocator, .failed) catch {};
        return err;
    };
    defer output_spec.deinit(allocator);
    const knx_digest_hex = validator.computeKnxDigestHex(parsed.canonical_json);

    var install_session: ?toolchain_installer.InstallSession = null;
    if (toolchain_spec.source != null) {
        install_session = toolchain_installer.InstallSession.init(allocator, &toolchain_spec, .{
            .cache_root = options.cache_root,
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
    var workspace_plan = workspace_projector.planWorkspace(allocator, &workspace_spec, .{
        .cache_root = options.cache_root,
    }) catch |err| {
        failed_at.* = .execute_build_graph;
        push(&trace, allocator, .failed) catch {};
        return err;
    };
    defer workspace_plan.deinit(allocator);
    const build_id = try std.fmt.allocPrint(
        allocator,
        "{s}-{d}",
        .{ knx_digest_hex[0..16], std.time.microTimestamp() },
    );
    defer allocator.free(build_id);
    const workspace_cwd = workspace_projector.projectWorkspace(allocator, &workspace_plan, build_id, .{
        .cache_root = options.cache_root,
    }) catch |err| {
        failed_at.* = .execute_build_graph;
        push(&trace, allocator, .failed) catch {};
        return err;
    };
    errdefer allocator.free(workspace_cwd);
    build_executor.executeBuildGraph(allocator, workspace_cwd, &build_spec, .{
        .toolchain_root = toolchain_tree_path,
    }) catch |err| {
        failed_at.* = .execute_build_graph;
        push(&trace, allocator, .failed) catch {};
        return err;
    };

    try push(&trace, allocator, .verify_outputs);
    output_publisher.verifyWorkspaceOutputs(allocator, workspace_cwd, &output_spec) catch |err| {
        failed_at.* = .verify_outputs;
        push(&trace, allocator, .failed) catch {};
        return err;
    };

    try push(&trace, allocator, .atomic_publish);
    output_publisher.atomicPublish(allocator, workspace_cwd, &output_spec, build_id, .{
        .output_root = options.output_root,
        .knx_digest_hex = knx_digest_hex[0..],
        .verify_mode = @tagName(validation.verify_mode),
        .toolchain_tree_root_hex = tree_hex[0..],
    }) catch |err| {
        failed_at.* = .atomic_publish;
        push(&trace, allocator, .failed) catch {};
        return err;
    };

    try push(&trace, allocator, .done);

    return .{
        .trace = trace,
        .canonical_json = parsed.canonical_json,
        .workspace_cwd = workspace_cwd,
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
        .resolve_toolchain => classifyResolve(err),
        .download_blob, .seal_cache_object => kx_error.classifyIo(err),
        .unpack_staging => classifyUnpack(err),
        .verify_blob => kx_error.classifyIntegrity(err),
        .compute_tree_root, .verify_tree_root => kx_error.classifyIntegrity(err),
        .execute_build_graph => classifyExecute(err),
        .verify_outputs, .atomic_publish => kx_error.classifyPublish(err),
        else => .KX_INTERNAL,
    };
}

fn normalizeCauseByState(state: State, err: anyerror) anyerror {
    return switch (state) {
        .init, .download_blob, .seal_cache_object => kx_error.normalizeIo(err),
        .resolve_toolchain => normalizeResolveCause(err),
        .unpack_staging => normalizeUnpackCause(err),
        .load_trust_metadata, .verify_metadata_chain => mini_tuf.normalizeError(err),
        .parse_knxfile => parse_errors.normalize(err),
        .verify_blob, .compute_tree_root, .verify_tree_root => kx_error.normalizeIntegrity(err),
        .execute_build_graph => normalizeExecuteCause(err),
        .verify_outputs, .atomic_publish => kx_error.normalizePublish(err),
        else => err,
    };
}

fn classifyUnpack(err: anyerror) kx_error.Code {
    const integrity_code = kx_error.classifyIntegrity(err);
    if (integrity_code != .KX_INTERNAL) return integrity_code;
    return kx_error.classifyIo(err);
}

fn normalizeUnpackCause(err: anyerror) anyerror {
    const integrity = kx_error.normalizeIntegrity(err);
    if (integrity != error.Internal) return integrity;
    return kx_error.normalizeIo(err);
}

fn classifyResolve(err: anyerror) kx_error.Code {
    const integrity_code = kx_error.classifyIntegrity(err);
    if (integrity_code != .KX_INTERNAL) return integrity_code;
    return kx_error.classifyIo(err);
}

fn normalizeResolveCause(err: anyerror) anyerror {
    const integrity = kx_error.normalizeIntegrity(err);
    if (integrity != error.Internal) return integrity;
    return kx_error.normalizeIo(err);
}

fn classifyExecute(err: anyerror) kx_error.Code {
    const build_code = kx_error.classifyBuild(err);
    if (build_code != .KX_INTERNAL) return build_code;

    const integrity_code = kx_error.classifyIntegrity(err);
    if (integrity_code != .KX_INTERNAL) return integrity_code;

    return kx_error.classifyIo(err);
}

fn normalizeExecuteCause(err: anyerror) anyerror {
    const build = kx_error.normalizeBuild(err);
    if (build != error.Internal) return build;

    const integrity = kx_error.normalizeIntegrity(err);
    if (integrity != error.Internal) return integrity;

    const io = kx_error.normalizeIo(err);
    if (io != error.Internal) return io;

    return err;
}

fn push(trace: *std.ArrayList(State), allocator: std.mem.Allocator, state: State) !void {
    try trace.append(allocator, state);
}

test "run completes bootstrap happy path" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("project");
    try tmp.dir.writeFile(.{
        .sub_path = "project/src/app",
        .data = "artifact\n",
    });

    const host_source = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/project/src/app", .{tmp.sub_path[0..]});
    defer allocator.free(host_source);
    const cache_root = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/cache", .{tmp.sub_path[0..]});
    defer allocator.free(cache_root);
    const output_root = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/final/kilnexus-out", .{tmp.sub_path[0..]});
    defer allocator.free(output_root);

    const source = try std.fmt.allocPrint(
        allocator,
        \\{{
        \\  "version": 1,
        \\  "target": "x86_64-unknown-linux-musl",
        \\  "toolchain": {{
        \\    "id": "zigcc-0.14.0",
        \\    "blob_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\    "tree_root": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        \\    "size": 1
        \\  }},
        \\  "policy": {{
        \\    "network": "off",
        \\    "clock": "fixed"
        \\  }},
        \\  "env": {{
        \\    "TZ": "UTC",
        \\    "LANG": "C",
        \\    "SOURCE_DATE_EPOCH": "1735689600"
        \\  }},
        \\  "inputs": [
        \\    {{ "path": "src/app", "source": "{s}" }}
        \\  ],
        \\  "build": [
        \\    {{ "op": "knx.fs.copy", "from": "src/app", "to": "kilnexus-out/app" }}
        \\  ],
        \\  "outputs": [
        \\    {{ "path": "kilnexus-out/app", "mode": "0755" }}
        \\  ]
        \\}}
    ,
        .{host_source},
    );
    defer allocator.free(source);

    var result = try runWithOptions(allocator, source, .{
        .trust_metadata_dir = null,
        .trust_state_path = null,
        .cache_root = cache_root,
        .output_root = output_root,
    });
    defer result.deinit(allocator);

    try std.testing.expectEqual(State.done, result.final_state);
    try std.testing.expectEqual(@as(usize, 15), result.trace.items.len);
    try std.testing.expectEqual(State.parse_knxfile, result.trace.items[3]);
    try std.testing.expectEqual(State.done, result.trace.items[result.trace.items.len - 1]);
    try std.testing.expectEqual(validator.VerifyMode.strict, result.verify_mode);
    try std.testing.expectEqual(@as(usize, 64), result.knx_digest_hex.len);
    try std.testing.expect(result.workspace_cwd.len > 0);

    const pointer_path = try std.fmt.allocPrint(allocator, "{s}.current", .{output_root});
    defer allocator.free(pointer_path);
    const pointer_raw = try std.fs.cwd().readFileAlloc(allocator, pointer_path, 2048);
    defer allocator.free(pointer_raw);
    const pointer_doc = try std.json.parseFromSlice(std.json.Value, allocator, pointer_raw, .{});
    defer pointer_doc.deinit();
    const pointer_obj = switch (pointer_doc.value) {
        .object => |obj| obj,
        else => return error.TestUnexpectedResult,
    };
    const pointer_knx = switch (pointer_obj.get("knx_digest") orelse return error.TestUnexpectedResult) {
        .string => |text| text,
        else => return error.TestUnexpectedResult,
    };
    const pointer_verify_mode = switch (pointer_obj.get("verify_mode") orelse return error.TestUnexpectedResult) {
        .string => |text| text,
        else => return error.TestUnexpectedResult,
    };
    const pointer_tree_root = switch (pointer_obj.get("toolchain_tree_root") orelse return error.TestUnexpectedResult) {
        .string => |text| text,
        else => return error.TestUnexpectedResult,
    };
    const pointer_release = switch (pointer_obj.get("release_rel") orelse return error.TestUnexpectedResult) {
        .string => |text| text,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expectEqualStrings(result.knx_digest_hex[0..], pointer_knx);
    try std.testing.expectEqualStrings("strict", pointer_verify_mode);
    try std.testing.expectEqualStrings("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", pointer_tree_root);

    const published = try std.fs.path.join(allocator, &.{ output_root, pointer_release, "app" });
    defer allocator.free(published);
    const bytes = try std.fs.cwd().readFileAlloc(allocator, published, 1024);
    defer allocator.free(bytes);
    try std.testing.expectEqualStrings("artifact\n", bytes);
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
    const mapped_resolve_tree = classifyByState(.resolve_toolchain, normalizeCauseByState(.resolve_toolchain, error.TreeRootMismatch));
    try std.testing.expectEqual(kx_error.Code.KX_INTEGRITY_TREE_MISMATCH, mapped_resolve_tree);

    _ = source;
    _ = allocator;
}

test "attemptRunWithOptions maps publish failure by error kind" {
    const mapped = classifyByState(.atomic_publish, normalizeCauseByState(.atomic_publish, error.FsyncFailed));
    try std.testing.expectEqual(kx_error.Code.KX_PUBLISH_FSYNC_FAILED, mapped);
    const hash_mapped = classifyByState(.verify_outputs, normalizeCauseByState(.verify_outputs, error.OutputHashMismatch));
    try std.testing.expectEqual(kx_error.Code.KX_PUBLISH_OUTPUT_HASH_MISMATCH, hash_mapped);
}

test "attemptRunWithOptions maps unpack traversal as integrity error" {
    const mapped = classifyByState(.unpack_staging, normalizeCauseByState(.unpack_staging, error.PathTraversalDetected));
    try std.testing.expectEqual(kx_error.Code.KX_INTEGRITY_PATH_TRAVERSAL, mapped);
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

test "attemptRunWithOptions fails in execute stage when declared source is missing" {
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
        \\  "inputs": [
        \\    { "path": "src/main.c", "source": "__missing_source__.c" }
        \\  ],
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
            try std.testing.expectEqual(State.execute_build_graph, failure.at);
            try std.testing.expectEqual(kx_error.Code.KX_IO_NOT_FOUND, failure.code);
            try std.testing.expectEqual(error.IoNotFound, failure.cause);
        },
    }
}

test "attemptRunWithOptions maps missing toolchain for c.compile to build failure" {
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
        \\  "build": [
        \\    { "op": "knx.c.compile", "src": "src/main.c", "out": "obj/main.o" }
        \\  ],
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
            try std.testing.expectEqual(State.execute_build_graph, failure.at);
            try std.testing.expectEqual(kx_error.Code.KX_BUILD_TOOLCHAIN_MISSING, failure.code);
            try std.testing.expectEqual(error.ToolchainMissing, failure.cause);
        },
    }
}

test "attemptRunWithOptions fails at verify_outputs on declared output sha mismatch" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("project/src");
    try tmp.dir.writeFile(.{
        .sub_path = "project/src/app",
        .data = "artifact\n",
    });

    const host_source = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/project/src/app", .{tmp.sub_path[0..]});
    defer allocator.free(host_source);
    const cache_root = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/cache", .{tmp.sub_path[0..]});
    defer allocator.free(cache_root);
    const output_root = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/final/kilnexus-out", .{tmp.sub_path[0..]});
    defer allocator.free(output_root);

    const source = try std.fmt.allocPrint(
        allocator,
        \\{{
        \\  "version": 1,
        \\  "target": "x86_64-unknown-linux-musl",
        \\  "toolchain": {{
        \\    "id": "zigcc-0.14.0",
        \\    "blob_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\    "tree_root": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        \\    "size": 1
        \\  }},
        \\  "policy": {{
        \\    "network": "off",
        \\    "clock": "fixed"
        \\  }},
        \\  "env": {{
        \\    "TZ": "UTC",
        \\    "LANG": "C",
        \\    "SOURCE_DATE_EPOCH": "1735689600"
        \\  }},
        \\  "inputs": [
        \\    {{ "path": "src/app", "source": "{s}" }}
        \\  ],
        \\  "build": [
        \\    {{ "op": "knx.fs.copy", "from": "src/app", "to": "kilnexus-out/app" }}
        \\  ],
        \\  "outputs": [
        \\    {{
        \\      "path": "kilnexus-out/app",
        \\      "mode": "0755",
        \\      "sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        \\    }}
        \\  ]
        \\}}
    ,
        .{host_source},
    );
    defer allocator.free(source);

    const attempt = attemptRunWithOptions(allocator, source, .{
        .trust_metadata_dir = null,
        .trust_state_path = null,
        .cache_root = cache_root,
        .output_root = output_root,
    });

    switch (attempt) {
        .success => |*result| {
            defer result.deinit(allocator);
            return error.ExpectedFailure;
        },
        .failure => |failure| {
            try std.testing.expectEqual(State.verify_outputs, failure.at);
            try std.testing.expectEqual(kx_error.Code.KX_PUBLISH_OUTPUT_HASH_MISMATCH, failure.code);
            try std.testing.expectEqual(error.OutputHashMismatch, failure.cause);
        },
    }
}

test "run publishes archive.pack output from workspace inputs" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("project/obj");
    try tmp.dir.writeFile(.{
        .sub_path = "project/obj/a.o",
        .data = "obj-a\n",
    });
    try tmp.dir.writeFile(.{
        .sub_path = "project/obj/b.o",
        .data = "obj-b\n",
    });

    const source_a = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/project/obj/a.o", .{tmp.sub_path[0..]});
    defer allocator.free(source_a);
    const source_b = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/project/obj/b.o", .{tmp.sub_path[0..]});
    defer allocator.free(source_b);
    const cache_root = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/cache", .{tmp.sub_path[0..]});
    defer allocator.free(cache_root);
    const output_root = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/final/kilnexus-out", .{tmp.sub_path[0..]});
    defer allocator.free(output_root);

    const source = try std.fmt.allocPrint(
        allocator,
        \\{{
        \\  "version": 1,
        \\  "target": "x86_64-unknown-linux-musl",
        \\  "toolchain": {{
        \\    "id": "zigcc-0.14.0",
        \\    "blob_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\    "tree_root": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        \\    "size": 1
        \\  }},
        \\  "policy": {{
        \\    "network": "off",
        \\    "clock": "fixed"
        \\  }},
        \\  "env": {{
        \\    "TZ": "UTC",
        \\    "LANG": "C",
        \\    "SOURCE_DATE_EPOCH": "1735689600"
        \\  }},
        \\  "inputs": [
        \\    {{ "path": "obj/a.o", "source": "{s}" }},
        \\    {{ "path": "obj/b.o", "source": "{s}" }}
        \\  ],
        \\  "build": [
        \\    {{
        \\      "op": "knx.archive.pack",
        \\      "inputs": ["obj/a.o", "obj/b.o"],
        \\      "out": "kilnexus-out/objects.tar"
        \\    }}
        \\  ],
        \\  "outputs": [
        \\    {{ "path": "kilnexus-out/objects.tar", "mode": "0644" }}
        \\  ]
        \\}}
    ,
        .{ source_a, source_b },
    );
    defer allocator.free(source);

    var result = try runWithOptions(allocator, source, .{
        .trust_metadata_dir = null,
        .trust_state_path = null,
        .cache_root = cache_root,
        .output_root = output_root,
    });
    defer result.deinit(allocator);

    try std.testing.expectEqual(State.done, result.final_state);

    const pointer_path = try std.fmt.allocPrint(allocator, "{s}.current", .{output_root});
    defer allocator.free(pointer_path);
    const pointer_raw = try std.fs.cwd().readFileAlloc(allocator, pointer_path, 2048);
    defer allocator.free(pointer_raw);
    const pointer_doc = try std.json.parseFromSlice(std.json.Value, allocator, pointer_raw, .{});
    defer pointer_doc.deinit();
    const pointer_obj = switch (pointer_doc.value) {
        .object => |obj| obj,
        else => return error.TestUnexpectedResult,
    };
    const pointer_release = switch (pointer_obj.get("release_rel") orelse return error.TestUnexpectedResult) {
        .string => |text| text,
        else => return error.TestUnexpectedResult,
    };

    const archive_path = try std.fs.path.join(allocator, &.{ output_root, pointer_release, "objects.tar" });
    defer allocator.free(archive_path);
    var archive_file = try std.fs.cwd().openFile(archive_path, .{});
    defer archive_file.close();

    var read_buffer: [64 * 1024]u8 = undefined;
    var file_reader = archive_file.reader(&read_buffer);
    var file_name_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var link_name_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var it: std.tar.Iterator = .init(&file_reader.interface, .{
        .file_name_buffer = &file_name_buffer,
        .link_name_buffer = &link_name_buffer,
    });

    const entry1 = (try it.next()) orelse return error.TestUnexpectedResult;
    try std.testing.expect(entry1.kind == .file);
    try std.testing.expectEqualStrings("obj/a.o", entry1.name);
    const entry2 = (try it.next()) orelse return error.TestUnexpectedResult;
    try std.testing.expect(entry2.kind == .file);
    try std.testing.expectEqualStrings("obj/b.o", entry2.name);
}

test "run publishes archive.pack tar.gz output from workspace inputs" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("project/obj");
    try tmp.dir.writeFile(.{
        .sub_path = "project/obj/a.o",
        .data = "obj-a\n",
    });
    try tmp.dir.writeFile(.{
        .sub_path = "project/obj/b.o",
        .data = "obj-b\n",
    });

    const source_a = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/project/obj/a.o", .{tmp.sub_path[0..]});
    defer allocator.free(source_a);
    const source_b = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/project/obj/b.o", .{tmp.sub_path[0..]});
    defer allocator.free(source_b);
    const cache_root = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/cache", .{tmp.sub_path[0..]});
    defer allocator.free(cache_root);
    const output_root = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/final/kilnexus-out", .{tmp.sub_path[0..]});
    defer allocator.free(output_root);

    const source = try std.fmt.allocPrint(
        allocator,
        \\{{
        \\  "version": 1,
        \\  "target": "x86_64-unknown-linux-musl",
        \\  "toolchain": {{
        \\    "id": "zigcc-0.14.0",
        \\    "blob_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\    "tree_root": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        \\    "size": 1
        \\  }},
        \\  "policy": {{
        \\    "network": "off",
        \\    "clock": "fixed"
        \\  }},
        \\  "env": {{
        \\    "TZ": "UTC",
        \\    "LANG": "C",
        \\    "SOURCE_DATE_EPOCH": "1735689600"
        \\  }},
        \\  "inputs": [
        \\    {{ "path": "obj/a.o", "source": "{s}" }},
        \\    {{ "path": "obj/b.o", "source": "{s}" }}
        \\  ],
        \\  "build": [
        \\    {{
        \\      "op": "knx.archive.pack",
        \\      "inputs": ["obj/a.o", "obj/b.o"],
        \\      "out": "kilnexus-out/objects.tar.gz",
        \\      "format": "tar.gz"
        \\    }}
        \\  ],
        \\  "outputs": [
        \\    {{ "path": "kilnexus-out/objects.tar.gz", "mode": "0644" }}
        \\  ]
        \\}}
    ,
        .{ source_a, source_b },
    );
    defer allocator.free(source);

    var result = try runWithOptions(allocator, source, .{
        .trust_metadata_dir = null,
        .trust_state_path = null,
        .cache_root = cache_root,
        .output_root = output_root,
    });
    defer result.deinit(allocator);

    try std.testing.expectEqual(State.done, result.final_state);

    const pointer_path = try std.fmt.allocPrint(allocator, "{s}.current", .{output_root});
    defer allocator.free(pointer_path);
    const pointer_raw = try std.fs.cwd().readFileAlloc(allocator, pointer_path, 2048);
    defer allocator.free(pointer_raw);
    const pointer_doc = try std.json.parseFromSlice(std.json.Value, allocator, pointer_raw, .{});
    defer pointer_doc.deinit();
    const pointer_obj = switch (pointer_doc.value) {
        .object => |obj| obj,
        else => return error.TestUnexpectedResult,
    };
    const pointer_release = switch (pointer_obj.get("release_rel") orelse return error.TestUnexpectedResult) {
        .string => |text| text,
        else => return error.TestUnexpectedResult,
    };

    const archive_path = try std.fs.path.join(allocator, &.{ output_root, pointer_release, "objects.tar.gz" });
    defer allocator.free(archive_path);
    var archive_file = try std.fs.cwd().openFile(archive_path, .{});
    defer archive_file.close();

    var read_buffer: [64 * 1024]u8 = undefined;
    var file_reader = archive_file.reader(&read_buffer);
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var decompress = std.compress.flate.Decompress.init(&file_reader.interface, .gzip, &window);

    var file_name_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var link_name_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var it: std.tar.Iterator = .init(&decompress.reader, .{
        .file_name_buffer = &file_name_buffer,
        .link_name_buffer = &link_name_buffer,
    });

    const entry1 = (try it.next()) orelse return error.TestUnexpectedResult;
    try std.testing.expect(entry1.kind == .file);
    try std.testing.expectEqualStrings("obj/a.o", entry1.name);
    const entry2 = (try it.next()) orelse return error.TestUnexpectedResult;
    try std.testing.expect(entry2.kind == .file);
    try std.testing.expectEqualStrings("obj/b.o", entry2.name);
}
