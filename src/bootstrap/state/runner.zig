const std = @import("std");
const abi_parser = @import("../../parser/abi_parser.zig");
const parse_errors = @import("../../parser/parse_errors.zig");
const validator = @import("../../knx/validator.zig");
const mini_tuf = @import("../../trust/mini_tuf.zig");
const toolchain_installer = @import("../toolchain_installer.zig");
const workspace_api = @import("../workspace/api.zig");
const build_executor = @import("../build_executor.zig");
const output_publisher = @import("../output_publisher.zig");
const state_types = @import("types.zig");

const State = state_types.State;
const RunResult = state_types.RunResult;
const RunOptions = state_types.RunOptions;

pub fn runWithOptionsCore(allocator: std.mem.Allocator, source: []const u8, options: RunOptions, failed_at: *State) !RunResult {
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
    validator.validateBuildWriteIsolation(&workspace_spec, &build_spec) catch |err| {
        failed_at.* = .parse_knxfile;
        push(&trace, allocator, .failed) catch {};
        return parse_errors.normalizeName(@errorName(err));
    };
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
    var workspace_plan = workspace_api.planWorkspace(allocator, &workspace_spec, .{
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
    const workspace_cwd = workspace_api.projectWorkspace(allocator, &workspace_plan, build_id, .{
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

fn push(trace: *std.ArrayList(State), allocator: std.mem.Allocator, state: State) !void {
    try trace.append(allocator, state);
}
