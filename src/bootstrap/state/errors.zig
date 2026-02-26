const std = @import("std");
const kx_error = @import("../../errors/kx_error.zig");
const boundary_map = @import("../../errors/boundary_map.zig");
const state_types = @import("types.zig");

const State = state_types.State;
const FailureCause = state_types.FailureCause;

pub fn classifyByState(state: State, cause: FailureCause) kx_error.Code {
    _ = state;
    return switch (cause) {
        .io => |err| kx_error.classifyIo(err),
        .trust => |err| kx_error.classifyTrust(err),
        .parse => |err| kx_error.classifyParse(err),
        .integrity => |err| kx_error.classifyIntegrity(err),
        .build => |err| kx_error.classifyBuild(err),
        .publish => |err| kx_error.classifyPublish(err),
        .internal => .KX_INTERNAL,
    };
}

pub fn translateCauseByState(state: State, err_name: []const u8) FailureCause {
    return switch (state) {
        .init, .download_blob, .seal_cache_object => .{ .io = boundary_map.mapIo(err_name) },
        .resolve_toolchain => translateResolveCause(err_name),
        .unpack_staging => translateUnpackCause(err_name),
        .load_trust_metadata, .verify_metadata_chain => .{ .trust = boundary_map.mapTrust(err_name) },
        .parse_knxfile => .{ .parse = boundary_map.mapParse(err_name) },
        .verify_blob, .compute_tree_root, .verify_tree_root => .{ .integrity = boundary_map.mapIntegrity(err_name) },
        .execute_build_graph => translateExecuteCause(err_name),
        .verify_outputs, .atomic_publish => .{ .publish = boundary_map.mapPublish(err_name) },
        else => .{ .internal = {} },
    };
}

fn translateUnpackCause(err_name: []const u8) FailureCause {
    const integrity = boundary_map.mapIntegrity(err_name);
    if (integrity != error.Internal) return .{ .integrity = integrity };
    return .{ .io = boundary_map.mapIo(err_name) };
}

fn translateResolveCause(err_name: []const u8) FailureCause {
    const integrity = boundary_map.mapIntegrity(err_name);
    if (integrity != error.Internal) return .{ .integrity = integrity };
    return .{ .io = boundary_map.mapIo(err_name) };
}

fn translateExecuteCause(err_name: []const u8) FailureCause {
    const build = boundary_map.mapBuild(err_name);
    if (build != error.Internal) return .{ .build = build };

    const integrity = boundary_map.mapIntegrity(err_name);
    if (integrity != error.Internal) return .{ .integrity = integrity };

    const io = boundary_map.mapIo(err_name);
    if (io != error.Internal) return .{ .io = io };

    return .{ .internal = {} };
}

test "classify/translate maps integrity failure by error kind" {
    const mapped_blob = classifyByState(.verify_blob, translateCauseByState(.verify_blob, "BlobHashMismatch"));
    try std.testing.expectEqual(kx_error.Code.KX_INTEGRITY_BLOB_MISMATCH, mapped_blob);

    const mapped_tree = classifyByState(.verify_tree_root, translateCauseByState(.verify_tree_root, "PathTraversalDetected"));
    try std.testing.expectEqual(kx_error.Code.KX_INTEGRITY_PATH_TRAVERSAL, mapped_tree);

    const mapped_resolve = classifyByState(.resolve_toolchain, translateCauseByState(.resolve_toolchain, "TreeRootMismatch"));
    try std.testing.expectEqual(kx_error.Code.KX_INTEGRITY_TREE_MISMATCH, mapped_resolve);
}

test "classify/translate maps publish failure by error kind" {
    const mapped_fsync = classifyByState(.atomic_publish, translateCauseByState(.atomic_publish, "FsyncFailed"));
    try std.testing.expectEqual(kx_error.Code.KX_PUBLISH_FSYNC_FAILED, mapped_fsync);

    const mapped_hash = classifyByState(.verify_outputs, translateCauseByState(.verify_outputs, "OutputHashMismatch"));
    try std.testing.expectEqual(kx_error.Code.KX_PUBLISH_OUTPUT_HASH_MISMATCH, mapped_hash);
}

test "classify/translate maps unpack traversal as integrity error" {
    const mapped = classifyByState(.unpack_staging, translateCauseByState(.unpack_staging, "PathTraversalDetected"));
    try std.testing.expectEqual(kx_error.Code.KX_INTEGRITY_PATH_TRAVERSAL, mapped);
}
