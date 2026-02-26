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

pub fn translateCauseByState(state: State, err: anyerror) FailureCause {
    return switch (state) {
        .init, .download_blob, .seal_cache_object => .{ .io = boundary_map.mapIo(err) },
        .resolve_toolchain => translateResolveCause(err),
        .unpack_staging => translateUnpackCause(err),
        .load_trust_metadata, .verify_metadata_chain => .{ .trust = boundary_map.mapTrust(err) },
        .parse_knxfile => .{ .parse = boundary_map.mapParse(err) },
        .verify_blob, .compute_tree_root, .verify_tree_root => .{ .integrity = boundary_map.mapIntegrity(err) },
        .execute_build_graph => translateExecuteCause(err),
        .verify_outputs, .atomic_publish => .{ .publish = boundary_map.mapPublish(err) },
        else => .{ .internal = {} },
    };
}

fn translateUnpackCause(err: anyerror) FailureCause {
    const integrity = boundary_map.mapIntegrity(err);
    if (integrity != error.Internal) return .{ .integrity = integrity };
    return .{ .io = boundary_map.mapIo(err) };
}

fn translateResolveCause(err: anyerror) FailureCause {
    const integrity = boundary_map.mapIntegrity(err);
    if (integrity != error.Internal) return .{ .integrity = integrity };
    return .{ .io = boundary_map.mapIo(err) };
}

fn translateExecuteCause(err: anyerror) FailureCause {
    const build = boundary_map.mapBuild(err);
    if (build != error.Internal) return .{ .build = build };

    const integrity = boundary_map.mapIntegrity(err);
    if (integrity != error.Internal) return .{ .integrity = integrity };

    const io = boundary_map.mapIo(err);
    if (io != error.Internal) return .{ .io = io };

    return .{ .internal = {} };
}

test "classify/translate maps integrity failure by error kind" {
    const mapped_blob = classifyByState(.verify_blob, translateCauseByState(.verify_blob, error.BlobHashMismatch));
    try std.testing.expectEqual(kx_error.Code.KX_INTEGRITY_BLOB_MISMATCH, mapped_blob);

    const mapped_tree = classifyByState(.verify_tree_root, translateCauseByState(.verify_tree_root, error.PathTraversalDetected));
    try std.testing.expectEqual(kx_error.Code.KX_INTEGRITY_PATH_TRAVERSAL, mapped_tree);

    const mapped_resolve = classifyByState(.resolve_toolchain, translateCauseByState(.resolve_toolchain, error.TreeRootMismatch));
    try std.testing.expectEqual(kx_error.Code.KX_INTEGRITY_TREE_MISMATCH, mapped_resolve);
}

test "classify/translate maps publish failure by error kind" {
    const mapped_fsync = classifyByState(.atomic_publish, translateCauseByState(.atomic_publish, error.FsyncFailed));
    try std.testing.expectEqual(kx_error.Code.KX_PUBLISH_FSYNC_FAILED, mapped_fsync);

    const mapped_hash = classifyByState(.verify_outputs, translateCauseByState(.verify_outputs, error.OutputHashMismatch));
    try std.testing.expectEqual(kx_error.Code.KX_PUBLISH_OUTPUT_HASH_MISMATCH, mapped_hash);
}

test "classify/translate maps unpack traversal as integrity error" {
    const mapped = classifyByState(.unpack_staging, translateCauseByState(.unpack_staging, error.PathTraversalDetected));
    try std.testing.expectEqual(kx_error.Code.KX_INTEGRITY_PATH_TRAVERSAL, mapped);
}
