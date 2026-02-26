const std = @import("std");
const parse_errors = @import("../../parser/parse_errors.zig");
const mini_tuf = @import("../../trust/mini_tuf.zig");
const kx_error = @import("../../errors/kx_error.zig");
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

pub fn normalizeCauseByState(state: State, err: anyerror) FailureCause {
    return switch (state) {
        .init, .download_blob, .seal_cache_object => .{ .io = kx_error.normalizeIo(err) },
        .resolve_toolchain => normalizeResolveCause(err),
        .unpack_staging => normalizeUnpackCause(err),
        .load_trust_metadata, .verify_metadata_chain => .{ .trust = mini_tuf.normalizeError(err) },
        .parse_knxfile => .{ .parse = parse_errors.normalize(err) },
        .verify_blob, .compute_tree_root, .verify_tree_root => .{ .integrity = kx_error.normalizeIntegrity(err) },
        .execute_build_graph => normalizeExecuteCause(err),
        .verify_outputs, .atomic_publish => .{ .publish = kx_error.normalizePublish(err) },
        else => .{ .internal = {} },
    };
}

fn normalizeUnpackCause(err: anyerror) FailureCause {
    const integrity = kx_error.normalizeIntegrity(err);
    if (integrity != error.Internal) return .{ .integrity = integrity };
    return .{ .io = kx_error.normalizeIo(err) };
}

fn normalizeResolveCause(err: anyerror) FailureCause {
    const integrity = kx_error.normalizeIntegrity(err);
    if (integrity != error.Internal) return .{ .integrity = integrity };
    return .{ .io = kx_error.normalizeIo(err) };
}

fn normalizeExecuteCause(err: anyerror) FailureCause {
    const build = kx_error.normalizeBuild(err);
    if (build != error.Internal) return .{ .build = build };

    const integrity = kx_error.normalizeIntegrity(err);
    if (integrity != error.Internal) return .{ .integrity = integrity };

    const io = kx_error.normalizeIo(err);
    if (io != error.Internal) return .{ .io = io };

    return .{ .internal = {} };
}

test "classify/normalize maps integrity failure by error kind" {
    const mapped_blob = classifyByState(.verify_blob, normalizeCauseByState(.verify_blob, error.BlobHashMismatch));
    try std.testing.expectEqual(kx_error.Code.KX_INTEGRITY_BLOB_MISMATCH, mapped_blob);

    const mapped_tree = classifyByState(.verify_tree_root, normalizeCauseByState(.verify_tree_root, error.PathTraversalDetected));
    try std.testing.expectEqual(kx_error.Code.KX_INTEGRITY_PATH_TRAVERSAL, mapped_tree);

    const mapped_resolve = classifyByState(.resolve_toolchain, normalizeCauseByState(.resolve_toolchain, error.TreeRootMismatch));
    try std.testing.expectEqual(kx_error.Code.KX_INTEGRITY_TREE_MISMATCH, mapped_resolve);
}

test "classify/normalize maps publish failure by error kind" {
    const mapped_fsync = classifyByState(.atomic_publish, normalizeCauseByState(.atomic_publish, error.FsyncFailed));
    try std.testing.expectEqual(kx_error.Code.KX_PUBLISH_FSYNC_FAILED, mapped_fsync);

    const mapped_hash = classifyByState(.verify_outputs, normalizeCauseByState(.verify_outputs, error.OutputHashMismatch));
    try std.testing.expectEqual(kx_error.Code.KX_PUBLISH_OUTPUT_HASH_MISMATCH, mapped_hash);
}

test "classify/normalize maps unpack traversal as integrity error" {
    const mapped = classifyByState(.unpack_staging, normalizeCauseByState(.unpack_staging, error.PathTraversalDetected));
    try std.testing.expectEqual(kx_error.Code.KX_INTEGRITY_PATH_TRAVERSAL, mapped);
}
