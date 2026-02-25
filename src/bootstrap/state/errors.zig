const std = @import("std");
const parse_errors = @import("../../parser/parse_errors.zig");
const mini_tuf = @import("../../trust/mini_tuf.zig");
const kx_error = @import("../../errors/kx_error.zig");
const state_types = @import("types.zig");

const State = state_types.State;

pub fn classifyByState(state: State, err: anyerror) kx_error.Code {
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

pub fn normalizeCauseByState(state: State, err: anyerror) anyerror {
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
