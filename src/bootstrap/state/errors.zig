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
