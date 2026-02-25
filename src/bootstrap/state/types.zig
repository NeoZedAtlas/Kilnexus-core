const std = @import("std");
const validator = @import("../../knx/validator.zig");
const mini_tuf = @import("../../trust/mini_tuf.zig");
const kx_error = @import("../../errors/kx_error.zig");

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

pub const RunOptions = struct {
    trust_metadata_dir: ?[]const u8 = "trust",
    trust_state_path: ?[]const u8 = ".kilnexus-trust-state.json",
    cache_root: []const u8 = ".kilnexus-cache",
    output_root: []const u8 = "kilnexus-out",
};

pub const max_knxfile_bytes: usize = 4 * 1024 * 1024;
