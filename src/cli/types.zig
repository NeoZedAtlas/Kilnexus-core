const std = @import("std");
const validator = @import("../knx/validator.zig");

pub const max_knxfile_bytes: usize = 4 * 1024 * 1024;

pub const CurrentPointerSummary = struct {
    build_id: []u8,
    release_rel: []u8,
    verify_mode: ?[]u8,
    toolchain_tree_root: ?[]u8,

    pub fn deinit(self: *CurrentPointerSummary, allocator: std.mem.Allocator) void {
        allocator.free(self.build_id);
        allocator.free(self.release_rel);
        if (self.verify_mode) |verify_mode| allocator.free(verify_mode);
        if (self.toolchain_tree_root) |tree_root| allocator.free(tree_root);
        self.* = undefined;
    }
};

pub const BootstrapCliArgs = struct {
    path: []const u8 = "Knxfile",
    trust_dir: ?[]const u8 = "trust",
    trust_state_path: ?[]const u8 = ".kilnexus-trust-state.json",
    cache_root: []const u8 = ".kilnexus-cache",
    output_root: []const u8 = "kilnexus-out",
    allow_unlocked: bool = false,
    json_output: bool = false,
};

pub const ParseOnlyCliArgs = struct {
    path: []const u8 = "Knxfile",
    json_output: bool = false,
};

pub const FreezeCliArgs = struct {
    path: []const u8 = "Knxfile",
    lock_path: ?[]const u8 = null,
    json_output: bool = false,
};

pub const JsonOnlyCliArgs = struct {
    json_output: bool = false,
};

pub const CacheCliArgs = struct {
    cache_root: []const u8 = ".kilnexus-cache",
    json_output: bool = false,
};

pub const ToolchainCliArgs = struct {
    cache_root: []const u8 = ".kilnexus-cache",
    json_output: bool = false,
};

pub const DoctorCliArgs = struct {
    cache_root: []const u8 = ".kilnexus-cache",
    output_root: []const u8 = "kilnexus-out",
    trust_dir: ?[]const u8 = "trust",
    json_output: bool = false,
};

pub const CleanScopeSet = struct {
    work: bool = false,
    staging: bool = false,
    local: bool = false,
    third_party: bool = false,
    official: bool = false,
    releases: bool = false,

    pub fn default() CleanScopeSet {
        return .{
            .work = true,
            .staging = true,
        };
    }

    pub fn all() CleanScopeSet {
        return .{
            .work = true,
            .staging = true,
            .local = true,
            .third_party = true,
            .official = true,
            .releases = true,
        };
    }
};

pub const CleanCliArgs = struct {
    cache_root: []const u8 = ".kilnexus-cache",
    output_root: []const u8 = "kilnexus-out",
    scopes: CleanScopeSet = CleanScopeSet.default(),
    older_than_secs: u64 = 72 * 60 * 60,
    toolchain_tree_root: ?[]const u8 = null,
    toolchain_prune: bool = false,
    keep_last: usize = 1,
    official_max_bytes: ?u64 = null,
    apply: bool = false,
    json_output: bool = false,
};

pub const CliCommand = enum {
    build,
    freeze,
    validate,
    plan,
    graph,
    doctor,
    clean,
    cache,
    toolchain,
    version,
};

pub const CommandSelection = struct {
    command: CliCommand,
    args: []const []const u8,
};

pub const KnxSummary = struct {
    canonical_json: []u8,
    validation: validator.ValidationSummary,
    toolchain_spec: validator.ToolchainSpec,
    workspace_spec: validator.WorkspaceSpec,
    build_spec: validator.BuildSpec,
    output_spec: validator.OutputSpec,
    knx_digest_hex: [64]u8,

    pub fn deinit(self: *KnxSummary, allocator: std.mem.Allocator) void {
        allocator.free(self.canonical_json);
        self.toolchain_spec.deinit(allocator);
        self.workspace_spec.deinit(allocator);
        self.build_spec.deinit(allocator);
        self.output_spec.deinit(allocator);
        self.* = undefined;
    }
};
