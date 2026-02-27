const std = @import("std");

pub const LinkMode = enum {
    hardlink_then_symlink,
    symlink_only,
};

pub const ProjectOptions = struct {
    cache_root: []const u8 = ".kilnexus-cache",
    link_mode: LinkMode = .hardlink_then_symlink,
    remote_download_attempts: u8 = 3,
    remote_download_timeout_ms: u64 = 30_000,
    remote_download_max_bytes: u64 = 1024 * 1024 * 1024,
    remote_extract_max_files: usize = 100_000,
    remote_extract_max_total_bytes: u64 = 4 * 1024 * 1024 * 1024,
    remote_extract_max_file_bytes: u64 = 512 * 1024 * 1024,
    allow_insecure_http_source: bool = false,
};

pub const VirtualMapping = struct {
    mount_path: []u8,
    source_abs_path: []u8,
    is_dependency: bool,

    pub fn deinit(self: *VirtualMapping, allocator: std.mem.Allocator) void {
        allocator.free(self.mount_path);
        allocator.free(self.source_abs_path);
        self.* = undefined;
    }
};

pub const WorkspacePlan = struct {
    mappings: []VirtualMapping,

    pub fn deinit(self: *WorkspacePlan, allocator: std.mem.Allocator) void {
        for (self.mappings) |*mapping| mapping.deinit(allocator);
        allocator.free(self.mappings);
        self.* = undefined;
    }
};
