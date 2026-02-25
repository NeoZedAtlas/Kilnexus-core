const std = @import("std");
const workspace_types = @import("../types.zig");
const path_utils = @import("../path_utils.zig");

const VirtualMapping = workspace_types.VirtualMapping;

pub fn appendMappingChecked(
    allocator: std.mem.Allocator,
    mappings: *std.ArrayList(VirtualMapping),
    seen_mounts: *std.StringHashMap(void),
    mount_path: []u8,
    source_abs_path: []u8,
    is_dependency: bool,
) !void {
    try path_utils.validateMountPath(mount_path);
    if (seen_mounts.contains(mount_path)) return error.DuplicateMountPath;
    try seen_mounts.put(mount_path, {});
    try mappings.append(allocator, .{
        .mount_path = mount_path,
        .source_abs_path = source_abs_path,
        .is_dependency = is_dependency,
    });
}

pub fn applyMountStripPrefix(
    allocator: std.mem.Allocator,
    rel_path: []const u8,
    strip_prefix_opt: ?[]u8,
) ![]u8 {
    const strip_prefix = strip_prefix_opt orelse return allocator.dupe(u8, rel_path);
    if (std.mem.eql(u8, rel_path, strip_prefix)) return error.InvalidBuildGraph;
    if (!std.mem.startsWith(u8, rel_path, strip_prefix)) return error.InvalidBuildGraph;
    if (rel_path.len <= strip_prefix.len or rel_path[strip_prefix.len] != '/') {
        return error.InvalidBuildGraph;
    }
    const trimmed = rel_path[strip_prefix.len + 1 ..];
    if (trimmed.len == 0) return error.InvalidBuildGraph;
    try path_utils.validateMountPath(trimmed);
    return allocator.dupe(u8, trimmed);
}

pub fn freeOwnedStrings(allocator: std.mem.Allocator, items: [][]u8) void {
    for (items) |item| allocator.free(item);
    allocator.free(items);
}

pub fn pathIsDirectory(path: []const u8) !bool {
    var dir = std.fs.cwd().openDir(path, .{}) catch |err| switch (err) {
        error.FileNotFound, error.NotDir => return false,
        else => return err,
    };
    dir.close();
    return true;
}

pub fn pathIsFile(path: []const u8) !bool {
    var file = std.fs.cwd().openFile(path, .{}) catch |err| switch (err) {
        error.FileNotFound, error.NotDir, error.IsDir => return false,
        else => return err,
    };
    file.close();
    return true;
}
