const std = @import("std");
const validator = @import("../../../knx/validator.zig");
const workspace_types = @import("../types.zig");
const path_utils = @import("../path_utils.zig");
const glob_utils = @import("../glob.zig");
const remote_utils = @import("../remote.zig");
const local_mounts = @import("local_mounts.zig");
const common = @import("common.zig");

const VirtualMapping = workspace_types.VirtualMapping;

pub fn appendRemoteMappingsForMount(
    allocator: std.mem.Allocator,
    mappings: *std.ArrayList(VirtualMapping),
    seen_mounts: *std.StringHashMap(void),
    mount: validator.WorkspaceMountSpec,
    source_ref: local_mounts.SourceRef,
    remote: remote_utils.Prepared,
) !void {
    if (!remote.is_tree) {
        if (mount.strip_prefix != null) return error.InvalidBuildGraph;
        if (source_ref.sub_path != null) return error.InvalidBuildGraph;
        const mount_path = try allocator.dupe(u8, mount.target);
        errdefer allocator.free(mount_path);
        const source_abs = try allocator.dupe(u8, remote.root_abs_path);
        errdefer allocator.free(source_abs);
        try common.appendMappingChecked(allocator, mappings, seen_mounts, mount_path, source_abs, true);
        return;
    }

    const selected_root_abs = if (source_ref.sub_path) |sub_path| blk: {
        const joined = try std.fs.path.join(allocator, &.{ remote.root_abs_path, sub_path });
        defer allocator.free(joined);
        const abs = try std.fs.cwd().realpathAlloc(allocator, joined);
        errdefer allocator.free(abs);
        try path_utils.ensurePathWithinRoot(abs, remote.root_abs_path);
        break :blk abs;
    } else try allocator.dupe(u8, remote.root_abs_path);
    defer allocator.free(selected_root_abs);

    if (try common.pathIsFile(selected_root_abs)) {
        if (mount.strip_prefix != null) return error.InvalidBuildGraph;
        const mount_path = try allocator.dupe(u8, mount.target);
        errdefer allocator.free(mount_path);
        const source_abs = try allocator.dupe(u8, selected_root_abs);
        errdefer allocator.free(source_abs);
        try common.appendMappingChecked(allocator, mappings, seen_mounts, mount_path, source_abs, true);
        return;
    }

    if (!(try common.pathIsDirectory(selected_root_abs))) return error.FileNotFound;
    const files = try listFilesRelativeTo(allocator, selected_root_abs);
    defer common.freeOwnedStrings(allocator, files);

    for (files) |rel| {
        const source_abs = try std.fs.path.join(allocator, &.{ selected_root_abs, rel });
        errdefer allocator.free(source_abs);
        const source_abs_real = try std.fs.cwd().realpathAlloc(allocator, source_abs);
        allocator.free(source_abs);
        errdefer allocator.free(source_abs_real);
        const projected_rel = try common.applyMountStripPrefix(allocator, rel, mount.strip_prefix);
        defer allocator.free(projected_rel);
        const mount_path = try path_utils.joinPosix(allocator, mount.target, projected_rel);
        errdefer allocator.free(mount_path);
        try common.appendMappingChecked(allocator, mappings, seen_mounts, mount_path, source_abs_real, true);
    }
}

fn listFilesRelativeTo(allocator: std.mem.Allocator, root_abs: []const u8) ![][]u8 {
    var root_dir = try std.fs.cwd().openDir(root_abs, .{ .iterate = true });
    defer root_dir.close();

    var walker = try root_dir.walk(allocator);
    defer walker.deinit();

    var files: std.ArrayList([]u8) = .empty;
    errdefer {
        for (files.items) |item| allocator.free(item);
        files.deinit(allocator);
    }

    while (try walker.next()) |entry| {
        if (entry.kind != .file) continue;
        const rel = try glob_utils.normalizePathOwned(allocator, entry.path);
        try files.append(allocator, rel);
    }
    std.sort.pdq([]u8, files.items, {}, struct {
        fn lessThan(_: void, lhs: []u8, rhs: []u8) bool {
            return std.mem.order(u8, lhs, rhs) == .lt;
        }
    }.lessThan);
    return files.toOwnedSlice(allocator);
}
