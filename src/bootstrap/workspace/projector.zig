const builtin = @import("builtin");
const std = @import("std");
const error_names = @import("../../errors/error_names.zig");
const workspace_types = @import("types.zig");

const LinkMode = workspace_types.LinkMode;
const ProjectOptions = workspace_types.ProjectOptions;
const WorkspacePlan = workspace_types.WorkspacePlan;

pub fn projectWorkspace(
    allocator: std.mem.Allocator,
    plan: *const WorkspacePlan,
    build_id: []const u8,
    options: ProjectOptions,
) ![]u8 {
    const work_root = try std.fs.path.join(allocator, &.{ options.cache_root, "work", build_id });
    defer allocator.free(work_root);
    const workspace_root = try std.fs.path.join(allocator, &.{ work_root, "workspace" });
    errdefer allocator.free(workspace_root);

    if (try pathIsDirectory(work_root)) {
        try std.fs.cwd().deleteTree(work_root);
    }
    try std.fs.cwd().makePath(workspace_root);

    for (plan.mappings) |mapping| {
        const target_path = try std.fs.path.join(allocator, &.{ workspace_root, mapping.mount_path });
        defer allocator.free(target_path);

        if (std.fs.path.dirname(target_path)) |parent| {
            try std.fs.cwd().makePath(parent);
        }

        try projectMapping(mapping.source_abs_path, target_path, options.link_mode);
    }

    return workspace_root;
}

fn projectMapping(source_abs_path: []const u8, target_path: []const u8, link_mode: LinkMode) !void {
    if (builtin.os.tag == .windows) {
        // On mingw targets, libc hardlink symbol resolution is unreliable.
        // Keep projection functional with symlink-first and safe file-copy fallback.
        return projectWindows(source_abs_path, target_path, link_mode);
    }

    switch (link_mode) {
        .symlink_only => try std.fs.cwd().symLink(source_abs_path, target_path, .{}),
        .hardlink_then_symlink => {
            std.posix.link(source_abs_path, target_path) catch |err| {
                if (!shouldFallbackToSymlinkName(@errorName(err))) return err;
                try std.fs.cwd().symLink(source_abs_path, target_path, .{});
            };
        },
    }
}

fn projectWindows(source_abs_path: []const u8, target_path: []const u8, link_mode: LinkMode) !void {
    switch (link_mode) {
        .symlink_only, .hardlink_then_symlink => {
            std.fs.cwd().symLink(source_abs_path, target_path, .{}) catch {
                // Windows symlink availability depends on privilege/policy.
                // Fall back to byte copy to keep projection deterministic.
                try std.fs.cwd().copyFile(source_abs_path, std.fs.cwd(), target_path, .{});
            };
        },
    }
}

fn shouldFallbackToSymlinkName(err_name: []const u8) bool {
    return error_names.isSymlinkFallback(err_name);
}

fn pathIsDirectory(path: []const u8) !bool {
    var dir = std.fs.cwd().openDir(path, .{}) catch |err| switch (err) {
        error.FileNotFound, error.NotDir => return false,
        else => return err,
    };
    dir.close();
    return true;
}
