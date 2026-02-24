const std = @import("std");
const validator = @import("../knx/validator.zig");

pub const PublishOptions = struct {
    output_root: []const u8 = "kilnexus-out",
};

pub fn verifyWorkspaceOutputs(
    allocator: std.mem.Allocator,
    workspace_cwd: []const u8,
    output_spec: *const validator.OutputSpec,
) !void {
    for (output_spec.entries) |entry| {
        const source_path = try std.fs.path.join(allocator, &.{ workspace_cwd, entry.path });
        defer allocator.free(source_path);

        var file = std.fs.cwd().openFile(source_path, .{}) catch |err| switch (err) {
            error.FileNotFound, error.NotDir, error.IsDir => return error.OutputMissing,
            else => return err,
        };
        file.close();
    }
}

pub fn atomicPublish(
    allocator: std.mem.Allocator,
    workspace_cwd: []const u8,
    output_spec: *const validator.OutputSpec,
    build_id: []const u8,
    options: PublishOptions,
) !void {
    const stage_root = try std.fmt.allocPrint(allocator, "{s}.staging-{s}", .{
        options.output_root,
        build_id,
    });
    defer allocator.free(stage_root);

    try deletePathIfExists(stage_root);
    errdefer deletePathIfExists(stage_root) catch {};

    if (try pathExists(options.output_root)) return error.AtomicRenameFailed;

    for (output_spec.entries) |entry| {
        const rel = try outputRelativePath(entry.path);
        const source_path = try std.fs.path.join(allocator, &.{ workspace_cwd, entry.path });
        defer allocator.free(source_path);
        const staged_path = try std.fs.path.join(allocator, &.{ stage_root, rel });
        defer allocator.free(staged_path);

        if (std.fs.path.dirname(staged_path)) |parent| {
            try std.fs.cwd().makePath(parent);
        }

        std.fs.cwd().copyFile(source_path, std.fs.cwd(), staged_path, .{}) catch |err| switch (err) {
            error.FileNotFound, error.NotDir, error.IsDir => return error.OutputMissing,
            else => return err,
        };
    }

    std.fs.cwd().rename(stage_root, options.output_root) catch |err| switch (err) {
        error.PathAlreadyExists,
        error.AccessDenied,
        error.PermissionDenied,
        error.RenameAcrossMountPoints,
        => return error.AtomicRenameFailed,
        else => return err,
    };
}

fn outputRelativePath(path: []const u8) ![]const u8 {
    const prefix = "kilnexus-out/";
    if (!std.mem.startsWith(u8, path, prefix)) return error.OutputMissing;
    const rel = path[prefix.len..];
    if (rel.len == 0) return error.OutputMissing;
    return rel;
}

fn deletePathIfExists(path: []const u8) !void {
    if (!(try pathExists(path))) return;
    std.fs.cwd().deleteTree(path) catch |err| switch (err) {
        error.NotDir => try std.fs.cwd().deleteFile(path),
        else => return err,
    };
}

fn pathExists(path: []const u8) !bool {
    std.fs.cwd().access(path, .{}) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    return true;
}

test "verifyWorkspaceOutputs and atomicPublish publish declared outputs" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("workspace/kilnexus-out");
    try tmp.dir.writeFile(.{
        .sub_path = "workspace/kilnexus-out/app",
        .data = "artifact\n",
    });

    const workspace_cwd = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/workspace", .{tmp.sub_path[0..]});
    defer allocator.free(workspace_cwd);
    const output_root = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/published/kilnexus-out", .{tmp.sub_path[0..]});
    defer allocator.free(output_root);

    var entries = try allocator.alloc(validator.OutputEntry, 1);
    entries[0] = .{
        .path = try allocator.dupe(u8, "kilnexus-out/app"),
        .mode = 0o755,
    };
    var spec: validator.OutputSpec = .{ .entries = entries };
    defer spec.deinit(allocator);

    try verifyWorkspaceOutputs(allocator, workspace_cwd, &spec);
    try atomicPublish(allocator, workspace_cwd, &spec, "build-test", .{
        .output_root = output_root,
    });

    const published = try std.fs.path.join(allocator, &.{ output_root, "app" });
    defer allocator.free(published);
    const bytes = try std.fs.cwd().readFileAlloc(allocator, published, 1024);
    defer allocator.free(bytes);
    try std.testing.expectEqualStrings("artifact\n", bytes);
}

test "atomicPublish fails when output root already exists" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("workspace/kilnexus-out");
    try tmp.dir.writeFile(.{
        .sub_path = "workspace/kilnexus-out/app",
        .data = "artifact\n",
    });
    try tmp.dir.makePath("published/kilnexus-out");

    const workspace_cwd = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/workspace", .{tmp.sub_path[0..]});
    defer allocator.free(workspace_cwd);
    const output_root = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/published/kilnexus-out", .{tmp.sub_path[0..]});
    defer allocator.free(output_root);

    var entries = try allocator.alloc(validator.OutputEntry, 1);
    entries[0] = .{
        .path = try allocator.dupe(u8, "kilnexus-out/app"),
        .mode = 0o755,
    };
    var spec: validator.OutputSpec = .{ .entries = entries };
    defer spec.deinit(allocator);

    try std.testing.expectError(
        error.AtomicRenameFailed,
        atomicPublish(allocator, workspace_cwd, &spec, "build-test", .{
            .output_root = output_root,
        }),
    );
}
