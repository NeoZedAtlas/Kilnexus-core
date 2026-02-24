const std = @import("std");
const validator = @import("../knx/validator.zig");

pub fn executeBuildGraph(
    allocator: std.mem.Allocator,
    workspace_cwd: []const u8,
    build_spec: *const validator.BuildSpec,
) !void {
    for (build_spec.ops) |op| {
        switch (op) {
            .fs_copy => |copy| try executeFsCopy(allocator, workspace_cwd, copy),
            .c_compile, .zig_link, .archive_pack => return error.OperatorExecutionFailed,
        }
    }
}

fn executeFsCopy(
    allocator: std.mem.Allocator,
    workspace_cwd: []const u8,
    copy: validator.FsCopyOp,
) !void {
    const source_path = try std.fs.path.join(allocator, &.{ workspace_cwd, copy.from_path });
    defer allocator.free(source_path);
    const target_path = try std.fs.path.join(allocator, &.{ workspace_cwd, copy.to_path });
    defer allocator.free(target_path);

    if (std.fs.path.dirname(target_path)) |parent| {
        try std.fs.cwd().makePath(parent);
    }

    if (try pathExists(target_path)) {
        std.fs.cwd().deleteFile(target_path) catch |err| switch (err) {
            error.IsDir => return error.OperatorExecutionFailed,
            else => return err,
        };
    }

    std.fs.cwd().copyFile(source_path, std.fs.cwd(), target_path, .{}) catch |err| switch (err) {
        error.FileNotFound, error.NotDir, error.IsDir => return error.OperatorExecutionFailed,
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

test "executeBuildGraph executes fs.copy inside workspace" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("workspace/src");
    try tmp.dir.writeFile(.{
        .sub_path = "workspace/src/main.c",
        .data = "int main(){return 0;}\n",
    });

    const workspace_cwd = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/workspace", .{tmp.sub_path[0..]});
    defer allocator.free(workspace_cwd);

    var ops = try allocator.alloc(validator.BuildOp, 1);
    ops[0] = .{
        .fs_copy = .{
            .from_path = try allocator.dupe(u8, "src/main.c"),
            .to_path = try allocator.dupe(u8, "kilnexus-out/app"),
        },
    };
    var build_spec: validator.BuildSpec = .{ .ops = ops };
    defer build_spec.deinit(allocator);

    try executeBuildGraph(allocator, workspace_cwd, &build_spec);

    const out_path = try std.fs.path.join(allocator, &.{ workspace_cwd, "kilnexus-out/app" });
    defer allocator.free(out_path);
    const out = try std.fs.cwd().readFileAlloc(allocator, out_path, 1024);
    defer allocator.free(out);
    try std.testing.expectEqualStrings("int main(){return 0;}\n", out);
}

test "executeBuildGraph fails on unimplemented builtin operator" {
    const allocator = std.testing.allocator;
    var ops = try allocator.alloc(validator.BuildOp, 1);
    ops[0] = .c_compile;
    var build_spec: validator.BuildSpec = .{ .ops = ops };
    defer build_spec.deinit(allocator);

    try std.testing.expectError(error.OperatorExecutionFailed, executeBuildGraph(allocator, ".", &build_spec));
}
