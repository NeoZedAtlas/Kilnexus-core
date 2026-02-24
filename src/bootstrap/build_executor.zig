const std = @import("std");
const validator = @import("../knx/validator.zig");

pub const ExecuteOptions = struct {
    toolchain_root: ?[]const u8 = null,
    max_output_bytes: usize = 256 * 1024,
};

pub fn executeBuildGraph(
    allocator: std.mem.Allocator,
    workspace_cwd: []const u8,
    build_spec: *const validator.BuildSpec,
    options: ExecuteOptions,
) !void {
    var zig_exe_path: ?[]u8 = null;
    defer if (zig_exe_path) |path| allocator.free(path);

    for (build_spec.ops) |op| {
        switch (op) {
            .fs_copy => |copy| try executeFsCopy(allocator, workspace_cwd, copy),
            .c_compile => |compile| {
                const zig_exe = try requireZigExecutable(allocator, options.toolchain_root, &zig_exe_path);
                try executeCCompile(allocator, workspace_cwd, zig_exe, compile, options.max_output_bytes);
            },
            .zig_link => |link| {
                const zig_exe = try requireZigExecutable(allocator, options.toolchain_root, &zig_exe_path);
                try executeZigLink(allocator, workspace_cwd, zig_exe, link, options.max_output_bytes);
            },
            .archive_pack => |pack| try executeArchivePack(allocator, workspace_cwd, pack),
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

fn executeCCompile(
    allocator: std.mem.Allocator,
    workspace_cwd: []const u8,
    zig_exe: []const u8,
    compile: validator.CCompileOp,
    max_output_bytes: usize,
) !void {
    const out_abs = try std.fs.path.join(allocator, &.{ workspace_cwd, compile.out_path });
    defer allocator.free(out_abs);
    if (std.fs.path.dirname(out_abs)) |parent| {
        try std.fs.cwd().makePath(parent);
    }

    const argv = [_][]const u8{
        zig_exe,
        "cc",
    };
    var full_argv: std.ArrayList([]const u8) = .empty;
    defer full_argv.deinit(allocator);
    try full_argv.appendSlice(allocator, &argv);
    for (compile.args) |arg| try full_argv.append(allocator, arg);
    try full_argv.append(allocator, "-c");
    try full_argv.append(allocator, compile.src_path);
    try full_argv.append(allocator, "-o");
    try full_argv.append(allocator, compile.out_path);
    try runCommand(allocator, workspace_cwd, full_argv.items, max_output_bytes);
}

fn executeZigLink(
    allocator: std.mem.Allocator,
    workspace_cwd: []const u8,
    zig_exe: []const u8,
    link: validator.ZigLinkOp,
    max_output_bytes: usize,
) !void {
    const out_abs = try std.fs.path.join(allocator, &.{ workspace_cwd, link.out_path });
    defer allocator.free(out_abs);
    if (std.fs.path.dirname(out_abs)) |parent| {
        try std.fs.cwd().makePath(parent);
    }

    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(allocator);
    try argv.append(allocator, zig_exe);
    try argv.append(allocator, "cc");
    for (link.args) |arg| try argv.append(allocator, arg);
    for (link.object_paths) |obj| try argv.append(allocator, obj);
    try argv.append(allocator, "-o");
    try argv.append(allocator, link.out_path);

    try runCommand(allocator, workspace_cwd, argv.items, max_output_bytes);
}

fn executeArchivePack(
    allocator: std.mem.Allocator,
    workspace_cwd: []const u8,
    pack: validator.ArchivePackOp,
) !void {
    const out_abs = try std.fs.path.join(allocator, &.{ workspace_cwd, pack.out_path });
    defer allocator.free(out_abs);
    if (std.fs.path.dirname(out_abs)) |parent| {
        try std.fs.cwd().makePath(parent);
    }

    if (try pathExists(out_abs)) {
        std.fs.cwd().deleteFile(out_abs) catch |err| switch (err) {
            error.IsDir => return error.OperatorExecutionFailed,
            else => return err,
        };
    }

    switch (pack.format) {
        .tar => try writeTarArchive(allocator, workspace_cwd, pack.input_paths, out_abs),
        .tar_gz => return error.OperatorExecutionFailed,
    }
}

fn writeTarArchive(
    allocator: std.mem.Allocator,
    workspace_cwd: []const u8,
    input_paths: [][]u8,
    out_abs: []const u8,
) !void {
    var out_file = std.fs.cwd().createFile(out_abs, .{}) catch |err| switch (err) {
        error.IsDir, error.FileNotFound, error.NotDir => return error.OperatorExecutionFailed,
        else => return err,
    };
    defer out_file.close();

    var out_buffer: [64 * 1024]u8 = undefined;
    var out_writer = out_file.writer(&out_buffer);
    var tar_writer: std.tar.Writer = .{ .underlying_writer = &out_writer.interface };

    for (input_paths) |input_path| {
        const input_abs = try std.fs.path.join(allocator, &.{ workspace_cwd, input_path });
        defer allocator.free(input_abs);

        var in_file = std.fs.cwd().openFile(input_abs, .{}) catch |err| switch (err) {
            error.FileNotFound, error.NotDir, error.IsDir => return error.OperatorExecutionFailed,
            else => return err,
        };
        defer in_file.close();

        const stat = in_file.stat() catch return error.OperatorExecutionFailed;
        if (stat.kind != .file) return error.OperatorExecutionFailed;

        var in_buffer: [32 * 1024]u8 = undefined;
        var in_reader = in_file.reader(&in_buffer);
        tar_writer.writeFileStream(input_path, stat.size, &in_reader.interface, .{
            .mode = 0o644,
            .mtime = 1,
        }) catch return error.OperatorExecutionFailed;
    }

    try out_writer.interface.flush();
}

fn runCommand(
    allocator: std.mem.Allocator,
    workspace_cwd: []const u8,
    argv: []const []const u8,
    max_output_bytes: usize,
) !void {
    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = argv,
        .cwd = workspace_cwd,
        .max_output_bytes = max_output_bytes,
    }) catch |err| switch (err) {
        error.FileNotFound => return error.ToolchainNotFound,
        else => return err,
    };
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    switch (result.term) {
        .Exited => |code| if (code != 0) return error.OperatorExecutionFailed,
        else => return error.OperatorExecutionFailed,
    }
}

fn requireZigExecutable(
    allocator: std.mem.Allocator,
    toolchain_root: ?[]const u8,
    cache: *?[]u8,
) ![]const u8 {
    if (cache.*) |path| return path;
    const root = toolchain_root orelse return error.ToolchainNotFound;
    cache.* = try resolveZigExecutable(allocator, root);
    return cache.*.?;
}

fn resolveZigExecutable(allocator: std.mem.Allocator, toolchain_root: []const u8) ![]u8 {
    const is_windows = @import("builtin").os.tag == .windows;
    const candidates = if (is_windows)
        [_][]const u8{
            "zig.exe",
            "bin/zig.exe",
        }
    else
        [_][]const u8{
            "zig",
            "bin/zig",
        };

    for (candidates) |rel| {
        const candidate = try std.fs.path.join(allocator, &.{ toolchain_root, rel });
        errdefer allocator.free(candidate);
        if (try pathIsFile(candidate)) return candidate;
        allocator.free(candidate);
    }
    return error.ToolchainNotFound;
}

fn pathExists(path: []const u8) !bool {
    std.fs.cwd().access(path, .{}) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    return true;
}

fn pathIsFile(path: []const u8) !bool {
    var file = std.fs.cwd().openFile(path, .{}) catch |err| switch (err) {
        error.FileNotFound, error.NotDir => return false,
        else => return err,
    };
    file.close();
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

    try executeBuildGraph(allocator, workspace_cwd, &build_spec, .{});

    const out_path = try std.fs.path.join(allocator, &.{ workspace_cwd, "kilnexus-out/app" });
    defer allocator.free(out_path);
    const out = try std.fs.cwd().readFileAlloc(allocator, out_path, 1024);
    defer allocator.free(out);
    try std.testing.expectEqualStrings("int main(){return 0;}\n", out);
}

test "executeBuildGraph reports missing toolchain for c.compile" {
    const allocator = std.testing.allocator;
    var ops = try allocator.alloc(validator.BuildOp, 1);
    ops[0] = .{
        .c_compile = .{
            .src_path = try allocator.dupe(u8, "src/main.c"),
            .out_path = try allocator.dupe(u8, "obj/main.o"),
            .args = try allocator.alloc([]u8, 0),
        },
    };
    var build_spec: validator.BuildSpec = .{ .ops = ops };
    defer build_spec.deinit(allocator);

    try std.testing.expectError(
        error.ToolchainNotFound,
        executeBuildGraph(allocator, ".", &build_spec, .{}),
    );
}

test "executeBuildGraph packs archive in workspace" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("workspace/obj");
    try tmp.dir.writeFile(.{
        .sub_path = "workspace/obj/a.o",
        .data = "obj-a\n",
    });
    try tmp.dir.writeFile(.{
        .sub_path = "workspace/obj/b.o",
        .data = "obj-b\n",
    });

    const workspace_cwd = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/workspace", .{tmp.sub_path[0..]});
    defer allocator.free(workspace_cwd);

    var inputs = try allocator.alloc([]u8, 2);
    inputs[0] = try allocator.dupe(u8, "obj/a.o");
    inputs[1] = try allocator.dupe(u8, "obj/b.o");

    var ops = try allocator.alloc(validator.BuildOp, 1);
    ops[0] = .{
        .archive_pack = .{
            .input_paths = inputs,
            .out_path = try allocator.dupe(u8, "kilnexus-out/objects.tar"),
            .format = .tar,
        },
    };
    var build_spec: validator.BuildSpec = .{ .ops = ops };
    defer build_spec.deinit(allocator);

    try executeBuildGraph(allocator, workspace_cwd, &build_spec, .{});

    const archive_path = try std.fs.path.join(allocator, &.{ workspace_cwd, "kilnexus-out/objects.tar" });
    defer allocator.free(archive_path);
    var archive_file = try std.fs.cwd().openFile(archive_path, .{});
    defer archive_file.close();

    var read_buffer: [64 * 1024]u8 = undefined;
    var file_reader = archive_file.reader(&read_buffer);
    var file_name_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var link_name_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var it: std.tar.Iterator = .init(&file_reader.interface, .{
        .file_name_buffer = &file_name_buffer,
        .link_name_buffer = &link_name_buffer,
    });

    const entry1 = (try it.next()) orelse return error.TestUnexpectedResult;
    try std.testing.expect(entry1.kind == .file);
    try std.testing.expectEqualStrings("obj/a.o", entry1.name);

    const entry2 = (try it.next()) orelse return error.TestUnexpectedResult;
    try std.testing.expect(entry2.kind == .file);
    try std.testing.expectEqualStrings("obj/b.o", entry2.name);
}

test "executeBuildGraph rejects archive.pack tar.gz until gzip writer is stabilized" {
    const allocator = std.testing.allocator;
    var inputs = try allocator.alloc([]u8, 1);
    inputs[0] = try allocator.dupe(u8, "obj/a.o");

    var ops = try allocator.alloc(validator.BuildOp, 1);
    ops[0] = .{
        .archive_pack = .{
            .input_paths = inputs,
            .out_path = try allocator.dupe(u8, "kilnexus-out/objects.tar.gz"),
            .format = .tar_gz,
        },
    };
    var build_spec: validator.BuildSpec = .{ .ops = ops };
    defer build_spec.deinit(allocator);

    try std.testing.expectError(
        error.OperatorExecutionFailed,
        executeBuildGraph(allocator, ".", &build_spec, .{}),
    );
}
