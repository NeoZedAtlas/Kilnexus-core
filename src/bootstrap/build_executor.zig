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
    var zig_lib_dir: ?[]u8 = null;
    defer if (zig_exe_path) |path| allocator.free(path);
    defer if (zig_lib_dir) |path| allocator.free(path);

    for (build_spec.ops) |op| {
        switch (op) {
            .fs_copy => |copy| try executeFsCopy(allocator, workspace_cwd, copy),
            .c_compile => |compile| {
                const zig_exe = try requireZigExecutable(allocator, options.toolchain_root, &zig_exe_path);
                if (zig_lib_dir == null) {
                    zig_lib_dir = try resolveZigLibDir(allocator, zig_exe);
                }
                try executeCCompile(allocator, workspace_cwd, zig_exe, zig_lib_dir.?, compile, options.max_output_bytes);
            },
            .zig_link => |link| {
                const zig_exe = try requireZigExecutable(allocator, options.toolchain_root, &zig_exe_path);
                if (zig_lib_dir == null) {
                    zig_lib_dir = try resolveZigLibDir(allocator, zig_exe);
                }
                try executeZigLink(allocator, workspace_cwd, zig_exe, zig_lib_dir.?, link, options.max_output_bytes);
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
    zig_lib_dir: []const u8,
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
    try runCommand(allocator, workspace_cwd, full_argv.items, max_output_bytes, zig_lib_dir);
}

fn executeZigLink(
    allocator: std.mem.Allocator,
    workspace_cwd: []const u8,
    zig_exe: []const u8,
    zig_lib_dir: []const u8,
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

    try runCommand(allocator, workspace_cwd, argv.items, max_output_bytes, zig_lib_dir);
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
        .tar_gz => try writeTarGzArchive(allocator, workspace_cwd, pack.input_paths, out_abs),
    }
}

fn writeTarGzArchive(
    allocator: std.mem.Allocator,
    workspace_cwd: []const u8,
    input_paths: [][]u8,
    out_abs: []const u8,
) !void {
    const temp_tar = try std.fmt.allocPrint(allocator, "{s}.tmp-tar-{d}", .{ out_abs, std.time.microTimestamp() });
    defer allocator.free(temp_tar);
    errdefer std.fs.cwd().deleteFile(temp_tar) catch {};

    try writeTarArchive(allocator, workspace_cwd, input_paths, temp_tar);
    try gzipFromFileStored(temp_tar, out_abs);
    std.fs.cwd().deleteFile(temp_tar) catch {};
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

fn gzipFromFileStored(input_path: []const u8, out_path: []const u8) !void {
    var input_file = std.fs.cwd().openFile(input_path, .{}) catch |err| switch (err) {
        error.FileNotFound, error.NotDir, error.IsDir => return error.OperatorExecutionFailed,
        else => return err,
    };
    defer input_file.close();

    var out_file = std.fs.cwd().createFile(out_path, .{}) catch |err| switch (err) {
        error.IsDir, error.FileNotFound, error.NotDir => return error.OperatorExecutionFailed,
        else => return err,
    };
    defer out_file.close();

    var out_buffer: [64 * 1024]u8 = undefined;
    var out_writer = out_file.writer(&out_buffer);
    // Deterministic gzip header: mtime=0, xfl=0, os=255.
    const gzip_header = [_]u8{ 0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff };
    out_writer.interface.writeAll(&gzip_header) catch return error.OperatorExecutionFailed;

    var crc: std.hash.Crc32 = .init();
    var gzip_size_mod32: u32 = 0;
    var buffer: [64 * 1024]u8 = undefined;

    while (true) {
        const read_len = input_file.read(&buffer) catch return error.OperatorExecutionFailed;
        if (read_len == 0) break;
        const chunk = buffer[0..read_len];
        crc.update(chunk);
        gzip_size_mod32 +%= @as(u32, @intCast(chunk.len));

        var offset: usize = 0;
        while (offset < chunk.len) {
            const block_len: usize = @min(@as(usize, 65_535), chunk.len - offset);
            try writeDeflateStoredBlock(&out_writer.interface, false, chunk[offset .. offset + block_len]);
            offset += block_len;
        }
    }

    try writeDeflateStoredBlock(&out_writer.interface, true, &.{});

    var crc_bytes: [4]u8 = undefined;
    var isize_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &crc_bytes, crc.final(), .little);
    std.mem.writeInt(u32, &isize_bytes, gzip_size_mod32, .little);
    out_writer.interface.writeAll(&crc_bytes) catch return error.OperatorExecutionFailed;
    out_writer.interface.writeAll(&isize_bytes) catch return error.OperatorExecutionFailed;
    out_writer.interface.flush() catch return error.OperatorExecutionFailed;
}

fn writeDeflateStoredBlock(writer: *std.Io.Writer, is_final: bool, payload: []const u8) !void {
    if (payload.len > 65_535) return error.OperatorExecutionFailed;

    const header = [_]u8{if (is_final) 0x01 else 0x00};
    writer.writeAll(&header) catch return error.OperatorExecutionFailed;

    const len_u16: u16 = @intCast(payload.len);
    var len_bytes: [2]u8 = undefined;
    var nlen_bytes: [2]u8 = undefined;
    std.mem.writeInt(u16, &len_bytes, len_u16, .little);
    std.mem.writeInt(u16, &nlen_bytes, ~len_u16, .little);
    writer.writeAll(&len_bytes) catch return error.OperatorExecutionFailed;
    writer.writeAll(&nlen_bytes) catch return error.OperatorExecutionFailed;
    if (payload.len != 0) {
        writer.writeAll(payload) catch return error.OperatorExecutionFailed;
    }
}

fn runCommand(
    allocator: std.mem.Allocator,
    workspace_cwd: []const u8,
    argv: []const []const u8,
    max_output_bytes: usize,
    zig_lib_dir: ?[]const u8,
) !void {
    var env_map = try std.process.getEnvMap(allocator);
    defer env_map.deinit();
    if (zig_lib_dir) |lib_dir| {
        try env_map.put("ZIG_LIB_DIR", lib_dir);
    }

    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = argv,
        .cwd = workspace_cwd,
        .env_map = &env_map,
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

fn resolveZigLibDir(allocator: std.mem.Allocator, zig_exe: []const u8) ![]u8 {
    const exe_dir = std.fs.path.dirname(zig_exe) orelse return error.ToolchainNotFound;

    const direct = try std.fs.path.join(allocator, &.{ exe_dir, "lib" });
    errdefer allocator.free(direct);
    if (try pathIsDirectory(direct)) return direct;
    allocator.free(direct);

    const parent = std.fs.path.dirname(exe_dir) orelse return error.ToolchainNotFound;
    const from_parent = try std.fs.path.join(allocator, &.{ parent, "lib" });
    errdefer allocator.free(from_parent);
    if (try pathIsDirectory(from_parent)) return from_parent;
    allocator.free(from_parent);

    return error.ToolchainNotFound;
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
        if (try pathIsFile(candidate)) {
            const absolute = try std.fs.cwd().realpathAlloc(allocator, candidate);
            allocator.free(candidate);
            return absolute;
        }
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

fn pathIsDirectory(path: []const u8) !bool {
    var dir = std.fs.cwd().openDir(path, .{}) catch |err| switch (err) {
        error.FileNotFound, error.NotDir => return false,
        else => return err,
    };
    dir.close();
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

test "executeBuildGraph packs archive.gz in workspace" {
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
            .out_path = try allocator.dupe(u8, "kilnexus-out/objects.tar.gz"),
            .format = .tar_gz,
        },
    };
    var build_spec: validator.BuildSpec = .{ .ops = ops };
    defer build_spec.deinit(allocator);

    try executeBuildGraph(allocator, workspace_cwd, &build_spec, .{});

    const archive_path = try std.fs.path.join(allocator, &.{ workspace_cwd, "kilnexus-out/objects.tar.gz" });
    defer allocator.free(archive_path);
    var archive_file = try std.fs.cwd().openFile(archive_path, .{});
    defer archive_file.close();

    var read_buffer: [64 * 1024]u8 = undefined;
    var file_reader = archive_file.reader(&read_buffer);
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var decompress = std.compress.flate.Decompress.init(&file_reader.interface, .gzip, &window);

    var file_name_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var link_name_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var it: std.tar.Iterator = .init(&decompress.reader, .{
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
