const std = @import("std");
const validator = @import("../knx/validator.zig");

pub const PublishOptions = struct {
    output_root: []const u8 = "kilnexus-out",
    knx_digest_hex: ?[]const u8 = null,
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
        defer file.close();

        if (entry.sha256) |expected_digest| {
            const actual = try hashOpenFile(&file);
            if (!std.mem.eql(u8, &actual, &expected_digest)) {
                return error.OutputHashMismatch;
            }
        }
    }
}

pub fn atomicPublish(
    allocator: std.mem.Allocator,
    workspace_cwd: []const u8,
    output_spec: *const validator.OutputSpec,
    build_id: []const u8,
    options: PublishOptions,
) !void {
    const release_parent = try std.fs.path.join(allocator, &.{ options.output_root, "releases" });
    defer allocator.free(release_parent);
    const release_root = try std.fs.path.join(allocator, &.{ release_parent, build_id });
    defer allocator.free(release_root);
    const stage_root = try std.fmt.allocPrint(allocator, "{s}.staging", .{release_root});
    defer allocator.free(stage_root);
    const release_rel = try std.fmt.allocPrint(allocator, "releases/{s}", .{build_id});
    defer allocator.free(release_rel);

    try std.fs.cwd().makePath(release_parent);
    try deletePathIfExists(stage_root);
    errdefer deletePathIfExists(stage_root) catch {};

    if (try pathExists(release_root)) return error.AtomicRenameFailed;

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

        if (std.fs.has_executable_bit) {
            var staged_file = std.fs.cwd().openFile(staged_path, .{}) catch |err| switch (err) {
                error.FileNotFound, error.NotDir, error.IsDir => return error.OutputMissing,
                else => return err,
            };
            defer staged_file.close();
            staged_file.chmod(entry.mode) catch return error.PermissionDenied;
            staged_file.sync() catch return error.FsyncFailed;
        } else {
            try syncFilePath(staged_path);
        }

        if (std.fs.path.dirname(staged_path)) |parent| {
            try syncDirPath(parent);
        }
    }

    std.fs.cwd().rename(stage_root, release_root) catch |err| switch (err) {
        error.PathAlreadyExists,
        error.AccessDenied,
        error.PermissionDenied,
        error.RenameAcrossMountPoints,
        => return error.AtomicRenameFailed,
        else => return err,
    };

    try syncDirPath(release_parent);
    try syncDirPath(options.output_root);
    try writeCurrentPointer(
        allocator,
        options.output_root,
        build_id,
        release_rel,
        release_root,
        output_spec,
        options.knx_digest_hex,
    );
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

fn syncFilePath(path: []const u8) !void {
    var file = std.fs.cwd().openFile(path, .{}) catch |err| switch (err) {
        error.FileNotFound, error.NotDir, error.IsDir => return error.OutputMissing,
        else => return err,
    };
    defer file.close();
    file.sync() catch return error.FsyncFailed;
}

fn syncDirPath(path: []const u8) !void {
    if (@import("builtin").os.tag == .windows) return;
    var dir = std.fs.cwd().openDir(path, .{}) catch |err| switch (err) {
        error.FileNotFound, error.NotDir => return error.AtomicRenameFailed,
        else => return err,
    };
    defer dir.close();
    dir.sync() catch return error.FsyncFailed;
}

fn writeCurrentPointer(
    allocator: std.mem.Allocator,
    output_root: []const u8,
    build_id: []const u8,
    release_rel: []const u8,
    release_root: []const u8,
    output_spec: *const validator.OutputSpec,
    knx_digest_hex: ?[]const u8,
) !void {
    const pointer_path = try std.fmt.allocPrint(allocator, "{s}.current", .{output_root});
    defer allocator.free(pointer_path);

    var write_buffer: [2 * 1024]u8 = undefined;
    var atomic_file = try std.fs.cwd().atomicFile(pointer_path, .{
        .mode = 0o644,
        .make_path = true,
        .write_buffer = &write_buffer,
    });
    defer atomic_file.deinit();

    var writer = &atomic_file.file_writer.interface;
    const published_at_unix_ms = std.time.milliTimestamp();
    try writer.writeAll("{\"version\":2,\"build_id\":");
    try std.json.Stringify.encodeJsonString(build_id, .{}, writer);
    try writer.writeAll(",\"release_rel\":");
    try std.json.Stringify.encodeJsonString(release_rel, .{}, writer);
    if (knx_digest_hex) |digest| {
        try writer.writeAll(",\"knx_digest\":");
        try std.json.Stringify.encodeJsonString(digest, .{}, writer);
    }
    try writer.writeAll(",\"outputs\":[");
    for (output_spec.entries, 0..) |entry, idx| {
        const rel = try outputRelativePath(entry.path);
        const output_abs = try std.fs.path.join(allocator, &.{ release_root, rel });
        defer allocator.free(output_abs);

        var file = std.fs.cwd().openFile(output_abs, .{}) catch |err| switch (err) {
            error.FileNotFound, error.NotDir, error.IsDir => return error.OutputMissing,
            else => return err,
        };
        defer file.close();
        const hashed = try hashOpenFileWithSize(&file);
        const digest_hex = std.fmt.bytesToHex(hashed.digest, .lower);

        if (idx != 0) try writer.writeAll(",");
        try writer.writeAll("{\"path\":");
        try std.json.Stringify.encodeJsonString(entry.path, .{}, writer);
        try writer.writeAll(",\"sha256\":\"");
        try writer.writeAll(digest_hex[0..]);
        try writer.writeAll("\",\"size\":");
        try writer.print("{d}", .{hashed.size});
        try writer.writeAll("}");
    }
    try writer.writeAll("]");
    try writer.print(",\"published_at_unix_ms\":{d}", .{published_at_unix_ms});
    try writer.writeAll("}");
    try atomic_file.finish();

    if (std.fs.path.dirname(pointer_path)) |parent| {
        try syncDirPath(parent);
    } else {
        try syncDirPath(".");
    }
}

fn hashOpenFile(file: *std.fs.File) ![32]u8 {
    return (try hashOpenFileWithSize(file)).digest;
}

const HashWithSize = struct {
    digest: [32]u8,
    size: u64,
};

fn hashOpenFileWithSize(file: *std.fs.File) !HashWithSize {
    try file.seekTo(0);
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var buffer: [64 * 1024]u8 = undefined;
    var total: u64 = 0;
    while (true) {
        const read_len = try file.read(&buffer);
        if (read_len == 0) break;
        hasher.update(buffer[0..read_len]);
        total += read_len;
    }
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    return .{
        .digest = digest,
        .size = total,
    };
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

    const published = try std.fs.path.join(allocator, &.{ output_root, "releases", "build-test", "app" });
    defer allocator.free(published);
    const bytes = try std.fs.cwd().readFileAlloc(allocator, published, 1024);
    defer allocator.free(bytes);
    try std.testing.expectEqualStrings("artifact\n", bytes);
    const pointer_path = try std.fmt.allocPrint(allocator, "{s}.current", .{output_root});
    defer allocator.free(pointer_path);
    const pointer = try std.fs.cwd().readFileAlloc(allocator, pointer_path, 1024);
    defer allocator.free(pointer);
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, pointer, .{});
    defer parsed.deinit();
    const root = switch (parsed.value) {
        .object => |obj| obj,
        else => return error.TestUnexpectedResult,
    };
    const build_id_val = root.get("build_id") orelse return error.TestUnexpectedResult;
    switch (build_id_val) {
        .string => |str| try std.testing.expectEqualStrings("build-test", str),
        else => return error.TestUnexpectedResult,
    }
    const release_rel_val = root.get("release_rel") orelse return error.TestUnexpectedResult;
    switch (release_rel_val) {
        .string => |str| try std.testing.expectEqualStrings("releases/build-test", str),
        else => return error.TestUnexpectedResult,
    }
    const outputs_val = root.get("outputs") orelse return error.TestUnexpectedResult;
    const outputs = switch (outputs_val) {
        .array => |arr| arr,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expectEqual(@as(usize, 1), outputs.items.len);
    const first_output = switch (outputs.items[0]) {
        .object => |obj| obj,
        else => return error.TestUnexpectedResult,
    };
    const out_path = switch (first_output.get("path") orelse return error.TestUnexpectedResult) {
        .string => |str| str,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expectEqualStrings("kilnexus-out/app", out_path);
    const out_sha = switch (first_output.get("sha256") orelse return error.TestUnexpectedResult) {
        .string => |str| str,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expectEqual(@as(usize, 64), out_sha.len);
    const out_size = switch (first_output.get("size") orelse return error.TestUnexpectedResult) {
        .integer => |n| n,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expectEqual(@as(i64, 9), out_size);

    if (std.fs.has_executable_bit) {
        var published_file = try std.fs.cwd().openFile(published, .{});
        defer published_file.close();
        const stat = try published_file.stat();
        try std.testing.expect((stat.mode & 0o111) != 0);
    }
}

test "atomicPublish fails when release id already exists" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("workspace/kilnexus-out");
    try tmp.dir.writeFile(.{
        .sub_path = "workspace/kilnexus-out/app",
        .data = "artifact\n",
    });
    try tmp.dir.makePath("published/kilnexus-out/releases/build-test");

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

test "verifyWorkspaceOutputs fails on sha256 mismatch" {
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

    var entries = try allocator.alloc(validator.OutputEntry, 1);
    entries[0] = .{
        .path = try allocator.dupe(u8, "kilnexus-out/app"),
        .mode = 0o755,
        .sha256 = [_]u8{0xaa} ** 32,
    };
    var spec: validator.OutputSpec = .{ .entries = entries };
    defer spec.deinit(allocator);

    try std.testing.expectError(error.OutputHashMismatch, verifyWorkspaceOutputs(allocator, workspace_cwd, &spec));
}

test "atomicPublish allows multiple builds under releases namespace" {
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

    try atomicPublish(allocator, workspace_cwd, &spec, "build-a", .{
        .output_root = output_root,
    });
    try atomicPublish(allocator, workspace_cwd, &spec, "build-b", .{
        .output_root = output_root,
    });

    const a_path = try std.fs.path.join(allocator, &.{ output_root, "releases", "build-a", "app" });
    defer allocator.free(a_path);
    const b_path = try std.fs.path.join(allocator, &.{ output_root, "releases", "build-b", "app" });
    defer allocator.free(b_path);
    try std.testing.expect(try pathExists(a_path));
    try std.testing.expect(try pathExists(b_path));
}
