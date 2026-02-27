const std = @import("std");

pub const BootstrapRole = struct {
    filename: []const u8,
    json: []const u8,
};

pub const roles = [_]BootstrapRole{
    .{ .filename = "root.json", .json = @embedFile("bootstrap/root.json") },
    .{ .filename = "timestamp.json", .json = @embedFile("bootstrap/timestamp.json") },
    .{ .filename = "snapshot.json", .json = @embedFile("bootstrap/snapshot.json") },
    .{ .filename = "targets.json", .json = @embedFile("bootstrap/targets.json") },
};

pub fn ensureMetadataDir(allocator: std.mem.Allocator, trust_dir_path: []const u8) !bool {
    try std.fs.cwd().makePath(trust_dir_path);

    var wrote_any = false;
    inline for (roles) |role| {
        const full_path = try std.fs.path.join(allocator, &.{ trust_dir_path, role.filename });
        defer allocator.free(full_path);
        if (!try fileExists(full_path)) {
            try writeFileAtomically(full_path, role.json);
            wrote_any = true;
        }
    }
    return wrote_any;
}

fn fileExists(path: []const u8) !bool {
    std.fs.cwd().access(path, .{}) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    return true;
}

fn writeFileAtomically(path: []const u8, contents: []const u8) !void {
    var buffer: [4096]u8 = undefined;
    var atomic_file = try std.fs.cwd().atomicFile(path, .{
        .mode = 0o644,
        .make_path = true,
        .write_buffer = &buffer,
    });
    defer atomic_file.deinit();
    try atomic_file.file_writer.interface.writeAll(contents);
    try atomic_file.finish();
}
