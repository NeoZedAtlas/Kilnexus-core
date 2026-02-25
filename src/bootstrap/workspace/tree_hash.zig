const std = @import("std");

pub const FileDigest = struct {
    digest: [32]u8,
    size: u64,
};

const TreeEntryDigest = struct {
    path: []u8,
    kind: u8,
    mode: u32,
    size: u64,
    digest: [32]u8,
};

pub fn computeTreeRootHexForDir(allocator: std.mem.Allocator, dir_path: []const u8) ![64]u8 {
    const digest = try computeTreeRootForDir(allocator, dir_path);
    return std.fmt.bytesToHex(digest, .lower);
}

pub fn hashFileAtPath(path: []const u8) !FileDigest {
    var file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    return hashFile(&file);
}

pub fn computeTreeRootForDir(allocator: std.mem.Allocator, dir_path: []const u8) ![32]u8 {
    var root_dir = try std.fs.cwd().openDir(dir_path, .{ .iterate = true });
    defer root_dir.close();

    var walker = try root_dir.walk(allocator);
    defer walker.deinit();

    var entries: std.ArrayList(TreeEntryDigest) = .empty;
    defer {
        for (entries.items) |entry| allocator.free(entry.path);
        entries.deinit(allocator);
    }

    while (try walker.next()) |entry| {
        switch (entry.kind) {
            .directory => continue,
            .sym_link => return error.SymlinkPolicyViolation,
            .file => {
                var file = try entry.dir.openFile(entry.basename, .{});
                defer file.close();
                const digest = try hashFile(&file);
                const stat = try file.stat();
                try entries.append(allocator, .{
                    .path = try allocator.dupe(u8, entry.path),
                    .kind = 1,
                    .mode = normalizeTreeEntryMode(stat.mode),
                    .size = digest.size,
                    .digest = digest.digest,
                });
            },
            else => return error.SymlinkPolicyViolation,
        }
    }

    std.sort.pdq(TreeEntryDigest, entries.items, {}, struct {
        fn lessThan(_: void, lhs: TreeEntryDigest, rhs: TreeEntryDigest) bool {
            return std.mem.order(u8, lhs.path, rhs.path) == .lt;
        }
    }.lessThan);

    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    for (entries.items) |entry| {
        var mode_bytes: [4]u8 = undefined;
        var size_bytes: [8]u8 = undefined;
        hasher.update(entry.path);
        hasher.update(&[_]u8{0});
        hasher.update(&[_]u8{entry.kind});
        std.mem.writeInt(u32, &mode_bytes, entry.mode, .little);
        hasher.update(&mode_bytes);
        std.mem.writeInt(u64, &size_bytes, entry.size, .little);
        hasher.update(&size_bytes);
        hasher.update(&entry.digest);
    }

    var root: [32]u8 = undefined;
    hasher.final(&root);
    return root;
}

fn hashFile(file: *std.fs.File) !FileDigest {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var buffer: [64 * 1024]u8 = undefined;
    var size: u64 = 0;

    while (true) {
        const read_len = try file.read(&buffer);
        if (read_len == 0) break;
        hasher.update(buffer[0..read_len]);
        size += read_len;
    }

    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    return .{
        .digest = digest,
        .size = size,
    };
}

fn normalizeTreeEntryMode(mode: std.fs.File.Mode) u32 {
    if (std.fs.has_executable_bit and (mode & 0o111) != 0) {
        return 0o755;
    }
    return 0o644;
}
