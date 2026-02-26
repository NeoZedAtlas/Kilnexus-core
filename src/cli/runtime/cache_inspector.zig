const std = @import("std");

pub const DirTreeStats = struct {
    exists: bool = false,
    files: usize = 0,
    dirs: usize = 0,
    bytes: u64 = 0,
};

pub const CacheStats = struct {
    cache_root: []u8,
    total: DirTreeStats,
    official_tree_count: usize = 0,
    official_blob_count: usize = 0,
    third_party_tree_count: usize = 0,
    third_party_blob_count: usize = 0,
    local_tree_count: usize = 0,
    local_blob_count: usize = 0,

    pub fn deinit(self: *CacheStats, allocator: std.mem.Allocator) void {
        allocator.free(self.cache_root);
        self.* = undefined;
    }
};

pub const ToolchainEntry = struct {
    tree_root: []u8,
    has_zig: bool,
    has_zig_exe: bool,
    files: usize,
    bytes: u64,

    pub fn deinit(self: *ToolchainEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.tree_root);
        self.* = undefined;
    }
};

pub fn loadCacheStats(allocator: std.mem.Allocator, cache_root: []const u8) !CacheStats {
    const out_cache_root = try allocator.dupe(u8, cache_root);
    errdefer allocator.free(out_cache_root);

    const total = try collectTreeStats(allocator, cache_root);
    const official_tree_count = try countDirectSubDirs(allocator, cache_root, "cas/official/tree");
    const official_blob_count = try countDirectSubDirs(allocator, cache_root, "cas/official/blob");
    const third_party_tree_count = try countDirectSubDirs(allocator, cache_root, "cas/third_party/tree");
    const third_party_blob_count = try countDirectSubDirs(allocator, cache_root, "cas/third_party/blob");
    const local_tree_count = try countDirectSubDirs(allocator, cache_root, "cas/local/tree");
    const local_blob_count = try countDirectSubDirs(allocator, cache_root, "cas/local/blob");

    return .{
        .cache_root = out_cache_root,
        .total = total,
        .official_tree_count = official_tree_count,
        .official_blob_count = official_blob_count,
        .third_party_tree_count = third_party_tree_count,
        .third_party_blob_count = third_party_blob_count,
        .local_tree_count = local_tree_count,
        .local_blob_count = local_blob_count,
    };
}

pub fn listOfficialToolchains(allocator: std.mem.Allocator, cache_root: []const u8) ![]ToolchainEntry {
    const tree_root_path = try std.fs.path.join(allocator, &.{ cache_root, "cas", "official", "tree" });
    defer allocator.free(tree_root_path);

    var dir = std.fs.cwd().openDir(tree_root_path, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => return try allocator.alloc(ToolchainEntry, 0),
        else => return err,
    };
    defer dir.close();

    var entries: std.ArrayList(ToolchainEntry) = .empty;
    errdefer {
        for (entries.items) |*entry| entry.deinit(allocator);
        entries.deinit(allocator);
    }

    var iter = dir.iterate();
    while (try iter.next()) |entry| {
        if (entry.kind != .directory) continue;
        const tree_root = try allocator.dupe(u8, entry.name);
        errdefer allocator.free(tree_root);

        const object_path = try std.fs.path.join(allocator, &.{ tree_root_path, entry.name });
        defer allocator.free(object_path);

        const stats = try collectTreeStats(allocator, object_path);
        const zig_path = try std.fs.path.join(allocator, &.{ object_path, "zig" });
        defer allocator.free(zig_path);
        const zig_exe_path = try std.fs.path.join(allocator, &.{ object_path, "zig.exe" });
        defer allocator.free(zig_exe_path);

        const has_zig = pathExists(zig_path);
        const has_zig_exe = pathExists(zig_exe_path);
        try entries.append(allocator, .{
            .tree_root = tree_root,
            .has_zig = has_zig,
            .has_zig_exe = has_zig_exe,
            .files = stats.files,
            .bytes = stats.bytes,
        });
    }

    std.mem.sort(ToolchainEntry, entries.items, {}, lessThanToolchainEntry);
    return try entries.toOwnedSlice(allocator);
}

fn lessThanToolchainEntry(_: void, a: ToolchainEntry, b: ToolchainEntry) bool {
    return std.mem.lessThan(u8, a.tree_root, b.tree_root);
}

fn pathExists(path: []const u8) bool {
    std.fs.cwd().access(path, .{}) catch return false;
    return true;
}

fn countDirectSubDirs(allocator: std.mem.Allocator, cache_root: []const u8, rel_path: []const u8) !usize {
    const full_path = try std.fs.path.join(allocator, &.{ cache_root, rel_path });
    defer allocator.free(full_path);

    var dir = std.fs.cwd().openDir(full_path, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => return 0,
        else => return err,
    };
    defer dir.close();

    var count: usize = 0;
    var iter = dir.iterate();
    while (try iter.next()) |entry| {
        if (entry.kind == .directory) count += 1;
    }
    return count;
}

fn collectTreeStats(allocator: std.mem.Allocator, path: []const u8) !DirTreeStats {
    var dir = std.fs.cwd().openDir(path, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => return .{ .exists = false },
        else => return err,
    };
    defer dir.close();

    var stats: DirTreeStats = .{ .exists = true };
    var walker = try dir.walk(allocator);
    defer walker.deinit();

    while (try walker.next()) |entry| {
        switch (entry.kind) {
            .directory => stats.dirs += 1,
            .file => {
                stats.files += 1;
                const file = try dir.openFile(entry.path, .{});
                defer file.close();
                const file_stat = try file.stat();
                stats.bytes += file_stat.size;
            },
            else => {},
        }
    }
    return stats;
}
