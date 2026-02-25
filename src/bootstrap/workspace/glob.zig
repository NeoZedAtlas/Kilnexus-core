const std = @import("std");
const validator = @import("../../knx/validator.zig");
const path_utils = @import("path_utils.zig");

pub fn expandLocalInputMatches(allocator: std.mem.Allocator, input: validator.LocalInputSpec) ![][]u8 {
    var matches: std.ArrayList([]u8) = .empty;
    errdefer {
        for (matches.items) |item| allocator.free(item);
        matches.deinit(allocator);
    }

    for (input.include) |pattern| {
        try collectPatternMatches(allocator, &matches, pattern);
    }

    for (input.exclude) |pattern| {
        var i: usize = 0;
        while (i < matches.items.len) {
            if (globMatchPath(pattern, matches.items[i])) {
                allocator.free(matches.items[i]);
                _ = matches.orderedRemove(i);
            } else {
                i += 1;
            }
        }
    }
    std.sort.pdq([]u8, matches.items, {}, struct {
        fn lessThan(_: void, lhs: []u8, rhs: []u8) bool {
            return std.mem.order(u8, lhs, rhs) == .lt;
        }
    }.lessThan);
    return matches.toOwnedSlice(allocator);
}

pub fn containsString(items: [][]u8, needle: []const u8) bool {
    for (items) |item| {
        if (std.mem.eql(u8, item, needle)) return true;
    }
    return false;
}

pub fn normalizePathOwned(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    return std.mem.replaceOwned(u8, allocator, path, "\\", "/");
}

fn collectPatternMatches(
    allocator: std.mem.Allocator,
    matches: *std.ArrayList([]u8),
    pattern_raw: []const u8,
) !void {
    const pattern = try normalizePathOwned(allocator, pattern_raw);
    defer allocator.free(pattern);
    try validatePatternPath(pattern);

    if (!hasGlobWildcard(pattern)) {
        if (try pathIsFile(pattern)) {
            if (!containsStringConst(matches.items, pattern)) {
                try matches.append(allocator, try allocator.dupe(u8, pattern));
            }
        }
        return;
    }

    const root = patternRoot(pattern);
    var root_dir = std.fs.cwd().openDir(root, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound, error.NotDir => return,
        else => return err,
    };
    defer root_dir.close();

    var walker = try root_dir.walk(allocator);
    defer walker.deinit();

    while (try walker.next()) |entry| {
        if (entry.kind != .file) continue;
        const rel = if (std.mem.eql(u8, root, ".")) blk: {
            break :blk try normalizePathOwned(allocator, entry.path);
        } else blk: {
            const joined = try std.fs.path.join(allocator, &.{ root, entry.path });
            defer allocator.free(joined);
            break :blk try normalizePathOwned(allocator, joined);
        };
        defer allocator.free(rel);
        if (globMatchPath(pattern, rel)) {
            if (!containsStringConst(matches.items, rel)) {
                try matches.append(allocator, try allocator.dupe(u8, rel));
            }
        }
    }
}

fn hasGlobWildcard(pattern: []const u8) bool {
    return std.mem.indexOfAny(u8, pattern, "*?[") != null;
}

fn patternRoot(pattern: []const u8) []const u8 {
    const wildcard = std.mem.indexOfAny(u8, pattern, "*?[") orelse {
        return std.fs.path.dirname(pattern) orelse ".";
    };
    const prefix = pattern[0..wildcard];
    const slash = std.mem.lastIndexOfScalar(u8, prefix, '/') orelse return ".";
    if (slash == 0) return ".";
    return pattern[0..slash];
}

fn validatePatternPath(path: []const u8) !void {
    if (path.len == 0) return error.PathTraversalDetected;
    if (std.fs.path.isAbsolute(path)) return error.PathTraversalDetected;
    if (std.mem.indexOfScalar(u8, path, ':') != null) return error.PathTraversalDetected;
    if (std.mem.indexOfScalar(u8, path, '\\') != null) return error.PathTraversalDetected;

    var it = std.mem.splitScalar(u8, path, '/');
    while (it.next()) |segment| {
        if (segment.len == 0) continue;
        if (std.mem.eql(u8, segment, ".") or std.mem.eql(u8, segment, "..")) {
            return error.PathTraversalDetected;
        }
    }
    try path_utils.validateMountPath(path);
}

fn globMatchPath(pattern: []const u8, path: []const u8) bool {
    var pattern_parts = std.mem.splitScalar(u8, pattern, '/');
    var path_parts = std.mem.splitScalar(u8, path, '/');

    var p_items: std.ArrayList([]const u8) = .empty;
    defer p_items.deinit(std.heap.page_allocator);
    while (pattern_parts.next()) |part| {
        if (part.len == 0) continue;
        p_items.append(std.heap.page_allocator, part) catch return false;
    }

    var t_items: std.ArrayList([]const u8) = .empty;
    defer t_items.deinit(std.heap.page_allocator);
    while (path_parts.next()) |part| {
        if (part.len == 0) continue;
        t_items.append(std.heap.page_allocator, part) catch return false;
    }

    return matchPathParts(p_items.items, t_items.items);
}

fn matchPathParts(pattern_parts: []const []const u8, path_parts: []const []const u8) bool {
    return matchPathPartsRec(pattern_parts, path_parts, 0, 0);
}

fn matchPathPartsRec(pattern_parts: []const []const u8, path_parts: []const []const u8, p_idx: usize, t_idx: usize) bool {
    if (p_idx == pattern_parts.len) return t_idx == path_parts.len;
    const part = pattern_parts[p_idx];
    if (std.mem.eql(u8, part, "**")) {
        var consume = t_idx;
        while (consume <= path_parts.len) : (consume += 1) {
            if (matchPathPartsRec(pattern_parts, path_parts, p_idx + 1, consume)) return true;
        }
        return false;
    }
    if (t_idx >= path_parts.len) return false;
    if (!matchSegment(part, path_parts[t_idx])) return false;
    return matchPathPartsRec(pattern_parts, path_parts, p_idx + 1, t_idx + 1);
}

fn matchSegment(pattern: []const u8, text: []const u8) bool {
    var dp: std.ArrayList(bool) = .empty;
    defer dp.deinit(std.heap.page_allocator);
    var next: std.ArrayList(bool) = .empty;
    defer next.deinit(std.heap.page_allocator);

    dp.resize(std.heap.page_allocator, text.len + 1) catch return false;
    @memset(dp.items, false);
    dp.items[0] = true;

    for (pattern) |ch| {
        next.resize(std.heap.page_allocator, text.len + 1) catch return false;
        @memset(next.items, false);
        if (ch == '*') {
            var any = false;
            for (0..text.len + 1) |i| {
                any = any or dp.items[i];
                if (any) next.items[i] = true;
            }
        } else {
            for (1..text.len + 1) |i| {
                if (dp.items[i - 1] and (ch == '?' or ch == text[i - 1])) {
                    next.items[i] = true;
                }
            }
        }
        std.mem.swap(std.ArrayList(bool), &dp, &next);
    }

    return dp.items[text.len];
}

fn containsStringConst(items: []const []u8, needle: []const u8) bool {
    for (items) |item| {
        if (std.mem.eql(u8, item, needle)) return true;
    }
    return false;
}

fn pathIsFile(path: []const u8) !bool {
    var file = std.fs.cwd().openFile(path, .{}) catch |err| switch (err) {
        error.FileNotFound, error.IsDir => return false,
        else => return err,
    };
    file.close();
    return true;
}
