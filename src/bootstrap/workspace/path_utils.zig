const std = @import("std");

pub fn validateMountPath(path: []const u8) !void {
    if (path.len == 0) return error.PathTraversalDetected;
    if (std.fs.path.isAbsolute(path)) return error.PathTraversalDetected;
    if (std.mem.indexOfScalar(u8, path, '\\') != null) return error.PathTraversalDetected;
    if (std.mem.indexOfScalar(u8, path, ':') != null) return error.PathTraversalDetected;

    var it = std.mem.splitScalar(u8, path, '/');
    while (it.next()) |segment| {
        if (segment.len == 0 or std.mem.eql(u8, segment, ".") or std.mem.eql(u8, segment, "..")) {
            return error.PathTraversalDetected;
        }
    }
}

pub fn ensurePathWithinRoot(path_abs: []const u8, root_abs: []const u8) !void {
    const normalized_root = trimTrailingSeparator(root_abs);
    if (std.mem.eql(u8, path_abs, normalized_root)) return;
    if (path_abs.len <= normalized_root.len) return error.PathTraversalDetected;
    if (!std.mem.startsWith(u8, path_abs, normalized_root)) return error.PathTraversalDetected;
    const sep = path_abs[normalized_root.len];
    if (sep != '/' and sep != '\\') return error.PathTraversalDetected;
}

pub fn joinPosix(allocator: std.mem.Allocator, base: []const u8, tail: []const u8) ![]u8 {
    if (base.len == 0) return allocator.dupe(u8, tail);
    if (tail.len == 0) return allocator.dupe(u8, base);
    return std.fmt.allocPrint(allocator, "{s}/{s}", .{ trimTrailingSlash(base), trimLeadingSlash(tail) });
}

pub fn trimTrailingSeparator(path: []const u8) []const u8 {
    var out = path;
    while (out.len > 0 and (out[out.len - 1] == '/' or out[out.len - 1] == '\\')) {
        out = out[0 .. out.len - 1];
    }
    return out;
}

pub fn trimTrailingSlash(path: []const u8) []const u8 {
    var out = path;
    while (out.len > 0 and out[out.len - 1] == '/') out = out[0 .. out.len - 1];
    return out;
}

pub fn trimLeadingSlash(path: []const u8) []const u8 {
    var out = path;
    while (out.len > 0 and out[0] == '/') out = out[1..];
    return out;
}
