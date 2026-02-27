const std = @import("std");
const keys = @import("keys.zig");
const model = @import("model.zig");

pub fn parseVerifyMode(policy: std.json.ObjectMap) !model.VerifyMode {
    const verify_mode_value = policy.get("verify_mode") orelse return .strict;
    const value = try expectString(verify_mode_value, "verify_mode");
    if (std.mem.eql(u8, value, "strict")) return .strict;
    if (std.mem.eql(u8, value, "fast")) return .fast;
    return error.InvalidVerifyMode;
}

pub fn parseCasDomain(text: []const u8) ?model.CasDomain {
    if (std.mem.eql(u8, text, "official")) return .official;
    if (std.mem.eql(u8, text, "third_party")) return .third_party;
    if (std.mem.eql(u8, text, "local")) return .local;
    return null;
}

pub fn parseArchiveFormat(text: []const u8) ?model.ArchiveFormat {
    if (std.mem.eql(u8, text, "tar")) return .tar;
    if (std.mem.eql(u8, text, "tar.gz")) return .tar_gz;
    return null;
}

pub fn parseStringArrayField(
    allocator: std.mem.Allocator,
    object: std.json.ObjectMap,
    key: []const u8,
) ![][]u8 {
    const value = object.get(key) orelse return error.MissingRequiredField;
    const array = try expectArray(value, key);
    if (array.items.len == 0) return error.ValueInvalid;

    var out: std.ArrayList([]u8) = .empty;
    errdefer {
        for (out.items) |item| allocator.free(item);
        out.deinit(allocator);
    }
    for (array.items) |item| {
        const text = try expectString(item, key);
        if (text.len == 0) return error.ValueInvalid;
        try out.append(allocator, try allocator.dupe(u8, text));
    }
    return out.toOwnedSlice(allocator);
}

pub fn dupeStringSlice(allocator: std.mem.Allocator, items: [][]u8) ![][]u8 {
    var out: std.ArrayList([]u8) = .empty;
    errdefer {
        for (out.items) |item| allocator.free(item);
        out.deinit(allocator);
    }
    for (items) |item| {
        try out.append(allocator, try allocator.dupe(u8, item));
    }
    return out.toOwnedSlice(allocator);
}

pub fn containsIndex(items: []const usize, value: usize) bool {
    for (items) |item| {
        if (item == value) return true;
    }
    return false;
}

pub fn trimTrailingSlash(path: []const u8) []const u8 {
    var out = path;
    while (out.len > 0 and out[out.len - 1] == '/') {
        out = out[0 .. out.len - 1];
    }
    return out;
}

pub fn parsePositiveU64(object: std.json.ObjectMap, key: []const u8) !u64 {
    const value = object.get(key) orelse return error.MissingRequiredField;
    const number = try expectInteger(value, key);
    if (number <= 0) return error.InvalidPositiveInt;
    return @intCast(number);
}

pub fn expectVersion(root: std.json.ObjectMap) !void {
    const value = root.get("version") orelse return error.MissingVersion;
    const number = try expectInteger(value, "version");
    if (number != 1) return error.UnsupportedVersion;
}

pub fn expectHex64(object: std.json.ObjectMap, key: []const u8) !void {
    const value = try expectNonEmptyString(object, key);
    if (value.len != 64) return error.InvalidHexLength;
    for (value) |ch| {
        if (!std.ascii.isHex(ch)) return error.InvalidHexChar;
    }
}

pub fn expectPositiveInt(object: std.json.ObjectMap, key: []const u8) !void {
    const value = object.get(key) orelse return error.MissingRequiredField;
    const number = try expectInteger(value, key);
    if (number <= 0) return error.InvalidPositiveInt;
}

pub fn expectModeString(value: []const u8) !void {
    if (value.len != 4) return error.InvalidMode;
    if (value[0] != '0') return error.InvalidMode;
    for (value[1..]) |ch| {
        if (ch < '0' or ch > '7') return error.InvalidMode;
    }
}

pub fn parseOutputMode(text: []const u8) !u16 {
    try expectModeString(text);
    var mode: u16 = 0;
    for (text[1..]) |ch| {
        mode = (mode << 3) | @as(u16, ch - '0');
    }
    return mode;
}

pub fn validateOutputPath(path: []const u8) !void {
    const prefix = "kilnexus-out/";
    if (!std.mem.startsWith(u8, path, prefix)) return error.InvalidOutputPath;
    if (std.mem.indexOfScalar(u8, path, '\\') != null) return error.InvalidOutputPath;
    if (std.mem.indexOfScalar(u8, path, ':') != null) return error.InvalidOutputPath;

    const rel = path[prefix.len..];
    if (rel.len == 0) return error.InvalidOutputPath;

    var it = std.mem.splitScalar(u8, rel, '/');
    while (it.next()) |segment| {
        if (segment.len == 0 or std.mem.eql(u8, segment, ".") or std.mem.eql(u8, segment, "..")) {
            return error.InvalidOutputPath;
        }
    }
}

pub fn outputRelativePath(path: []const u8) ![]const u8 {
    const prefix = "kilnexus-out/";
    if (!std.mem.startsWith(u8, path, prefix)) return error.InvalidOutputPath;
    const rel = path[prefix.len..];
    if (rel.len == 0) return error.InvalidOutputPath;
    return rel;
}

pub fn validatePublishName(name: []const u8) !void {
    if (name.len == 0) return error.InvalidOutputPath;
    if (std.fs.path.isAbsolute(name)) return error.InvalidOutputPath;
    if (std.mem.indexOfScalar(u8, name, '\\') != null) return error.InvalidOutputPath;
    if (std.mem.indexOfScalar(u8, name, ':') != null) return error.InvalidOutputPath;

    var it = std.mem.splitScalar(u8, name, '/');
    while (it.next()) |segment| {
        if (segment.len == 0 or std.mem.eql(u8, segment, ".") or std.mem.eql(u8, segment, "..")) {
            return error.InvalidOutputPath;
        }
    }
}

pub fn freeOwnedStrings(allocator: std.mem.Allocator, items: [][]u8) void {
    for (items) |item| allocator.free(item);
    allocator.free(items);
}

pub fn isAllowedCompileArg(arg: []const u8) bool {
    const allowed = [_][]const u8{
        "-O0",
        "-O1",
        "-O2",
        "-O3",
        "-Os",
        "-Oz",
        "-g",
        "-g0",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-std=c89",
        "-std=c99",
        "-std=c11",
        "-std=c17",
    };
    for (allowed) |item| {
        if (std.mem.eql(u8, arg, item)) return true;
    }
    if (std.mem.startsWith(u8, arg, "-D")) {
        return isAllowedDefine(arg[2..]);
    }
    if (std.mem.startsWith(u8, arg, "-I")) {
        return isAllowedIncludePath(arg[2..]);
    }
    return false;
}

fn isAllowedDefine(value: []const u8) bool {
    if (value.len == 0) return false;
    for (value) |ch| {
        if (std.ascii.isAlphanumeric(ch)) continue;
        switch (ch) {
            '_', '=', '.', '-', ':' => continue,
            else => return false,
        }
    }
    return true;
}

fn isAllowedIncludePath(path: []const u8) bool {
    if (path.len == 0) return false;
    validateWorkspaceRelativePath(path) catch return false;
    return true;
}

pub fn isAllowedLinkArg(arg: []const u8) bool {
    const allowed = [_][]const u8{
        "-static",
        "-s",
        "-Wl,--gc-sections",
        "-Wl,--strip-all",
    };
    for (allowed) |item| {
        if (std.mem.eql(u8, arg, item)) return true;
    }
    return false;
}

pub fn validateWorkspaceRelativePath(path: []const u8) !void {
    if (path.len == 0) return error.ValueInvalid;
    if (std.fs.path.isAbsolute(path)) return error.ValueInvalid;
    if (std.mem.indexOfScalar(u8, path, '\\') != null) return error.ValueInvalid;
    if (std.mem.indexOfScalar(u8, path, ':') != null) return error.ValueInvalid;

    var it = std.mem.splitScalar(u8, path, '/');
    while (it.next()) |segment| {
        if (segment.len == 0 or std.mem.eql(u8, segment, ".") or std.mem.eql(u8, segment, "..")) {
            return error.ValueInvalid;
        }
    }
}

pub fn isEqualOrDescendant(path: []const u8, base: []const u8) bool {
    if (std.mem.eql(u8, path, base)) return true;
    if (path.len <= base.len) return false;
    if (!std.mem.startsWith(u8, path, base)) return false;
    return path[base.len] == '/';
}

pub fn expectAsciiDigits(value: []const u8, field: []const u8) !void {
    _ = field;
    for (value) |ch| {
        if (!std.ascii.isDigit(ch)) return error.InvalidDigits;
    }
}

pub fn isAllowedOperator(name: []const u8) bool {
    for (keys.allowed_operators) |allowed| {
        if (std.mem.eql(u8, name, allowed)) return true;
    }
    return false;
}

pub fn validateOperatorId(id: []const u8) !void {
    if (id.len == 0) return error.ValueInvalid;
    for (id) |ch| {
        if (!std.ascii.isAlphanumeric(ch) and ch != '-' and ch != '_' and ch != '.') {
            return error.ValueInvalid;
        }
    }
}

pub fn ensureOnlyKeys(object: std.json.ObjectMap, allowed_keys: []const []const u8) !void {
    var it = object.iterator();
    while (it.next()) |entry| {
        if (!containsAllowedKey(entry.key_ptr.*, allowed_keys)) return error.ValueInvalid;
    }
}

pub fn containsAllowedKey(key: []const u8, allowed_keys: []const []const u8) bool {
    for (allowed_keys) |allowed| {
        if (std.mem.eql(u8, key, allowed)) return true;
    }
    return false;
}

pub fn expectObjectField(object: std.json.ObjectMap, key: []const u8) !std.json.ObjectMap {
    const value = object.get(key) orelse return error.MissingRequiredField;
    return expectObject(value, key);
}

pub fn expectArrayField(object: std.json.ObjectMap, key: []const u8) !std.json.Array {
    const value = object.get(key) orelse return error.MissingRequiredField;
    return expectArray(value, key);
}

pub fn expectObject(value: std.json.Value, _: []const u8) !std.json.ObjectMap {
    return switch (value) {
        .object => |object| object,
        else => error.ExpectedObject,
    };
}

pub fn expectArray(value: std.json.Value, _: []const u8) !std.json.Array {
    return switch (value) {
        .array => |array| array,
        else => error.ExpectedArray,
    };
}

pub fn expectString(value: std.json.Value, _: []const u8) ![]const u8 {
    return switch (value) {
        .string => |string| string,
        else => error.ExpectedString,
    };
}

pub fn expectInteger(value: std.json.Value, _: []const u8) !i64 {
    return switch (value) {
        .integer => |number| number,
        else => error.ExpectedInteger,
    };
}

pub fn expectBool(value: std.json.Value, _: []const u8) !bool {
    return switch (value) {
        .bool => |b| b,
        else => error.TypeMismatch,
    };
}

pub fn expectNonEmptyString(object: std.json.ObjectMap, key: []const u8) ![]const u8 {
    const value = object.get(key) orelse return error.MissingRequiredField;
    const string = try expectString(value, key);
    if (string.len == 0) return error.EmptyString;
    return string;
}

pub fn parseHexFixed(comptime byte_len: usize, text: []const u8) ![byte_len]u8 {
    if (text.len != byte_len * 2) return error.InvalidHexLength;
    var output: [byte_len]u8 = undefined;
    _ = std.fmt.hexToBytes(&output, text) catch |err| switch (err) {
        error.InvalidCharacter => return error.InvalidHexChar,
        error.InvalidLength => return error.InvalidHexLength,
        error.NoSpaceLeft => return error.InvalidHexLength,
    };
    return output;
}

test "isAllowedCompileArg accepts constrained -D and -I" {
    try std.testing.expect(isAllowedCompileArg("-DHELLO=1"));
    try std.testing.expect(isAllowedCompileArg("-DNAME=value-1"));
    try std.testing.expect(isAllowedCompileArg("-Isrc/include"));
    try std.testing.expect(!isAllowedCompileArg("-D"));
    try std.testing.expect(!isAllowedCompileArg("-DHELLO value"));
    try std.testing.expect(!isAllowedCompileArg("-I../include"));
    try std.testing.expect(!isAllowedCompileArg("-I"));
}
