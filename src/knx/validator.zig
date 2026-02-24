const std = @import("std");
const parse_errors = @import("../parser/parse_errors.zig");

const allowed_operators = [_][]const u8{
    "knx.c.compile",
    "knx.zig.link",
    "knx.fs.copy",
    "knx.archive.pack",
};

pub const VerifyMode = enum {
    strict,
    fast,
};

pub const ValidationSummary = struct {
    verify_mode: VerifyMode,
};

pub fn validateCanonicalJson(allocator: std.mem.Allocator, canonical_json: []const u8) !ValidationSummary {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, canonical_json, .{});
    defer parsed.deinit();

    const root = try expectObject(parsed.value, "root");
    try expectVersion(root);
    _ = try expectNonEmptyString(root, "target");

    const toolchain = try expectObjectField(root, "toolchain");
    _ = try expectNonEmptyString(toolchain, "id");
    try expectHex64(toolchain, "blob_sha256");
    try expectHex64(toolchain, "tree_root");
    try expectPositiveInt(toolchain, "size");

    const policy = try expectObjectField(root, "policy");
    const network = try expectNonEmptyString(policy, "network");
    if (!std.mem.eql(u8, network, "off")) return error.InvalidPolicyNetwork;
    const verify_mode = try parseVerifyMode(policy);
    const clock = try expectNonEmptyString(policy, "clock");
    if (!std.mem.eql(u8, clock, "fixed")) return error.InvalidPolicyClock;

    const env = try expectObjectField(root, "env");
    const tz = try expectNonEmptyString(env, "TZ");
    if (!std.mem.eql(u8, tz, "UTC")) return error.InvalidEnvTZ;
    const lang = try expectNonEmptyString(env, "LANG");
    if (!std.mem.eql(u8, lang, "C")) return error.InvalidEnvLang;
    const source_date_epoch = try expectNonEmptyString(env, "SOURCE_DATE_EPOCH");
    try expectAsciiDigits(source_date_epoch, "SOURCE_DATE_EPOCH");

    const outputs = try expectArrayField(root, "outputs");
    if (outputs.items.len == 0) return error.OutputsEmpty;
    for (outputs.items) |entry| {
        const output = try expectObject(entry, "output");
        const path = try expectNonEmptyString(output, "path");
        if (!std.mem.startsWith(u8, path, "kilnexus-out/")) return error.InvalidOutputPath;
        if (std.mem.indexOf(u8, path, "..") != null) return error.InvalidOutputPath;
        const mode = try expectNonEmptyString(output, "mode");
        try expectModeString(mode);
    }

    if (root.get("operators")) |operators_value| {
        const operators = try expectArray(operators_value, "operators");
        for (operators.items) |op_value| {
            const op = try expectString(op_value, "operator");
            if (!isAllowedOperator(op)) return error.OperatorNotAllowed;
        }
    }

    return .{ .verify_mode = verify_mode };
}

pub fn validateCanonicalJsonStrict(allocator: std.mem.Allocator, canonical_json: []const u8) parse_errors.ParseError!ValidationSummary {
    return validateCanonicalJson(allocator, canonical_json) catch |err| return parse_errors.normalize(err);
}

pub fn computeKnxDigestHex(canonical_json: []const u8) [64]u8 {
    var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(canonical_json, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

fn parseVerifyMode(policy: std.json.ObjectMap) !VerifyMode {
    const verify_mode_value = policy.get("verify_mode") orelse return .strict;
    const value = try expectString(verify_mode_value, "verify_mode");
    if (std.mem.eql(u8, value, "strict")) return .strict;
    if (std.mem.eql(u8, value, "fast")) return .fast;
    return error.InvalidVerifyMode;
}

fn expectVersion(root: std.json.ObjectMap) !void {
    const value = root.get("version") orelse return error.MissingVersion;
    const number = try expectInteger(value, "version");
    if (number != 1) return error.UnsupportedVersion;
}

fn expectHex64(object: std.json.ObjectMap, key: []const u8) !void {
    const value = try expectNonEmptyString(object, key);
    if (value.len != 64) return error.InvalidHexLength;
    for (value) |ch| {
        if (!std.ascii.isHex(ch)) return error.InvalidHexChar;
    }
}

fn expectPositiveInt(object: std.json.ObjectMap, key: []const u8) !void {
    const value = object.get(key) orelse return error.MissingRequiredField;
    const number = try expectInteger(value, key);
    if (number <= 0) return error.InvalidPositiveInt;
}

fn expectModeString(value: []const u8) !void {
    if (value.len != 4) return error.InvalidMode;
    if (value[0] != '0') return error.InvalidMode;
    for (value[1..]) |ch| {
        if (ch < '0' or ch > '7') return error.InvalidMode;
    }
}

fn expectAsciiDigits(value: []const u8, field: []const u8) !void {
    _ = field;
    for (value) |ch| {
        if (!std.ascii.isDigit(ch)) return error.InvalidDigits;
    }
}

fn isAllowedOperator(name: []const u8) bool {
    for (allowed_operators) |allowed| {
        if (std.mem.eql(u8, name, allowed)) return true;
    }
    return false;
}

fn expectObjectField(object: std.json.ObjectMap, key: []const u8) !std.json.ObjectMap {
    const value = object.get(key) orelse return error.MissingRequiredField;
    return expectObject(value, key);
}

fn expectArrayField(object: std.json.ObjectMap, key: []const u8) !std.json.Array {
    const value = object.get(key) orelse return error.MissingRequiredField;
    return expectArray(value, key);
}

fn expectObject(value: std.json.Value, _: []const u8) !std.json.ObjectMap {
    return switch (value) {
        .object => |object| object,
        else => error.ExpectedObject,
    };
}

fn expectArray(value: std.json.Value, _: []const u8) !std.json.Array {
    return switch (value) {
        .array => |array| array,
        else => error.ExpectedArray,
    };
}

fn expectString(value: std.json.Value, _: []const u8) ![]const u8 {
    return switch (value) {
        .string => |string| string,
        else => error.ExpectedString,
    };
}

fn expectInteger(value: std.json.Value, _: []const u8) !i64 {
    return switch (value) {
        .integer => |number| number,
        else => error.ExpectedInteger,
    };
}

fn expectNonEmptyString(object: std.json.ObjectMap, key: []const u8) ![]const u8 {
    const value = object.get(key) orelse return error.MissingRequiredField;
    const string = try expectString(value, key);
    if (string.len == 0) return error.EmptyString;
    return string;
}

test "validateCanonicalJson accepts minimal valid knxfile" {
    const allocator = std.testing.allocator;
    const json =
        \\{
        \\  "version": 1,
        \\  "target": "x86_64-unknown-linux-musl",
        \\  "toolchain": {
        \\    "id": "zigcc-0.14.0",
        \\    "blob_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\    "tree_root": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        \\    "size": 1
        \\  },
        \\  "policy": {
        \\    "network": "off",
        \\    "clock": "fixed"
        \\  },
        \\  "env": {
        \\    "TZ": "UTC",
        \\    "LANG": "C",
        \\    "SOURCE_DATE_EPOCH": "1735689600"
        \\  },
        \\  "outputs": [
        \\    { "path": "kilnexus-out/app", "mode": "0755" }
        \\  ],
        \\  "operators": [
        \\    "knx.c.compile",
        \\    "knx.zig.link"
        \\  ]
        \\}
    ;

    const summary = try validateCanonicalJson(allocator, json);
    try std.testing.expectEqual(VerifyMode.strict, summary.verify_mode);
}

test "validateCanonicalJson rejects custom operator" {
    const allocator = std.testing.allocator;
    const json =
        \\{
        \\  "version": 1,
        \\  "target": "x86_64-unknown-linux-musl",
        \\  "toolchain": {
        \\    "id": "zigcc-0.14.0",
        \\    "blob_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\    "tree_root": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        \\    "size": 1
        \\  },
        \\  "policy": {
        \\    "network": "off",
        \\    "clock": "fixed",
        \\    "verify_mode": "strict"
        \\  },
        \\  "env": {
        \\    "TZ": "UTC",
        \\    "LANG": "C",
        \\    "SOURCE_DATE_EPOCH": "1735689600"
        \\  },
        \\  "outputs": [
        \\    { "path": "kilnexus-out/app", "mode": "0755" }
        \\  ],
        \\  "operators": [
        \\    "sh -c x"
        \\  ]
        \\}
    ;

    try std.testing.expectError(error.OperatorNotAllowed, validateCanonicalJson(allocator, json));
}

test "computeKnxDigestHex is stable length" {
    const hex = computeKnxDigestHex("{\"version\":1}");
    try std.testing.expectEqual(@as(usize, 64), hex.len);
}

test "validateCanonicalJsonStrict normalizes policy errors" {
    const allocator = std.testing.allocator;
    const json =
        \\{
        \\  "version": 1,
        \\  "target": "x86_64-unknown-linux-musl",
        \\  "toolchain": {
        \\    "id": "zigcc-0.14.0",
        \\    "blob_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\    "tree_root": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        \\    "size": 1
        \\  },
        \\  "policy": {
        \\    "network": "on",
        \\    "clock": "fixed"
        \\  },
        \\  "env": {
        \\    "TZ": "UTC",
        \\    "LANG": "C",
        \\    "SOURCE_DATE_EPOCH": "1735689600"
        \\  },
        \\  "outputs": [
        \\    { "path": "kilnexus-out/app", "mode": "0755" }
        \\  ]
        \\}
    ;

    try std.testing.expectError(error.ValueInvalid, validateCanonicalJsonStrict(allocator, json));
}
