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

pub const ToolchainSpec = struct {
    id: []u8,
    source: ?[]u8,
    blob_sha256: [32]u8,
    tree_root: [32]u8,
    size: u64,

    pub fn deinit(self: *ToolchainSpec, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        if (self.source) |source| allocator.free(source);
        self.* = undefined;
    }
};

pub const CasDomain = enum {
    official,
    third_party,
    local,
};

pub const WorkspaceEntry = struct {
    mount_path: []u8,
    host_source: ?[]u8 = null,
    cas_sha256: ?[32]u8 = null,
    cas_domain: CasDomain = .local,
    is_dependency: bool = false,

    pub fn deinit(self: *WorkspaceEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.mount_path);
        if (self.host_source) |source| allocator.free(source);
        self.* = undefined;
    }
};

pub const WorkspaceSpec = struct {
    entries: []WorkspaceEntry,

    pub fn deinit(self: *WorkspaceSpec, allocator: std.mem.Allocator) void {
        for (self.entries) |*entry| entry.deinit(allocator);
        allocator.free(self.entries);
        self.* = undefined;
    }
};

pub const OutputEntry = struct {
    path: []u8,
    mode: u16,

    pub fn deinit(self: *OutputEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.path);
        self.* = undefined;
    }
};

pub const OutputSpec = struct {
    entries: []OutputEntry,

    pub fn deinit(self: *OutputSpec, allocator: std.mem.Allocator) void {
        for (self.entries) |*entry| entry.deinit(allocator);
        allocator.free(self.entries);
        self.* = undefined;
    }
};

pub const FsCopyOp = struct {
    from_path: []u8,
    to_path: []u8,

    pub fn deinit(self: *FsCopyOp, allocator: std.mem.Allocator) void {
        allocator.free(self.from_path);
        allocator.free(self.to_path);
        self.* = undefined;
    }
};

pub const BuildOp = union(enum) {
    fs_copy: FsCopyOp,
    c_compile,
    zig_link,
    archive_pack,

    pub fn deinit(self: *BuildOp, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .fs_copy => |*copy| copy.deinit(allocator),
            else => {},
        }
        self.* = undefined;
    }
};

pub const BuildSpec = struct {
    ops: []BuildOp,

    pub fn deinit(self: *BuildSpec, allocator: std.mem.Allocator) void {
        for (self.ops) |*op| op.deinit(allocator);
        allocator.free(self.ops);
        self.* = undefined;
    }
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
        try validateOutputPath(path);
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

pub fn parseToolchainSpec(allocator: std.mem.Allocator, canonical_json: []const u8) !ToolchainSpec {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, canonical_json, .{});
    defer parsed.deinit();

    const root = try expectObject(parsed.value, "root");
    const toolchain = try expectObjectField(root, "toolchain");

    const id_text = try expectNonEmptyString(toolchain, "id");
    const id = try allocator.dupe(u8, id_text);
    errdefer allocator.free(id);

    const blob_sha_text = try expectNonEmptyString(toolchain, "blob_sha256");
    const tree_root_text = try expectNonEmptyString(toolchain, "tree_root");
    const size_u64 = try parsePositiveU64(toolchain, "size");

    var source_copy: ?[]u8 = null;
    errdefer if (source_copy) |source| allocator.free(source);
    if (toolchain.get("source")) |source_value| {
        const source_text = try expectString(source_value, "source");
        if (source_text.len == 0) return error.EmptyString;
        source_copy = try allocator.dupe(u8, source_text);
    }

    return .{
        .id = id,
        .source = source_copy,
        .blob_sha256 = try parseHexFixed(32, blob_sha_text),
        .tree_root = try parseHexFixed(32, tree_root_text),
        .size = size_u64,
    };
}

pub fn parseToolchainSpecStrict(allocator: std.mem.Allocator, canonical_json: []const u8) parse_errors.ParseError!ToolchainSpec {
    return parseToolchainSpec(allocator, canonical_json) catch |err| return parse_errors.normalize(err);
}

pub fn parseWorkspaceSpec(allocator: std.mem.Allocator, canonical_json: []const u8) !WorkspaceSpec {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, canonical_json, .{});
    defer parsed.deinit();

    const root = try expectObject(parsed.value, "root");

    var entries: std.ArrayList(WorkspaceEntry) = .empty;
    errdefer {
        for (entries.items) |*entry| entry.deinit(allocator);
        entries.deinit(allocator);
    }

    if (root.get("inputs")) |inputs_value| {
        const inputs = try expectArray(inputs_value, "inputs");
        try parseWorkspaceEntries(allocator, &entries, inputs, false);
    }
    if (root.get("deps")) |deps_value| {
        const deps = try expectArray(deps_value, "deps");
        try parseWorkspaceEntries(allocator, &entries, deps, true);
    }

    return .{
        .entries = try entries.toOwnedSlice(allocator),
    };
}

pub fn parseWorkspaceSpecStrict(allocator: std.mem.Allocator, canonical_json: []const u8) parse_errors.ParseError!WorkspaceSpec {
    return parseWorkspaceSpec(allocator, canonical_json) catch |err| return parse_errors.normalize(err);
}

pub fn parseOutputSpec(allocator: std.mem.Allocator, canonical_json: []const u8) !OutputSpec {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, canonical_json, .{});
    defer parsed.deinit();

    const root = try expectObject(parsed.value, "root");
    const outputs = try expectArrayField(root, "outputs");
    if (outputs.items.len == 0) return error.OutputsEmpty;

    var entries: std.ArrayList(OutputEntry) = .empty;
    errdefer {
        for (entries.items) |*entry| entry.deinit(allocator);
        entries.deinit(allocator);
    }

    for (outputs.items) |item| {
        const obj = try expectObject(item, "output");
        const path_text = try expectNonEmptyString(obj, "path");
        try validateOutputPath(path_text);
        const mode_text = try expectNonEmptyString(obj, "mode");
        const mode = try parseOutputMode(mode_text);

        const path = try allocator.dupe(u8, path_text);
        errdefer allocator.free(path);

        try entries.append(allocator, .{
            .path = path,
            .mode = mode,
        });
    }

    return .{
        .entries = try entries.toOwnedSlice(allocator),
    };
}

pub fn parseOutputSpecStrict(allocator: std.mem.Allocator, canonical_json: []const u8) parse_errors.ParseError!OutputSpec {
    return parseOutputSpec(allocator, canonical_json) catch |err| return parse_errors.normalize(err);
}

pub fn parseBuildSpec(allocator: std.mem.Allocator, canonical_json: []const u8) !BuildSpec {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, canonical_json, .{});
    defer parsed.deinit();

    const root = try expectObject(parsed.value, "root");
    const build_value = root.get("build") orelse {
        return .{
            .ops = try allocator.alloc(BuildOp, 0),
        };
    };
    const build_array = try expectArray(build_value, "build");

    var ops: std.ArrayList(BuildOp) = .empty;
    errdefer {
        for (ops.items) |*op| op.deinit(allocator);
        ops.deinit(allocator);
    }

    for (build_array.items) |item| {
        const obj = try expectObject(item, "build op");
        const op_name = try expectNonEmptyString(obj, "op");

        if (std.mem.eql(u8, op_name, "knx.fs.copy")) {
            const from_text = try expectNonEmptyString(obj, "from");
            const to_text = try expectNonEmptyString(obj, "to");
            try validateWorkspaceRelativePath(from_text);
            try validateWorkspaceRelativePath(to_text);

            const from_path = try allocator.dupe(u8, from_text);
            errdefer allocator.free(from_path);
            const to_path = try allocator.dupe(u8, to_text);
            errdefer allocator.free(to_path);

            try ops.append(allocator, .{
                .fs_copy = .{
                    .from_path = from_path,
                    .to_path = to_path,
                },
            });
            continue;
        }

        if (std.mem.eql(u8, op_name, "knx.c.compile")) {
            try ops.append(allocator, .c_compile);
            continue;
        }
        if (std.mem.eql(u8, op_name, "knx.zig.link")) {
            try ops.append(allocator, .zig_link);
            continue;
        }
        if (std.mem.eql(u8, op_name, "knx.archive.pack")) {
            try ops.append(allocator, .archive_pack);
            continue;
        }
        return error.OperatorNotAllowed;
    }

    return .{
        .ops = try ops.toOwnedSlice(allocator),
    };
}

pub fn parseBuildSpecStrict(allocator: std.mem.Allocator, canonical_json: []const u8) parse_errors.ParseError!BuildSpec {
    return parseBuildSpec(allocator, canonical_json) catch |err| return parse_errors.normalize(err);
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

fn parseWorkspaceEntries(
    allocator: std.mem.Allocator,
    entries: *std.ArrayList(WorkspaceEntry),
    items: std.json.Array,
    is_dependency: bool,
) !void {
    for (items.items) |item| {
        const obj = try expectObject(item, "workspace entry");
        const mount_path_text = try expectNonEmptyString(obj, "path");
        const mount_path = try allocator.dupe(u8, mount_path_text);
        errdefer allocator.free(mount_path);

        var entry: WorkspaceEntry = .{
            .mount_path = mount_path,
            .is_dependency = is_dependency,
        };
        errdefer entry.deinit(allocator);

        const has_source = obj.get("source") != null;
        const has_cas = obj.get("cas_sha256") != null;
        if (has_source == has_cas) {
            return error.ValueInvalid;
        }

        if (has_source) {
            const source_text = try expectNonEmptyString(obj, "source");
            entry.host_source = try allocator.dupe(u8, source_text);
        } else {
            const cas_text = try expectNonEmptyString(obj, "cas_sha256");
            entry.cas_sha256 = try parseHexFixed(32, cas_text);

            if (obj.get("cas_domain")) |domain_value| {
                const domain_text = try expectString(domain_value, "cas_domain");
                entry.cas_domain = parseCasDomain(domain_text) orelse return error.ValueInvalid;
            }
        }

        try entries.append(allocator, entry);
    }
}

fn parseCasDomain(text: []const u8) ?CasDomain {
    if (std.mem.eql(u8, text, "official")) return .official;
    if (std.mem.eql(u8, text, "third_party")) return .third_party;
    if (std.mem.eql(u8, text, "local")) return .local;
    return null;
}

fn parsePositiveU64(object: std.json.ObjectMap, key: []const u8) !u64 {
    const value = object.get(key) orelse return error.MissingRequiredField;
    const number = try expectInteger(value, key);
    if (number <= 0) return error.InvalidPositiveInt;
    return @intCast(number);
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

fn parseOutputMode(text: []const u8) !u16 {
    try expectModeString(text);
    var mode: u16 = 0;
    for (text[1..]) |ch| {
        mode = (mode << 3) | @as(u16, ch - '0');
    }
    return mode;
}

fn validateOutputPath(path: []const u8) !void {
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

fn validateWorkspaceRelativePath(path: []const u8) !void {
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

fn parseHexFixed(comptime byte_len: usize, text: []const u8) ![byte_len]u8 {
    if (text.len != byte_len * 2) return error.InvalidHexLength;
    var output: [byte_len]u8 = undefined;
    _ = std.fmt.hexToBytes(&output, text) catch |err| switch (err) {
        error.InvalidCharacter => return error.InvalidHexChar,
        error.InvalidLength => return error.InvalidHexLength,
        error.NoSpaceLeft => return error.InvalidHexLength,
    };
    return output;
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

test "parseToolchainSpec extracts source and hashes" {
    const allocator = std.testing.allocator;
    const json =
        \\{
        \\  "version": 1,
        \\  "target": "x86_64-unknown-linux-musl",
        \\  "toolchain": {
        \\    "id": "zigcc-0.14.0",
        \\    "source": "file://tmp/toolchain.blob",
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
        \\  ]
        \\}
    ;

    var spec = try parseToolchainSpec(allocator, json);
    defer spec.deinit(allocator);

    try std.testing.expectEqualStrings("zigcc-0.14.0", spec.id);
    try std.testing.expect(spec.source != null);
    try std.testing.expectEqualStrings("file://tmp/toolchain.blob", spec.source.?);
    try std.testing.expectEqual(@as(u64, 1), spec.size);
}

test "parseWorkspaceSpec parses inputs and deps entries" {
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
        \\  "inputs": [
        \\    { "path": "src/main.c", "source": "project/src/main.c" }
        \\  ],
        \\  "deps": [
        \\    {
        \\      "path": "deps/libc.a",
        \\      "cas_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        \\      "cas_domain": "third_party"
        \\    }
        \\  ],
        \\  "outputs": [
        \\    { "path": "kilnexus-out/app", "mode": "0755" }
        \\  ]
        \\}
    ;

    var spec = try parseWorkspaceSpec(allocator, json);
    defer spec.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 2), spec.entries.len);
    try std.testing.expectEqualStrings("src/main.c", spec.entries[0].mount_path);
    try std.testing.expect(spec.entries[0].host_source != null);
    try std.testing.expect(!spec.entries[0].is_dependency);
    try std.testing.expect(spec.entries[1].cas_sha256 != null);
    try std.testing.expectEqual(CasDomain.third_party, spec.entries[1].cas_domain);
    try std.testing.expect(spec.entries[1].is_dependency);
}

test "parseOutputSpec parses output entries" {
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
        \\  ]
        \\}
    ;

    var spec = try parseOutputSpec(allocator, json);
    defer spec.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), spec.entries.len);
    try std.testing.expectEqualStrings("kilnexus-out/app", spec.entries[0].path);
    try std.testing.expectEqual(@as(u16, 0o755), spec.entries[0].mode);
}

test "parseBuildSpec parses fs.copy operation" {
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
        \\  "build": [
        \\    { "op": "knx.fs.copy", "from": "src/main.c", "to": "kilnexus-out/app" }
        \\  ],
        \\  "outputs": [
        \\    { "path": "kilnexus-out/app", "mode": "0755" }
        \\  ]
        \\}
    ;

    var spec = try parseBuildSpec(allocator, json);
    defer spec.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), spec.ops.len);
    switch (spec.ops[0]) {
        .fs_copy => |copy| {
            try std.testing.expectEqualStrings("src/main.c", copy.from_path);
            try std.testing.expectEqualStrings("kilnexus-out/app", copy.to_path);
        },
        else => return error.TestUnexpectedResult,
    }
}
