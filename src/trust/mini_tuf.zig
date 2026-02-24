const std = @import("std");

pub const MetadataBundle = struct {
    root_json: []u8,
    timestamp_json: []u8,
    snapshot_json: []u8,
    targets_json: []u8,

    pub fn deinit(self: *MetadataBundle, allocator: std.mem.Allocator) void {
        allocator.free(self.root_json);
        allocator.free(self.timestamp_json);
        allocator.free(self.snapshot_json);
        allocator.free(self.targets_json);
        self.* = undefined;
    }
};

pub const VerifyOptions = struct {
    state_path: ?[]const u8 = null,
    now_unix_seconds: ?i64 = null,
};

pub const VerificationSummary = struct {
    root_version: u64,
    timestamp_version: u64,
    snapshot_version: u64,
    targets_version: u64,
};

pub const TrustError = error{
    MetadataMissing,
    MetadataMalformed,
    RolePolicyInvalid,
    KeyUnsupported,
    SignatureInvalid,
    SignatureThresholdNotMet,
    MetadataExpired,
    RollbackDetected,
    VersionLinkMismatch,
    VersionInvalid,
    StateIo,
    StateInvalid,
    Internal,
};

pub fn loadFromDir(allocator: std.mem.Allocator, trust_dir_path: []const u8) !MetadataBundle {
    const root_json = try readRoleFromDir(allocator, trust_dir_path, "root.json");
    errdefer allocator.free(root_json);
    const timestamp_json = try readRoleFromDir(allocator, trust_dir_path, "timestamp.json");
    errdefer allocator.free(timestamp_json);
    const snapshot_json = try readRoleFromDir(allocator, trust_dir_path, "snapshot.json");
    errdefer allocator.free(snapshot_json);
    const targets_json = try readRoleFromDir(allocator, trust_dir_path, "targets.json");
    errdefer allocator.free(targets_json);

    return .{
        .root_json = root_json,
        .timestamp_json = timestamp_json,
        .snapshot_json = snapshot_json,
        .targets_json = targets_json,
    };
}

pub fn loadFromDirStrict(allocator: std.mem.Allocator, trust_dir_path: []const u8) TrustError!MetadataBundle {
    return loadFromDir(allocator, trust_dir_path) catch |err| return normalizeError(err);
}

pub fn verify(allocator: std.mem.Allocator, bundle: *const MetadataBundle, options: VerifyOptions) !VerificationSummary {
    var root_doc = try std.json.parseFromSlice(std.json.Value, allocator, bundle.root_json, .{});
    defer root_doc.deinit();
    var timestamp_doc = try std.json.parseFromSlice(std.json.Value, allocator, bundle.timestamp_json, .{});
    defer timestamp_doc.deinit();
    var snapshot_doc = try std.json.parseFromSlice(std.json.Value, allocator, bundle.snapshot_json, .{});
    defer snapshot_doc.deinit();
    var targets_doc = try std.json.parseFromSlice(std.json.Value, allocator, bundle.targets_json, .{});
    defer targets_doc.deinit();

    const now_unix = options.now_unix_seconds orelse std.time.timestamp();

    var trust = try parseRootTrust(allocator, root_doc.value);
    defer trust.deinit(allocator);

    const root_meta = try verifySignedMetadata(allocator, root_doc.value, "root", trust.root, now_unix, &trust.keys);
    const timestamp_meta = try verifySignedMetadata(allocator, timestamp_doc.value, "timestamp", trust.timestamp, now_unix, &trust.keys);
    const snapshot_meta = try verifySignedMetadata(allocator, snapshot_doc.value, "snapshot", trust.snapshot, now_unix, &trust.keys);
    const targets_meta = try verifySignedMetadata(allocator, targets_doc.value, "targets", trust.targets, now_unix, &trust.keys);

    try verifyRoleLinkVersion(timestamp_meta.signed_object, "snapshot.json", snapshot_meta.version);
    try verifyRoleLinkVersion(snapshot_meta.signed_object, "targets.json", targets_meta.version);

    const summary: VerificationSummary = .{
        .root_version = root_meta.version,
        .timestamp_version = timestamp_meta.version,
        .snapshot_version = snapshot_meta.version,
        .targets_version = targets_meta.version,
    };

    if (options.state_path) |state_path| {
        const previous = try loadPersistedState(allocator, state_path);
        try enforceRollback(previous, summary);
        try persistStateAtomically(state_path, summary);
    }

    return summary;
}

pub fn verifyStrict(allocator: std.mem.Allocator, bundle: *const MetadataBundle, options: VerifyOptions) TrustError!VerificationSummary {
    return verify(allocator, bundle, options) catch |err| return normalizeError(err);
}

pub fn enforceRollback(previous: VerificationSummary, current: VerificationSummary) !void {
    if (current.root_version < previous.root_version) return error.RollbackDetected;
    if (current.timestamp_version < previous.timestamp_version) return error.RollbackDetected;
    if (current.snapshot_version < previous.snapshot_version) return error.RollbackDetected;
    if (current.targets_version < previous.targets_version) return error.RollbackDetected;
}

pub fn normalizeError(err: anyerror) TrustError {
    if (err == error.MetadataMissing or err == error.FileNotFound) {
        return error.MetadataMissing;
    }

    if (err == error.MetadataMalformed or err == error.ExpectedObject or err == error.ExpectedArray or err == error.ExpectedString or err == error.ExpectedInteger or err == error.MissingRequiredField or err == error.MissingSignedSection or err == error.MissingSignaturesSection) {
        return error.MetadataMalformed;
    }

    if (err == error.RolePolicyInvalid or err == error.MissingRoleRule or err == error.InvalidRoleType or err == error.InvalidThreshold or err == error.EmptyRoleKeyIds or err == error.EmptyRoleKeyId or err == error.InvalidSignatureEntry or err == error.EmptySignatures) {
        return error.RolePolicyInvalid;
    }

    if (err == error.KeyUnsupported or err == error.UnsupportedKeyType or err == error.UnsupportedSignatureScheme) {
        return error.KeyUnsupported;
    }

    if (err == error.SignatureInvalid or err == error.SignatureVerificationFailed or err == error.EncodingError or err == error.IdentityElement or err == error.WeakPublicKey or err == error.NonCanonical or err == error.InvalidHexLength or err == error.InvalidCharacter) {
        return error.SignatureInvalid;
    }

    if (err == error.SignatureThresholdNotMet) {
        return error.SignatureThresholdNotMet;
    }

    if (err == error.MetadataExpired or err == error.InvalidTimestampFormat or err == error.InvalidTimestampYear or err == error.InvalidTimestampMonth or err == error.InvalidTimestampDay or err == error.InvalidTimestampClock) {
        return error.MetadataExpired;
    }

    if (err == error.RollbackDetected) return error.RollbackDetected;

    if (err == error.VersionLinkMismatch or err == error.LinkedMetadataVersionMismatch or err == error.InvalidLinkedVersion or err == error.MissingLinkedMetadata) {
        return error.VersionLinkMismatch;
    }

    if (err == error.VersionInvalid or err == error.InvalidMetadataVersion) {
        return error.VersionInvalid;
    }

    if (err == error.StateInvalid or err == error.InvalidStateVersion) {
        return error.StateInvalid;
    }

    if (err == error.StateIo or err == error.AccessDenied or err == error.PermissionDenied or err == error.ReadOnlyFileSystem or err == error.NoSpaceLeft or err == error.DiskQuota or err == error.FileBusy or err == error.InputOutput or err == error.RenameAcrossMountPoints) {
        return error.StateIo;
    }

    return error.Internal;
}

const max_role_file_bytes: usize = 2 * 1024 * 1024;
const max_state_bytes: usize = 64 * 1024;

const SignatureEntry = struct {
    keyid: []const u8,
    sig_hex: []const u8,
};

const SignedMetadata = struct {
    signed_object: std.json.ObjectMap,
    version: u64,
};

const TrustedKey = struct {
    keyid: []const u8,
    public_key: [32]u8,
};

const RoleRule = struct {
    threshold: usize,
    keyids: std.ArrayList([]const u8),

    fn deinit(self: *RoleRule, allocator: std.mem.Allocator) void {
        self.keyids.deinit(allocator);
        self.* = undefined;
    }
};

const RootTrust = struct {
    keys: std.ArrayList(TrustedKey),
    root: RoleRule,
    targets: RoleRule,
    snapshot: RoleRule,
    timestamp: RoleRule,

    fn deinit(self: *RootTrust, allocator: std.mem.Allocator) void {
        self.keys.deinit(allocator);
        self.root.deinit(allocator);
        self.targets.deinit(allocator);
        self.snapshot.deinit(allocator);
        self.timestamp.deinit(allocator);
        self.* = undefined;
    }
};

fn readRoleFromDir(allocator: std.mem.Allocator, trust_dir_path: []const u8, role_filename: []const u8) ![]u8 {
    const full_path = try std.fs.path.join(allocator, &.{ trust_dir_path, role_filename });
    defer allocator.free(full_path);
    return std.fs.cwd().readFileAlloc(allocator, full_path, max_role_file_bytes);
}

fn parseRootTrust(allocator: std.mem.Allocator, document_value: std.json.Value) !RootTrust {
    const top = try expectObject(document_value, "root document");
    const signed_value = top.get("signed") orelse return error.MissingSignedSection;
    const signed = try expectObject(signed_value, "signed");

    const role_type = try expectStringField(signed, "_type");
    if (!std.mem.eql(u8, role_type, "root")) return error.InvalidRoleType;

    const keys_obj = try expectObjectField(signed, "keys");
    var keys: std.ArrayList(TrustedKey) = .empty;
    errdefer keys.deinit(allocator);
    var key_it = keys_obj.iterator();
    while (key_it.next()) |entry| {
        const keyid = entry.key_ptr.*;
        const key_data = try expectObject(entry.value_ptr.*, "key data");
        const key_type = try expectStringField(key_data, "keytype");
        if (!std.mem.eql(u8, key_type, "ed25519")) return error.UnsupportedKeyType;
        const scheme = try expectStringField(key_data, "scheme");
        if (!std.mem.eql(u8, scheme, "ed25519")) return error.UnsupportedSignatureScheme;
        const keyval = try expectObjectField(key_data, "keyval");
        const public_hex = try expectStringField(keyval, "public");
        const public_bytes = try parseHexFixed(32, public_hex);
        try keys.append(allocator, .{
            .keyid = keyid,
            .public_key = public_bytes,
        });
    }

    const roles_obj = try expectObjectField(signed, "roles");
    var root_role = try parseRoleRule(allocator, roles_obj, "root");
    errdefer root_role.deinit(allocator);
    var targets_role = try parseRoleRule(allocator, roles_obj, "targets");
    errdefer targets_role.deinit(allocator);
    var snapshot_role = try parseRoleRule(allocator, roles_obj, "snapshot");
    errdefer snapshot_role.deinit(allocator);
    var timestamp_role = try parseRoleRule(allocator, roles_obj, "timestamp");
    errdefer timestamp_role.deinit(allocator);

    return .{
        .keys = keys,
        .root = root_role,
        .targets = targets_role,
        .snapshot = snapshot_role,
        .timestamp = timestamp_role,
    };
}

fn parseRoleRule(allocator: std.mem.Allocator, roles_obj: std.json.ObjectMap, role_name: []const u8) !RoleRule {
    const raw = roles_obj.get(role_name) orelse return error.MissingRoleRule;
    const obj = try expectObject(raw, "role rule");
    const threshold_i64 = try expectIntegerField(obj, "threshold");
    if (threshold_i64 <= 0) return error.InvalidThreshold;

    const keyids_array = try expectArrayField(obj, "keyids");
    if (keyids_array.items.len == 0) return error.EmptyRoleKeyIds;
    var keyids: std.ArrayList([]const u8) = .empty;
    errdefer keyids.deinit(allocator);
    for (keyids_array.items) |item| {
        const keyid = try expectString(item, "keyid");
        if (keyid.len == 0) return error.EmptyRoleKeyId;
        try keyids.append(allocator, keyid);
    }

    return .{
        .threshold = @as(usize, @intCast(threshold_i64)),
        .keyids = keyids,
    };
}

fn verifySignedMetadata(
    allocator: std.mem.Allocator,
    document_value: std.json.Value,
    role_name: []const u8,
    role_rule: RoleRule,
    now_unix: i64,
    trusted_keys: *const std.ArrayList(TrustedKey),
) !SignedMetadata {
    const top = try expectObject(document_value, "metadata document");
    const signed_value = top.get("signed") orelse return error.MissingSignedSection;
    const signatures_value = top.get("signatures") orelse return error.MissingSignaturesSection;
    const signed_obj = try expectObject(signed_value, "signed");
    const signatures_array = try expectArray(signatures_value, "signatures");
    if (signatures_array.items.len == 0) return error.EmptySignatures;

    const signed_type = try expectStringField(signed_obj, "_type");
    if (!std.mem.eql(u8, signed_type, role_name)) return error.InvalidRoleType;
    const version_i64 = try expectIntegerField(signed_obj, "version");
    if (version_i64 <= 0) return error.InvalidMetadataVersion;
    const expires = try expectStringField(signed_obj, "expires");
    try verifyNotExpired(expires, now_unix);

    var signatures: std.ArrayList(SignatureEntry) = .empty;
    defer signatures.deinit(allocator);
    for (signatures_array.items) |item| {
        const signature_obj = try expectObject(item, "signature");
        const keyid = try expectStringField(signature_obj, "keyid");
        const sig_hex = try expectStringField(signature_obj, "sig");
        if (keyid.len == 0 or sig_hex.len == 0) return error.InvalidSignatureEntry;
        try signatures.append(allocator, .{
            .keyid = keyid,
            .sig_hex = sig_hex,
        });
    }

    const canonical_signed = try canonicalizeJsonValueAlloc(allocator, signed_value);
    defer allocator.free(canonical_signed);

    try verifyRoleThreshold(allocator, role_rule, trusted_keys, signatures.items, canonical_signed);

    return .{
        .signed_object = signed_obj,
        .version = @as(u64, @intCast(version_i64)),
    };
}

fn verifyRoleThreshold(
    allocator: std.mem.Allocator,
    role_rule: RoleRule,
    trusted_keys: *const std.ArrayList(TrustedKey),
    signatures: []const SignatureEntry,
    canonical_signed: []const u8,
) !void {
    var seen: std.ArrayList([]const u8) = .empty;
    defer seen.deinit(allocator);
    var valid_count: usize = 0;

    for (signatures) |sig_entry| {
        if (!containsKeyId(role_rule.keyids.items, sig_entry.keyid)) continue;
        if (containsKeyId(seen.items, sig_entry.keyid)) continue;

        const trusted_key = findTrustedKey(trusted_keys.items, sig_entry.keyid) orelse continue;
        const signature_bytes = try parseHexFixed(64, sig_entry.sig_hex);
        const signature = std.crypto.sign.Ed25519.Signature.fromBytes(signature_bytes);
        const public_key = std.crypto.sign.Ed25519.PublicKey.fromBytes(trusted_key.public_key) catch continue;

        signature.verify(canonical_signed, public_key) catch continue;

        try seen.append(allocator, sig_entry.keyid);
        valid_count += 1;
    }

    if (valid_count < role_rule.threshold) return error.SignatureThresholdNotMet;
}

fn verifyRoleLinkVersion(signed_obj: std.json.ObjectMap, linked_filename: []const u8, expected_version: u64) !void {
    const meta = try expectObjectField(signed_obj, "meta");
    const linked_value = meta.get(linked_filename) orelse return error.MissingLinkedMetadata;
    const linked_obj = try expectObject(linked_value, "linked metadata");
    const linked_version_i64 = try expectIntegerField(linked_obj, "version");
    if (linked_version_i64 <= 0) return error.InvalidLinkedVersion;
    const linked_version: u64 = @intCast(linked_version_i64);
    if (linked_version != expected_version) return error.LinkedMetadataVersionMismatch;
}

fn verifyNotExpired(expires: []const u8, now_unix: i64) !void {
    const expires_unix = try parseIso8601Utc(expires);
    if (now_unix > expires_unix) return error.MetadataExpired;
}

fn loadPersistedState(allocator: std.mem.Allocator, state_path: []const u8) !VerificationSummary {
    const bytes = std.fs.cwd().readFileAlloc(allocator, state_path, max_state_bytes) catch |err| switch (err) {
        error.FileNotFound => return .{
            .root_version = 0,
            .timestamp_version = 0,
            .snapshot_version = 0,
            .targets_version = 0,
        },
        else => return err,
    };
    defer allocator.free(bytes);

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{});
    defer parsed.deinit();
    const root = try expectObject(parsed.value, "state");

    return .{
        .root_version = try readStateVersion(root, "root"),
        .timestamp_version = try readStateVersion(root, "timestamp"),
        .snapshot_version = try readStateVersion(root, "snapshot"),
        .targets_version = try readStateVersion(root, "targets"),
    };
}

fn readStateVersion(state: std.json.ObjectMap, key: []const u8) !u64 {
    const value = state.get(key) orelse return 0;
    const as_int = try expectInteger(value, "state version");
    if (as_int < 0) return error.InvalidStateVersion;
    return @as(u64, @intCast(as_int));
}

fn persistStateAtomically(state_path: []const u8, summary: VerificationSummary) !void {
    var buffer: [512]u8 = undefined;
    var atomic_file = try std.fs.cwd().atomicFile(state_path, .{
        .mode = 0o644,
        .make_path = true,
        .write_buffer = &buffer,
    });
    defer atomic_file.deinit();

    try atomic_file.file_writer.interface.print(
        "{{\"root\":{d},\"timestamp\":{d},\"snapshot\":{d},\"targets\":{d}}}",
        .{
            summary.root_version,
            summary.timestamp_version,
            summary.snapshot_version,
            summary.targets_version,
        },
    );
    try atomic_file.finish();
}

fn parseIso8601Utc(text: []const u8) !i64 {
    if (text.len != 20) return error.InvalidTimestampFormat;
    if (text[4] != '-' or text[7] != '-' or text[10] != 'T' or text[13] != ':' or text[16] != ':' or text[19] != 'Z') {
        return error.InvalidTimestampFormat;
    }

    const year = try parseUint(text[0..4]);
    if (year < 1970) return error.InvalidTimestampYear;
    const month = try parseUint(text[5..7]);
    const day = try parseUint(text[8..10]);
    const hour = try parseUint(text[11..13]);
    const minute = try parseUint(text[14..16]);
    const second = try parseUint(text[17..19]);

    if (month < 1 or month > 12) return error.InvalidTimestampMonth;
    if (hour > 23 or minute > 59 or second > 59) return error.InvalidTimestampClock;

    const month_enum: std.time.epoch.Month = @enumFromInt(month);
    const max_day = std.time.epoch.getDaysInMonth(@as(std.time.epoch.Year, @intCast(year)), month_enum);
    if (day < 1 or day > max_day) return error.InvalidTimestampDay;

    var days: i64 = 0;
    var current_year: u64 = 1970;
    while (current_year < year) : (current_year += 1) {
        days += @as(i64, std.time.epoch.getDaysInYear(@as(std.time.epoch.Year, @intCast(current_year))));
    }

    var current_month: u64 = 1;
    while (current_month < month) : (current_month += 1) {
        const m: std.time.epoch.Month = @enumFromInt(current_month);
        days += @as(i64, std.time.epoch.getDaysInMonth(@as(std.time.epoch.Year, @intCast(year)), m));
    }

    days += @as(i64, @intCast(day - 1));
    return days * std.time.s_per_day +
        @as(i64, @intCast(hour * std.time.s_per_hour + minute * std.time.s_per_min + second));
}

fn parseUint(text: []const u8) !u64 {
    return std.fmt.parseUnsigned(u64, text, 10);
}

fn canonicalizeJsonValueAlloc(allocator: std.mem.Allocator, value: std.json.Value) ![]u8 {
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    try writeCanonicalValue(&output.writer, value, allocator);
    return output.toOwnedSlice();
}

fn writeCanonicalValue(writer: *std.Io.Writer, value: std.json.Value, allocator: std.mem.Allocator) !void {
    switch (value) {
        .null => try writer.writeAll("null"),
        .bool => |b| try writer.writeAll(if (b) "true" else "false"),
        .integer => |n| try writer.print("{d}", .{n}),
        .number_string => |n| try writer.writeAll(n),
        .float => return error.UnsupportedFloatInCanonicalization,
        .string => |s| try std.json.Stringify.encodeJsonString(s, .{}, writer),
        .array => |array| {
            try writer.writeAll("[");
            for (array.items, 0..) |item, idx| {
                if (idx != 0) try writer.writeAll(",");
                try writeCanonicalValue(writer, item, allocator);
            }
            try writer.writeAll("]");
        },
        .object => |object| {
            var keys: std.ArrayList([]const u8) = .empty;
            defer keys.deinit(allocator);
            try keys.ensureTotalCapacity(allocator, object.count());

            var it = object.iterator();
            while (it.next()) |entry| {
                keys.appendAssumeCapacity(entry.key_ptr.*);
            }

            std.sort.pdq([]const u8, keys.items, {}, struct {
                fn lessThan(_: void, lhs: []const u8, rhs: []const u8) bool {
                    return std.mem.order(u8, lhs, rhs) == .lt;
                }
            }.lessThan);

            try writer.writeAll("{");
            for (keys.items, 0..) |key, idx| {
                if (idx != 0) try writer.writeAll(",");
                try std.json.Stringify.encodeJsonString(key, .{}, writer);
                try writer.writeAll(":");
                const child = object.get(key) orelse return error.InvalidCanonicalObject;
                try writeCanonicalValue(writer, child, allocator);
            }
            try writer.writeAll("}");
        },
    }
}

fn parseHexFixed(comptime byte_len: usize, text: []const u8) ![byte_len]u8 {
    if (text.len != byte_len * 2) return error.InvalidHexLength;
    var output: [byte_len]u8 = undefined;
    _ = try std.fmt.hexToBytes(&output, text);
    return output;
}

fn containsKeyId(keyids: []const []const u8, keyid: []const u8) bool {
    for (keyids) |candidate| {
        if (std.mem.eql(u8, candidate, keyid)) return true;
    }
    return false;
}

fn findTrustedKey(keys: []const TrustedKey, keyid: []const u8) ?TrustedKey {
    for (keys) |trusted| {
        if (std.mem.eql(u8, trusted.keyid, keyid)) return trusted;
    }
    return null;
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
        .integer => |integer| integer,
        else => error.ExpectedInteger,
    };
}

fn expectObjectField(object: std.json.ObjectMap, key: []const u8) !std.json.ObjectMap {
    const value = object.get(key) orelse return error.MissingRequiredField;
    return expectObject(value, key);
}

fn expectArrayField(object: std.json.ObjectMap, key: []const u8) !std.json.Array {
    const value = object.get(key) orelse return error.MissingRequiredField;
    return expectArray(value, key);
}

fn expectStringField(object: std.json.ObjectMap, key: []const u8) ![]const u8 {
    const value = object.get(key) orelse return error.MissingRequiredField;
    return expectString(value, key);
}

fn expectIntegerField(object: std.json.ObjectMap, key: []const u8) !i64 {
    const value = object.get(key) orelse return error.MissingRequiredField;
    return expectInteger(value, key);
}

test "verify accepts valid mini-tuf chain" {
    const allocator = std.testing.allocator;
    const key_pair = std.crypto.sign.Ed25519.KeyPair.generateDeterministic([_]u8{7} ** 32) catch unreachable;
    const keyid = "root-key-1";
    const pub_hex = std.fmt.bytesToHex(key_pair.public_key.toBytes(), .lower);

    const root_signed = try std.fmt.allocPrint(
        allocator,
        "{{\"_type\":\"root\",\"version\":1,\"expires\":\"2099-01-01T00:00:00Z\",\"keys\":{{\"{s}\":{{\"keytype\":\"ed25519\",\"scheme\":\"ed25519\",\"keyval\":{{\"public\":\"{s}\"}}}}}},\"roles\":{{\"root\":{{\"keyids\":[\"{s}\"],\"threshold\":1}},\"targets\":{{\"keyids\":[\"{s}\"],\"threshold\":1}},\"snapshot\":{{\"keyids\":[\"{s}\"],\"threshold\":1}},\"timestamp\":{{\"keyids\":[\"{s}\"],\"threshold\":1}}}}}}",
        .{ keyid, pub_hex, keyid, keyid, keyid, keyid },
    );
    defer allocator.free(root_signed);
    const timestamp_signed = "{\"_type\":\"timestamp\",\"version\":1,\"expires\":\"2099-01-01T00:00:00Z\",\"meta\":{\"snapshot.json\":{\"version\":1}}}";
    const snapshot_signed = "{\"_type\":\"snapshot\",\"version\":1,\"expires\":\"2099-01-01T00:00:00Z\",\"meta\":{\"targets.json\":{\"version\":1}}}";
    const targets_signed = "{\"_type\":\"targets\",\"version\":1,\"expires\":\"2099-01-01T00:00:00Z\",\"targets\":{}}";

    const root_doc = try signRoleDocument(allocator, key_pair, keyid, root_signed);
    defer allocator.free(root_doc);
    const timestamp_doc = try signRoleDocument(allocator, key_pair, keyid, timestamp_signed);
    defer allocator.free(timestamp_doc);
    const snapshot_doc = try signRoleDocument(allocator, key_pair, keyid, snapshot_signed);
    defer allocator.free(snapshot_doc);
    const targets_doc = try signRoleDocument(allocator, key_pair, keyid, targets_signed);
    defer allocator.free(targets_doc);

    var bundle: MetadataBundle = .{
        .root_json = try allocator.dupe(u8, root_doc),
        .timestamp_json = try allocator.dupe(u8, timestamp_doc),
        .snapshot_json = try allocator.dupe(u8, snapshot_doc),
        .targets_json = try allocator.dupe(u8, targets_doc),
    };
    defer bundle.deinit(allocator);

    const summary = try verify(allocator, &bundle, .{
        .state_path = null,
        .now_unix_seconds = 1_800_000_000,
    });

    try std.testing.expectEqual(@as(u64, 1), summary.root_version);
    try std.testing.expectEqual(@as(u64, 1), summary.timestamp_version);
    try std.testing.expectEqual(@as(u64, 1), summary.snapshot_version);
    try std.testing.expectEqual(@as(u64, 1), summary.targets_version);
}

test "verify rejects rollback" {
    const previous: VerificationSummary = .{
        .root_version = 2,
        .timestamp_version = 5,
        .snapshot_version = 4,
        .targets_version = 3,
    };
    const current: VerificationSummary = .{
        .root_version = 1,
        .timestamp_version = 5,
        .snapshot_version = 4,
        .targets_version = 3,
    };
    try std.testing.expectError(error.RollbackDetected, enforceRollback(previous, current));
}

test "normalizeError maps raw errors into canonical trust errors" {
    try std.testing.expect(normalizeError(error.InvalidThreshold) == error.RolePolicyInvalid);
    try std.testing.expect(normalizeError(error.InvalidTimestampFormat) == error.MetadataExpired);
    try std.testing.expect(normalizeError(error.InvalidStateVersion) == error.StateInvalid);
}

test "parseIso8601Utc validates format and value" {
    try std.testing.expectError(error.InvalidTimestampFormat, parseIso8601Utc("2026-01-01"));
    try std.testing.expectError(error.InvalidTimestampDay, parseIso8601Utc("2026-02-31T00:00:00Z"));
    const unix = try parseIso8601Utc("1970-01-02T00:00:00Z");
    try std.testing.expectEqual(@as(i64, 86_400), unix);
}

fn signRoleDocument(
    allocator: std.mem.Allocator,
    key_pair: std.crypto.sign.Ed25519.KeyPair,
    keyid: []const u8,
    signed_json: []const u8,
) ![]u8 {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, signed_json, .{});
    defer parsed.deinit();
    const canonical_signed = try canonicalizeJsonValueAlloc(allocator, parsed.value);
    defer allocator.free(canonical_signed);

    const signature = try key_pair.sign(canonical_signed, null);
    const sig_hex = std.fmt.bytesToHex(signature.toBytes(), .lower);

    return std.fmt.allocPrint(
        allocator,
        "{{\"signed\":{s},\"signatures\":[{{\"keyid\":\"{s}\",\"sig\":\"{s}\"}}]}}",
        .{ signed_json, keyid, sig_hex },
    );
}
