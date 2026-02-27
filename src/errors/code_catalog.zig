const std = @import("std");

pub const Family = enum {
    parse,
    trust,
    io,
    integrity,
    build,
    publish,
    internal,
};

pub const Descriptor = struct {
    family: Family,
    summary: []const u8,
};

const Entry = struct {
    name: [:0]const u8,
    value: u32,
    descriptor: Descriptor,
};

pub const entries: []const Entry = &.{
    .{ .name = "KX_OK", .value = 0, .descriptor = .{ .family = .internal, .summary = "ok" } },

    .{ .name = "KX_PARSE_SYNTAX", .value = 1001, .descriptor = .{ .family = .parse, .summary = "invalid syntax in lockfile" } },
    .{ .name = "KX_PARSE_SCHEMA", .value = 1002, .descriptor = .{ .family = .parse, .summary = "lockfile schema validation failed" } },
    .{ .name = "KX_PARSE_CANONICAL", .value = 1003, .descriptor = .{ .family = .parse, .summary = "lockfile canonicalization failed" } },
    .{ .name = "KX_PARSE_EMPTY_INPUT", .value = 1004, .descriptor = .{ .family = .parse, .summary = "lockfile is empty or whitespace only" } },
    .{ .name = "KX_PARSE_MISSING_FIELD", .value = 1005, .descriptor = .{ .family = .parse, .summary = "required lockfile field missing" } },
    .{ .name = "KX_PARSE_TYPE_MISMATCH", .value = 1006, .descriptor = .{ .family = .parse, .summary = "lockfile field type mismatch" } },
    .{ .name = "KX_PARSE_VALUE_INVALID", .value = 1007, .descriptor = .{ .family = .parse, .summary = "lockfile field value invalid" } },
    .{ .name = "KX_PARSE_VERSION_UNSUPPORTED", .value = 1008, .descriptor = .{ .family = .parse, .summary = "lockfile version unsupported" } },
    .{ .name = "KX_PARSE_OPERATOR_DISALLOWED", .value = 1009, .descriptor = .{ .family = .parse, .summary = "lockfile contains disallowed operator" } },
    .{ .name = "KX_PARSE_OUTPUT_INVALID", .value = 1010, .descriptor = .{ .family = .parse, .summary = "lockfile output mapping invalid" } },
    .{ .name = "KX_PARSE_LEGACY_BUILD_BLOCK", .value = 1011, .descriptor = .{ .family = .parse, .summary = "legacy build block is disallowed; use operators" } },

    .{ .name = "KX_TRUST_METADATA_MISSING", .value = 2001, .descriptor = .{ .family = .trust, .summary = "required trust metadata missing" } },
    .{ .name = "KX_TRUST_METADATA_MALFORMED", .value = 2002, .descriptor = .{ .family = .trust, .summary = "trust metadata JSON is malformed or missing required fields" } },
    .{ .name = "KX_TRUST_ROLE_POLICY", .value = 2003, .descriptor = .{ .family = .trust, .summary = "trust role policy is invalid" } },
    .{ .name = "KX_TRUST_KEY_UNSUPPORTED", .value = 2004, .descriptor = .{ .family = .trust, .summary = "trust key type or signature scheme is unsupported" } },
    .{ .name = "KX_TRUST_SIGNATURE_INVALID", .value = 2005, .descriptor = .{ .family = .trust, .summary = "trust signature verification failed" } },
    .{ .name = "KX_TRUST_SIGNATURE_THRESHOLD", .value = 2006, .descriptor = .{ .family = .trust, .summary = "trust signature threshold not met" } },
    .{ .name = "KX_TRUST_METADATA_EXPIRED", .value = 2007, .descriptor = .{ .family = .trust, .summary = "trust metadata expired or has invalid expiry timestamp" } },
    .{ .name = "KX_TRUST_ROLLBACK", .value = 2008, .descriptor = .{ .family = .trust, .summary = "rollback detected in trust metadata versions" } },
    .{ .name = "KX_TRUST_VERSION_LINK", .value = 2009, .descriptor = .{ .family = .trust, .summary = "metadata version link mismatch" } },
    .{ .name = "KX_TRUST_VERSION_INVALID", .value = 2010, .descriptor = .{ .family = .trust, .summary = "metadata version is invalid" } },
    .{ .name = "KX_TRUST_STATE_IO", .value = 2011, .descriptor = .{ .family = .trust, .summary = "trust state persistence IO failed" } },
    .{ .name = "KX_TRUST_STATE_INVALID", .value = 2012, .descriptor = .{ .family = .trust, .summary = "trust state file is malformed or invalid" } },

    .{ .name = "KX_IO_NOT_FOUND", .value = 3001, .descriptor = .{ .family = .io, .summary = "path or file not found" } },
    .{ .name = "KX_IO_ACCESS_DENIED", .value = 3002, .descriptor = .{ .family = .io, .summary = "access denied for filesystem operation" } },
    .{ .name = "KX_IO_PATH_INVALID", .value = 3003, .descriptor = .{ .family = .io, .summary = "path is invalid for filesystem operation" } },
    .{ .name = "KX_IO_READ_FAILED", .value = 3004, .descriptor = .{ .family = .io, .summary = "file read failed" } },
    .{ .name = "KX_IO_WRITE_FAILED", .value = 3005, .descriptor = .{ .family = .io, .summary = "file write failed" } },
    .{ .name = "KX_IO_NO_SPACE", .value = 3006, .descriptor = .{ .family = .io, .summary = "no space or disk quota left" } },
    .{ .name = "KX_IO_RENAME_FAILED", .value = 3007, .descriptor = .{ .family = .io, .summary = "atomic rename failed" } },
    .{ .name = "KX_IO_ALREADY_EXISTS", .value = 3008, .descriptor = .{ .family = .io, .summary = "target path already exists" } },

    .{ .name = "KX_INTEGRITY_BLOB_MISMATCH", .value = 4001, .descriptor = .{ .family = .integrity, .summary = "blob integrity mismatch" } },
    .{ .name = "KX_INTEGRITY_TREE_MISMATCH", .value = 4002, .descriptor = .{ .family = .integrity, .summary = "tree integrity mismatch" } },
    .{ .name = "KX_INTEGRITY_SIZE_MISMATCH", .value = 4003, .descriptor = .{ .family = .integrity, .summary = "content size mismatch" } },
    .{ .name = "KX_INTEGRITY_HASH_UNSUPPORTED", .value = 4004, .descriptor = .{ .family = .integrity, .summary = "unsupported hash algorithm in metadata" } },
    .{ .name = "KX_INTEGRITY_PATH_TRAVERSAL", .value = 4005, .descriptor = .{ .family = .integrity, .summary = "path traversal detected while unpacking" } },
    .{ .name = "KX_INTEGRITY_SYMLINK_POLICY", .value = 4006, .descriptor = .{ .family = .integrity, .summary = "symlink policy violation in unpacked tree" } },

    .{ .name = "KX_BUILD_OPERATOR_FAILED", .value = 5001, .descriptor = .{ .family = .build, .summary = "build operator failed" } },
    .{ .name = "KX_BUILD_OPERATOR_DISALLOWED", .value = 5002, .descriptor = .{ .family = .build, .summary = "operator is disallowed by policy" } },
    .{ .name = "KX_BUILD_TOOLCHAIN_MISSING", .value = 5003, .descriptor = .{ .family = .build, .summary = "required toolchain not available" } },
    .{ .name = "KX_BUILD_SANDBOX_VIOLATION", .value = 5004, .descriptor = .{ .family = .build, .summary = "sandbox policy violation during build" } },
    .{ .name = "KX_BUILD_GRAPH_INVALID", .value = 5005, .descriptor = .{ .family = .build, .summary = "build graph is invalid" } },
    .{ .name = "KX_BUILD_TIMEOUT", .value = 5006, .descriptor = .{ .family = .build, .summary = "build step timeout exceeded" } },
    .{ .name = "KX_BUILD_NOT_IMPLEMENTED", .value = 5007, .descriptor = .{ .family = .build, .summary = "build feature is not implemented in current MVP" } },
    .{ .name = "KX_BUILD_LOCK_MISSING", .value = 5008, .descriptor = .{ .family = .build, .summary = "lockfile missing; run knx freeze first" } },
    .{ .name = "KX_BUILD_LOCK_DRIFT", .value = 5009, .descriptor = .{ .family = .build, .summary = "knxfile changed since lock was generated; run knx freeze" } },
    .{ .name = "KX_BUILD_ALLOW_UNLOCKED_FORBIDDEN", .value = 5010, .descriptor = .{ .family = .build, .summary = "--allow-unlocked is forbidden when CI is enabled" } },
    .{ .name = "KX_BUILD_CI_LOCKFILE_REQUIRED", .value = 5011, .descriptor = .{ .family = .build, .summary = "CI requires explicit .lock input path (run knx build <Knxfile.lock>)" } },

    .{ .name = "KX_PUBLISH_ATOMIC", .value = 6001, .descriptor = .{ .family = .publish, .summary = "atomic publish failed" } },
    .{ .name = "KX_PUBLISH_OUTPUT_MISSING", .value = 6002, .descriptor = .{ .family = .publish, .summary = "declared output missing at publish boundary" } },
    .{ .name = "KX_PUBLISH_OUTPUT_HASH_MISMATCH", .value = 6003, .descriptor = .{ .family = .publish, .summary = "published output hash mismatch" } },
    .{ .name = "KX_PUBLISH_FSYNC_FAILED", .value = 6004, .descriptor = .{ .family = .publish, .summary = "fsync failed before publish" } },
    .{ .name = "KX_PUBLISH_PERMISSION", .value = 6005, .descriptor = .{ .family = .publish, .summary = "publish path permission failure" } },

    .{ .name = "KX_INTERNAL", .value = 9000, .descriptor = .{ .family = .internal, .summary = "internal error" } },
};

pub const Code = makeCodeEnum();

fn makeCodeEnum() type {
    const fields = comptime buildEnumFields();
    return @Type(.{
        .@"enum" = .{
            .tag_type = u32,
            .fields = &fields,
            .decls = &.{},
            .is_exhaustive = true,
        },
    });
}

fn buildEnumFields() [entries.len]std.builtin.Type.EnumField {
    var fields: [entries.len]std.builtin.Type.EnumField = undefined;
    inline for (entries, 0..) |entry, idx| {
        fields[idx] = .{
            .name = entry.name,
            .value = entry.value,
        };
    }
    return fields;
}

pub fn describe(code: Code) Descriptor {
    return describeByCodeValue(@intFromEnum(code));
}

pub fn describeByCodeValue(code_value: u32) Descriptor {
    inline for (entries) |entry| {
        if (code_value == entry.value) return entry.descriptor;
    }
    return .{ .family = .internal, .summary = "internal error" };
}

test "catalog lookup resolves known and unknown code values" {
    const parse = describeByCodeValue(1001);
    try std.testing.expectEqual(Family.parse, parse.family);
    try std.testing.expectEqualStrings("invalid syntax in lockfile", parse.summary);

    const unknown = describeByCodeValue(999_999);
    try std.testing.expectEqual(Family.internal, unknown.family);
    try std.testing.expectEqualStrings("internal error", unknown.summary);

    try std.testing.expectEqual(@as(u32, 1001), @intFromEnum(Code.KX_PARSE_SYNTAX));
    try std.testing.expectEqual(@as(u32, 9000), @intFromEnum(Code.KX_INTERNAL));
}
