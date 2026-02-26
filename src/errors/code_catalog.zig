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
    code_value: u32,
    descriptor: Descriptor,
};

pub const entries: []const Entry = &.{
    .{ .code_value = 0, .descriptor = .{ .family = .internal, .summary = "ok" } },

    .{ .code_value = 1001, .descriptor = .{ .family = .parse, .summary = "invalid syntax in lockfile" } },
    .{ .code_value = 1002, .descriptor = .{ .family = .parse, .summary = "lockfile schema validation failed" } },
    .{ .code_value = 1003, .descriptor = .{ .family = .parse, .summary = "lockfile canonicalization failed" } },
    .{ .code_value = 1004, .descriptor = .{ .family = .parse, .summary = "lockfile is empty or whitespace only" } },
    .{ .code_value = 1005, .descriptor = .{ .family = .parse, .summary = "required lockfile field missing" } },
    .{ .code_value = 1006, .descriptor = .{ .family = .parse, .summary = "lockfile field type mismatch" } },
    .{ .code_value = 1007, .descriptor = .{ .family = .parse, .summary = "lockfile field value invalid" } },
    .{ .code_value = 1008, .descriptor = .{ .family = .parse, .summary = "lockfile version unsupported" } },
    .{ .code_value = 1009, .descriptor = .{ .family = .parse, .summary = "lockfile contains disallowed operator" } },
    .{ .code_value = 1010, .descriptor = .{ .family = .parse, .summary = "lockfile output mapping invalid" } },
    .{ .code_value = 1011, .descriptor = .{ .family = .parse, .summary = "legacy build block is disallowed; use operators" } },

    .{ .code_value = 2001, .descriptor = .{ .family = .trust, .summary = "required trust metadata missing" } },
    .{ .code_value = 2002, .descriptor = .{ .family = .trust, .summary = "trust metadata JSON is malformed or missing required fields" } },
    .{ .code_value = 2003, .descriptor = .{ .family = .trust, .summary = "trust role policy is invalid" } },
    .{ .code_value = 2004, .descriptor = .{ .family = .trust, .summary = "trust key type or signature scheme is unsupported" } },
    .{ .code_value = 2005, .descriptor = .{ .family = .trust, .summary = "trust signature verification failed" } },
    .{ .code_value = 2006, .descriptor = .{ .family = .trust, .summary = "trust signature threshold not met" } },
    .{ .code_value = 2007, .descriptor = .{ .family = .trust, .summary = "trust metadata expired or has invalid expiry timestamp" } },
    .{ .code_value = 2008, .descriptor = .{ .family = .trust, .summary = "rollback detected in trust metadata versions" } },
    .{ .code_value = 2009, .descriptor = .{ .family = .trust, .summary = "metadata version link mismatch" } },
    .{ .code_value = 2010, .descriptor = .{ .family = .trust, .summary = "metadata version is invalid" } },
    .{ .code_value = 2011, .descriptor = .{ .family = .trust, .summary = "trust state persistence IO failed" } },
    .{ .code_value = 2012, .descriptor = .{ .family = .trust, .summary = "trust state file is malformed or invalid" } },

    .{ .code_value = 3001, .descriptor = .{ .family = .io, .summary = "path or file not found" } },
    .{ .code_value = 3002, .descriptor = .{ .family = .io, .summary = "access denied for filesystem operation" } },
    .{ .code_value = 3003, .descriptor = .{ .family = .io, .summary = "path is invalid for filesystem operation" } },
    .{ .code_value = 3004, .descriptor = .{ .family = .io, .summary = "file read failed" } },
    .{ .code_value = 3005, .descriptor = .{ .family = .io, .summary = "file write failed" } },
    .{ .code_value = 3006, .descriptor = .{ .family = .io, .summary = "no space or disk quota left" } },
    .{ .code_value = 3007, .descriptor = .{ .family = .io, .summary = "atomic rename failed" } },
    .{ .code_value = 3008, .descriptor = .{ .family = .io, .summary = "target path already exists" } },

    .{ .code_value = 4001, .descriptor = .{ .family = .integrity, .summary = "blob integrity mismatch" } },
    .{ .code_value = 4002, .descriptor = .{ .family = .integrity, .summary = "tree integrity mismatch" } },
    .{ .code_value = 4003, .descriptor = .{ .family = .integrity, .summary = "content size mismatch" } },
    .{ .code_value = 4004, .descriptor = .{ .family = .integrity, .summary = "unsupported hash algorithm in metadata" } },
    .{ .code_value = 4005, .descriptor = .{ .family = .integrity, .summary = "path traversal detected while unpacking" } },
    .{ .code_value = 4006, .descriptor = .{ .family = .integrity, .summary = "symlink policy violation in unpacked tree" } },

    .{ .code_value = 5001, .descriptor = .{ .family = .build, .summary = "build operator failed" } },
    .{ .code_value = 5002, .descriptor = .{ .family = .build, .summary = "operator is disallowed by policy" } },
    .{ .code_value = 5003, .descriptor = .{ .family = .build, .summary = "required toolchain not available" } },
    .{ .code_value = 5004, .descriptor = .{ .family = .build, .summary = "sandbox policy violation during build" } },
    .{ .code_value = 5005, .descriptor = .{ .family = .build, .summary = "build graph is invalid" } },
    .{ .code_value = 5006, .descriptor = .{ .family = .build, .summary = "build step timeout exceeded" } },
    .{ .code_value = 5007, .descriptor = .{ .family = .build, .summary = "build feature is not implemented in current MVP" } },

    .{ .code_value = 6001, .descriptor = .{ .family = .publish, .summary = "atomic publish failed" } },
    .{ .code_value = 6002, .descriptor = .{ .family = .publish, .summary = "declared output missing at publish boundary" } },
    .{ .code_value = 6003, .descriptor = .{ .family = .publish, .summary = "published output hash mismatch" } },
    .{ .code_value = 6004, .descriptor = .{ .family = .publish, .summary = "fsync failed before publish" } },
    .{ .code_value = 6005, .descriptor = .{ .family = .publish, .summary = "publish path permission failure" } },

    .{ .code_value = 9000, .descriptor = .{ .family = .internal, .summary = "internal error" } },
};

pub fn describeByCodeValue(code_value: u32) Descriptor {
    inline for (entries) |entry| {
        if (code_value == entry.code_value) return entry.descriptor;
    }
    return .{ .family = .internal, .summary = "internal error" };
}

pub fn hasCodeValue(comptime code_value: u32) bool {
    inline for (entries) |entry| {
        if (code_value == entry.code_value) return true;
    }
    return false;
}

test "catalog lookup resolves known and unknown code values" {
    const parse = describeByCodeValue(1001);
    try std.testing.expectEqual(Family.parse, parse.family);
    try std.testing.expectEqualStrings("invalid syntax in lockfile", parse.summary);

    const unknown = describeByCodeValue(999_999);
    try std.testing.expectEqual(Family.internal, unknown.family);
    try std.testing.expectEqualStrings("internal error", unknown.summary);
}
