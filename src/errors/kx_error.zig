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

pub const Code = enum(u32) {
    KX_OK = 0,

    KX_PARSE_SYNTAX = 1001,
    KX_PARSE_SCHEMA = 1002,
    KX_PARSE_CANONICAL = 1003,

    KX_TRUST_METADATA_MISSING = 2001,
    KX_TRUST_METADATA_MALFORMED = 2002,
    KX_TRUST_ROLE_POLICY = 2003,
    KX_TRUST_KEY_UNSUPPORTED = 2004,
    KX_TRUST_SIGNATURE_INVALID = 2005,
    KX_TRUST_SIGNATURE_THRESHOLD = 2006,
    KX_TRUST_METADATA_EXPIRED = 2007,
    KX_TRUST_ROLLBACK = 2008,
    KX_TRUST_VERSION_LINK = 2009,
    KX_TRUST_VERSION_INVALID = 2010,
    KX_TRUST_STATE_IO = 2011,
    KX_TRUST_STATE_INVALID = 2012,

    KX_IO_READ = 3001,
    KX_IO_WRITE = 3002,
    KX_IO_RENAME = 3003,

    KX_INTEGRITY_BLOB_MISMATCH = 4001,
    KX_INTEGRITY_TREE_MISMATCH = 4002,

    KX_BUILD_OPERATOR_FAILED = 5001,
    KX_PUBLISH_ATOMIC = 6001,

    KX_INTERNAL = 9000,
};

pub const Descriptor = struct {
    family: Family,
    summary: []const u8,
};

pub fn describe(code: Code) Descriptor {
    return switch (code) {
        .KX_OK => .{ .family = .internal, .summary = "ok" },
        .KX_PARSE_SYNTAX => .{ .family = .parse, .summary = "invalid syntax in lockfile" },
        .KX_PARSE_SCHEMA => .{ .family = .parse, .summary = "lockfile schema validation failed" },
        .KX_PARSE_CANONICAL => .{ .family = .parse, .summary = "lockfile canonicalization failed" },

        .KX_TRUST_METADATA_MISSING => .{ .family = .trust, .summary = "required trust metadata missing" },
        .KX_TRUST_METADATA_MALFORMED => .{ .family = .trust, .summary = "trust metadata JSON is malformed or missing required fields" },
        .KX_TRUST_ROLE_POLICY => .{ .family = .trust, .summary = "trust role policy is invalid" },
        .KX_TRUST_KEY_UNSUPPORTED => .{ .family = .trust, .summary = "trust key type or signature scheme is unsupported" },
        .KX_TRUST_SIGNATURE_INVALID => .{ .family = .trust, .summary = "trust signature verification failed" },
        .KX_TRUST_SIGNATURE_THRESHOLD => .{ .family = .trust, .summary = "trust signature threshold not met" },
        .KX_TRUST_METADATA_EXPIRED => .{ .family = .trust, .summary = "trust metadata expired or has invalid expiry timestamp" },
        .KX_TRUST_ROLLBACK => .{ .family = .trust, .summary = "rollback detected in trust metadata versions" },
        .KX_TRUST_VERSION_LINK => .{ .family = .trust, .summary = "metadata version link mismatch" },
        .KX_TRUST_VERSION_INVALID => .{ .family = .trust, .summary = "metadata version is invalid" },
        .KX_TRUST_STATE_IO => .{ .family = .trust, .summary = "trust state persistence IO failed" },
        .KX_TRUST_STATE_INVALID => .{ .family = .trust, .summary = "trust state file is malformed or invalid" },

        .KX_IO_READ => .{ .family = .io, .summary = "file read failed" },
        .KX_IO_WRITE => .{ .family = .io, .summary = "file write failed" },
        .KX_IO_RENAME => .{ .family = .io, .summary = "atomic rename failed" },

        .KX_INTEGRITY_BLOB_MISMATCH => .{ .family = .integrity, .summary = "blob integrity mismatch" },
        .KX_INTEGRITY_TREE_MISMATCH => .{ .family = .integrity, .summary = "tree integrity mismatch" },

        .KX_BUILD_OPERATOR_FAILED => .{ .family = .build, .summary = "build operator failed" },
        .KX_PUBLISH_ATOMIC => .{ .family = .publish, .summary = "atomic publish failed" },

        .KX_INTERNAL => .{ .family = .internal, .summary = "internal error" },
    };
}

pub fn buildErrorId(
    buffer: []u8,
    code: Code,
    state_name: []const u8,
    cause_name: []const u8,
) []const u8 {
    return std.fmt.bufPrint(
        buffer,
        "kx:{d}:{s}:{s}",
        .{ @intFromEnum(code), state_name, cause_name },
    ) catch "kx:id_overflow";
}

pub fn classifyTrust(err: anyerror) Code {
    if (err == error.FileNotFound) {
        return .KX_TRUST_METADATA_MISSING;
    }

    if (err == error.ExpectedObject or err == error.ExpectedArray or err == error.ExpectedString or err == error.ExpectedInteger or err == error.MissingRequiredField or err == error.MissingSignedSection or err == error.MissingSignaturesSection) {
        return .KX_TRUST_METADATA_MALFORMED;
    }

    if (err == error.MissingRoleRule or err == error.InvalidRoleType or err == error.InvalidThreshold or err == error.EmptyRoleKeyIds or err == error.EmptyRoleKeyId or err == error.InvalidSignatureEntry) {
        return .KX_TRUST_ROLE_POLICY;
    }

    if (err == error.UnsupportedKeyType or err == error.UnsupportedSignatureScheme) {
        return .KX_TRUST_KEY_UNSUPPORTED;
    }

    if (err == error.SignatureVerificationFailed or err == error.EncodingError or err == error.IdentityElement or err == error.WeakPublicKey or err == error.NonCanonical or err == error.InvalidHexLength or err == error.InvalidCharacter) {
        return .KX_TRUST_SIGNATURE_INVALID;
    }

    if (err == error.SignatureThresholdNotMet) {
        return .KX_TRUST_SIGNATURE_THRESHOLD;
    }

    if (err == error.MetadataExpired or err == error.InvalidTimestampFormat or err == error.InvalidTimestampYear or err == error.InvalidTimestampMonth or err == error.InvalidTimestampDay or err == error.InvalidTimestampClock) {
        return .KX_TRUST_METADATA_EXPIRED;
    }

    if (err == error.RollbackDetected) return .KX_TRUST_ROLLBACK;

    if (err == error.LinkedMetadataVersionMismatch or err == error.InvalidLinkedVersion or err == error.MissingLinkedMetadata) {
        return .KX_TRUST_VERSION_LINK;
    }

    if (err == error.InvalidMetadataVersion) {
        return .KX_TRUST_VERSION_INVALID;
    }

    if (err == error.InvalidStateVersion) {
        return .KX_TRUST_STATE_INVALID;
    }

    if (err == error.AccessDenied or err == error.PermissionDenied or err == error.ReadOnlyFileSystem or err == error.NoSpaceLeft or err == error.InputOutput) {
        return .KX_TRUST_STATE_IO;
    }

    return .KX_INTERNAL;
}

pub fn classifyParse(err: anyerror) Code {
    if (err == error.Parse) return .KX_PARSE_SYNTAX;

    if (err == error.Schema or err == error.ExpectedObject or err == error.ExpectedArray or err == error.ExpectedString or err == error.ExpectedInteger or err == error.MissingRequiredField or err == error.MissingVersion or err == error.UnsupportedVersion or err == error.InvalidHexLength or err == error.InvalidHexChar or err == error.InvalidPositiveInt or err == error.InvalidPolicyNetwork or err == error.InvalidPolicyClock or err == error.InvalidEnvTZ or err == error.InvalidEnvLang or err == error.InvalidDigits or err == error.InvalidMode or err == error.OutputsEmpty or err == error.InvalidOutputPath or err == error.OperatorNotAllowed or err == error.InvalidVerifyMode or err == error.EmptyString) {
        return .KX_PARSE_SCHEMA;
    }

    if (err == error.UnsupportedFloatInCanonicalization or err == error.InvalidCanonicalObject) return .KX_PARSE_CANONICAL;

    return .KX_INTERNAL;
}

pub fn classifyIo(err: anyerror) Code {
    if (err == error.FileNotFound or err == error.AccessDenied or err == error.PathAlreadyExists or err == error.NameTooLong or err == error.NotDir or err == error.InvalidUtf8 or err == error.InvalidWtf8) {
        return .KX_IO_READ;
    }

    if (err == error.ReadOnlyFileSystem or err == error.DiskQuota or err == error.NoSpaceLeft or err == error.InputOutput) {
        return .KX_IO_WRITE;
    }

    if (err == error.RenameAcrossMountPoints or err == error.PathAlreadyExists) return .KX_IO_RENAME;

    return .KX_INTERNAL;
}

test "classifyTrust maps rollback and expiry" {
    try std.testing.expectEqual(Code.KX_TRUST_ROLLBACK, classifyTrust(error.RollbackDetected));
    try std.testing.expectEqual(Code.KX_TRUST_METADATA_EXPIRED, classifyTrust(error.MetadataExpired));
}

test "classifyTrust maps signature and policy details" {
    try std.testing.expectEqual(Code.KX_TRUST_SIGNATURE_THRESHOLD, classifyTrust(error.SignatureThresholdNotMet));
    try std.testing.expectEqual(Code.KX_TRUST_ROLE_POLICY, classifyTrust(error.InvalidThreshold));
}

test "classifyParse maps schema and syntax" {
    try std.testing.expectEqual(Code.KX_PARSE_SYNTAX, classifyParse(error.Parse));
    try std.testing.expectEqual(Code.KX_PARSE_SCHEMA, classifyParse(error.InvalidPolicyNetwork));
}

test "buildErrorId is stable" {
    var buf: [96]u8 = undefined;
    const id = buildErrorId(&buf, .KX_TRUST_METADATA_MISSING, "load_trust_metadata", "FileNotFound");
    try std.testing.expectEqualStrings("kx:2001:load_trust_metadata:FileNotFound", id);
}
