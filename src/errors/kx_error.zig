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
    KX_TRUST_SIGNATURE = 2002,
    KX_TRUST_EXPIRED = 2003,
    KX_TRUST_ROLLBACK = 2004,
    KX_TRUST_VERSION_LINK = 2005,
    KX_TRUST_POLICY = 2006,

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
        .KX_TRUST_SIGNATURE => .{ .family = .trust, .summary = "signature threshold verification failed" },
        .KX_TRUST_EXPIRED => .{ .family = .trust, .summary = "trust metadata expired or has invalid expiry timestamp" },
        .KX_TRUST_ROLLBACK => .{ .family = .trust, .summary = "rollback detected in trust metadata versions" },
        .KX_TRUST_VERSION_LINK => .{ .family = .trust, .summary = "metadata version link mismatch" },
        .KX_TRUST_POLICY => .{ .family = .trust, .summary = "trust metadata policy is invalid" },

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

pub fn classifyTrust(err: anyerror) Code {
    if (err == error.FileNotFound or err == error.MissingRequiredField or err == error.MissingSignedSection or err == error.MissingSignaturesSection or err == error.MissingRoleRule) {
        return .KX_TRUST_METADATA_MISSING;
    }

    if (err == error.SignatureThresholdNotMet or err == error.SignatureVerificationFailed or err == error.EncodingError or err == error.IdentityElement or err == error.WeakPublicKey or err == error.NonCanonical) {
        return .KX_TRUST_SIGNATURE;
    }

    if (err == error.MetadataExpired or err == error.InvalidTimestampFormat or err == error.InvalidTimestampYear or err == error.InvalidTimestampMonth or err == error.InvalidTimestampDay or err == error.InvalidTimestampClock) {
        return .KX_TRUST_EXPIRED;
    }

    if (err == error.RollbackDetected) return .KX_TRUST_ROLLBACK;

    if (err == error.LinkedMetadataVersionMismatch or err == error.InvalidLinkedVersion or err == error.MissingLinkedMetadata or err == error.InvalidMetadataVersion) {
        return .KX_TRUST_VERSION_LINK;
    }

    if (err == error.InvalidRoleType or err == error.InvalidThreshold or err == error.EmptyRoleKeyIds or err == error.EmptyRoleKeyId or err == error.UnsupportedKeyType or err == error.UnsupportedSignatureScheme or err == error.InvalidSignatureEntry) {
        return .KX_TRUST_POLICY;
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
    try std.testing.expectEqual(Code.KX_TRUST_EXPIRED, classifyTrust(error.MetadataExpired));
}

test "classifyParse maps schema and syntax" {
    try std.testing.expectEqual(Code.KX_PARSE_SYNTAX, classifyParse(error.Parse));
    try std.testing.expectEqual(Code.KX_PARSE_SCHEMA, classifyParse(error.InvalidPolicyNetwork));
}
