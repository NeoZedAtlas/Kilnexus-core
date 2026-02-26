const std = @import("std");
const parse_errors = @import("../parser/parse_errors.zig");
const mini_tuf = @import("../trust/mini_tuf.zig");

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
    KX_PARSE_EMPTY_INPUT = 1004,
    KX_PARSE_MISSING_FIELD = 1005,
    KX_PARSE_TYPE_MISMATCH = 1006,
    KX_PARSE_VALUE_INVALID = 1007,
    KX_PARSE_VERSION_UNSUPPORTED = 1008,
    KX_PARSE_OPERATOR_DISALLOWED = 1009,
    KX_PARSE_OUTPUT_INVALID = 1010,
    KX_PARSE_LEGACY_BUILD_BLOCK = 1011,

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

    KX_IO_NOT_FOUND = 3001,
    KX_IO_ACCESS_DENIED = 3002,
    KX_IO_PATH_INVALID = 3003,
    KX_IO_READ_FAILED = 3004,
    KX_IO_WRITE_FAILED = 3005,
    KX_IO_NO_SPACE = 3006,
    KX_IO_RENAME_FAILED = 3007,
    KX_IO_ALREADY_EXISTS = 3008,

    KX_INTEGRITY_BLOB_MISMATCH = 4001,
    KX_INTEGRITY_TREE_MISMATCH = 4002,
    KX_INTEGRITY_SIZE_MISMATCH = 4003,
    KX_INTEGRITY_HASH_UNSUPPORTED = 4004,
    KX_INTEGRITY_PATH_TRAVERSAL = 4005,
    KX_INTEGRITY_SYMLINK_POLICY = 4006,

    KX_BUILD_OPERATOR_FAILED = 5001,
    KX_BUILD_OPERATOR_DISALLOWED = 5002,
    KX_BUILD_TOOLCHAIN_MISSING = 5003,
    KX_BUILD_SANDBOX_VIOLATION = 5004,
    KX_BUILD_GRAPH_INVALID = 5005,
    KX_BUILD_TIMEOUT = 5006,
    KX_BUILD_NOT_IMPLEMENTED = 5007,

    KX_PUBLISH_ATOMIC = 6001,
    KX_PUBLISH_OUTPUT_MISSING = 6002,
    KX_PUBLISH_OUTPUT_HASH_MISMATCH = 6003,
    KX_PUBLISH_FSYNC_FAILED = 6004,
    KX_PUBLISH_PERMISSION = 6005,

    KX_INTERNAL = 9000,
};

pub const Descriptor = struct {
    family: Family,
    summary: []const u8,
};

pub const IntegrityError = error{
    BlobMismatch,
    TreeMismatch,
    SizeMismatch,
    HashUnsupported,
    PathTraversal,
    SymlinkPolicy,
    Internal,
};

pub const BuildError = error{
    OperatorFailed,
    OperatorDisallowed,
    ToolchainMissing,
    SandboxViolation,
    GraphInvalid,
    Timeout,
    NotImplemented,
    Internal,
};

pub const PublishError = error{
    AtomicFailed,
    OutputMissing,
    OutputHashMismatch,
    FsyncFailed,
    PermissionDenied,
    Internal,
};

pub const IoError = error{
    IoNotFound,
    IoAccessDenied,
    IoPathInvalid,
    IoReadFailed,
    IoWriteFailed,
    IoNoSpace,
    IoRenameFailed,
    IoAlreadyExists,
    Internal,
};

pub fn describe(code: Code) Descriptor {
    return switch (code) {
        .KX_OK => .{ .family = .internal, .summary = "ok" },
        .KX_PARSE_SYNTAX => .{ .family = .parse, .summary = "invalid syntax in lockfile" },
        .KX_PARSE_SCHEMA => .{ .family = .parse, .summary = "lockfile schema validation failed" },
        .KX_PARSE_CANONICAL => .{ .family = .parse, .summary = "lockfile canonicalization failed" },
        .KX_PARSE_EMPTY_INPUT => .{ .family = .parse, .summary = "lockfile is empty or whitespace only" },
        .KX_PARSE_MISSING_FIELD => .{ .family = .parse, .summary = "required lockfile field missing" },
        .KX_PARSE_TYPE_MISMATCH => .{ .family = .parse, .summary = "lockfile field type mismatch" },
        .KX_PARSE_VALUE_INVALID => .{ .family = .parse, .summary = "lockfile field value invalid" },
        .KX_PARSE_VERSION_UNSUPPORTED => .{ .family = .parse, .summary = "lockfile version unsupported" },
        .KX_PARSE_OPERATOR_DISALLOWED => .{ .family = .parse, .summary = "lockfile contains disallowed operator" },
        .KX_PARSE_OUTPUT_INVALID => .{ .family = .parse, .summary = "lockfile output mapping invalid" },
        .KX_PARSE_LEGACY_BUILD_BLOCK => .{ .family = .parse, .summary = "legacy build block is disallowed; use operators" },

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

        .KX_IO_NOT_FOUND => .{ .family = .io, .summary = "path or file not found" },
        .KX_IO_ACCESS_DENIED => .{ .family = .io, .summary = "access denied for filesystem operation" },
        .KX_IO_PATH_INVALID => .{ .family = .io, .summary = "path is invalid for filesystem operation" },
        .KX_IO_READ_FAILED => .{ .family = .io, .summary = "file read failed" },
        .KX_IO_WRITE_FAILED => .{ .family = .io, .summary = "file write failed" },
        .KX_IO_NO_SPACE => .{ .family = .io, .summary = "no space or disk quota left" },
        .KX_IO_RENAME_FAILED => .{ .family = .io, .summary = "atomic rename failed" },
        .KX_IO_ALREADY_EXISTS => .{ .family = .io, .summary = "target path already exists" },

        .KX_INTEGRITY_BLOB_MISMATCH => .{ .family = .integrity, .summary = "blob integrity mismatch" },
        .KX_INTEGRITY_TREE_MISMATCH => .{ .family = .integrity, .summary = "tree integrity mismatch" },
        .KX_INTEGRITY_SIZE_MISMATCH => .{ .family = .integrity, .summary = "content size mismatch" },
        .KX_INTEGRITY_HASH_UNSUPPORTED => .{ .family = .integrity, .summary = "unsupported hash algorithm in metadata" },
        .KX_INTEGRITY_PATH_TRAVERSAL => .{ .family = .integrity, .summary = "path traversal detected while unpacking" },
        .KX_INTEGRITY_SYMLINK_POLICY => .{ .family = .integrity, .summary = "symlink policy violation in unpacked tree" },

        .KX_BUILD_OPERATOR_FAILED => .{ .family = .build, .summary = "build operator failed" },
        .KX_BUILD_OPERATOR_DISALLOWED => .{ .family = .build, .summary = "operator is disallowed by policy" },
        .KX_BUILD_TOOLCHAIN_MISSING => .{ .family = .build, .summary = "required toolchain not available" },
        .KX_BUILD_SANDBOX_VIOLATION => .{ .family = .build, .summary = "sandbox policy violation during build" },
        .KX_BUILD_GRAPH_INVALID => .{ .family = .build, .summary = "build graph is invalid" },
        .KX_BUILD_TIMEOUT => .{ .family = .build, .summary = "build step timeout exceeded" },
        .KX_BUILD_NOT_IMPLEMENTED => .{ .family = .build, .summary = "build feature is not implemented in current MVP" },

        .KX_PUBLISH_ATOMIC => .{ .family = .publish, .summary = "atomic publish failed" },
        .KX_PUBLISH_OUTPUT_MISSING => .{ .family = .publish, .summary = "declared output missing at publish boundary" },
        .KX_PUBLISH_OUTPUT_HASH_MISMATCH => .{ .family = .publish, .summary = "published output hash mismatch" },
        .KX_PUBLISH_FSYNC_FAILED => .{ .family = .publish, .summary = "fsync failed before publish" },
        .KX_PUBLISH_PERMISSION => .{ .family = .publish, .summary = "publish path permission failure" },

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

const AliasRule = struct {
    from: []const u8,
    to: []const u8,
};

const Convention = struct {
    family: []const u8,
    strip_prefix: ?[]const u8 = null,
    aliases: []const AliasRule = &.{},
};

const trust_convention = Convention{
    .family = "TRUST",
    .aliases = &.{
        .{ .from = "RolePolicyInvalid", .to = "RolePolicy" },
        .{ .from = "SignatureThresholdNotMet", .to = "SignatureThreshold" },
        .{ .from = "RollbackDetected", .to = "Rollback" },
        .{ .from = "VersionLinkMismatch", .to = "VersionLink" },
    },
};

const parse_convention = Convention{
    .family = "PARSE",
    .aliases = &.{
        .{ .from = "Canonicalization", .to = "Canonical" },
    },
};

const io_convention = Convention{
    .family = "IO",
    .strip_prefix = "Io",
};

const integrity_convention = Convention{
    .family = "INTEGRITY",
};

const build_convention = Convention{
    .family = "BUILD",
};

const publish_convention = Convention{
    .family = "PUBLISH",
    .aliases = &.{
        .{ .from = "AtomicFailed", .to = "Atomic" },
        .{ .from = "PermissionDenied", .to = "Permission" },
    },
};

pub fn classifyTrust(err: mini_tuf.TrustError) Code {
    return classifyByConvention(trust_convention, @errorName(err));
}

pub fn classifyParse(err: parse_errors.ParseError) Code {
    return classifyByConvention(parse_convention, @errorName(err));
}

pub fn classifyIo(err: IoError) Code {
    return classifyByConvention(io_convention, @errorName(err));
}

pub fn classifyIntegrity(err: IntegrityError) Code {
    return classifyByConvention(integrity_convention, @errorName(err));
}

pub fn classifyBuild(err: BuildError) Code {
    return classifyByConvention(build_convention, @errorName(err));
}

pub fn classifyPublish(err: PublishError) Code {
    return classifyByConvention(publish_convention, @errorName(err));
}

fn classifyByConvention(comptime convention: Convention, err_name: []const u8) Code {
    const mapped = resolveAlias(convention.aliases, maybeStripPrefix(err_name, convention.strip_prefix));
    var code_buf: [128]u8 = undefined;
    const prefix = std.fmt.bufPrint(&code_buf, "KX_{s}_", .{convention.family}) catch return .KX_INTERNAL;
    const written = writeUpperSnake(code_buf[prefix.len..], mapped);
    const code_name = code_buf[0 .. prefix.len + written];
    return lookupCodeByName(code_name) orelse .KX_INTERNAL;
}

fn maybeStripPrefix(name: []const u8, maybe_prefix: ?[]const u8) []const u8 {
    const prefix = maybe_prefix orelse return name;
    if (std.mem.startsWith(u8, name, prefix)) return name[prefix.len..];
    return name;
}

fn resolveAlias(comptime aliases: []const AliasRule, name: []const u8) []const u8 {
    inline for (aliases) |alias| {
        if (std.mem.eql(u8, name, alias.from)) return alias.to;
    }
    return name;
}

fn writeUpperSnake(buffer: []u8, camel: []const u8) usize {
    var out: usize = 0;
    for (camel, 0..) |ch, idx| {
        if (idx != 0 and std.ascii.isUpper(ch)) {
            if (out >= buffer.len) break;
            buffer[out] = '_';
            out += 1;
        }
        if (out >= buffer.len) break;
        buffer[out] = std.ascii.toUpper(ch);
        out += 1;
    }
    return out;
}

fn lookupCodeByName(name: []const u8) ?Code {
    inline for (@typeInfo(Code).@"enum".fields) |field| {
        if (std.mem.eql(u8, name, field.name)) {
            return @enumFromInt(field.value);
        }
    }
    return null;
}

fn assertConventionCoverage(
    comptime ErrorSet: type,
    comptime convention: Convention,
    comptime ignored: []const []const u8,
) void {
    const info = @typeInfo(ErrorSet);
    const fields = info.error_set.?;
    inline for (fields) |field| {
        if (isIgnored(field.name, ignored)) continue;
        const code = classifyByConvention(convention, field.name);
        if (code == .KX_INTERNAL) {
            @compileError(std.fmt.comptimePrint(
                "No Code mapping for {s}.{s} via convention family={s}",
                .{ @typeName(ErrorSet), field.name, convention.family },
            ));
        }
    }
}

fn isIgnored(comptime name: []const u8, comptime ignored: []const []const u8) bool {
    inline for (ignored) |item| {
        if (std.mem.eql(u8, name, item)) return true;
    }
    return false;
}

comptime {
    @setEvalBranchQuota(50_000);
    assertConventionCoverage(mini_tuf.TrustError, trust_convention, &.{"Internal"});
    assertConventionCoverage(parse_errors.ParseError, parse_convention, &.{"Internal"});
    assertConventionCoverage(IoError, io_convention, &.{"Internal"});
    assertConventionCoverage(IntegrityError, integrity_convention, &.{"Internal"});
    assertConventionCoverage(BuildError, build_convention, &.{"Internal"});
    assertConventionCoverage(PublishError, publish_convention, &.{"Internal"});
}

pub fn normalizeIntegrity(err: anyerror) IntegrityError {
    if (err == error.BlobMismatch or err == error.BlobHashMismatch or err == error.BlobDigestMismatch) {
        return error.BlobMismatch;
    }

    if (err == error.TreeMismatch or err == error.TreeRootMismatch or err == error.TreeDigestMismatch) {
        return error.TreeMismatch;
    }

    if (err == error.SizeMismatch) {
        return error.SizeMismatch;
    }

    if (err == error.HashUnsupported or err == error.UnsupportedHashAlgorithm) {
        return error.HashUnsupported;
    }

    if (err == error.PathTraversal or err == error.PathTraversalDetected) {
        return error.PathTraversal;
    }

    if (err == error.SymlinkPolicy or err == error.SymlinkPolicyViolation) {
        return error.SymlinkPolicy;
    }

    return error.Internal;
}

pub fn normalizeBuild(err: anyerror) BuildError {
    if (err == error.OperatorFailed or err == error.OperatorExecutionFailed) {
        return error.OperatorFailed;
    }

    if (err == error.OperatorDisallowed or err == error.OperatorNotAllowed) {
        return error.OperatorDisallowed;
    }

    if (err == error.ToolchainMissing or err == error.ToolchainNotFound or err == error.CompilerNotFound) {
        return error.ToolchainMissing;
    }

    if (err == error.SandboxViolation or err == error.NetworkDisabled) {
        return error.SandboxViolation;
    }

    if (err == error.GraphInvalid or err == error.InvalidBuildGraph or err == error.DependencyCycle or err == error.DuplicateMountPath) {
        return error.GraphInvalid;
    }

    if (err == error.Timeout) {
        return error.Timeout;
    }

    if (err == error.NotImplemented) {
        return error.NotImplemented;
    }

    return error.Internal;
}

pub fn normalizePublish(err: anyerror) PublishError {
    if (err == error.AtomicFailed or err == error.AtomicRenameFailed) {
        return error.AtomicFailed;
    }

    if (err == error.OutputMissing) {
        return error.OutputMissing;
    }

    if (err == error.OutputHashMismatch) {
        return error.OutputHashMismatch;
    }

    if (err == error.FsyncFailed) {
        return error.FsyncFailed;
    }

    if (err == error.PermissionDenied or err == error.AccessDenied) {
        return error.PermissionDenied;
    }

    return error.Internal;
}

pub fn normalizeIo(err: anyerror) IoError {
    if (err == error.IoNotFound or err == error.FileNotFound) {
        return error.IoNotFound;
    }

    if (err == error.IoAccessDenied or err == error.AccessDenied or err == error.PermissionDenied) {
        return error.IoAccessDenied;
    }

    if (err == error.IoAlreadyExists or err == error.PathAlreadyExists) {
        return error.IoAlreadyExists;
    }

    if (err == error.IoPathInvalid or err == error.NameTooLong or err == error.NotDir or err == error.InvalidUtf8 or err == error.InvalidWtf8 or err == error.BadPathName or err == error.SymLinkLoop or err == error.UnsupportedUriScheme or err == error.UriMissingHost or err == error.UriHostTooLong) {
        return error.IoPathInvalid;
    }

    if (err == error.IoNoSpace or err == error.DiskQuota or err == error.NoSpaceLeft) {
        return error.IoNoSpace;
    }

    if (err == error.IoRenameFailed or err == error.RenameAcrossMountPoints) {
        return error.IoRenameFailed;
    }

    if (err == error.IoWriteFailed or err == error.ReadOnlyFileSystem or err == error.FileBusy or err == error.WriteFailed) {
        return error.IoWriteFailed;
    }

    if (err == error.IoReadFailed or err == error.InputOutput or err == error.Unexpected or err == error.ConnectionTimedOut or err == error.ConnectionRefused or err == error.ConnectionResetByPeer or err == error.NetworkUnreachable or err == error.TemporaryNameServerFailure or err == error.NameServerFailure or err == error.UnknownHostName or err == error.HostLacksNetworkAddresses or err == error.UnexpectedConnectFailure or err == error.CertificateBundleLoadFailure or err == error.TlsInitializationFailed or err == error.HttpHeadersInvalid or err == error.HttpHeadersOversize or err == error.HttpChunkInvalid or err == error.HttpChunkTruncated or err == error.HttpRedirectLocationMissing or err == error.HttpRedirectLocationOversize or err == error.HttpRedirectLocationInvalid or err == error.TooManyHttpRedirects or err == error.RedirectRequiresResend or err == error.HttpContentEncodingUnsupported or err == error.ReadFailed) {
        return error.IoReadFailed;
    }

    return error.Internal;
}

test "classifyTrust maps rollback and expiry" {
    try std.testing.expectEqual(Code.KX_TRUST_ROLLBACK, classifyTrust(error.RollbackDetected));
    try std.testing.expectEqual(Code.KX_TRUST_METADATA_EXPIRED, classifyTrust(error.MetadataExpired));
}

test "classifyTrust maps signature and policy details" {
    try std.testing.expectEqual(Code.KX_TRUST_SIGNATURE_THRESHOLD, classifyTrust(error.SignatureThresholdNotMet));
    try std.testing.expectEqual(Code.KX_TRUST_ROLE_POLICY, classifyTrust(error.RolePolicyInvalid));
}

test "classifyParse maps schema and syntax" {
    try std.testing.expectEqual(Code.KX_PARSE_EMPTY_INPUT, classifyParse(error.EmptyInput));
    try std.testing.expectEqual(Code.KX_PARSE_SYNTAX, classifyParse(error.Syntax));
    try std.testing.expectEqual(Code.KX_PARSE_SCHEMA, classifyParse(error.Schema));
    try std.testing.expectEqual(Code.KX_PARSE_VALUE_INVALID, classifyParse(error.ValueInvalid));
    try std.testing.expectEqual(Code.KX_PARSE_LEGACY_BUILD_BLOCK, classifyParse(error.LegacyBuildBlock));
}

test "buildErrorId is stable" {
    var buf: [96]u8 = undefined;
    const id = buildErrorId(&buf, .KX_TRUST_METADATA_MISSING, "load_trust_metadata", "FileNotFound");
    try std.testing.expectEqualStrings("kx:2001:load_trust_metadata:FileNotFound", id);
}

test "classifyIo maps not-found and no-space" {
    try std.testing.expectEqual(Code.KX_IO_NOT_FOUND, classifyIo(error.IoNotFound));
    try std.testing.expectEqual(Code.KX_IO_NO_SPACE, classifyIo(error.IoNoSpace));
}

test "classifyIntegrity maps blob and traversal" {
    try std.testing.expectEqual(Code.KX_INTEGRITY_BLOB_MISMATCH, classifyIntegrity(error.BlobMismatch));
    try std.testing.expectEqual(Code.KX_INTEGRITY_PATH_TRAVERSAL, classifyIntegrity(error.PathTraversal));
}

test "classifyBuild maps operator and timeout" {
    try std.testing.expectEqual(Code.KX_BUILD_OPERATOR_FAILED, classifyBuild(error.OperatorFailed));
    try std.testing.expectEqual(Code.KX_BUILD_TIMEOUT, classifyBuild(error.Timeout));
}

test "classifyPublish maps output and fsync" {
    try std.testing.expectEqual(Code.KX_PUBLISH_OUTPUT_MISSING, classifyPublish(error.OutputMissing));
    try std.testing.expectEqual(Code.KX_PUBLISH_FSYNC_FAILED, classifyPublish(error.FsyncFailed));
}

test "normalizeIntegrity maps legacy aliases" {
    try std.testing.expect(normalizeIntegrity(error.BlobHashMismatch) == error.BlobMismatch);
    try std.testing.expect(normalizeIntegrity(error.PathTraversalDetected) == error.PathTraversal);
}

test "normalizeBuild maps legacy aliases" {
    try std.testing.expect(normalizeBuild(error.OperatorExecutionFailed) == error.OperatorFailed);
    try std.testing.expect(normalizeBuild(error.DependencyCycle) == error.GraphInvalid);
}

test "normalizePublish maps legacy aliases" {
    try std.testing.expect(normalizePublish(error.AtomicRenameFailed) == error.AtomicFailed);
    try std.testing.expect(normalizePublish(error.AccessDenied) == error.PermissionDenied);
}

test "normalizeIo maps filesystem aliases" {
    try std.testing.expect(normalizeIo(error.FileNotFound) == error.IoNotFound);
    try std.testing.expect(normalizeIo(error.PermissionDenied) == error.IoAccessDenied);
    try std.testing.expect(normalizeIo(error.NoSpaceLeft) == error.IoNoSpace);
    try std.testing.expect(normalizeIo(error.ConnectionTimedOut) == error.IoReadFailed);
}
