const std = @import("std");
const parse_errors = @import("../parser/parse_errors.zig");
const mini_tuf = @import("../trust/mini_tuf.zig");
const error_names = @import("error_names.zig");
const code_catalog = @import("code_catalog.zig");

pub const Family = code_catalog.Family;
pub const Code = code_catalog.Code;

pub const Descriptor = code_catalog.Descriptor;

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
    LockMissing,
    LockDrift,
    AllowUnlockedForbidden,
    CiLockfileRequired,
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
    Unavailable,
    Denied,
    PathInvalid,
    ReadFailed,
    WriteFailed,
    Internal,
};

pub fn describe(code: Code) Descriptor {
    return code_catalog.describe(code);
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

const AliasRule = error_names.Alias;

const Convention = struct {
    family: []const u8,
    strip_prefix: ?[]const u8 = null,
    aliases: []const AliasRule = &.{},
};

const trust_convention = Convention{
    .family = "TRUST",
    .aliases = error_names.kx_classify_trust_aliases,
};

const parse_convention = Convention{
    .family = "PARSE",
    .aliases = error_names.kx_classify_parse_aliases,
};

const io_convention = Convention{
    .family = "IO",
    .aliases = error_names.kx_classify_io_aliases,
};

const integrity_convention = Convention{
    .family = "INTEGRITY",
};

const build_convention = Convention{
    .family = "BUILD",
};

const publish_convention = Convention{
    .family = "PUBLISH",
    .aliases = error_names.kx_classify_publish_aliases,
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
    const mapped = error_names.resolveAlias(maybeStripPrefix(err_name, convention.strip_prefix), convention.aliases);
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

test "classifyIo maps unavailable and denied/write" {
    try std.testing.expectEqual(Code.KX_IO_NOT_FOUND, classifyIo(error.Unavailable));
    try std.testing.expectEqual(Code.KX_IO_ACCESS_DENIED, classifyIo(error.Denied));
    try std.testing.expectEqual(Code.KX_IO_WRITE_FAILED, classifyIo(error.WriteFailed));
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
