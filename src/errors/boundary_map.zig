const std = @import("std");
const parse_errors = @import("../parser/parse_errors.zig");
const mini_tuf = @import("../trust/mini_tuf.zig");
const kx_error = @import("kx_error.zig");

const Alias = struct {
    from: []const u8,
    to: []const u8,
};

pub fn mapTrust(err_name: []const u8) mini_tuf.TrustError {
    return mini_tuf.normalizeErrorName(err_name);
}

pub fn mapParse(err_name: []const u8) parse_errors.ParseError {
    return parse_errors.normalizeName(err_name);
}

pub fn mapIntegrity(err_name: []const u8) kx_error.IntegrityError {
    return normalizeTo(kx_error.IntegrityError, err_name, &.{
        .{ .from = "BlobHashMismatch", .to = "BlobMismatch" },
        .{ .from = "BlobDigestMismatch", .to = "BlobMismatch" },
        .{ .from = "TreeRootMismatch", .to = "TreeMismatch" },
        .{ .from = "TreeDigestMismatch", .to = "TreeMismatch" },
        .{ .from = "UnsupportedHashAlgorithm", .to = "HashUnsupported" },
        .{ .from = "PathTraversalDetected", .to = "PathTraversal" },
        .{ .from = "SymlinkPolicyViolation", .to = "SymlinkPolicy" },
    });
}

pub fn mapBuild(err_name: []const u8) kx_error.BuildError {
    return normalizeTo(kx_error.BuildError, err_name, &.{
        .{ .from = "OperatorExecutionFailed", .to = "OperatorFailed" },
        .{ .from = "OperatorNotAllowed", .to = "OperatorDisallowed" },
        .{ .from = "ToolchainNotFound", .to = "ToolchainMissing" },
        .{ .from = "CompilerNotFound", .to = "ToolchainMissing" },
        .{ .from = "NetworkDisabled", .to = "SandboxViolation" },
        .{ .from = "InvalidBuildGraph", .to = "GraphInvalid" },
        .{ .from = "DependencyCycle", .to = "GraphInvalid" },
        .{ .from = "DuplicateMountPath", .to = "GraphInvalid" },
    });
}

pub fn mapPublish(err_name: []const u8) kx_error.PublishError {
    return normalizeTo(kx_error.PublishError, err_name, &.{
        .{ .from = "AtomicRenameFailed", .to = "AtomicFailed" },
        .{ .from = "AccessDenied", .to = "PermissionDenied" },
    });
}

pub fn mapIo(err_name: []const u8) kx_error.IoError {
    return normalizeTo(kx_error.IoError, err_name, &.{
        .{ .from = "IoNotFound", .to = "Unavailable" },
        .{ .from = "FileNotFound", .to = "Unavailable" },
        .{ .from = "IoAccessDenied", .to = "Denied" },
        .{ .from = "AccessDenied", .to = "Denied" },
        .{ .from = "PermissionDenied", .to = "Denied" },
        .{ .from = "IoPathInvalid", .to = "PathInvalid" },
        .{ .from = "NameTooLong", .to = "PathInvalid" },
        .{ .from = "NotDir", .to = "PathInvalid" },
        .{ .from = "InvalidUtf8", .to = "PathInvalid" },
        .{ .from = "InvalidWtf8", .to = "PathInvalid" },
        .{ .from = "BadPathName", .to = "PathInvalid" },
        .{ .from = "SymLinkLoop", .to = "PathInvalid" },
        .{ .from = "UnsupportedUriScheme", .to = "PathInvalid" },
        .{ .from = "UriMissingHost", .to = "PathInvalid" },
        .{ .from = "UriHostTooLong", .to = "PathInvalid" },
        .{ .from = "IoReadFailed", .to = "ReadFailed" },
        .{ .from = "InputOutput", .to = "ReadFailed" },
        .{ .from = "Unexpected", .to = "ReadFailed" },
        .{ .from = "ConnectionTimedOut", .to = "ReadFailed" },
        .{ .from = "ConnectionRefused", .to = "ReadFailed" },
        .{ .from = "ConnectionResetByPeer", .to = "ReadFailed" },
        .{ .from = "NetworkUnreachable", .to = "ReadFailed" },
        .{ .from = "TemporaryNameServerFailure", .to = "ReadFailed" },
        .{ .from = "NameServerFailure", .to = "ReadFailed" },
        .{ .from = "UnknownHostName", .to = "ReadFailed" },
        .{ .from = "HostLacksNetworkAddresses", .to = "ReadFailed" },
        .{ .from = "UnexpectedConnectFailure", .to = "ReadFailed" },
        .{ .from = "CertificateBundleLoadFailure", .to = "ReadFailed" },
        .{ .from = "TlsInitializationFailed", .to = "ReadFailed" },
        .{ .from = "HttpHeadersInvalid", .to = "ReadFailed" },
        .{ .from = "HttpHeadersOversize", .to = "ReadFailed" },
        .{ .from = "HttpChunkInvalid", .to = "ReadFailed" },
        .{ .from = "HttpChunkTruncated", .to = "ReadFailed" },
        .{ .from = "HttpRedirectLocationMissing", .to = "ReadFailed" },
        .{ .from = "HttpRedirectLocationOversize", .to = "ReadFailed" },
        .{ .from = "HttpRedirectLocationInvalid", .to = "ReadFailed" },
        .{ .from = "TooManyHttpRedirects", .to = "ReadFailed" },
        .{ .from = "RedirectRequiresResend", .to = "ReadFailed" },
        .{ .from = "HttpContentEncodingUnsupported", .to = "ReadFailed" },
        .{ .from = "ReadFailed", .to = "ReadFailed" },
        .{ .from = "IoWriteFailed", .to = "WriteFailed" },
        .{ .from = "IoNoSpace", .to = "WriteFailed" },
        .{ .from = "IoRenameFailed", .to = "WriteFailed" },
        .{ .from = "IoAlreadyExists", .to = "WriteFailed" },
        .{ .from = "PathAlreadyExists", .to = "WriteFailed" },
        .{ .from = "DiskQuota", .to = "WriteFailed" },
        .{ .from = "NoSpaceLeft", .to = "WriteFailed" },
        .{ .from = "RenameAcrossMountPoints", .to = "WriteFailed" },
        .{ .from = "ReadOnlyFileSystem", .to = "WriteFailed" },
        .{ .from = "FileBusy", .to = "WriteFailed" },
        .{ .from = "WriteFailed", .to = "WriteFailed" },
    });
}

fn normalizeTo(comptime Target: type, err_name: []const u8, comptime aliases: []const Alias) Target {
    const resolved = resolveAliasName(err_name, aliases);
    return errorFromName(Target, resolved) orelse error.Internal;
}

fn resolveAliasName(name: []const u8, comptime aliases: []const Alias) []const u8 {
    inline for (aliases) |alias| {
        if (std.mem.eql(u8, name, alias.from)) return alias.to;
    }
    return name;
}

fn errorFromName(comptime Target: type, name: []const u8) ?Target {
    inline for (@typeInfo(Target).error_set.?) |field| {
        if (std.mem.eql(u8, name, field.name)) {
            return @field(Target, field.name);
        }
    }
    return null;
}

test "mapIo maps filesystem aliases" {
    try std.testing.expect(mapIo("FileNotFound") == error.Unavailable);
    try std.testing.expect(mapIo("PermissionDenied") == error.Denied);
    try std.testing.expect(mapIo("NoSpaceLeft") == error.WriteFailed);
    try std.testing.expect(mapIo("ConnectionTimedOut") == error.ReadFailed);
}

test "mapIntegrity maps legacy aliases" {
    try std.testing.expect(mapIntegrity("BlobHashMismatch") == error.BlobMismatch);
    try std.testing.expect(mapIntegrity("PathTraversalDetected") == error.PathTraversal);
}

test "mapBuild and mapPublish map legacy aliases" {
    try std.testing.expect(mapBuild("OperatorExecutionFailed") == error.OperatorFailed);
    try std.testing.expect(mapBuild("DependencyCycle") == error.GraphInvalid);
    try std.testing.expect(mapPublish("AtomicRenameFailed") == error.AtomicFailed);
    try std.testing.expect(mapPublish("AccessDenied") == error.PermissionDenied);
}
