const std = @import("std");
const parse_errors = @import("../parser/parse_errors.zig");
const mini_tuf = @import("../trust/mini_tuf.zig");
const kx_error = @import("kx_error.zig");

const Alias = struct {
    from: []const u8,
    to: []const u8,
};

pub fn mapTrust(err: anyerror) mini_tuf.TrustError {
    return mini_tuf.normalizeError(err);
}

pub fn mapParse(err: anyerror) parse_errors.ParseError {
    return parse_errors.normalize(err);
}

pub fn mapIntegrity(err: anyerror) kx_error.IntegrityError {
    return normalizeTo(kx_error.IntegrityError, err, &.{
        .{ .from = "BlobHashMismatch", .to = "BlobMismatch" },
        .{ .from = "BlobDigestMismatch", .to = "BlobMismatch" },
        .{ .from = "TreeRootMismatch", .to = "TreeMismatch" },
        .{ .from = "TreeDigestMismatch", .to = "TreeMismatch" },
        .{ .from = "UnsupportedHashAlgorithm", .to = "HashUnsupported" },
        .{ .from = "PathTraversalDetected", .to = "PathTraversal" },
        .{ .from = "SymlinkPolicyViolation", .to = "SymlinkPolicy" },
    });
}

pub fn mapBuild(err: anyerror) kx_error.BuildError {
    return normalizeTo(kx_error.BuildError, err, &.{
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

pub fn mapPublish(err: anyerror) kx_error.PublishError {
    return normalizeTo(kx_error.PublishError, err, &.{
        .{ .from = "AtomicRenameFailed", .to = "AtomicFailed" },
        .{ .from = "AccessDenied", .to = "PermissionDenied" },
    });
}

pub fn mapIo(err: anyerror) kx_error.IoError {
    return normalizeTo(kx_error.IoError, err, &.{
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

fn normalizeTo(comptime Target: type, err: anyerror, comptime aliases: []const Alias) Target {
    const resolved = resolveAliasName(@errorName(err), aliases);
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
    try std.testing.expect(mapIo(error.FileNotFound) == error.Unavailable);
    try std.testing.expect(mapIo(error.PermissionDenied) == error.Denied);
    try std.testing.expect(mapIo(error.NoSpaceLeft) == error.WriteFailed);
    try std.testing.expect(mapIo(error.ConnectionTimedOut) == error.ReadFailed);
}

test "mapIntegrity maps legacy aliases" {
    try std.testing.expect(mapIntegrity(error.BlobHashMismatch) == error.BlobMismatch);
    try std.testing.expect(mapIntegrity(error.PathTraversalDetected) == error.PathTraversal);
}

test "mapBuild and mapPublish map legacy aliases" {
    try std.testing.expect(mapBuild(error.OperatorExecutionFailed) == error.OperatorFailed);
    try std.testing.expect(mapBuild(error.DependencyCycle) == error.GraphInvalid);
    try std.testing.expect(mapPublish(error.AtomicRenameFailed) == error.AtomicFailed);
    try std.testing.expect(mapPublish(error.AccessDenied) == error.PermissionDenied);
}
