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
        .{ .from = "FileNotFound", .to = "IoNotFound" },
        .{ .from = "AccessDenied", .to = "IoAccessDenied" },
        .{ .from = "PermissionDenied", .to = "IoAccessDenied" },
        .{ .from = "PathAlreadyExists", .to = "IoAlreadyExists" },
        .{ .from = "NameTooLong", .to = "IoPathInvalid" },
        .{ .from = "NotDir", .to = "IoPathInvalid" },
        .{ .from = "InvalidUtf8", .to = "IoPathInvalid" },
        .{ .from = "InvalidWtf8", .to = "IoPathInvalid" },
        .{ .from = "BadPathName", .to = "IoPathInvalid" },
        .{ .from = "SymLinkLoop", .to = "IoPathInvalid" },
        .{ .from = "UnsupportedUriScheme", .to = "IoPathInvalid" },
        .{ .from = "UriMissingHost", .to = "IoPathInvalid" },
        .{ .from = "UriHostTooLong", .to = "IoPathInvalid" },
        .{ .from = "DiskQuota", .to = "IoNoSpace" },
        .{ .from = "NoSpaceLeft", .to = "IoNoSpace" },
        .{ .from = "RenameAcrossMountPoints", .to = "IoRenameFailed" },
        .{ .from = "ReadOnlyFileSystem", .to = "IoWriteFailed" },
        .{ .from = "FileBusy", .to = "IoWriteFailed" },
        .{ .from = "WriteFailed", .to = "IoWriteFailed" },
        .{ .from = "InputOutput", .to = "IoReadFailed" },
        .{ .from = "Unexpected", .to = "IoReadFailed" },
        .{ .from = "ConnectionTimedOut", .to = "IoReadFailed" },
        .{ .from = "ConnectionRefused", .to = "IoReadFailed" },
        .{ .from = "ConnectionResetByPeer", .to = "IoReadFailed" },
        .{ .from = "NetworkUnreachable", .to = "IoReadFailed" },
        .{ .from = "TemporaryNameServerFailure", .to = "IoReadFailed" },
        .{ .from = "NameServerFailure", .to = "IoReadFailed" },
        .{ .from = "UnknownHostName", .to = "IoReadFailed" },
        .{ .from = "HostLacksNetworkAddresses", .to = "IoReadFailed" },
        .{ .from = "UnexpectedConnectFailure", .to = "IoReadFailed" },
        .{ .from = "CertificateBundleLoadFailure", .to = "IoReadFailed" },
        .{ .from = "TlsInitializationFailed", .to = "IoReadFailed" },
        .{ .from = "HttpHeadersInvalid", .to = "IoReadFailed" },
        .{ .from = "HttpHeadersOversize", .to = "IoReadFailed" },
        .{ .from = "HttpChunkInvalid", .to = "IoReadFailed" },
        .{ .from = "HttpChunkTruncated", .to = "IoReadFailed" },
        .{ .from = "HttpRedirectLocationMissing", .to = "IoReadFailed" },
        .{ .from = "HttpRedirectLocationOversize", .to = "IoReadFailed" },
        .{ .from = "HttpRedirectLocationInvalid", .to = "IoReadFailed" },
        .{ .from = "TooManyHttpRedirects", .to = "IoReadFailed" },
        .{ .from = "RedirectRequiresResend", .to = "IoReadFailed" },
        .{ .from = "HttpContentEncodingUnsupported", .to = "IoReadFailed" },
        .{ .from = "ReadFailed", .to = "IoReadFailed" },
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
    try std.testing.expect(mapIo(error.FileNotFound) == error.IoNotFound);
    try std.testing.expect(mapIo(error.PermissionDenied) == error.IoAccessDenied);
    try std.testing.expect(mapIo(error.NoSpaceLeft) == error.IoNoSpace);
    try std.testing.expect(mapIo(error.ConnectionTimedOut) == error.IoReadFailed);
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
