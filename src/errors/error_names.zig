const std = @import("std");

pub const Alias = struct {
    from: []const u8,
    to: []const u8,
};

pub const retryable_download: []const []const u8 = &.{
    "ConnectionTimedOut",
    "ConnectionResetByPeer",
    "ConnectionRefused",
    "NetworkUnreachable",
    "TemporaryNameServerFailure",
    "NameServerFailure",
    "HttpHeadersInvalid",
    "HttpHeadersOversize",
    "HttpChunkInvalid",
    "HttpChunkTruncated",
    "ReadFailed",
    "WriteFailed",
};

pub const retryable_windows_seal: []const []const u8 = &.{
    "AccessDenied",
    "PermissionDenied",
    "FileBusy",
};

pub const symlink_fallback: []const []const u8 = &.{
    "NotSameFileSystem",
    "AccessDenied",
    "PermissionDenied",
    "FileSystem",
    "ReadOnlyFileSystem",
    "LinkQuotaExceeded",
};

pub const parse_aliases: []const Alias = &.{
    .{ .from = "Parse", .to = "Syntax" },
    .{ .from = "UnsupportedFloatInCanonicalization", .to = "Canonicalization" },
    .{ .from = "InvalidCanonicalObject", .to = "Canonicalization" },
    .{ .from = "MissingRequiredField", .to = "MissingField" },
    .{ .from = "MissingVersion", .to = "MissingField" },
    .{ .from = "ExpectedObject", .to = "TypeMismatch" },
    .{ .from = "ExpectedArray", .to = "TypeMismatch" },
    .{ .from = "ExpectedString", .to = "TypeMismatch" },
    .{ .from = "ExpectedInteger", .to = "TypeMismatch" },
    .{ .from = "InvalidHexLength", .to = "ValueInvalid" },
    .{ .from = "InvalidHexChar", .to = "ValueInvalid" },
    .{ .from = "InvalidPositiveInt", .to = "ValueInvalid" },
    .{ .from = "InvalidPolicyNetwork", .to = "ValueInvalid" },
    .{ .from = "InvalidPolicyClock", .to = "ValueInvalid" },
    .{ .from = "InvalidEnvTZ", .to = "ValueInvalid" },
    .{ .from = "InvalidEnvLang", .to = "ValueInvalid" },
    .{ .from = "InvalidDigits", .to = "ValueInvalid" },
    .{ .from = "InvalidVerifyMode", .to = "ValueInvalid" },
    .{ .from = "EmptyString", .to = "ValueInvalid" },
    .{ .from = "InvalidBuildGraph", .to = "ValueInvalid" },
    .{ .from = "UnsupportedVersion", .to = "VersionUnsupported" },
    .{ .from = "OperatorNotAllowed", .to = "OperatorDisallowed" },
    .{ .from = "OutputsEmpty", .to = "OutputInvalid" },
    .{ .from = "InvalidOutputPath", .to = "OutputInvalid" },
    .{ .from = "InvalidMode", .to = "OutputInvalid" },
};

pub const trust_aliases: []const Alias = &.{
    .{ .from = "FileNotFound", .to = "MetadataMissing" },
    .{ .from = "ExpectedObject", .to = "MetadataMalformed" },
    .{ .from = "ExpectedArray", .to = "MetadataMalformed" },
    .{ .from = "ExpectedString", .to = "MetadataMalformed" },
    .{ .from = "ExpectedInteger", .to = "MetadataMalformed" },
    .{ .from = "MissingRequiredField", .to = "MetadataMalformed" },
    .{ .from = "MissingSignedSection", .to = "MetadataMalformed" },
    .{ .from = "MissingSignaturesSection", .to = "MetadataMalformed" },
    .{ .from = "MissingRoleRule", .to = "RolePolicyInvalid" },
    .{ .from = "InvalidRoleType", .to = "RolePolicyInvalid" },
    .{ .from = "InvalidThreshold", .to = "RolePolicyInvalid" },
    .{ .from = "EmptyRoleKeyIds", .to = "RolePolicyInvalid" },
    .{ .from = "EmptyRoleKeyId", .to = "RolePolicyInvalid" },
    .{ .from = "InvalidSignatureEntry", .to = "RolePolicyInvalid" },
    .{ .from = "EmptySignatures", .to = "RolePolicyInvalid" },
    .{ .from = "UnsupportedKeyType", .to = "KeyUnsupported" },
    .{ .from = "UnsupportedSignatureScheme", .to = "KeyUnsupported" },
    .{ .from = "SignatureVerificationFailed", .to = "SignatureInvalid" },
    .{ .from = "EncodingError", .to = "SignatureInvalid" },
    .{ .from = "IdentityElement", .to = "SignatureInvalid" },
    .{ .from = "WeakPublicKey", .to = "SignatureInvalid" },
    .{ .from = "NonCanonical", .to = "SignatureInvalid" },
    .{ .from = "InvalidHexLength", .to = "SignatureInvalid" },
    .{ .from = "InvalidCharacter", .to = "SignatureInvalid" },
    .{ .from = "InvalidTimestampFormat", .to = "MetadataExpired" },
    .{ .from = "InvalidTimestampYear", .to = "MetadataExpired" },
    .{ .from = "InvalidTimestampMonth", .to = "MetadataExpired" },
    .{ .from = "InvalidTimestampDay", .to = "MetadataExpired" },
    .{ .from = "InvalidTimestampClock", .to = "MetadataExpired" },
    .{ .from = "LinkedMetadataVersionMismatch", .to = "VersionLinkMismatch" },
    .{ .from = "InvalidLinkedVersion", .to = "VersionLinkMismatch" },
    .{ .from = "MissingLinkedMetadata", .to = "VersionLinkMismatch" },
    .{ .from = "InvalidMetadataVersion", .to = "VersionInvalid" },
    .{ .from = "InvalidStateVersion", .to = "StateInvalid" },
    .{ .from = "AccessDenied", .to = "StateIo" },
    .{ .from = "PermissionDenied", .to = "StateIo" },
    .{ .from = "ReadOnlyFileSystem", .to = "StateIo" },
    .{ .from = "NoSpaceLeft", .to = "StateIo" },
    .{ .from = "DiskQuota", .to = "StateIo" },
    .{ .from = "FileBusy", .to = "StateIo" },
    .{ .from = "InputOutput", .to = "StateIo" },
    .{ .from = "RenameAcrossMountPoints", .to = "StateIo" },
};

pub const integrity_aliases: []const Alias = &.{
    .{ .from = "BlobHashMismatch", .to = "BlobMismatch" },
    .{ .from = "BlobDigestMismatch", .to = "BlobMismatch" },
    .{ .from = "TreeRootMismatch", .to = "TreeMismatch" },
    .{ .from = "TreeDigestMismatch", .to = "TreeMismatch" },
    .{ .from = "UnsupportedHashAlgorithm", .to = "HashUnsupported" },
    .{ .from = "PathTraversalDetected", .to = "PathTraversal" },
    .{ .from = "SymlinkPolicyViolation", .to = "SymlinkPolicy" },
};

pub const build_aliases: []const Alias = &.{
    .{ .from = "OperatorExecutionFailed", .to = "OperatorFailed" },
    .{ .from = "OperatorNotAllowed", .to = "OperatorDisallowed" },
    .{ .from = "ToolchainNotFound", .to = "ToolchainMissing" },
    .{ .from = "CompilerNotFound", .to = "ToolchainMissing" },
    .{ .from = "NetworkDisabled", .to = "SandboxViolation" },
    .{ .from = "InvalidBuildGraph", .to = "GraphInvalid" },
    .{ .from = "DependencyCycle", .to = "GraphInvalid" },
    .{ .from = "DuplicateMountPath", .to = "GraphInvalid" },
};

pub const publish_aliases: []const Alias = &.{
    .{ .from = "AtomicRenameFailed", .to = "AtomicFailed" },
    .{ .from = "AccessDenied", .to = "PermissionDenied" },
};

pub const io_aliases: []const Alias = &.{
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
};

pub fn contains(err_name: []const u8, comptime names: []const []const u8) bool {
    inline for (names) |name| {
        if (std.mem.eql(u8, err_name, name)) return true;
    }
    return false;
}

pub fn isRetryableDownload(err_name: []const u8) bool {
    return contains(err_name, retryable_download);
}

pub fn isRetryableWindowsSeal(err_name: []const u8) bool {
    return contains(err_name, retryable_windows_seal);
}

pub fn isSymlinkFallback(err_name: []const u8) bool {
    return contains(err_name, symlink_fallback);
}

pub fn resolveAlias(name: []const u8, comptime aliases: []const Alias) []const u8 {
    inline for (aliases) |alias| {
        if (std.mem.eql(u8, name, alias.from)) return alias.to;
    }
    return name;
}

test "shared error-name sets include expected entries" {
    try std.testing.expect(isRetryableDownload("ConnectionTimedOut"));
    try std.testing.expect(isRetryableWindowsSeal("FileBusy"));
    try std.testing.expect(isSymlinkFallback("NotSameFileSystem"));
    try std.testing.expect(!isRetryableDownload("AccessDenied"));
    try std.testing.expect(std.mem.eql(u8, resolveAlias("Parse", parse_aliases), "Syntax"));
    try std.testing.expect(std.mem.eql(u8, resolveAlias("BlobHashMismatch", integrity_aliases), "BlobMismatch"));
    try std.testing.expect(std.mem.eql(u8, resolveAlias("InvalidThreshold", trust_aliases), "RolePolicyInvalid"));
}
