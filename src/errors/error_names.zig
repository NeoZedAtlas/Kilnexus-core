const std = @import("std");

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

test "shared error-name sets include expected entries" {
    try std.testing.expect(isRetryableDownload("ConnectionTimedOut"));
    try std.testing.expect(isRetryableWindowsSeal("FileBusy"));
    try std.testing.expect(isSymlinkFallback("NotSameFileSystem"));
    try std.testing.expect(!isRetryableDownload("AccessDenied"));
}
