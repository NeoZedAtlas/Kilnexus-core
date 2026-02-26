const std = @import("std");
const parse_errors = @import("../parser/parse_errors.zig");
const mini_tuf = @import("../trust/mini_tuf.zig");
const kx_error = @import("kx_error.zig");
const error_names = @import("error_names.zig");

const Alias = error_names.Alias;

pub fn mapTrust(err_name: []const u8) mini_tuf.TrustError {
    return mini_tuf.normalizeErrorName(err_name);
}

pub fn mapParse(err_name: []const u8) parse_errors.ParseError {
    return parse_errors.normalizeName(err_name);
}

pub fn mapIntegrity(err_name: []const u8) kx_error.IntegrityError {
    return normalizeTo(kx_error.IntegrityError, err_name, error_names.integrity_aliases);
}

pub fn mapBuild(err_name: []const u8) kx_error.BuildError {
    return normalizeTo(kx_error.BuildError, err_name, error_names.build_aliases);
}

pub fn mapPublish(err_name: []const u8) kx_error.PublishError {
    return normalizeTo(kx_error.PublishError, err_name, error_names.publish_aliases);
}

pub fn mapIo(err_name: []const u8) kx_error.IoError {
    return normalizeTo(kx_error.IoError, err_name, error_names.io_aliases);
}

fn normalizeTo(comptime Target: type, err_name: []const u8, comptime aliases: []const Alias) Target {
    const resolved = error_names.resolveAlias(err_name, aliases);
    return errorFromName(Target, resolved) orelse error.Internal;
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
