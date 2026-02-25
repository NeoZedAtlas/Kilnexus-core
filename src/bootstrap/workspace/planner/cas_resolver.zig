const std = @import("std");
const validator = @import("../../../knx/validator.zig");

pub fn resolveSourceAbsolutePath(
    allocator: std.mem.Allocator,
    entry: validator.WorkspaceEntry,
    cache_root: []const u8,
) ![]u8 {
    if (entry.host_source) |host_source| {
        return std.fs.cwd().realpathAlloc(allocator, host_source);
    }

    const cas_digest = entry.cas_sha256 orelse return error.FileNotFound;
    const digest_hex = std.fmt.bytesToHex(cas_digest, .lower);
    const domain_name = switch (entry.cas_domain) {
        .official => "official",
        .third_party => "third_party",
        .local => "local",
    };
    const cas_path = try std.fs.path.join(allocator, &.{
        cache_root,
        "cas",
        domain_name,
        "blob",
        digest_hex[0..],
        "blob.bin",
    });
    defer allocator.free(cas_path);
    return std.fs.cwd().realpathAlloc(allocator, cas_path);
}
