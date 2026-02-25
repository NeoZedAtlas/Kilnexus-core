const std = @import("std");

pub fn computeKnxDigestHex(canonical_json: []const u8) [64]u8 {
    var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(canonical_json, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}
