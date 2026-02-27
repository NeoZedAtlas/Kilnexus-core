const std = @import("std");
const parse_errors = @import("../../parser/parse_errors.zig");
const abi_parser = @import("../../parser/abi_parser.zig");
const validator = @import("../../knx/validator.zig");

pub const planner_marker = "knx-freeze-v2";

pub fn canonicalizeWithSourceMetadata(
    allocator: std.mem.Allocator,
    lock_canonical: []const u8,
    intent_canonical: []const u8,
) parse_errors.ParseError![]u8 {
    if (lock_canonical.len < 2 or lock_canonical[0] != '{' or lock_canonical[lock_canonical.len - 1] != '}') {
        return error.Canonicalization;
    }

    const intent_digest = validator.computeKnxDigestHex(intent_canonical);
    const base = lock_canonical[0 .. lock_canonical.len - 1];

    const enriched = std.fmt.allocPrint(
        allocator,
        "{s},\"source\":{{\"knxfile_digest_sha256\":\"{s}\",\"planner\":\"{s}\"}}}}",
        .{ base, intent_digest[0..], planner_marker },
    ) catch return error.Internal;
    defer allocator.free(enriched);

    const parsed = abi_parser.parseLockfileStrict(allocator, enriched) catch |err| return err;
    return parsed.canonical_json;
}
