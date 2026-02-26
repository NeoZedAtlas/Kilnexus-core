const std = @import("std");
const common = @import("common.zig");
const types = @import("../types.zig");

pub fn parseCacheCliArgs(args: []const []const u8) !types.CacheCliArgs {
    var output: types.CacheCliArgs = .{};
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            return error.HelpRequested;
        }
        if (std.mem.eql(u8, arg, "--json")) {
            output.json_output = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--cache-root")) {
            output.cache_root = try common.nextOptionValue(args, &i);
            continue;
        }
        return error.InvalidCommand;
    }
    return output;
}

test "parseCacheCliArgs parses cache root and json" {
    const defaults = try parseCacheCliArgs(&.{});
    try std.testing.expectEqualStrings(".kilnexus-cache", defaults.cache_root);
    try std.testing.expect(!defaults.json_output);

    const parsed = try parseCacheCliArgs(&.{ "--cache-root", "cache-x", "--json" });
    try std.testing.expectEqualStrings("cache-x", parsed.cache_root);
    try std.testing.expect(parsed.json_output);
}
