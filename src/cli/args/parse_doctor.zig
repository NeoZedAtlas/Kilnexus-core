const std = @import("std");
const common = @import("common.zig");
const types = @import("../types.zig");

pub fn parseDoctorCliArgs(args: []const []const u8) !types.DoctorCliArgs {
    var output: types.DoctorCliArgs = .{};
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
        if (std.mem.eql(u8, arg, "--output-root")) {
            output.output_root = try common.nextOptionValue(args, &i);
            continue;
        }
        if (std.mem.eql(u8, arg, "--trust-off")) {
            output.trust_dir = null;
            continue;
        }
        if (std.mem.eql(u8, arg, "--trust-dir")) {
            output.trust_dir = try common.nextOptionValue(args, &i);
            continue;
        }
        return error.InvalidCommand;
    }
    return output;
}

test "parseDoctorCliArgs parses options" {
    const defaults = try parseDoctorCliArgs(&.{});
    try std.testing.expectEqualStrings(".kilnexus-cache", defaults.cache_root);
    try std.testing.expectEqualStrings("kilnexus-out", defaults.output_root);
    try std.testing.expect(defaults.trust_dir != null);
    try std.testing.expectEqualStrings("trust", defaults.trust_dir.?);
    try std.testing.expect(!defaults.json_output);

    const parsed = try parseDoctorCliArgs(&.{
        "--cache-root",
        "cache-x",
        "--output-root",
        "out-x",
        "--trust-off",
        "--json",
    });
    try std.testing.expectEqualStrings("cache-x", parsed.cache_root);
    try std.testing.expectEqualStrings("out-x", parsed.output_root);
    try std.testing.expect(parsed.trust_dir == null);
    try std.testing.expect(parsed.json_output);
}
