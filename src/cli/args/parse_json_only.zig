const std = @import("std");
const types = @import("../types.zig");

pub fn parseJsonOnlyCliArgs(args: []const []const u8) !types.JsonOnlyCliArgs {
    var output: types.JsonOnlyCliArgs = .{};

    for (args) |arg| {
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            return error.HelpRequested;
        }
        if (std.mem.eql(u8, arg, "--json")) {
            output.json_output = true;
            continue;
        }
        return error.InvalidCommand;
    }

    return output;
}

test "parseJsonOnlyCliArgs supports json and help" {
    const defaults = try parseJsonOnlyCliArgs(&.{});
    try std.testing.expect(!defaults.json_output);

    const json = try parseJsonOnlyCliArgs(&.{"--json"});
    try std.testing.expect(json.json_output);

    try std.testing.expectError(error.HelpRequested, parseJsonOnlyCliArgs(&.{"--help"}));
}
