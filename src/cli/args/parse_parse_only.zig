const std = @import("std");
const common = @import("common.zig");
const types = @import("../types.zig");

pub fn parseParseOnlyCliArgs(args: []const []const u8) !types.ParseOnlyCliArgs {
    var output: types.ParseOnlyCliArgs = .{};
    var positional_index: usize = 0;
    var path_set = false;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            return error.HelpRequested;
        }

        if (std.mem.startsWith(u8, arg, "--")) {
            if (std.mem.eql(u8, arg, "--json")) {
                output.json_output = true;
                continue;
            }
            if (std.mem.eql(u8, arg, "--knxfile")) {
                output.path = try common.nextOptionValue(args, &i);
                path_set = true;
                continue;
            }
            return error.InvalidCommand;
        }

        if (positional_index > 0 or path_set) return error.InvalidCommand;
        output.path = arg;
        positional_index += 1;
    }

    try common.validateKnxfileCliPath(output.path);
    return output;
}

test "parseParseOnlyCliArgs parses positional and named forms" {
    const positional = try parseParseOnlyCliArgs(&.{"Knxfile.plan"});
    try std.testing.expectEqualStrings("Knxfile.plan", positional.path);
    try std.testing.expect(!positional.json_output);

    const named = try parseParseOnlyCliArgs(&.{
        "--knxfile",
        "Knxfile.validate",
        "--json",
    });
    try std.testing.expectEqualStrings("Knxfile.validate", named.path);
    try std.testing.expect(named.json_output);
}
