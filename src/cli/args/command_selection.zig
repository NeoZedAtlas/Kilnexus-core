const std = @import("std");
const types = @import("../types.zig");

pub fn selectCommand(tokens: []const []const u8) !types.CommandSelection {
    if (tokens.len == 0) {
        return .{ .command = .build, .args = tokens };
    }

    if (std.mem.eql(u8, tokens[0], "--help") or std.mem.eql(u8, tokens[0], "-h")) {
        return error.HelpRequested;
    }

    if (std.mem.eql(u8, tokens[0], "knx")) {
        if (tokens.len == 1) {
            return .{ .command = .build, .args = tokens[1..] };
        }
        return parseNamedCommand(tokens[1], tokens[2..]);
    }

    if (isKnownCommand(tokens[0])) {
        return parseNamedCommand(tokens[0], tokens[1..]);
    }

    if (std.mem.startsWith(u8, tokens[0], "--")) {
        return .{ .command = .build, .args = tokens };
    }

    // Treat unknown first token as knxfile path for build convenience.
    return .{ .command = .build, .args = tokens };
}

fn isKnownCommand(token: []const u8) bool {
    return std.mem.eql(u8, token, "build") or
        std.mem.eql(u8, token, "bootstrap") or
        std.mem.eql(u8, token, "validate") or
        std.mem.eql(u8, token, "plan");
}

fn parseNamedCommand(token: []const u8, args: []const []const u8) !types.CommandSelection {
    if (std.mem.eql(u8, token, "build") or std.mem.eql(u8, token, "bootstrap")) {
        return .{ .command = .build, .args = args };
    }
    if (std.mem.eql(u8, token, "validate")) {
        return .{ .command = .validate, .args = args };
    }
    if (std.mem.eql(u8, token, "plan")) {
        return .{ .command = .plan, .args = args };
    }
    return error.InvalidCommand;
}

test "selectCommand supports knx prefix and defaults" {
    const prefixed = try selectCommand(&.{ "knx", "build", "Knxfile" });
    try std.testing.expectEqual(types.CliCommand.build, prefixed.command);
    try std.testing.expectEqual(@as(usize, 1), prefixed.args.len);
    try std.testing.expectEqualStrings("Knxfile", prefixed.args[0]);

    const validate_cmd = try selectCommand(&.{ "validate", "Knxfile" });
    try std.testing.expectEqual(types.CliCommand.validate, validate_cmd.command);
    try std.testing.expectEqual(@as(usize, 1), validate_cmd.args.len);

    const default_build = try selectCommand(&.{"Knxfile"});
    try std.testing.expectEqual(types.CliCommand.build, default_build.command);
    try std.testing.expectEqual(@as(usize, 1), default_build.args.len);
}
