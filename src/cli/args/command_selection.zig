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
        std.mem.eql(u8, token, "freeze") or
        std.mem.eql(u8, token, "validate") or
        std.mem.eql(u8, token, "plan") or
        std.mem.eql(u8, token, "graph") or
        std.mem.eql(u8, token, "doctor") or
        std.mem.eql(u8, token, "clean") or
        std.mem.eql(u8, token, "cache") or
        std.mem.eql(u8, token, "toolchain") or
        std.mem.eql(u8, token, "version");
}

fn parseNamedCommand(token: []const u8, args: []const []const u8) !types.CommandSelection {
    if (std.mem.eql(u8, token, "build") or std.mem.eql(u8, token, "bootstrap")) {
        return .{ .command = .build, .args = args };
    }
    if (std.mem.eql(u8, token, "freeze")) {
        return .{ .command = .freeze, .args = args };
    }
    if (std.mem.eql(u8, token, "validate")) {
        return .{ .command = .validate, .args = args };
    }
    if (std.mem.eql(u8, token, "plan")) {
        return .{ .command = .plan, .args = args };
    }
    if (std.mem.eql(u8, token, "graph")) {
        return .{ .command = .graph, .args = args };
    }
    if (std.mem.eql(u8, token, "doctor")) {
        return .{ .command = .doctor, .args = args };
    }
    if (std.mem.eql(u8, token, "clean")) {
        return .{ .command = .clean, .args = args };
    }
    if (std.mem.eql(u8, token, "cache")) {
        return .{ .command = .cache, .args = args };
    }
    if (std.mem.eql(u8, token, "toolchain")) {
        return .{ .command = .toolchain, .args = args };
    }
    if (std.mem.eql(u8, token, "version")) {
        return .{ .command = .version, .args = args };
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

    const freeze_cmd = try selectCommand(&.{"freeze"});
    try std.testing.expectEqual(types.CliCommand.freeze, freeze_cmd.command);

    const default_build = try selectCommand(&.{"Knxfile"});
    try std.testing.expectEqual(types.CliCommand.build, default_build.command);
    try std.testing.expectEqual(@as(usize, 1), default_build.args.len);

    const version_cmd = try selectCommand(&.{"version"});
    try std.testing.expectEqual(types.CliCommand.version, version_cmd.command);

    const graph_cmd = try selectCommand(&.{ "knx", "graph", "Knxfile" });
    try std.testing.expectEqual(types.CliCommand.graph, graph_cmd.command);
    try std.testing.expectEqual(@as(usize, 1), graph_cmd.args.len);

    const clean_cmd = try selectCommand(&.{"clean"});
    try std.testing.expectEqual(types.CliCommand.clean, clean_cmd.command);
}
