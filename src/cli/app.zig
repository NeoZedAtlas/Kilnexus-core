const std = @import("std");
const cli_args = @import("args.zig");
const cli_types = @import("types.zig");
const cli_output = @import("output.zig");
const build_command = @import("commands/build_command.zig");
const validate_command = @import("commands/validate_command.zig");
const plan_command = @import("commands/plan_command.zig");
const graph_command = @import("commands/graph_command.zig");
const doctor_command = @import("commands/doctor_command.zig");
const cache_command = @import("commands/cache_command.zig");
const toolchain_command = @import("commands/toolchain_command.zig");
const version_command = @import("commands/version_command.zig");

pub fn runMain() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();

    var cli_tokens: std.ArrayList([]const u8) = .empty;
    defer cli_tokens.deinit(allocator);
    _ = args.next();
    while (args.next()) |arg| {
        try cli_tokens.append(allocator, arg);
    }

    const selection = cli_args.selectCommand(cli_tokens.items) catch |err| {
        if (err == error.HelpRequested) {
            cli_output.printUsage();
            return;
        }
        if (cli_tokens.items.len > 0) {
            std.debug.print("Unknown command: {s}\n", .{cli_tokens.items[0]});
        } else {
            std.debug.print("Invalid command\n", .{});
        }
        cli_output.printUsage();
        return error.InvalidCommand;
    };

    switch (selection.command) {
        .build => try build_command.run(allocator, selection.args),
        .validate => try validate_command.run(allocator, selection.args),
        .plan => try plan_command.run(allocator, selection.args),
        .graph => try graph_command.run(allocator, selection.args),
        .doctor => try doctor_command.run(allocator, selection.args),
        .cache => try cache_command.run(allocator, selection.args),
        .toolchain => try toolchain_command.run(allocator, selection.args),
        .version => try version_command.run(allocator, selection.args),
    }
}

test {
    _ = cli_args;
    _ = cli_output;
    _ = cli_types;
    _ = build_command;
    _ = validate_command;
    _ = plan_command;
    _ = graph_command;
    _ = doctor_command;
    _ = cache_command;
    _ = toolchain_command;
    _ = version_command;
}
