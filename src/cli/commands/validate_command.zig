const std = @import("std");
const cli_args = @import("../args.zig");
const cli_output = @import("../output.zig");
const cli_summary = @import("../summary.zig");

pub fn run(allocator: std.mem.Allocator, args: []const []const u8) !void {
    const cli = cli_args.parseParseOnlyCliArgs(args) catch |err| {
        if (err == error.HelpRequested) {
            cli_output.printUsage();
            return;
        }
        cli_output.printUsage();
        return error.InvalidCommand;
    };

    var summary = cli_summary.loadKnxSummary(allocator, cli.path) catch |err| {
        if (cli.json_output) {
            try cli_output.printSimpleFailureJson(allocator, "validate", @errorName(err));
        } else {
            cli_output.printSimpleFailureHuman("validate", @errorName(err));
        }
        return error.InvalidCommand;
    };
    defer summary.deinit(allocator);

    if (cli.json_output) {
        try cli_output.printValidateJson(allocator, &summary);
    } else {
        cli_output.printValidateHuman(&summary);
    }
}
