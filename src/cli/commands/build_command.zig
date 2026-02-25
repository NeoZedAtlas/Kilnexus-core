const std = @import("std");
const bootstrap = @import("../../bootstrap/state_machine.zig");
const cli_args = @import("../args.zig");
const cli_output = @import("../output.zig");

pub fn run(allocator: std.mem.Allocator, args: []const []const u8) !void {
    const cli = cli_args.parseBootstrapCliArgs(args) catch |err| {
        if (err == error.HelpRequested) {
            cli_output.printUsage();
            return;
        }
        cli_output.printUsage();
        return error.InvalidCommand;
    };

    var attempt = bootstrap.attemptRunFromPathWithOptions(allocator, cli.path, .{
        .trust_metadata_dir = cli.trust_dir,
        .trust_state_path = if (cli.trust_dir == null) null else cli.trust_state_path,
        .cache_root = cli.cache_root,
        .output_root = cli.output_root,
    });

    switch (attempt) {
        .success => |*run_result| {
            defer run_result.deinit(allocator);
            if (cli.json_output) {
                try cli_output.printSuccessJson(allocator, run_result, &cli);
            } else {
                cli_output.printSuccessHuman(allocator, run_result, &cli);
            }
        },
        .failure => |failure| {
            if (cli.json_output) {
                try cli_output.printFailureJson(allocator, failure);
            } else {
                cli_output.printFailureHuman(failure);
            }
            return error.BootstrapFailed;
        },
    }
}
