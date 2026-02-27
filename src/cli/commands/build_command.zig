const std = @import("std");
const bootstrap = @import("../../bootstrap/state_machine.zig");
const cli_args = @import("../args.zig");
const cli_output = @import("../output.zig");
const cli_summary = @import("../summary.zig");

pub fn run(allocator: std.mem.Allocator, args: []const []const u8) !void {
    const cli = cli_args.parseBootstrapCliArgs(args) catch |err| {
        if (err == error.HelpRequested) {
            cli_output.printUsage();
            return;
        }
        cli_output.printUsage();
        return error.InvalidCommand;
    };

    runWithCli(allocator, cli) catch |err| {
        if (cli.json_output) {
            try cli_output.printSimpleFailureJson(allocator, "build", @errorName(err));
        } else {
            if (err == error.LockMissing) {
                std.debug.print("Lockfile missing for {s}. Run `knx freeze --knxfile {s}` first.\n", .{ cli.path, cli.path });
            } else if (err == error.LockDrift) {
                std.debug.print("Lock drift detected for {s}. Re-run `knx freeze --knxfile {s}`.\n", .{ cli.path, cli.path });
            }
            cli_output.printSimpleFailureHuman("build", @errorName(err));
        }
        return err;
    };
}

fn runWithCli(allocator: std.mem.Allocator, cli: @import("../types.zig").BootstrapCliArgs) !void {
    const resolved_path = try resolveBuildPathWithLockPolicy(allocator, cli.path);
    defer if (!std.mem.eql(u8, resolved_path, cli.path)) allocator.free(resolved_path);

    if (!hasLockSuffixIgnoreCase(cli.path)) {
        try validateLockDrift(allocator, cli.path, resolved_path);
    }

    var attempt = bootstrap.attemptRunFromPathWithOptions(allocator, resolved_path, .{
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

fn resolveBuildPathWithLockPolicy(allocator: std.mem.Allocator, path: []const u8) ![]const u8 {
    if (hasLockSuffixIgnoreCase(path)) return path;

    const lock_path = try std.fmt.allocPrint(allocator, "{s}.lock", .{path});
    if (try pathExists(lock_path)) {
        return lock_path;
    }
    allocator.free(lock_path);
    return error.LockMissing;
}

fn validateLockDrift(allocator: std.mem.Allocator, knx_path: []const u8, lock_path: []const u8) !void {
    if (!try pathExists(knx_path)) return;

    var knx_summary = try cli_summary.loadKnxSummary(allocator, knx_path);
    defer knx_summary.deinit(allocator);
    var lock_summary = try cli_summary.loadKnxSummary(allocator, lock_path);
    defer lock_summary.deinit(allocator);

    if (!std.mem.eql(u8, knx_summary.knx_digest_hex[0..], lock_summary.knx_digest_hex[0..])) {
        return error.LockDrift;
    }
}

fn pathExists(path: []const u8) !bool {
    var file = std.fs.cwd().openFile(path, .{}) catch |err| switch (err) {
        error.FileNotFound, error.PathAlreadyExists, error.NotDir, error.NameTooLong, error.BadPathName => return false,
        else => return err,
    };
    file.close();
    return true;
}

fn hasLockSuffixIgnoreCase(path: []const u8) bool {
    return path.len >= 5 and std.ascii.eqlIgnoreCase(path[path.len - 5 ..], ".lock");
}
