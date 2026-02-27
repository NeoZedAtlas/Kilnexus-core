const std = @import("std");
const cli_args = @import("../args.zig");
const cli_output = @import("../output.zig");
const cli_summary = @import("../summary.zig");
const cli_types = @import("../types.zig");
const abi_parser = @import("../../parser/abi_parser.zig");
const lock_infer = @import("../runtime/lock_infer.zig");

pub fn run(allocator: std.mem.Allocator, args: []const []const u8) !void {
    const cli = cli_args.parseParseOnlyCliArgs(args) catch |err| {
        if (err == error.HelpRequested) {
            cli_output.printUsage();
            return;
        }
        cli_output.printUsage();
        return error.InvalidCommand;
    };

    const source = std.fs.cwd().readFileAlloc(allocator, cli.path, cli_types.max_knxfile_bytes) catch |err| {
        if (cli.json_output) {
            try cli_output.printSimpleFailureJson(allocator, "plan", @errorName(err));
        } else {
            cli_output.printSimpleFailureHuman("plan", @errorName(err));
        }
        return error.InvalidCommand;
    };
    defer allocator.free(source);

    const parsed = abi_parser.parseLockfileStrict(allocator, source) catch |err| {
        if (cli.json_output) {
            try cli_output.printSimpleFailureJson(allocator, "plan", @errorName(err));
        } else {
            cli_output.printSimpleFailureHuman("plan", @errorName(err));
        }
        return error.InvalidCommand;
    };
    defer allocator.free(parsed.canonical_json);

    const intent_version = parseVersion(parsed.canonical_json) catch |err| {
        if (cli.json_output) {
            try cli_output.printSimpleFailureJson(allocator, "plan", @errorName(err));
        } else {
            cli_output.printSimpleFailureHuman("plan", @errorName(err));
        }
        return error.InvalidCommand;
    };

    if (intent_version != lock_infer.current_intent_version) {
        if (cli.json_output) {
            try cli_output.printSimpleFailureJson(allocator, "plan", "VersionUnsupported");
        } else {
            cli_output.printSimpleFailureHuman("plan", "VersionUnsupported");
        }
        return error.InvalidCommand;
    }

    const lock_canonical = lock_infer.inferLockCanonicalJsonFromIntentCanonical(allocator, parsed.canonical_json) catch |err| {
        if (cli.json_output) {
            try cli_output.printSimpleFailureJson(allocator, "plan", @errorName(err));
        } else {
            cli_output.printSimpleFailureHuman("plan", @errorName(err));
        }
        return error.InvalidCommand;
    };
    defer allocator.free(lock_canonical);

    var summary = cli_summary.loadKnxSummaryFromCanonicalJson(allocator, lock_canonical) catch |err| {
        if (cli.json_output) {
            try cli_output.printSimpleFailureJson(allocator, "plan", @errorName(err));
        } else {
            cli_output.printSimpleFailureHuman("plan", @errorName(err));
        }
        return error.InvalidCommand;
    };
    defer summary.deinit(allocator);

    if (cli.json_output) {
        try cli_output.printPlanJson(allocator, &summary);
    } else {
        cli_output.printPlanHuman(&summary);
    }
}

fn parseVersion(canonical_json: []const u8) !i64 {
    const parsed = try std.json.parseFromSlice(std.json.Value, std.heap.page_allocator, canonical_json, .{});
    defer parsed.deinit();
    const root = switch (parsed.value) {
        .object => |obj| obj,
        else => return error.TypeMismatch,
    };
    const version_value = root.get("version") orelse return error.MissingField;
    return switch (version_value) {
        .integer => |num| num,
        else => error.TypeMismatch,
    };
}
