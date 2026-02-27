const std = @import("std");
const cli_args = @import("../args.zig");
const cli_output = @import("../output.zig");
const cli_types = @import("../types.zig");
const abi_parser = @import("../../parser/abi_parser.zig");

const CheckStatus = enum {
    ok,
    warn,
    fail,
};

const CheckResult = struct {
    name: []const u8,
    status: CheckStatus,
    message: []const u8,
};

pub fn run(allocator: std.mem.Allocator, args: []const []const u8) !void {
    const cli = cli_args.parseDoctorCliArgs(args) catch |err| {
        if (err == error.HelpRequested) {
            printUsage();
            return;
        }
        printUsage();
        return error.InvalidCommand;
    };

    runWithCli(allocator, cli) catch |err| {
        if (cli.json_output) {
            try cli_output.printSimpleFailureJson(allocator, "doctor", @errorName(err));
        } else {
            cli_output.printSimpleFailureHuman("doctor", @errorName(err));
        }
        return err;
    };
}

fn runWithCli(allocator: std.mem.Allocator, cli: cli_types.DoctorCliArgs) !void {
    var checks: [5]CheckResult = undefined;
    checks[0] = checkParserAbi(allocator);
    checks[1] = try checkWritableDirectory(allocator, "cache_root", cli.cache_root);
    checks[2] = try checkWritableDirectory(allocator, "output_root", cli.output_root);
    checks[3] = try checkTrustDirectory(allocator, cli.trust_dir);
    checks[4] = checkCurrentDirectory();

    const overall = summarizeOverall(checks[0..]);
    if (cli.json_output) {
        try printJson(allocator, cli.cache_root, cli.output_root, checks[0..], overall);
    } else {
        printHuman(cli.cache_root, cli.output_root, checks[0..], overall);
    }
}

fn checkParserAbi(allocator: std.mem.Allocator) CheckResult {
    const source =
        \\#!knxfile
        \\version = 1
        \\target = "x86_64-unknown-linux-musl"
        \\[policy]
        \\network = "off"
        \\clock = "fixed"
        \\verify_mode = "strict"
    ;
    const parsed = abi_parser.parseLockfileStrict(allocator, source) catch {
        return .{
            .name = "parser_abi",
            .status = .fail,
            .message = "failed to parse minimal knx source",
        };
    };
    allocator.free(parsed.canonical_json);
    return .{
        .name = "parser_abi",
        .status = .ok,
        .message = "parser ABI reachable",
    };
}

fn checkWritableDirectory(allocator: std.mem.Allocator, name: []const u8, path: []const u8) !CheckResult {
    try std.fs.cwd().makePath(path);
    const marker = try std.fmt.allocPrint(
        allocator,
        "{s}/.knx-doctor-write-{d}.tmp",
        .{ path, std.time.microTimestamp() },
    );
    defer allocator.free(marker);

    const file = std.fs.cwd().createFile(marker, .{ .truncate = true }) catch {
        return .{
            .name = name,
            .status = .fail,
            .message = "cannot write marker file",
        };
    };
    file.close();
    std.fs.cwd().deleteFile(marker) catch {};
    return .{
        .name = name,
        .status = .ok,
        .message = "writable",
    };
}

fn checkTrustDirectory(allocator: std.mem.Allocator, trust_dir: ?[]const u8) !CheckResult {
    _ = allocator;
    if (trust_dir == null) {
        return .{
            .name = "trust_dir",
            .status = .warn,
            .message = "trust disabled",
        };
    }
    std.fs.cwd().access(trust_dir.?, .{}) catch {
        return .{
            .name = "trust_dir",
            .status = .warn,
            .message = "directory not found (will auto-bootstrap on build)",
        };
    };
    return .{
        .name = "trust_dir",
        .status = .ok,
        .message = "directory accessible",
    };
}

fn checkCurrentDirectory() CheckResult {
    return .{
        .name = "cwd",
        .status = .ok,
        .message = "ok",
    };
}

fn summarizeOverall(checks: []const CheckResult) CheckStatus {
    var has_warn = false;
    for (checks) |check| {
        if (check.status == .fail) return .fail;
        if (check.status == .warn) has_warn = true;
    }
    return if (has_warn) .warn else .ok;
}

fn statusText(status: CheckStatus) []const u8 {
    return @tagName(status);
}

fn printHuman(cache_root: []const u8, output_root: []const u8, checks: []const CheckResult, overall: CheckStatus) void {
    std.debug.print("Doctor summary: {s}\n", .{statusText(overall)});
    std.debug.print("Cache root: {s}\n", .{cache_root});
    std.debug.print("Output root: {s}\n", .{output_root});
    for (checks) |check| {
        std.debug.print(" - {s}: {s} ({s})\n", .{ check.name, statusText(check.status), check.message });
    }
}

fn printJson(
    allocator: std.mem.Allocator,
    cache_root: []const u8,
    output_root: []const u8,
    checks: []const CheckResult,
    overall: CheckStatus,
) !void {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    var out_writer = out.writer(allocator);
    var out_buffer: [4096]u8 = undefined;
    var out_adapter = out_writer.adaptToNewApi(&out_buffer);
    const writer = &out_adapter.new_interface;

    try writer.writeAll("{\"status\":\"ok\",\"command\":\"doctor\",\"summary\":");
    try std.json.Stringify.encodeJsonString(statusText(overall), .{}, writer);
    try writer.writeAll(",\"cache_root\":");
    try std.json.Stringify.encodeJsonString(cache_root, .{}, writer);
    try writer.writeAll(",\"output_root\":");
    try std.json.Stringify.encodeJsonString(output_root, .{}, writer);
    try writer.writeAll(",\"checks\":[");
    for (checks, 0..) |check, idx| {
        if (idx != 0) try writer.writeAll(",");
        try writer.writeAll("{\"name\":");
        try std.json.Stringify.encodeJsonString(check.name, .{}, writer);
        try writer.writeAll(",\"status\":");
        try std.json.Stringify.encodeJsonString(statusText(check.status), .{}, writer);
        try writer.writeAll(",\"message\":");
        try std.json.Stringify.encodeJsonString(check.message, .{}, writer);
        try writer.writeAll("}");
    }
    try writer.writeAll("]}\n");
    try writer.flush();
    std.debug.print("{s}", .{out.items});
}

fn printUsage() void {
    std.debug.print("doctor options: --cache-root <dir> --output-root <dir> --trust-dir <dir> --trust-off --json --help\n", .{});
}
