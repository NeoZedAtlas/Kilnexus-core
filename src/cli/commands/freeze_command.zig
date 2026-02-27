const std = @import("std");
const cli_args = @import("../args.zig");
const cli_output = @import("../output.zig");
const cli_summary = @import("../summary.zig");

pub fn run(allocator: std.mem.Allocator, args: []const []const u8) !void {
    const cli = cli_args.parseFreezeCliArgs(args) catch |err| {
        if (err == error.HelpRequested) {
            cli_output.printUsage();
            return;
        }
        cli_output.printUsage();
        return error.InvalidCommand;
    };

    runWithCli(allocator, cli) catch |err| {
        if (cli.json_output) {
            try cli_output.printSimpleFailureJson(allocator, "freeze", @errorName(err));
        } else {
            cli_output.printSimpleFailureHuman("freeze", @errorName(err));
        }
        return err;
    };
}

fn runWithCli(allocator: std.mem.Allocator, cli: @import("../types.zig").FreezeCliArgs) !void {
    const lock_path = if (cli.lock_path) |explicit| explicit else try deriveLockPath(allocator, cli.path);
    defer if (cli.lock_path == null) allocator.free(lock_path);

    var summary = try cli_summary.loadKnxSummary(allocator, cli.path);
    defer summary.deinit(allocator);

    try writeFileAtomic(allocator, lock_path, summary.canonical_json);

    if (cli.json_output) {
        try printFreezeJson(allocator, cli.path, lock_path, summary.knx_digest_hex[0..], summary.canonical_json.len);
    } else {
        printFreezeHuman(cli.path, lock_path, summary.knx_digest_hex[0..], summary.canonical_json.len);
    }
}

fn deriveLockPath(allocator: std.mem.Allocator, knx_path: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}.lock", .{knx_path});
}

fn writeFileAtomic(allocator: std.mem.Allocator, path: []const u8, content: []const u8) !void {
    const tmp_path = try std.fmt.allocPrint(allocator, "{s}.tmp-{d}", .{ path, std.time.microTimestamp() });
    defer allocator.free(tmp_path);
    errdefer std.fs.cwd().deleteFile(tmp_path) catch {};

    if (std.fs.path.dirname(path)) |dir| {
        try std.fs.cwd().makePath(dir);
    }

    var file = try std.fs.cwd().createFile(tmp_path, .{});
    defer file.close();
    try file.writeAll(content);
    try file.sync();
    try std.fs.cwd().rename(tmp_path, path);
}

fn printFreezeHuman(knx_path: []const u8, lock_path: []const u8, knx_digest: []const u8, bytes: usize) void {
    std.debug.print("Freeze completed\n", .{});
    std.debug.print("Knxfile: {s}\n", .{knx_path});
    std.debug.print("Lockfile: {s}\n", .{lock_path});
    std.debug.print("Knx digest: {s}\n", .{knx_digest});
    std.debug.print("Canonical bytes: {d}\n", .{bytes});
}

fn printFreezeJson(allocator: std.mem.Allocator, knx_path: []const u8, lock_path: []const u8, knx_digest: []const u8, bytes: usize) !void {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    var out_writer = out.writer(allocator);
    var out_buffer: [2048]u8 = undefined;
    var out_adapter = out_writer.adaptToNewApi(&out_buffer);
    const writer = &out_adapter.new_interface;

    try writer.writeAll("{\"status\":\"ok\",\"command\":\"freeze\",\"knxfile\":");
    try std.json.Stringify.encodeJsonString(knx_path, .{}, writer);
    try writer.writeAll(",\"lockfile\":");
    try std.json.Stringify.encodeJsonString(lock_path, .{}, writer);
    try writer.writeAll(",\"knx_digest\":");
    try std.json.Stringify.encodeJsonString(knx_digest, .{}, writer);
    try writer.writeAll(",\"canonical_json_bytes\":");
    try writer.print("{d}", .{bytes});
    try writer.writeAll("}\n");
    try writer.flush();
    std.debug.print("{s}", .{out.items});
}
