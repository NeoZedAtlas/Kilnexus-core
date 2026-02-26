const std = @import("std");
const cli_args = @import("../args.zig");
const cli_types = @import("../types.zig");
const cleaner = @import("../runtime/cleaner.zig");

pub fn run(allocator: std.mem.Allocator, args: []const []const u8) !void {
    const cli = cli_args.parseCleanCliArgs(args) catch |err| {
        if (err == error.HelpRequested) {
            printUsage();
            return;
        }
        printUsage();
        return error.InvalidCommand;
    };

    const started_ms = std.time.milliTimestamp();
    var report = cleaner.runClean(allocator, .{
        .cache_root = cli.cache_root,
        .output_root = cli.output_root,
        .scopes = cli.scopes,
        .older_than_secs = cli.older_than_secs,
        .toolchain_tree_root = cli.toolchain_tree_root,
        .toolchain_prune = cli.toolchain_prune,
        .keep_last = cli.keep_last,
        .official_max_bytes = cli.official_max_bytes,
        .apply = cli.apply,
    }) catch |err| {
        if (cli.json_output) {
            try printErrorJson(allocator, @errorName(err));
        } else {
            std.debug.print("clean failed: {s}\n", .{@errorName(err)});
        }
        return err;
    };
    defer report.deinit(allocator);
    const ended_ms = std.time.milliTimestamp();
    const duration_ms: u64 = if (ended_ms <= started_ms) 0 else @intCast(ended_ms - started_ms);

    if (cli.json_output) {
        try printJson(allocator, cli, report, duration_ms);
    } else {
        printHuman(cli, report, duration_ms);
    }
}

fn printHuman(cli: cli_types.CleanCliArgs, report: cleaner.CleanReport, duration_ms: u64) void {
    std.debug.print("Clean mode: {s}\n", .{if (report.dry_run) "dry-run" else "apply"});
    std.debug.print("Cache root: {s}\n", .{cli.cache_root});
    std.debug.print("Output root: {s}\n", .{cli.output_root});
    std.debug.print("Older than: {d}s\n", .{cli.older_than_secs});
    if (cli.toolchain_tree_root) |tree_root| {
        std.debug.print("Target toolchain: {s}\n", .{tree_root});
    }
    std.debug.print("Toolchain prune: {}\n", .{cli.toolchain_prune});
    std.debug.print("Keep last: {d}\n", .{cli.keep_last});
    if (cli.official_max_bytes) |max_bytes| {
        std.debug.print("Official max bytes: {d}\n", .{max_bytes});
    }
    std.debug.print("Planned objects/bytes: {d}/{d}\n", .{ report.planned_objects, report.planned_bytes });
    std.debug.print("Deleted objects/bytes: {d}/{d}\n", .{ report.deleted_objects, report.deleted_bytes });
    std.debug.print("Skipped in-use/locked: {d}/{d}\n", .{ report.skipped_in_use, report.skipped_locked });
    for (report.skipped_items) |item| {
        std.debug.print(" - skipped {s}: {s}\n", .{ @tagName(item.reason), item.path });
    }
    std.debug.print("Errors: {d}\n", .{report.errors});
    for (report.error_items) |item| {
        std.debug.print(" - {s} {s}: {s}\n", .{ @tagName(item.phase), item.path, item.reason });
    }
    std.debug.print("Duration ms: {d}\n", .{duration_ms});
}

fn printJson(allocator: std.mem.Allocator, cli: cli_types.CleanCliArgs, report: cleaner.CleanReport, duration_ms: u64) !void {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    var out_writer = out.writer(allocator);
    var out_buffer: [4096]u8 = undefined;
    var out_adapter = out_writer.adaptToNewApi(&out_buffer);
    const writer = &out_adapter.new_interface;

    try writer.writeAll("{\"status\":\"ok\",\"command\":\"clean\",\"mode\":");
    try std.json.Stringify.encodeJsonString(if (report.dry_run) "dry-run" else "apply", .{}, writer);
    try writer.writeAll(",\"cache_root\":");
    try std.json.Stringify.encodeJsonString(cli.cache_root, .{}, writer);
    try writer.writeAll(",\"output_root\":");
    try std.json.Stringify.encodeJsonString(cli.output_root, .{}, writer);
    try writer.writeAll(",\"older_than_secs\":");
    try writer.print("{}", .{cli.older_than_secs});
    if (cli.toolchain_tree_root) |tree_root| {
        try writer.writeAll(",\"toolchain_tree_root\":");
        try std.json.Stringify.encodeJsonString(tree_root, .{}, writer);
    }
    try writer.writeAll(",\"toolchain_prune\":");
    try writer.print("{}", .{cli.toolchain_prune});
    try writer.writeAll(",\"keep_last\":");
    try writer.print("{}", .{cli.keep_last});
    if (cli.official_max_bytes) |max_bytes| {
        try writer.writeAll(",\"official_max_bytes\":");
        try writer.print("{}", .{max_bytes});
    }
    try writer.writeAll(",\"planned_objects\":");
    try writer.print("{}", .{report.planned_objects});
    try writer.writeAll(",\"planned_bytes\":");
    try writer.print("{}", .{report.planned_bytes});
    try writer.writeAll(",\"deleted_objects\":");
    try writer.print("{}", .{report.deleted_objects});
    try writer.writeAll(",\"deleted_bytes\":");
    try writer.print("{}", .{report.deleted_bytes});
    try writer.writeAll(",\"skipped_in_use\":");
    try writer.print("{}", .{report.skipped_in_use});
    try writer.writeAll(",\"skipped_locked\":");
    try writer.print("{}", .{report.skipped_locked});
    try writer.writeAll(",\"skipped_items\":[");
    for (report.skipped_items, 0..) |item, idx| {
        if (idx != 0) try writer.writeAll(",");
        try writer.writeAll("{\"reason\":");
        try std.json.Stringify.encodeJsonString(@tagName(item.reason), .{}, writer);
        try writer.writeAll(",\"path\":");
        try std.json.Stringify.encodeJsonString(item.path, .{}, writer);
        try writer.writeAll("}");
    }
    try writer.writeAll("]");
    try writer.writeAll(",\"errors\":");
    try writer.print("{}", .{report.errors});
    try writer.writeAll(",\"error_items\":[");
    for (report.error_items, 0..) |item, idx| {
        if (idx != 0) try writer.writeAll(",");
        try writer.writeAll("{\"phase\":");
        try std.json.Stringify.encodeJsonString(@tagName(item.phase), .{}, writer);
        try writer.writeAll(",\"path\":");
        try std.json.Stringify.encodeJsonString(item.path, .{}, writer);
        try writer.writeAll(",\"reason\":");
        try std.json.Stringify.encodeJsonString(item.reason, .{}, writer);
        try writer.writeAll("}");
    }
    try writer.writeAll("]");
    try writer.writeAll(",\"duration_ms\":");
    try writer.print("{}", .{duration_ms});
    try writer.writeAll("}\n");
    try writer.flush();
    std.debug.print("{s}", .{out.items});
}

fn printErrorJson(allocator: std.mem.Allocator, err_name: []const u8) !void {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    var out_writer = out.writer(allocator);
    var out_buffer: [512]u8 = undefined;
    var out_adapter = out_writer.adaptToNewApi(&out_buffer);
    const writer = &out_adapter.new_interface;
    try writer.writeAll("{\"status\":\"failed\",\"command\":\"clean\",\"error\":");
    try std.json.Stringify.encodeJsonString(err_name, .{}, writer);
    try writer.writeAll("}\n");
    try writer.flush();
    std.debug.print("{s}", .{out.items});
}

fn printUsage() void {
    std.debug.print("clean options: --scope <csv> --older-than <Ns|Nm|Nh|Nd> --toolchain <tree_root> --toolchain-prune --keep-last <N> --official-max-bytes <N|NKB|NMB|NGB> --cache-root <dir> --output-root <dir> --apply --dry-run --json --help\n", .{});
}
