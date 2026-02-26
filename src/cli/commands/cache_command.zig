const std = @import("std");
const cli_args = @import("../args.zig");
const inspector = @import("../runtime/cache_inspector.zig");

pub fn run(allocator: std.mem.Allocator, args: []const []const u8) !void {
    const cli = cli_args.parseCacheCliArgs(args) catch |err| {
        if (err == error.HelpRequested) {
            printUsage();
            return;
        }
        printUsage();
        return error.InvalidCommand;
    };

    var stats = try inspector.loadCacheStats(allocator, cli.cache_root);
    defer stats.deinit(allocator);

    if (cli.json_output) {
        try printJson(allocator, &stats);
        return;
    }

    std.debug.print("Cache root: {s}\n", .{stats.cache_root});
    std.debug.print("Exists: {}\n", .{stats.total.exists});
    std.debug.print("Total files/dirs/bytes: {d}/{d}/{d}\n", .{ stats.total.files, stats.total.dirs, stats.total.bytes });
    std.debug.print(
        "Objects official(tree/blob) third_party(tree/blob) local(tree/blob): {d}/{d} {d}/{d} {d}/{d}\n",
        .{
            stats.official_tree_count,
            stats.official_blob_count,
            stats.third_party_tree_count,
            stats.third_party_blob_count,
            stats.local_tree_count,
            stats.local_blob_count,
        },
    );
}

fn printUsage() void {
    std.debug.print("cache options: --cache-root <dir> --json --help\n", .{});
}

fn printJson(allocator: std.mem.Allocator, stats: *const inspector.CacheStats) !void {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    var out_writer = out.writer(allocator);
    var out_buffer: [2048]u8 = undefined;
    var out_adapter = out_writer.adaptToNewApi(&out_buffer);
    const writer = &out_adapter.new_interface;

    try writer.writeAll("{\"status\":\"ok\",\"command\":\"cache\",\"cache_root\":");
    try std.json.Stringify.encodeJsonString(stats.cache_root, .{}, writer);
    try writer.writeAll(",\"exists\":");
    try writer.print("{}", .{stats.total.exists});
    try writer.writeAll(",\"total\":{\"files\":");
    try writer.print("{}", .{stats.total.files});
    try writer.writeAll(",\"dirs\":");
    try writer.print("{}", .{stats.total.dirs});
    try writer.writeAll(",\"bytes\":");
    try writer.print("{}", .{stats.total.bytes});
    try writer.writeAll("},\"objects\":{\"official\":{\"tree\":");
    try writer.print("{}", .{stats.official_tree_count});
    try writer.writeAll(",\"blob\":");
    try writer.print("{}", .{stats.official_blob_count});
    try writer.writeAll("},\"third_party\":{\"tree\":");
    try writer.print("{}", .{stats.third_party_tree_count});
    try writer.writeAll(",\"blob\":");
    try writer.print("{}", .{stats.third_party_blob_count});
    try writer.writeAll("},\"local\":{\"tree\":");
    try writer.print("{}", .{stats.local_tree_count});
    try writer.writeAll(",\"blob\":");
    try writer.print("{}", .{stats.local_blob_count});
    try writer.writeAll("}}}\n");
    try writer.flush();
    std.debug.print("{s}", .{out.items});
}
