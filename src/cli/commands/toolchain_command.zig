const std = @import("std");
const cli_args = @import("../args.zig");
const inspector = @import("../runtime/cache_inspector.zig");

pub fn run(allocator: std.mem.Allocator, args: []const []const u8) !void {
    const cli = cli_args.parseToolchainCliArgs(args) catch |err| {
        if (err == error.HelpRequested) {
            printUsage();
            return;
        }
        printUsage();
        return error.InvalidCommand;
    };

    const toolchains = try inspector.listOfficialToolchains(allocator, cli.cache_root);
    defer {
        for (toolchains) |*entry| entry.deinit(allocator);
        allocator.free(toolchains);
    }

    if (cli.json_output) {
        try printJson(allocator, cli.cache_root, toolchains);
        return;
    }

    std.debug.print("Toolchains in cache: {d}\n", .{toolchains.len});
    for (toolchains, 0..) |entry, idx| {
        std.debug.print(
            " {d}. {s} (zig:{}, zig.exe:{}, files:{d}, bytes:{d})\n",
            .{ idx + 1, entry.tree_root, entry.has_zig, entry.has_zig_exe, entry.files, entry.bytes },
        );
    }
}

fn printUsage() void {
    std.debug.print("toolchain options: --cache-root <dir> --json --help\n", .{});
}

fn printJson(allocator: std.mem.Allocator, cache_root: []const u8, toolchains: []const inspector.ToolchainEntry) !void {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    var out_writer = out.writer(allocator);
    var out_buffer: [4096]u8 = undefined;
    var out_adapter = out_writer.adaptToNewApi(&out_buffer);
    const writer = &out_adapter.new_interface;

    try writer.writeAll("{\"status\":\"ok\",\"command\":\"toolchain\",\"cache_root\":");
    try std.json.Stringify.encodeJsonString(cache_root, .{}, writer);
    try writer.writeAll(",\"count\":");
    try writer.print("{}", .{toolchains.len});
    try writer.writeAll(",\"items\":[");
    for (toolchains, 0..) |entry, idx| {
        if (idx != 0) try writer.writeAll(",");
        try writer.writeAll("{\"tree_root\":");
        try std.json.Stringify.encodeJsonString(entry.tree_root, .{}, writer);
        try writer.writeAll(",\"has_zig\":");
        try writer.print("{}", .{entry.has_zig});
        try writer.writeAll(",\"has_zig_exe\":");
        try writer.print("{}", .{entry.has_zig_exe});
        try writer.writeAll(",\"files\":");
        try writer.print("{}", .{entry.files});
        try writer.writeAll(",\"bytes\":");
        try writer.print("{}", .{entry.bytes});
        try writer.writeAll("}");
    }
    try writer.writeAll("]}\n");
    try writer.flush();
    std.debug.print("{s}", .{out.items});
}
