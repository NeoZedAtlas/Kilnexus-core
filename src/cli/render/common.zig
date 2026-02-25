const std = @import("std");

pub fn printUsage() void {
    std.debug.print(
        "Usage: Kilnexus_core [knx] <build|validate|plan> [args]\n",
        .{},
    );
    std.debug.print("Or: Kilnexus_core [Knxfile] (defaults to build)\n", .{});
    std.debug.print("Knxfile path must be extensionless (no .toml).\n", .{});
    std.debug.print("build positional: [Knxfile] [trust-dir] [cache-root] [output-root]\n", .{});
    std.debug.print(
        "build options: --knxfile <path> --trust-off --trust-dir <dir> --trust-state <path|off> --cache-root <dir> --output-root <dir> --json --help\n",
        .{},
    );
    std.debug.print("validate options: [Knxfile] --knxfile <path> --json --help\n", .{});
    std.debug.print("plan options: [Knxfile] --knxfile <path> --json --help\n", .{});
}

pub fn printSimpleFailureHuman(command: []const u8, err: anyerror) void {
    std.debug.print("{s} failed: {s}\n", .{ command, @errorName(err) });
}

pub fn printSimpleFailureJson(allocator: std.mem.Allocator, command: []const u8, err: anyerror) !void {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    var out_writer = out.writer(allocator);
    var out_buffer: [512]u8 = undefined;
    var out_adapter = out_writer.adaptToNewApi(&out_buffer);
    const writer = &out_adapter.new_interface;

    try writer.writeAll("{\"status\":\"failed\",\"command\":");
    try std.json.Stringify.encodeJsonString(command, .{}, writer);
    try writer.writeAll(",\"error\":");
    try std.json.Stringify.encodeJsonString(@errorName(err), .{}, writer);
    try writer.writeAll("}\n");
    try writer.flush();
    std.debug.print("{s}", .{out.items});
}
