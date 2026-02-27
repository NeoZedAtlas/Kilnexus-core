const std = @import("std");
const kx_error = @import("../../errors/kx_error.zig");
const boundary_map = @import("../../errors/boundary_map.zig");

pub fn printUsage() void {
    std.debug.print(
        "Usage: Kilnexus_core [knx] <build|freeze|sync|validate|plan|graph|doctor|clean|cache|toolchain|version> [args]\n",
        .{},
    );
    std.debug.print("Or: Kilnexus_core [Knxfile] (defaults to build)\n", .{});
    std.debug.print("Knxfile path must be extensionless (no .toml).\n", .{});
    std.debug.print("build positional: [Knxfile] [trust-dir] [cache-root] [output-root]\n", .{});
    std.debug.print(
        "build options: --knxfile <path> --trust-off --trust-dir <dir> --trust-state <path|off> --cache-root <dir> --output-root <dir> --allow-unlocked --json --help (defaults to <Knxfile>.lock)\n",
        .{},
    );
    std.debug.print("freeze options: [Knxfile] [Knxfile.lock] --knxfile <path> --lockfile <path> --dry-run --json --help\n", .{});
    std.debug.print("sync options: [Knxfile] [Knxfile.lock] --knxfile <path> --lockfile <path> --dry-run --json --help\n", .{});
    std.debug.print("validate options: [Knxfile] --knxfile <path> --json --help\n", .{});
    std.debug.print("plan options: [Knxfile] --knxfile <path> --json --help\n", .{});
    std.debug.print("graph options: [Knxfile] --knxfile <path> --json --help\n", .{});
    std.debug.print("doctor options: --cache-root <dir> --output-root <dir> --trust-dir <dir> --trust-off --json --help\n", .{});
    std.debug.print("clean options: --scope <csv> --older-than <Ns|Nm|Nh|Nd> --toolchain <tree_root> --toolchain-prune --keep-last <N> --official-max-bytes <N|NKB|NMB|NGB> --cache-root <dir> --output-root <dir> --apply --dry-run --json --help\n", .{});
    std.debug.print("cache options: --cache-root <dir> --json --help\n", .{});
    std.debug.print("toolchain options: --cache-root <dir> --json --help\n", .{});
    std.debug.print("version options: --json --help\n", .{});
}

pub fn printSimpleFailureHuman(command: []const u8, err_name: []const u8) void {
    const code = classifyCliError(err_name);
    const descriptor = kx_error.describe(code);
    var error_id_buf: [128]u8 = undefined;
    const error_id = kx_error.buildErrorId(&error_id_buf, code, command, err_name);

    std.debug.print("{s} failed\n", .{command});
    std.debug.print("Error id: {s}\n", .{error_id});
    std.debug.print("Code: {s} ({d})\n", .{ @tagName(code), @intFromEnum(code) });
    std.debug.print("Family: {s}\n", .{@tagName(descriptor.family)});
    std.debug.print("Cause: {s}\n", .{err_name});
    std.debug.print("Summary: {s}\n", .{descriptor.summary});
}

pub fn printSimpleFailureJson(allocator: std.mem.Allocator, command: []const u8, err_name: []const u8) !void {
    const code = classifyCliError(err_name);
    const descriptor = kx_error.describe(code);
    var error_id_buf: [128]u8 = undefined;
    const error_id = kx_error.buildErrorId(&error_id_buf, code, command, err_name);

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    var out_writer = out.writer(allocator);
    var out_buffer: [512]u8 = undefined;
    var out_adapter = out_writer.adaptToNewApi(&out_buffer);
    const writer = &out_adapter.new_interface;

    try writer.writeAll("{\"status\":\"failed\",\"command\":");
    try std.json.Stringify.encodeJsonString(command, .{}, writer);
    try writer.writeAll(",\"error_id\":");
    try std.json.Stringify.encodeJsonString(error_id, .{}, writer);
    try writer.writeAll(",\"code\":");
    try std.json.Stringify.encodeJsonString(@tagName(code), .{}, writer);
    try writer.writeAll(",\"code_num\":");
    try writer.print("{d}", .{@intFromEnum(code)});
    try writer.writeAll(",\"family\":");
    try std.json.Stringify.encodeJsonString(@tagName(descriptor.family), .{}, writer);
    try writer.writeAll(",\"summary\":");
    try std.json.Stringify.encodeJsonString(descriptor.summary, .{}, writer);
    try writer.writeAll(",\"cause\":");
    try std.json.Stringify.encodeJsonString(err_name, .{}, writer);
    try writer.writeAll(",\"error\":");
    try std.json.Stringify.encodeJsonString(err_name, .{}, writer);
    try writer.writeAll("}\n");
    try writer.flush();
    std.debug.print("{s}", .{out.items});
}

fn classifyCliError(err_name: []const u8) kx_error.Code {
    const parse = boundary_map.mapParse(err_name);
    if (parse != error.Internal) return kx_error.classifyParse(parse);

    const io = boundary_map.mapIo(err_name);
    if (io != error.Internal) return kx_error.classifyIo(io);

    const trust = boundary_map.mapTrust(err_name);
    if (trust != error.Internal) return kx_error.classifyTrust(trust);

    const integrity = boundary_map.mapIntegrity(err_name);
    if (integrity != error.Internal) return kx_error.classifyIntegrity(integrity);

    const build = boundary_map.mapBuild(err_name);
    if (build != error.Internal) return kx_error.classifyBuild(build);

    const publish = boundary_map.mapPublish(err_name);
    if (publish != error.Internal) return kx_error.classifyPublish(publish);

    return .KX_INTERNAL;
}

test "classifyCliError prioritizes parse and io families" {
    try std.testing.expectEqual(kx_error.Code.KX_PARSE_SYNTAX, classifyCliError("Parse"));
    try std.testing.expectEqual(kx_error.Code.KX_IO_NOT_FOUND, classifyCliError("FileNotFound"));
    try std.testing.expectEqual(kx_error.Code.KX_INTERNAL, classifyCliError("SomeUnknownError"));
}
