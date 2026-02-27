const std = @import("std");
const types = @import("../types.zig");

pub fn printPlanHuman(summary: *const types.KnxSummary) void {
    printPlanHumanWithInfo(summary, null);
}

pub fn printPlanHumanWithInfo(summary: *const types.KnxSummary, inferred_from_version: ?i64) void {
    std.debug.print("Plan generated\n", .{});
    if (inferred_from_version) |version| {
        std.debug.print("Inferred from Knxfile version: {d}\n", .{version});
    }
    std.debug.print("Verify mode: {s}\n", .{@tagName(summary.validation.verify_mode)});
    std.debug.print("Knx digest: {s}\n", .{summary.knx_digest_hex[0..]});
    std.debug.print("Operators ({d}):\n", .{summary.build_spec.ops.len});
    for (summary.build_spec.ops, 0..) |op, idx| {
        switch (op) {
            .fs_copy => |copy| {
                std.debug.print(" {d}. knx.fs.copy {s} -> {s}\n", .{ idx + 1, copy.from_path, copy.to_path });
            },
            .c_compile => |compile| {
                std.debug.print(" {d}. knx.c.compile {s} -> {s} (flags:{d})\n", .{ idx + 1, compile.src_path, compile.out_path, compile.args.len });
            },
            .zig_link => |link| {
                std.debug.print(" {d}. knx.zig.link objs:{d} -> {s} (flags:{d})\n", .{ idx + 1, link.object_paths.len, link.out_path, link.args.len });
            },
            .archive_pack => |pack| {
                std.debug.print(" {d}. knx.archive.pack inputs:{d} -> {s} ({s})\n", .{ idx + 1, pack.input_paths.len, pack.out_path, @tagName(pack.format) });
            },
        }
    }
    std.debug.print("Publish outputs ({d}):\n", .{summary.output_spec.entries.len});
    for (summary.output_spec.entries) |entry| {
        const source = entry.source_path orelse entry.path;
        const publish_as = entry.publish_as orelse entry.path;
        std.debug.print(" - {s} => {s} (mode {o})\n", .{ source, publish_as, entry.mode });
    }
}

pub fn printPlanJson(allocator: std.mem.Allocator, summary: *const types.KnxSummary) !void {
    try printPlanJsonWithInfo(allocator, summary, null);
}

pub fn printPlanJsonWithInfo(allocator: std.mem.Allocator, summary: *const types.KnxSummary, inferred_from_version: ?i64) !void {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    var out_writer = out.writer(allocator);
    var out_buffer: [8 * 1024]u8 = undefined;
    var out_adapter = out_writer.adaptToNewApi(&out_buffer);
    const writer = &out_adapter.new_interface;

    try writer.writeAll("{\"status\":\"ok\",\"command\":\"plan\",\"verify_mode\":");
    try std.json.Stringify.encodeJsonString(@tagName(summary.validation.verify_mode), .{}, writer);
    try writer.writeAll(",\"inferred_from_version\":");
    if (inferred_from_version) |version| {
        try writer.print("{d}", .{version});
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll(",\"knx_digest\":");
    try std.json.Stringify.encodeJsonString(summary.knx_digest_hex[0..], .{}, writer);
    try writer.writeAll(",\"operators\":[");
    for (summary.build_spec.ops, 0..) |op, idx| {
        if (idx != 0) try writer.writeAll(",");
        switch (op) {
            .fs_copy => |copy| {
                try writer.writeAll("{\"run\":\"knx.fs.copy\",\"inputs\":[");
                try std.json.Stringify.encodeJsonString(copy.from_path, .{}, writer);
                try writer.writeAll("],\"outputs\":[");
                try std.json.Stringify.encodeJsonString(copy.to_path, .{}, writer);
                try writer.writeAll("]}");
            },
            .c_compile => |compile| {
                try writer.writeAll("{\"run\":\"knx.c.compile\",\"inputs\":[");
                try std.json.Stringify.encodeJsonString(compile.src_path, .{}, writer);
                try writer.writeAll("],\"outputs\":[");
                try std.json.Stringify.encodeJsonString(compile.out_path, .{}, writer);
                try writer.writeAll("],\"flags\":[");
                for (compile.args, 0..) |arg, i| {
                    if (i != 0) try writer.writeAll(",");
                    try std.json.Stringify.encodeJsonString(arg, .{}, writer);
                }
                try writer.writeAll("]}");
            },
            .zig_link => |link| {
                try writer.writeAll("{\"run\":\"knx.zig.link\",\"inputs\":[");
                for (link.object_paths, 0..) |obj, i| {
                    if (i != 0) try writer.writeAll(",");
                    try std.json.Stringify.encodeJsonString(obj, .{}, writer);
                }
                try writer.writeAll("],\"outputs\":[");
                try std.json.Stringify.encodeJsonString(link.out_path, .{}, writer);
                try writer.writeAll("],\"flags\":[");
                for (link.args, 0..) |arg, i| {
                    if (i != 0) try writer.writeAll(",");
                    try std.json.Stringify.encodeJsonString(arg, .{}, writer);
                }
                try writer.writeAll("]}");
            },
            .archive_pack => |pack| {
                try writer.writeAll("{\"run\":\"knx.archive.pack\",\"inputs\":[");
                for (pack.input_paths, 0..) |in_path, i| {
                    if (i != 0) try writer.writeAll(",");
                    try std.json.Stringify.encodeJsonString(in_path, .{}, writer);
                }
                try writer.writeAll("],\"outputs\":[");
                try std.json.Stringify.encodeJsonString(pack.out_path, .{}, writer);
                try writer.writeAll("],\"format\":");
                try std.json.Stringify.encodeJsonString(@tagName(pack.format), .{}, writer);
                try writer.writeAll("}");
            },
        }
    }
    try writer.writeAll("],\"outputs\":[");
    for (summary.output_spec.entries, 0..) |entry, idx| {
        if (idx != 0) try writer.writeAll(",");
        const source = entry.source_path orelse entry.path;
        const publish_as = entry.publish_as orelse entry.path;
        try writer.writeAll("{\"source\":");
        try std.json.Stringify.encodeJsonString(source, .{}, writer);
        try writer.writeAll(",\"publish_as\":");
        try std.json.Stringify.encodeJsonString(publish_as, .{}, writer);
        try writer.writeAll(",\"mode\":");
        try writer.print("{d}", .{entry.mode});
        try writer.writeAll("}");
    }
    try writer.writeAll("]}\n");
    try writer.flush();
    std.debug.print("{s}", .{out.items});
}
