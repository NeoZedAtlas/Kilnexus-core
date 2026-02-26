const std = @import("std");
const cli_args = @import("../args.zig");
const cli_output = @import("../output.zig");
const cli_summary = @import("../summary.zig");
const cli_types = @import("../types.zig");
const validator = @import("../../knx/validator.zig");

const GraphEdge = struct {
    from_idx: usize,
    to_idx: usize,
    via_path: []const u8,
};

pub fn run(allocator: std.mem.Allocator, args: []const []const u8) !void {
    const cli = cli_args.parseParseOnlyCliArgs(args) catch |err| {
        if (err == error.HelpRequested) {
            cli_output.printUsage();
            return;
        }
        cli_output.printUsage();
        return error.InvalidCommand;
    };

    var summary = cli_summary.loadKnxSummary(allocator, cli.path) catch |err| {
        if (cli.json_output) {
            try cli_output.printSimpleFailureJson(allocator, "graph", err);
        } else {
            cli_output.printSimpleFailureHuman("graph", err);
        }
        return error.InvalidCommand;
    };
    defer summary.deinit(allocator);

    var edges = try buildEdges(allocator, summary.build_spec.ops);
    defer edges.deinit(allocator);

    if (cli.json_output) {
        try printGraphJson(allocator, &summary, edges.items);
    } else {
        printGraphHuman(&summary, edges.items);
    }
}

fn buildEdges(allocator: std.mem.Allocator, ops: []const validator.BuildOp) !std.ArrayList(GraphEdge) {
    var producers: std.StringHashMap(usize) = .init(allocator);
    defer producers.deinit();

    for (ops, 0..) |op, idx| {
        const out_path = outputPath(op);
        const gop = try producers.getOrPut(out_path);
        if (!gop.found_existing) gop.value_ptr.* = idx;
    }

    var edges: std.ArrayList(GraphEdge) = .empty;
    for (ops, 0..) |op, idx| {
        switch (op) {
            .fs_copy => |copy| {
                if (producers.get(copy.from_path)) |producer| {
                    try edges.append(allocator, .{
                        .from_idx = producer,
                        .to_idx = idx,
                        .via_path = copy.from_path,
                    });
                }
            },
            .c_compile => |compile| {
                if (producers.get(compile.src_path)) |producer| {
                    try edges.append(allocator, .{
                        .from_idx = producer,
                        .to_idx = idx,
                        .via_path = compile.src_path,
                    });
                }
            },
            .zig_link => |link| {
                for (link.object_paths) |object_path| {
                    if (producers.get(object_path)) |producer| {
                        try edges.append(allocator, .{
                            .from_idx = producer,
                            .to_idx = idx,
                            .via_path = object_path,
                        });
                    }
                }
            },
            .archive_pack => |pack| {
                for (pack.input_paths) |input_path| {
                    if (producers.get(input_path)) |producer| {
                        try edges.append(allocator, .{
                            .from_idx = producer,
                            .to_idx = idx,
                            .via_path = input_path,
                        });
                    }
                }
            },
        }
    }

    return edges;
}

fn outputPath(op: validator.BuildOp) []const u8 {
    return switch (op) {
        .fs_copy => |copy| copy.to_path,
        .c_compile => |compile| compile.out_path,
        .zig_link => |link| link.out_path,
        .archive_pack => |pack| pack.out_path,
    };
}

fn opRunName(op: validator.BuildOp) []const u8 {
    return switch (op) {
        .fs_copy => "knx.fs.copy",
        .c_compile => "knx.c.compile",
        .zig_link => "knx.zig.link",
        .archive_pack => "knx.archive.pack",
    };
}

fn printGraphHuman(summary: *const cli_types.KnxSummary, edges: []const GraphEdge) void {
    std.debug.print("Graph generated\n", .{});
    std.debug.print("Operators: {d}\n", .{summary.build_spec.ops.len});
    for (summary.build_spec.ops, 0..) |op, idx| {
        switch (op) {
            .fs_copy => |copy| {
                std.debug.print(" {d}. {s} [{s}] -> [{s}]\n", .{ idx + 1, opRunName(op), copy.from_path, copy.to_path });
            },
            .c_compile => |compile| {
                std.debug.print(" {d}. {s} [{s}] -> [{s}]\n", .{ idx + 1, opRunName(op), compile.src_path, compile.out_path });
            },
            .zig_link => |link| {
                std.debug.print(" {d}. {s} in:{d} -> [{s}]\n", .{ idx + 1, opRunName(op), link.object_paths.len, link.out_path });
            },
            .archive_pack => |pack| {
                std.debug.print(" {d}. {s} in:{d} -> [{s}]\n", .{ idx + 1, opRunName(op), pack.input_paths.len, pack.out_path });
            },
        }
    }
    std.debug.print("Edges: {d}\n", .{edges.len});
    for (edges) |edge| {
        std.debug.print(" {d} -> {d} via {s}\n", .{ edge.from_idx + 1, edge.to_idx + 1, edge.via_path });
    }
}

fn printGraphJson(allocator: std.mem.Allocator, summary: *const cli_types.KnxSummary, edges: []const GraphEdge) !void {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);

    var out_writer = out.writer(allocator);
    var out_buffer: [8192]u8 = undefined;
    var out_adapter = out_writer.adaptToNewApi(&out_buffer);
    const writer = &out_adapter.new_interface;

    try writer.writeAll("{\"status\":\"ok\",\"command\":\"graph\",\"operators\":[");
    for (summary.build_spec.ops, 0..) |op, idx| {
        if (idx != 0) try writer.writeAll(",");
        try writer.writeAll("{\"idx\":");
        try writer.print("{}", .{idx});
        try writer.writeAll(",\"run\":");
        try std.json.Stringify.encodeJsonString(opRunName(op), .{}, writer);
        try writer.writeAll(",\"inputs\":[");
        switch (op) {
            .fs_copy => |copy| {
                try std.json.Stringify.encodeJsonString(copy.from_path, .{}, writer);
            },
            .c_compile => |compile| {
                try std.json.Stringify.encodeJsonString(compile.src_path, .{}, writer);
            },
            .zig_link => |link| {
                for (link.object_paths, 0..) |path, i| {
                    if (i != 0) try writer.writeAll(",");
                    try std.json.Stringify.encodeJsonString(path, .{}, writer);
                }
            },
            .archive_pack => |pack| {
                for (pack.input_paths, 0..) |path, i| {
                    if (i != 0) try writer.writeAll(",");
                    try std.json.Stringify.encodeJsonString(path, .{}, writer);
                }
            },
        }
        try writer.writeAll("],\"outputs\":[");
        try std.json.Stringify.encodeJsonString(outputPath(op), .{}, writer);
        try writer.writeAll("]}");
    }
    try writer.writeAll("],\"edges\":[");
    for (edges, 0..) |edge, idx| {
        if (idx != 0) try writer.writeAll(",");
        try writer.writeAll("{\"from\":");
        try writer.print("{}", .{edge.from_idx});
        try writer.writeAll(",\"to\":");
        try writer.print("{}", .{edge.to_idx});
        try writer.writeAll(",\"via\":");
        try std.json.Stringify.encodeJsonString(edge.via_path, .{}, writer);
        try writer.writeAll("}");
    }
    try writer.writeAll("]}\n");
    try writer.flush();
    std.debug.print("{s}", .{out.items});
}
