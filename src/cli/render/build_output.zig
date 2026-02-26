const std = @import("std");
const bootstrap = @import("../../bootstrap/state_machine.zig");
const kx_error = @import("../../errors/kx_error.zig");
const current_pointer = @import("current_pointer.zig");
const types = @import("../types.zig");

pub fn printSuccessHuman(allocator: std.mem.Allocator, run_result: *const bootstrap.RunResult, cli: *const types.BootstrapCliArgs) void {
    std.debug.print("Bootstrap completed with state: {s}\n", .{@tagName(run_result.final_state)});
    std.debug.print(
        "Trust versions root/timestamp/snapshot/targets: {d}/{d}/{d}/{d}\n",
        .{
            run_result.trust.root_version,
            run_result.trust.timestamp_version,
            run_result.trust.snapshot_version,
            run_result.trust.targets_version,
        },
    );
    std.debug.print("Verify mode: {s}\n", .{@tagName(run_result.verify_mode)});
    std.debug.print("Knx digest: {s}\n", .{run_result.knx_digest_hex[0..]});
    std.debug.print("Workspace cwd: {s}\n", .{run_result.workspace_cwd});
    std.debug.print("Canonical lockfile bytes: {d}\n", .{run_result.canonical_json.len});
    current_pointer.printCurrentPointerSummary(allocator, cli.output_root) catch |err| {
        std.debug.print("Current pointer read failed: {s}\n", .{@errorName(err)});
    };

    for (run_result.trace.items) |state| {
        std.debug.print(" - {s}\n", .{@tagName(state)});
    }
}

pub fn printFailureHuman(failure: bootstrap.RunFailure) void {
    const descriptor = kx_error.describe(failure.code);
    var error_id_buf: [128]u8 = undefined;
    const error_id = kx_error.buildErrorId(
        &error_id_buf,
        failure.code,
        @tagName(failure.at),
        failure.cause.name(),
    );

    std.debug.print("Bootstrap failed\n", .{});
    std.debug.print("Error id: {s}\n", .{error_id});
    std.debug.print("Code: {s} ({d})\n", .{ @tagName(failure.code), @intFromEnum(failure.code) });
    std.debug.print("Family: {s}\n", .{@tagName(descriptor.family)});
    std.debug.print("State: {s}\n", .{@tagName(failure.at)});
    std.debug.print("Cause: {s}\n", .{failure.cause.name()});
    std.debug.print("Summary: {s}\n", .{descriptor.summary});
}

pub fn printFailureJson(allocator: std.mem.Allocator, failure: bootstrap.RunFailure) !void {
    const output = try buildFailureJsonLine(allocator, failure);
    defer allocator.free(output);
    std.debug.print("{s}", .{output});
}

pub fn buildFailureJsonLine(allocator: std.mem.Allocator, failure: bootstrap.RunFailure) ![]u8 {
    const descriptor = kx_error.describe(failure.code);
    var error_id_buf: [128]u8 = undefined;
    const error_id = kx_error.buildErrorId(
        &error_id_buf,
        failure.code,
        @tagName(failure.at),
        failure.cause.name(),
    );

    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(allocator);
    var output_writer = output.writer(allocator);
    var output_buffer: [1024]u8 = undefined;
    var output_adapter = output_writer.adaptToNewApi(&output_buffer);
    const writer = &output_adapter.new_interface;

    try writer.writeAll("{\"status\":\"failed\",\"error_id\":");
    try std.json.Stringify.encodeJsonString(error_id, .{}, writer);
    try writer.writeAll(",\"code\":");
    try std.json.Stringify.encodeJsonString(@tagName(failure.code), .{}, writer);
    try writer.writeAll(",\"code_num\":");
    try writer.print("{d}", .{@intFromEnum(failure.code)});
    try writer.writeAll(",\"family\":");
    try std.json.Stringify.encodeJsonString(@tagName(descriptor.family), .{}, writer);
    try writer.writeAll(",\"state\":");
    try std.json.Stringify.encodeJsonString(@tagName(failure.at), .{}, writer);
    try writer.writeAll(",\"cause\":");
    try std.json.Stringify.encodeJsonString(failure.cause.name(), .{}, writer);
    try writer.writeAll(",\"summary\":");
    try std.json.Stringify.encodeJsonString(descriptor.summary, .{}, writer);
    try writer.writeAll("}\n");
    try writer.flush();

    return try output.toOwnedSlice(allocator);
}

pub fn printSuccessJson(
    allocator: std.mem.Allocator,
    run_result: *const bootstrap.RunResult,
    cli: *const types.BootstrapCliArgs,
) !void {
    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(allocator);
    var output_writer = output.writer(allocator);
    var output_buffer: [4096]u8 = undefined;
    var output_adapter = output_writer.adaptToNewApi(&output_buffer);
    const writer = &output_adapter.new_interface;

    try writer.writeAll("{\"status\":\"ok\",\"state\":");
    try std.json.Stringify.encodeJsonString(@tagName(run_result.final_state), .{}, writer);
    try writer.writeAll(",\"verify_mode\":");
    try std.json.Stringify.encodeJsonString(@tagName(run_result.verify_mode), .{}, writer);
    try writer.writeAll(",\"knx_digest\":");
    try std.json.Stringify.encodeJsonString(run_result.knx_digest_hex[0..], .{}, writer);
    try writer.writeAll(",\"workspace_cwd\":");
    try std.json.Stringify.encodeJsonString(run_result.workspace_cwd, .{}, writer);
    try writer.writeAll(",\"canonical_json_bytes\":");
    try writer.print("{d}", .{run_result.canonical_json.len});
    try writer.writeAll(",\"trust\":{\"root\":");
    try writer.print("{d}", .{run_result.trust.root_version});
    try writer.writeAll(",\"timestamp\":");
    try writer.print("{d}", .{run_result.trust.timestamp_version});
    try writer.writeAll(",\"snapshot\":");
    try writer.print("{d}", .{run_result.trust.snapshot_version});
    try writer.writeAll(",\"targets\":");
    try writer.print("{d}", .{run_result.trust.targets_version});
    try writer.writeAll("}");

    var pointer = current_pointer.readCurrentPointerSummary(allocator, cli.output_root) catch |err| {
        try writer.writeAll(",\"published_error\":");
        try std.json.Stringify.encodeJsonString(@errorName(err), .{}, writer);
        try writeTraceJson(writer, run_result);
        try writer.writeAll("}\n");
        try writer.flush();
        std.debug.print("{s}", .{output.items});
        return;
    };
    defer pointer.deinit(allocator);

    const release_abs = try std.fs.path.join(allocator, &.{ cli.output_root, pointer.release_rel });
    defer allocator.free(release_abs);
    try writer.writeAll(",\"published\":{\"build_id\":");
    try std.json.Stringify.encodeJsonString(pointer.build_id, .{}, writer);
    try writer.writeAll(",\"release_rel\":");
    try std.json.Stringify.encodeJsonString(pointer.release_rel, .{}, writer);
    try writer.writeAll(",\"release_path\":");
    try std.json.Stringify.encodeJsonString(release_abs, .{}, writer);
    if (pointer.verify_mode) |mode| {
        try writer.writeAll(",\"verify_mode\":");
        try std.json.Stringify.encodeJsonString(mode, .{}, writer);
    }
    if (pointer.toolchain_tree_root) |tree_root| {
        try writer.writeAll(",\"toolchain_tree_root\":");
        try std.json.Stringify.encodeJsonString(tree_root, .{}, writer);
    }
    try writer.writeAll("}");

    try writeTraceJson(writer, run_result);
    try writer.writeAll("}\n");
    try writer.flush();
    std.debug.print("{s}", .{output.items});
}

fn writeTraceJson(writer: *std.Io.Writer, run_result: *const bootstrap.RunResult) !void {
    try writer.writeAll(",\"trace\":[");
    for (run_result.trace.items, 0..) |state, idx| {
        if (idx != 0) try writer.writeAll(",");
        try std.json.Stringify.encodeJsonString(@tagName(state), .{}, writer);
    }
    try writer.writeAll("]");
}

test "buildFailureJsonLine renders stable failure payload" {
    const allocator = std.testing.allocator;
    const failure: bootstrap.RunFailure = .{
        .at = .init,
        .code = .KX_IO_NOT_FOUND,
        .cause = .{ .io = error.Unavailable },
    };

    const line = try buildFailureJsonLine(allocator, failure);
    defer allocator.free(line);
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, line, .{});
    defer parsed.deinit();
    const root = switch (parsed.value) {
        .object => |obj| obj,
        else => return error.TestUnexpectedResult,
    };

    const status = switch (root.get("status") orelse return error.TestUnexpectedResult) {
        .string => |text| text,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expectEqualStrings("failed", status);

    const code = switch (root.get("code") orelse return error.TestUnexpectedResult) {
        .string => |text| text,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expectEqualStrings("KX_IO_NOT_FOUND", code);

    const state = switch (root.get("state") orelse return error.TestUnexpectedResult) {
        .string => |text| text,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expectEqualStrings("init", state);
}
