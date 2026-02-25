const std = @import("std");
const validator = @import("../../knx/validator.zig");
const summary_mod = @import("../summary.zig");
const types = @import("../types.zig");

pub fn printValidateHuman(summary: *const types.KnxSummary) void {
    std.debug.print("Validation passed\n", .{});
    std.debug.print("Verify mode: {s}\n", .{@tagName(summary.validation.verify_mode)});
    std.debug.print("Knx digest: {s}\n", .{summary.knx_digest_hex[0..]});
    std.debug.print("Toolchain id: {s}\n", .{summary.toolchain_spec.id});
    std.debug.print(
        "Workspace entries/local/remote/mounts: {d}/{d}/{d}/{d}\n",
        .{
            summary.workspace_spec.entries.len,
            summary_mod.countOptionalSlice(validator.LocalInputSpec, summary.workspace_spec.local_inputs),
            summary_mod.countOptionalSlice(validator.RemoteInputSpec, summary.workspace_spec.remote_inputs),
            summary_mod.countOptionalSlice(validator.WorkspaceMountSpec, summary.workspace_spec.mounts),
        },
    );
    std.debug.print("Operators: {d}\n", .{summary.build_spec.ops.len});
    std.debug.print("Outputs: {d}\n", .{summary.output_spec.entries.len});
}

pub fn printValidateJson(allocator: std.mem.Allocator, summary: *const types.KnxSummary) !void {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    var out_writer = out.writer(allocator);
    var out_buffer: [2048]u8 = undefined;
    var out_adapter = out_writer.adaptToNewApi(&out_buffer);
    const writer = &out_adapter.new_interface;

    try writer.writeAll("{\"status\":\"ok\",\"command\":\"validate\",\"verify_mode\":");
    try std.json.Stringify.encodeJsonString(@tagName(summary.validation.verify_mode), .{}, writer);
    try writer.writeAll(",\"knx_digest\":");
    try std.json.Stringify.encodeJsonString(summary.knx_digest_hex[0..], .{}, writer);
    try writer.writeAll(",\"toolchain_id\":");
    try std.json.Stringify.encodeJsonString(summary.toolchain_spec.id, .{}, writer);
    try writer.writeAll(",\"stats\":{\"workspace_entries\":");
    try writer.print("{d}", .{summary.workspace_spec.entries.len});
    try writer.writeAll(",\"local_inputs\":");
    try writer.print("{d}", .{summary_mod.countOptionalSlice(validator.LocalInputSpec, summary.workspace_spec.local_inputs)});
    try writer.writeAll(",\"remote_inputs\":");
    try writer.print("{d}", .{summary_mod.countOptionalSlice(validator.RemoteInputSpec, summary.workspace_spec.remote_inputs)});
    try writer.writeAll(",\"mounts\":");
    try writer.print("{d}", .{summary_mod.countOptionalSlice(validator.WorkspaceMountSpec, summary.workspace_spec.mounts)});
    try writer.writeAll(",\"operators\":");
    try writer.print("{d}", .{summary.build_spec.ops.len});
    try writer.writeAll(",\"outputs\":");
    try writer.print("{d}", .{summary.output_spec.entries.len});
    try writer.writeAll("}}\n");
    try writer.flush();
    std.debug.print("{s}", .{out.items});
}
