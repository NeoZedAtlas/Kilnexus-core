const std = @import("std");
const bootstrap = @import("bootstrap/state_machine.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();

    _ = args.next();
    const command = args.next() orelse "bootstrap";

    if (!std.mem.eql(u8, command, "bootstrap")) {
        std.debug.print("Unknown command: {s}\n", .{command});
        std.debug.print("Usage: Kilnexus_core bootstrap [Knxfile]\n", .{});
        return error.InvalidCommand;
    }

    const path = args.next() orelse "Knxfile";

    var run_result = try bootstrap.runFromPath(allocator, path);
    defer run_result.deinit(allocator);

    std.debug.print("Bootstrap completed with state: {s}\n", .{@tagName(run_result.final_state)});
    std.debug.print("Verify mode: {s}\n", .{@tagName(run_result.verify_mode)});
    std.debug.print("Knx digest: {s}\n", .{run_result.knx_digest_hex[0..]});
    std.debug.print("Canonical lockfile bytes: {d}\n", .{run_result.canonical_json.len});

    for (run_result.trace.items) |state| {
        std.debug.print(" - {s}\n", .{@tagName(state)});
    }
}
