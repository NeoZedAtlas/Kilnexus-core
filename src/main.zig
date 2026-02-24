const std = @import("std");
const bootstrap = @import("bootstrap/state_machine.zig");
const kx_error = @import("errors/kx_error.zig");

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
        std.debug.print("Usage: Kilnexus_core bootstrap [Knxfile] [trust-dir]\n", .{});
        return error.InvalidCommand;
    }

    const path = args.next() orelse "Knxfile";
    const trust_dir = args.next() orelse "trust";

    var attempt = bootstrap.attemptRunFromPathWithOptions(allocator, path, .{
        .trust_metadata_dir = trust_dir,
        .trust_state_path = ".kilnexus-trust-state.json",
    });

    switch (attempt) {
        .success => |*run_result| {
            defer run_result.deinit(allocator);
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

            for (run_result.trace.items) |state| {
                std.debug.print(" - {s}\n", .{@tagName(state)});
            }
        },
        .failure => |failure| {
            const descriptor = kx_error.describe(failure.code);
            var error_id_buf: [128]u8 = undefined;
            const error_id = kx_error.buildErrorId(
                &error_id_buf,
                failure.code,
                @tagName(failure.at),
                @errorName(failure.cause),
            );
            std.debug.print(
                "{{\"status\":\"failed\",\"error_id\":\"{s}\",\"code\":\"{s}\",\"code_num\":{d},\"family\":\"{s}\",\"state\":\"{s}\",\"cause\":\"{s}\",\"summary\":\"{s}\"}}\n",
                .{
                    error_id,
                    @tagName(failure.code),
                    @intFromEnum(failure.code),
                    @tagName(descriptor.family),
                    @tagName(failure.at),
                    @errorName(failure.cause),
                    descriptor.summary,
                },
            );
            return error.BootstrapFailed;
        },
    }
}
