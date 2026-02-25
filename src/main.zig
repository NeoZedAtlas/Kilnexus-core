const std = @import("std");
const bootstrap = @import("bootstrap/state_machine.zig");
const kx_error = @import("errors/kx_error.zig");

const CurrentPointerSummary = struct {
    build_id: []u8,
    release_rel: []u8,
    verify_mode: ?[]u8,
    toolchain_tree_root: ?[]u8,

    fn deinit(self: *CurrentPointerSummary, allocator: std.mem.Allocator) void {
        allocator.free(self.build_id);
        allocator.free(self.release_rel);
        if (self.verify_mode) |verify_mode| allocator.free(verify_mode);
        if (self.toolchain_tree_root) |tree_root| allocator.free(tree_root);
        self.* = undefined;
    }
};

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
            printCurrentPointerSummary(allocator, "kilnexus-out") catch |err| {
                std.debug.print("Current pointer read failed: {s}\n", .{@errorName(err)});
            };

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

fn printCurrentPointerSummary(allocator: std.mem.Allocator, output_root: []const u8) !void {
    const pointer_path = try std.fmt.allocPrint(allocator, "{s}.current", .{output_root});
    defer allocator.free(pointer_path);

    const raw = try std.fs.cwd().readFileAlloc(allocator, pointer_path, 1024 * 1024);
    defer allocator.free(raw);

    var summary = try parseCurrentPointerSummary(allocator, raw);
    defer summary.deinit(allocator);
    const release_abs = try std.fs.path.join(allocator, &.{ output_root, summary.release_rel });
    defer allocator.free(release_abs);

    std.debug.print("Published build id: {s}\n", .{summary.build_id});
    std.debug.print("Published release path: {s}\n", .{release_abs});
    if (summary.verify_mode) |verify_mode| {
        std.debug.print("Published verify mode: {s}\n", .{verify_mode});
    }
    if (summary.toolchain_tree_root) |tree_root| {
        std.debug.print("Published toolchain tree root: {s}\n", .{tree_root});
    }
}

fn parseCurrentPointerSummary(allocator: std.mem.Allocator, raw: []const u8) !CurrentPointerSummary {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, raw, .{});
    defer parsed.deinit();

    const root = switch (parsed.value) {
        .object => |obj| obj,
        else => return error.InvalidCurrentPointer,
    };
    const build_id = try requireStringField(root, "build_id");
    const release_rel = try requireStringField(root, "release_rel");
    const verify_mode = optionalStringField(root, "verify_mode");
    const toolchain_tree_root = optionalStringField(root, "toolchain_tree_root");

    const out_build_id = try allocator.dupe(u8, build_id);
    errdefer allocator.free(out_build_id);
    const out_release_rel = try allocator.dupe(u8, release_rel);
    errdefer allocator.free(out_release_rel);
    const out_verify_mode = if (verify_mode) |value| try allocator.dupe(u8, value) else null;
    errdefer if (out_verify_mode) |value| allocator.free(value);
    const out_tree_root = if (toolchain_tree_root) |value| try allocator.dupe(u8, value) else null;
    errdefer if (out_tree_root) |value| allocator.free(value);

    return .{
        .build_id = out_build_id,
        .release_rel = out_release_rel,
        .verify_mode = out_verify_mode,
        .toolchain_tree_root = out_tree_root,
    };
}

fn requireStringField(object: std.json.ObjectMap, key: []const u8) ![]const u8 {
    const value = object.get(key) orelse return error.InvalidCurrentPointer;
    return switch (value) {
        .string => |text| text,
        else => error.InvalidCurrentPointer,
    };
}

fn optionalStringField(object: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const value = object.get(key) orelse return null;
    return switch (value) {
        .string => |text| text,
        else => null,
    };
}

test "parseCurrentPointerSummary parses required and optional fields" {
    const allocator = std.testing.allocator;
    const raw =
        \\{
        \\  "version": 2,
        \\  "build_id": "build-42",
        \\  "release_rel": "releases/build-42",
        \\  "verify_mode": "strict",
        \\  "toolchain_tree_root": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        \\}
    ;
    var summary = try parseCurrentPointerSummary(allocator, raw);
    defer summary.deinit(allocator);
    try std.testing.expectEqualStrings("build-42", summary.build_id);
    try std.testing.expectEqualStrings("releases/build-42", summary.release_rel);
    try std.testing.expect(summary.verify_mode != null);
    try std.testing.expect(summary.toolchain_tree_root != null);
    try std.testing.expectEqualStrings("strict", summary.verify_mode.?);
}

test "parseCurrentPointerSummary rejects missing required fields" {
    const allocator = std.testing.allocator;
    const raw =
        \\{
        \\  "version": 2,
        \\  "release_rel": "releases/build-42"
        \\}
    ;
    try std.testing.expectError(error.InvalidCurrentPointer, parseCurrentPointerSummary(allocator, raw));
}
