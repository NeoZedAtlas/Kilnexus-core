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

const BootstrapCliArgs = struct {
    path: []const u8 = "Knxfile",
    trust_dir: ?[]const u8 = "trust",
    trust_state_path: ?[]const u8 = ".kilnexus-trust-state.json",
    cache_root: []const u8 = ".kilnexus-cache",
    output_root: []const u8 = "kilnexus-out",
    json_output: bool = false,
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
        printUsage();
        return error.InvalidCommand;
    }

    var cli_tokens: std.ArrayList([]const u8) = .empty;
    defer cli_tokens.deinit(allocator);
    while (args.next()) |arg| {
        try cli_tokens.append(allocator, arg);
    }
    const cli = parseBootstrapCliArgs(cli_tokens.items) catch |err| {
        if (err == error.HelpRequested) {
            printUsage();
            return;
        }
        printUsage();
        return error.InvalidCommand;
    };

    var attempt = bootstrap.attemptRunFromPathWithOptions(allocator, cli.path, .{
        .trust_metadata_dir = cli.trust_dir,
        .trust_state_path = if (cli.trust_dir == null) null else cli.trust_state_path,
        .cache_root = cli.cache_root,
        .output_root = cli.output_root,
    });

    switch (attempt) {
        .success => |*run_result| {
            defer run_result.deinit(allocator);
            if (cli.json_output) {
                try printSuccessJson(allocator, run_result, &cli);
            } else {
                printSuccessHuman(allocator, run_result, &cli);
            }
        },
        .failure => |failure| {
            if (cli.json_output) {
                try printFailureJson(allocator, failure);
            } else {
                printFailureHuman(failure);
            }
            return error.BootstrapFailed;
        },
    }
}

fn printUsage() void {
    std.debug.print(
        "Usage: Kilnexus_core bootstrap [Knxfile] [trust-dir] [cache-root] [output-root] [options]\n",
        .{},
    );
    std.debug.print(
        "Options: --trust-off --trust-dir <dir> --trust-state <path|off> --cache-root <dir> --output-root <dir> --json --help\n",
        .{},
    );
}

fn parseBootstrapCliArgs(args: []const []const u8) !BootstrapCliArgs {
    var output: BootstrapCliArgs = .{};
    var positional_index: usize = 0;
    var trust_set = false;
    var cache_set = false;
    var output_set = false;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            return error.HelpRequested;
        }

        if (std.mem.startsWith(u8, arg, "--")) {
            if (std.mem.eql(u8, arg, "--json")) {
                output.json_output = true;
                continue;
            }
            if (std.mem.eql(u8, arg, "--trust-off")) {
                output.trust_dir = null;
                output.trust_state_path = null;
                trust_set = true;
                continue;
            }
            if (std.mem.eql(u8, arg, "--trust-dir")) {
                const value = try nextOptionValue(args, &i);
                output.trust_dir = value;
                if (output.trust_state_path == null) {
                    output.trust_state_path = ".kilnexus-trust-state.json";
                }
                trust_set = true;
                continue;
            }
            if (std.mem.eql(u8, arg, "--trust-state")) {
                const value = try nextOptionValue(args, &i);
                if (std.mem.eql(u8, value, "off")) {
                    output.trust_state_path = null;
                } else {
                    output.trust_state_path = value;
                }
                continue;
            }
            if (std.mem.eql(u8, arg, "--cache-root")) {
                output.cache_root = try nextOptionValue(args, &i);
                cache_set = true;
                continue;
            }
            if (std.mem.eql(u8, arg, "--output-root")) {
                output.output_root = try nextOptionValue(args, &i);
                output_set = true;
                continue;
            }
            return error.InvalidCommand;
        }

        switch (positional_index) {
            0 => output.path = arg,
            1 => {
                if (trust_set) return error.InvalidCommand;
                output.trust_dir = arg;
                trust_set = true;
            },
            2 => {
                if (cache_set) return error.InvalidCommand;
                output.cache_root = arg;
                cache_set = true;
            },
            3 => {
                if (output_set) return error.InvalidCommand;
                output.output_root = arg;
                output_set = true;
            },
            else => return error.InvalidCommand,
        }
        positional_index += 1;
    }

    return output;
}

fn nextOptionValue(args: []const []const u8, index: *usize) ![]const u8 {
    index.* += 1;
    if (index.* >= args.len) return error.InvalidCommand;
    const value = args[index.*];
    if (std.mem.startsWith(u8, value, "--")) return error.InvalidCommand;
    return value;
}

fn printSuccessHuman(allocator: std.mem.Allocator, run_result: *const bootstrap.RunResult, cli: *const BootstrapCliArgs) void {
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
    printCurrentPointerSummary(allocator, cli.output_root) catch |err| {
        std.debug.print("Current pointer read failed: {s}\n", .{@errorName(err)});
    };

    for (run_result.trace.items) |state| {
        std.debug.print(" - {s}\n", .{@tagName(state)});
    }
}

fn printFailureHuman(failure: bootstrap.RunFailure) void {
    const descriptor = kx_error.describe(failure.code);
    var error_id_buf: [128]u8 = undefined;
    const error_id = kx_error.buildErrorId(
        &error_id_buf,
        failure.code,
        @tagName(failure.at),
        @errorName(failure.cause),
    );

    std.debug.print("Bootstrap failed\n", .{});
    std.debug.print("Error id: {s}\n", .{error_id});
    std.debug.print("Code: {s} ({d})\n", .{ @tagName(failure.code), @intFromEnum(failure.code) });
    std.debug.print("Family: {s}\n", .{@tagName(descriptor.family)});
    std.debug.print("State: {s}\n", .{@tagName(failure.at)});
    std.debug.print("Cause: {s}\n", .{@errorName(failure.cause)});
    std.debug.print("Summary: {s}\n", .{descriptor.summary});
}

fn printFailureJson(allocator: std.mem.Allocator, failure: bootstrap.RunFailure) !void {
    const output = try buildFailureJsonLine(allocator, failure);
    defer allocator.free(output);
    std.debug.print("{s}", .{output});
}

fn buildFailureJsonLine(allocator: std.mem.Allocator, failure: bootstrap.RunFailure) ![]u8 {
    const descriptor = kx_error.describe(failure.code);
    var error_id_buf: [128]u8 = undefined;
    const error_id = kx_error.buildErrorId(
        &error_id_buf,
        failure.code,
        @tagName(failure.at),
        @errorName(failure.cause),
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
    try std.json.Stringify.encodeJsonString(@errorName(failure.cause), .{}, writer);
    try writer.writeAll(",\"summary\":");
    try std.json.Stringify.encodeJsonString(descriptor.summary, .{}, writer);
    try writer.writeAll("}\n");
    try writer.flush();

    return try output.toOwnedSlice(allocator);
}

fn printSuccessJson(
    allocator: std.mem.Allocator,
    run_result: *const bootstrap.RunResult,
    cli: *const BootstrapCliArgs,
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

    var pointer = readCurrentPointerSummary(allocator, cli.output_root) catch |err| {
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

fn printCurrentPointerSummary(allocator: std.mem.Allocator, output_root: []const u8) !void {
    var summary = try readCurrentPointerSummary(allocator, output_root);
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

fn readCurrentPointerSummary(allocator: std.mem.Allocator, output_root: []const u8) !CurrentPointerSummary {
    const pointer_path = try std.fmt.allocPrint(allocator, "{s}.current", .{output_root});
    defer allocator.free(pointer_path);

    const raw = try std.fs.cwd().readFileAlloc(allocator, pointer_path, 1024 * 1024);
    defer allocator.free(raw);

    return parseCurrentPointerSummary(allocator, raw);
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

test "parseBootstrapCliArgs applies defaults and optional overrides" {
    const defaults = try parseBootstrapCliArgs(&.{});
    try std.testing.expectEqualStrings("Knxfile", defaults.path);
    try std.testing.expect(defaults.trust_dir != null);
    try std.testing.expectEqualStrings("trust", defaults.trust_dir.?);
    try std.testing.expect(defaults.trust_state_path != null);
    try std.testing.expectEqualStrings(".kilnexus-trust-state.json", defaults.trust_state_path.?);
    try std.testing.expectEqualStrings(".kilnexus-cache", defaults.cache_root);
    try std.testing.expectEqualStrings("kilnexus-out", defaults.output_root);
    try std.testing.expect(!defaults.json_output);

    const custom = try parseBootstrapCliArgs(&.{
        "Custom.knx",
        "custom-trust",
        "cache-dir",
        "out-dir",
    });
    try std.testing.expectEqualStrings("Custom.knx", custom.path);
    try std.testing.expect(custom.trust_dir != null);
    try std.testing.expectEqualStrings("custom-trust", custom.trust_dir.?);
    try std.testing.expectEqualStrings("cache-dir", custom.cache_root);
    try std.testing.expectEqualStrings("out-dir", custom.output_root);
}

test "parseBootstrapCliArgs rejects too many positional arguments" {
    try std.testing.expectError(
        error.InvalidCommand,
        parseBootstrapCliArgs(&.{ "a", "b", "c", "d", "e" }),
    );
}

test "parseBootstrapCliArgs parses named options" {
    const parsed = try parseBootstrapCliArgs(&.{
        "Knxfile.prod",
        "--trust-dir",
        "trust-prod",
        "--trust-state",
        "trust-state-prod.json",
        "--cache-root",
        ".cache-prod",
        "--output-root",
        "out-prod",
        "--json",
    });
    try std.testing.expectEqualStrings("Knxfile.prod", parsed.path);
    try std.testing.expect(parsed.trust_dir != null);
    try std.testing.expectEqualStrings("trust-prod", parsed.trust_dir.?);
    try std.testing.expect(parsed.trust_state_path != null);
    try std.testing.expectEqualStrings("trust-state-prod.json", parsed.trust_state_path.?);
    try std.testing.expectEqualStrings(".cache-prod", parsed.cache_root);
    try std.testing.expectEqualStrings("out-prod", parsed.output_root);
    try std.testing.expect(parsed.json_output);
}

test "parseBootstrapCliArgs parses trust off and disabled trust state" {
    const parsed = try parseBootstrapCliArgs(&.{
        "--trust-off",
        "--trust-state",
        "off",
    });
    try std.testing.expect(parsed.trust_dir == null);
    try std.testing.expect(parsed.trust_state_path == null);
}

test "parseBootstrapCliArgs rejects conflict between trust option and trust positional" {
    try std.testing.expectError(
        error.InvalidCommand,
        parseBootstrapCliArgs(&.{ "Knxfile", "--trust-off", "trust-positional" }),
    );
}

test "parseBootstrapCliArgs returns help requested" {
    try std.testing.expectError(error.HelpRequested, parseBootstrapCliArgs(&.{"--help"}));
}

test "buildFailureJsonLine renders stable failure payload" {
    const allocator = std.testing.allocator;
    const failure: bootstrap.RunFailure = .{
        .at = .init,
        .code = .KX_IO_NOT_FOUND,
        .cause = error.IoNotFound,
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
