const std = @import("std");
const cli_args = @import("../args.zig");
const cli_output = @import("../output.zig");
const cli_types = @import("../types.zig");
const parse_errors = @import("../../parser/parse_errors.zig");
const abi_parser = @import("../../parser/abi_parser.zig");
const validator = @import("../../knx/validator.zig");
const v2_infer = @import("../runtime/v2_lock_infer.zig");

pub fn run(allocator: std.mem.Allocator, args: []const []const u8) !void {
    const cli = cli_args.parseFreezeCliArgs(args) catch |err| {
        if (err == error.HelpRequested) {
            cli_output.printUsage();
            return;
        }
        cli_output.printUsage();
        return error.InvalidCommand;
    };

    runWithCli(allocator, cli) catch |err| {
        if (cli.json_output) {
            try cli_output.printSimpleFailureJson(allocator, "freeze", @errorName(err));
        } else {
            cli_output.printSimpleFailureHuman("freeze", @errorName(err));
        }
        return err;
    };
}

fn runWithCli(allocator: std.mem.Allocator, cli: @import("../types.zig").FreezeCliArgs) !void {
    const lock_path = if (cli.lock_path) |explicit| explicit else try deriveLockPath(allocator, cli.path);
    defer if (cli.lock_path == null) allocator.free(lock_path);

    const source = try std.fs.cwd().readFileAlloc(allocator, cli.path, cli_types.max_knxfile_bytes);
    defer allocator.free(source);

    const parsed_intent = try abi_parser.parseLockfileStrict(allocator, source);
    defer allocator.free(parsed_intent.canonical_json);
    const intent_version = try parseVersion(parsed_intent.canonical_json);

    const lock_canonical = try switch (intent_version) {
        1 => allocator.dupe(u8, parsed_intent.canonical_json),
        2 => v2_infer.inferLockCanonicalJsonFromV2Canonical(allocator, parsed_intent.canonical_json),
        else => error.VersionUnsupported,
    };
    defer allocator.free(lock_canonical);

    try validateLockCanonical(allocator, lock_canonical);
    const knx_digest_hex = validator.computeKnxDigestHex(lock_canonical);

    try writeFileAtomic(allocator, lock_path, lock_canonical);
    if (cli.json_output) {
        try printFreezeJson(allocator, cli.path, lock_path, knx_digest_hex[0..], lock_canonical.len);
    } else {
        printFreezeHuman(cli.path, lock_path, knx_digest_hex[0..], lock_canonical.len);
    }
}

fn parseVersion(canonical_json: []const u8) parse_errors.ParseError!i64 {
    const parsed = std.json.parseFromSlice(std.json.Value, std.heap.page_allocator, canonical_json, .{}) catch |err| {
        return parse_errors.normalizeName(@errorName(err));
    };
    defer parsed.deinit();

    const root = switch (parsed.value) {
        .object => |obj| obj,
        else => return error.TypeMismatch,
    };
    const version_value = root.get("version") orelse return error.MissingField;
    return switch (version_value) {
        .integer => |num| num,
        else => error.TypeMismatch,
    };
}

fn validateLockCanonical(allocator: std.mem.Allocator, canonical_json: []const u8) parse_errors.ParseError!void {
    _ = try validator.validateCanonicalJsonStrict(allocator, canonical_json);
    var workspace_spec = try validator.parseWorkspaceSpecStrict(allocator, canonical_json);
    defer workspace_spec.deinit(allocator);
    var build_spec = try validator.parseBuildSpecStrict(allocator, canonical_json);
    defer build_spec.deinit(allocator);
    validator.validateBuildWriteIsolation(&workspace_spec, &build_spec) catch |err| {
        return parse_errors.normalizeName(@errorName(err));
    };
    var output_spec = try validator.parseOutputSpecStrict(allocator, canonical_json);
    defer output_spec.deinit(allocator);
}

fn deriveLockPath(allocator: std.mem.Allocator, knx_path: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}.lock", .{knx_path});
}

fn writeFileAtomic(allocator: std.mem.Allocator, path: []const u8, content: []const u8) !void {
    const tmp_path = try std.fmt.allocPrint(allocator, "{s}.tmp-{d}", .{ path, std.time.microTimestamp() });
    defer allocator.free(tmp_path);
    errdefer std.fs.cwd().deleteFile(tmp_path) catch {};

    if (std.fs.path.dirname(path)) |dir| {
        try std.fs.cwd().makePath(dir);
    }

    var file = try std.fs.cwd().createFile(tmp_path, .{});
    defer file.close();
    try file.writeAll(content);
    try file.sync();
    try std.fs.cwd().rename(tmp_path, path);
}

fn printFreezeHuman(knx_path: []const u8, lock_path: []const u8, knx_digest: []const u8, bytes: usize) void {
    std.debug.print("Freeze completed\n", .{});
    std.debug.print("Knxfile: {s}\n", .{knx_path});
    std.debug.print("Lockfile: {s}\n", .{lock_path});
    std.debug.print("Knx digest: {s}\n", .{knx_digest});
    std.debug.print("Canonical bytes: {d}\n", .{bytes});
}

fn printFreezeJson(allocator: std.mem.Allocator, knx_path: []const u8, lock_path: []const u8, knx_digest: []const u8, bytes: usize) !void {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    var out_writer = out.writer(allocator);
    var out_buffer: [2048]u8 = undefined;
    var out_adapter = out_writer.adaptToNewApi(&out_buffer);
    const writer = &out_adapter.new_interface;

    try writer.writeAll("{\"status\":\"ok\",\"command\":\"freeze\",\"knxfile\":");
    try std.json.Stringify.encodeJsonString(knx_path, .{}, writer);
    try writer.writeAll(",\"lockfile\":");
    try std.json.Stringify.encodeJsonString(lock_path, .{}, writer);
    try writer.writeAll(",\"knx_digest\":");
    try std.json.Stringify.encodeJsonString(knx_digest, .{}, writer);
    try writer.writeAll(",\"canonical_json_bytes\":");
    try writer.print("{d}", .{bytes});
    try writer.writeAll("}\n");
    try writer.flush();
    std.debug.print("{s}", .{out.items});
}
