const std = @import("std");
const common = @import("common.zig");
const types = @import("../types.zig");

pub fn parseCleanCliArgs(args: []const []const u8) !types.CleanCliArgs {
    var output: types.CleanCliArgs = .{};
    var scope_explicit = false;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            return error.HelpRequested;
        }
        if (std.mem.eql(u8, arg, "--json")) {
            output.json_output = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--apply")) {
            output.apply = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--dry-run")) {
            output.apply = false;
            continue;
        }
        if (std.mem.eql(u8, arg, "--cache-root")) {
            output.cache_root = try common.nextOptionValue(args, &i);
            continue;
        }
        if (std.mem.eql(u8, arg, "--output-root")) {
            output.output_root = try common.nextOptionValue(args, &i);
            continue;
        }
        if (std.mem.eql(u8, arg, "--toolchain")) {
            const value = try common.nextOptionValue(args, &i);
            try validateTreeRoot(value);
            output.toolchain_tree_root = value;
            continue;
        }
        if (std.mem.eql(u8, arg, "--older-than")) {
            const value = try common.nextOptionValue(args, &i);
            output.older_than_secs = try parseDurationSeconds(value);
            continue;
        }
        if (std.mem.eql(u8, arg, "--scope")) {
            const value = try common.nextOptionValue(args, &i);
            if (!scope_explicit) {
                output.scopes = .{};
                scope_explicit = true;
            }
            try applyScopeValue(&output.scopes, value);
            continue;
        }
        return error.InvalidCommand;
    }

    return output;
}

fn applyScopeValue(scopes: *types.CleanScopeSet, text: []const u8) !void {
    var parts = std.mem.splitScalar(u8, text, ',');
    while (parts.next()) |part_raw| {
        const part = std.mem.trim(u8, part_raw, " \t");
        if (part.len == 0) return error.InvalidCommand;
        if (std.mem.eql(u8, part, "all")) {
            scopes.* = types.CleanScopeSet.all();
            continue;
        }
        if (std.mem.eql(u8, part, "work")) {
            scopes.work = true;
            continue;
        }
        if (std.mem.eql(u8, part, "staging")) {
            scopes.staging = true;
            continue;
        }
        if (std.mem.eql(u8, part, "local")) {
            scopes.local = true;
            continue;
        }
        if (std.mem.eql(u8, part, "third_party")) {
            scopes.third_party = true;
            continue;
        }
        if (std.mem.eql(u8, part, "official")) {
            scopes.official = true;
            continue;
        }
        if (std.mem.eql(u8, part, "releases")) {
            scopes.releases = true;
            continue;
        }
        return error.InvalidCommand;
    }
}

fn validateTreeRoot(value: []const u8) !void {
    if (value.len != 64) return error.InvalidCommand;
    for (value) |ch| {
        if (!std.ascii.isHex(ch)) return error.InvalidCommand;
    }
}

fn parseDurationSeconds(text: []const u8) !u64 {
    if (text.len == 0) return error.InvalidCommand;
    const suffix = text[text.len - 1];
    const body = if (std.ascii.isDigit(suffix)) text else text[0 .. text.len - 1];
    if (body.len == 0) return error.InvalidCommand;
    const value = std.fmt.parseUnsigned(u64, body, 10) catch return error.InvalidCommand;

    const factor: u64 = if (std.ascii.isDigit(suffix))
        1
    else if (suffix == 's' or suffix == 'S')
        1
    else if (suffix == 'm' or suffix == 'M')
        60
    else if (suffix == 'h' or suffix == 'H')
        60 * 60
    else if (suffix == 'd' or suffix == 'D')
        24 * 60 * 60
    else
        return error.InvalidCommand;

    return std.math.mul(u64, value, factor) catch return error.InvalidCommand;
}

test "parseCleanCliArgs defaults to dry-run and safe scopes" {
    const cli = try parseCleanCliArgs(&.{});
    try std.testing.expect(!cli.apply);
    try std.testing.expect(cli.scopes.work);
    try std.testing.expect(cli.scopes.staging);
    try std.testing.expect(!cli.scopes.official);
    try std.testing.expectEqual(@as(u64, 72 * 60 * 60), cli.older_than_secs);
}

test "parseCleanCliArgs parses explicit scope and apply" {
    const cli = try parseCleanCliArgs(&.{
        "--scope",
        "official,releases",
        "--apply",
        "--older-than",
        "7d",
        "--toolchain",
        "dec4aa4dbe7ccaec0bac913f77e69350a53d46096c6529912e987cde018ee1fc",
        "--json",
    });
    try std.testing.expect(cli.apply);
    try std.testing.expect(cli.scopes.official);
    try std.testing.expect(cli.scopes.releases);
    try std.testing.expect(!cli.scopes.work);
    try std.testing.expectEqual(@as(u64, 7 * 24 * 60 * 60), cli.older_than_secs);
    try std.testing.expect(cli.toolchain_tree_root != null);
    try std.testing.expect(cli.json_output);
}

test "parseCleanCliArgs rejects invalid scope" {
    try std.testing.expectError(
        error.InvalidCommand,
        parseCleanCliArgs(&.{ "--scope", "bad" }),
    );
}
