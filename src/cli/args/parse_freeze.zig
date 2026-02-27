const std = @import("std");
const common = @import("common.zig");
const types = @import("../types.zig");

pub fn parseFreezeCliArgs(args: []const []const u8) !types.FreezeCliArgs {
    var output: types.FreezeCliArgs = .{};
    var positional_index: usize = 0;
    var path_set = false;
    var lock_set = false;

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
            if (std.mem.eql(u8, arg, "--dry-run")) {
                output.dry_run = true;
                continue;
            }
            if (std.mem.eql(u8, arg, "--knxfile")) {
                output.path = try common.nextOptionValue(args, &i);
                path_set = true;
                continue;
            }
            if (std.mem.eql(u8, arg, "--lockfile")) {
                output.lock_path = try common.nextOptionValue(args, &i);
                lock_set = true;
                continue;
            }
            return error.InvalidCommand;
        }

        switch (positional_index) {
            0 => {
                if (path_set) return error.InvalidCommand;
                output.path = arg;
                path_set = true;
            },
            1 => {
                if (lock_set) return error.InvalidCommand;
                output.lock_path = arg;
                lock_set = true;
            },
            else => return error.InvalidCommand,
        }
        positional_index += 1;
    }

    try common.validateKnxfileCliPath(output.path);
    if (output.lock_path) |lock_path| {
        if (lock_path.len == 0) return error.InvalidCommand;
    }
    return output;
}

test "parseFreezeCliArgs parses positional and named forms" {
    const defaults = try parseFreezeCliArgs(&.{});
    try std.testing.expectEqualStrings("Knxfile", defaults.path);
    try std.testing.expect(defaults.lock_path == null);
    try std.testing.expect(!defaults.json_output);

    const positional = try parseFreezeCliArgs(&.{ "examples/app/Knxfile", "examples/app/Knxfile.lock" });
    try std.testing.expectEqualStrings("examples/app/Knxfile", positional.path);
    try std.testing.expect(positional.lock_path != null);
    try std.testing.expectEqualStrings("examples/app/Knxfile.lock", positional.lock_path.?);

    const named = try parseFreezeCliArgs(&.{
        "--knxfile",
        "Knxfile.prod",
        "--lockfile",
        "Knxfile.prod.lock",
        "--json",
    });
    try std.testing.expectEqualStrings("Knxfile.prod", named.path);
    try std.testing.expect(named.lock_path != null);
    try std.testing.expectEqualStrings("Knxfile.prod.lock", named.lock_path.?);
    try std.testing.expect(named.json_output);
    try std.testing.expect(!named.dry_run);
}

test "parseFreezeCliArgs rejects invalid combinations" {
    try std.testing.expectError(error.InvalidCommand, parseFreezeCliArgs(&.{ "a", "b", "c" }));
    try std.testing.expectError(error.InvalidCommand, parseFreezeCliArgs(&.{"--lockfile"}));
    try std.testing.expectError(error.InvalidCommand, parseFreezeCliArgs(&.{ "--knxfile", "Knxfile.toml" }));
}

test "parseFreezeCliArgs supports dry-run" {
    const parsed = try parseFreezeCliArgs(&.{"--dry-run"});
    try std.testing.expect(parsed.dry_run);
    try std.testing.expectEqualStrings("Knxfile", parsed.path);
}
