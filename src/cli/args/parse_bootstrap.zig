const std = @import("std");
const common = @import("common.zig");
const types = @import("../types.zig");

pub fn parseBootstrapCliArgs(args: []const []const u8) !types.BootstrapCliArgs {
    var output: types.BootstrapCliArgs = .{};
    var positional_index: usize = 0;
    var path_set = false;
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
            if (std.mem.eql(u8, arg, "--allow-unlocked")) {
                output.allow_unlocked = true;
                continue;
            }
            if (std.mem.eql(u8, arg, "--knxfile")) {
                output.path = try common.nextOptionValue(args, &i);
                path_set = true;
                continue;
            }
            if (std.mem.eql(u8, arg, "--trust-off")) {
                output.trust_dir = null;
                output.trust_state_path = null;
                trust_set = true;
                continue;
            }
            if (std.mem.eql(u8, arg, "--trust-dir")) {
                const value = try common.nextOptionValue(args, &i);
                output.trust_dir = value;
                if (output.trust_state_path == null) {
                    output.trust_state_path = ".kilnexus-trust-state.json";
                }
                trust_set = true;
                continue;
            }
            if (std.mem.eql(u8, arg, "--trust-state")) {
                const value = try common.nextOptionValue(args, &i);
                if (std.mem.eql(u8, value, "off")) {
                    output.trust_state_path = null;
                } else {
                    output.trust_state_path = value;
                }
                continue;
            }
            if (std.mem.eql(u8, arg, "--cache-root")) {
                output.cache_root = try common.nextOptionValue(args, &i);
                cache_set = true;
                continue;
            }
            if (std.mem.eql(u8, arg, "--output-root")) {
                output.output_root = try common.nextOptionValue(args, &i);
                output_set = true;
                continue;
            }
            return error.InvalidCommand;
        }

        switch (positional_index) {
            0 => {
                if (path_set) return error.InvalidCommand;
                output.path = arg;
            },
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

    try common.validateKnxfileCliPath(output.path);
    return output;
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
    try std.testing.expect(!custom.allow_unlocked);
}

test "parseBootstrapCliArgs accepts --knxfile option" {
    const parsed = try parseBootstrapCliArgs(&.{
        "--knxfile",
        "Knxfile.prod",
        "--allow-unlocked",
        "--json",
    });
    try std.testing.expectEqualStrings("Knxfile.prod", parsed.path);
    try std.testing.expect(parsed.allow_unlocked);
    try std.testing.expect(parsed.json_output);
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

test "parseBootstrapCliArgs rejects toml lockfile suffix" {
    try std.testing.expectError(error.InvalidCommand, parseBootstrapCliArgs(&.{"Knxfile.toml"}));
    try std.testing.expectError(error.InvalidCommand, parseBootstrapCliArgs(&.{"Knxfile.TOML"}));
}
