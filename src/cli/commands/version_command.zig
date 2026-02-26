const std = @import("std");
const cli_args = @import("../args.zig");
const version_info = @import("../version_info.zig");

pub fn run(allocator: std.mem.Allocator, args: []const []const u8) !void {
    _ = allocator;
    const cli = cli_args.parseJsonOnlyCliArgs(args) catch |err| {
        if (err == error.HelpRequested) {
            printUsage();
            return;
        }
        printUsage();
        return error.InvalidCommand;
    };

    if (cli.json_output) {
        std.debug.print(
            "{{\"status\":\"ok\",\"command\":\"version\",\"name\":\"{s}\",\"version\":\"{s}\",\"zig\":\"{s}\"}}\n",
            .{ version_info.app_name, version_info.app_version, version_info.zig_version },
        );
        return;
    }

    std.debug.print("{s} {s}\n", .{ version_info.app_name, version_info.app_version });
    std.debug.print("zig {s}\n", .{version_info.zig_version});
}

fn printUsage() void {
    std.debug.print("version options: --json --help\n", .{});
}
