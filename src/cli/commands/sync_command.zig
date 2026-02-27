const std = @import("std");
const freeze_command = @import("freeze_command.zig");

pub fn run(allocator: std.mem.Allocator, args: []const []const u8) !void {
    return freeze_command.runAs(allocator, args, "sync");
}

test {
    _ = freeze_command;
}
