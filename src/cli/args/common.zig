const std = @import("std");

pub fn validateKnxfileCliPath(path: []const u8) !void {
    if (hasSuffixIgnoreCase(path, ".toml")) return error.InvalidCommand;
}

pub fn nextOptionValue(args: []const []const u8, index: *usize) ![]const u8 {
    index.* += 1;
    if (index.* >= args.len) return error.InvalidCommand;
    const value = args[index.*];
    if (std.mem.startsWith(u8, value, "--")) return error.InvalidCommand;
    return value;
}

fn hasSuffixIgnoreCase(text: []const u8, suffix: []const u8) bool {
    if (text.len < suffix.len) return false;
    return std.ascii.eqlIgnoreCase(text[text.len - suffix.len ..], suffix);
}
