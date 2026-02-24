const std = @import("std");
const parse_errors = @import("parse_errors.zig");

const c = @cImport({
    @cInclude("kx_parser.h");
});

pub const ParseResult = struct {
    canonical_json: []u8,
};

pub fn parseLockfile(allocator: std.mem.Allocator, input: []const u8) !ParseResult {
    var buffer = try allocator.alloc(u8, 64);
    errdefer allocator.free(buffer);

    while (true) {
        var out_len: usize = 0;
        const rc = c.kx_parse_lockfile(input.ptr, input.len, buffer.ptr, buffer.len, &out_len);
        switch (rc) {
            c.KX_OK => {
                if (out_len != buffer.len) {
                    buffer = try allocator.realloc(buffer, out_len);
                }
                return .{ .canonical_json = buffer };
            },
            c.KX_E_BUFFER_TOO_SMALL => {
                if (out_len == 0) return error.BufferTooSmall;
                buffer = try allocator.realloc(buffer, out_len);
            },
            c.KX_E_INVALID_ARG => return error.InvalidArg,
            c.KX_E_PARSE => return error.Parse,
            c.KX_E_SCHEMA => return error.Schema,
            c.KX_E_OOM => return error.OutOfMemory,
            c.KX_E_INTERNAL => return error.Internal,
            else => return error.UnexpectedParserStatus,
        }
    }
}

pub fn parseLockfileStrict(allocator: std.mem.Allocator, input: []const u8) parse_errors.ParseError!ParseResult {
    if (std.mem.trim(u8, input, " \t\r\n").len == 0) {
        return error.EmptyInput;
    }

    return parseLockfile(allocator, input) catch |err| return parse_errors.normalize(err);
}

test "parseLockfile normalizes CRLF and trims outer whitespace" {
    const allocator = std.testing.allocator;
    const source =
        \\ 
        \\{"version":1,"target":"x86_64-unknown-linux-musl"}
        \\
    ;
    const parsed = try parseLockfile(allocator, source);
    defer allocator.free(parsed.canonical_json);

    try std.testing.expectEqualStrings(
        "{\"version\":1,\"target\":\"x86_64-unknown-linux-musl\"}",
        parsed.canonical_json,
    );
}

test "parseLockfile handles buffer growth" {
    const allocator = std.testing.allocator;
    const long_source =
        \\{"version":1,"payload":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
    ;
    const parsed = try parseLockfile(allocator, long_source);
    defer allocator.free(parsed.canonical_json);

    try std.testing.expect(parsed.canonical_json.len > 64);
    try std.testing.expectEqualStrings(long_source, parsed.canonical_json);
}

test "parseLockfileStrict rejects empty input" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.EmptyInput, parseLockfileStrict(allocator, "   \r\n"));
}
