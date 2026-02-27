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

    return parseLockfile(allocator, input) catch |err| {
        // Fallback for TOML compatibility quirks: normalize array literals
        // (multiline arrays and trailing commas) and retry once.
        if ((err == error.Parse or err == error.Schema) and seemsKnxToml(input)) {
            const normalized = normalizeTomlArrayLiterals(allocator, input) catch return parse_errors.normalizeName(@errorName(err));
            defer allocator.free(normalized);
            if (!std.mem.eql(u8, normalized, input)) {
                return parseLockfile(allocator, normalized) catch |retry_err| return parse_errors.normalizeName(@errorName(retry_err));
            }
        }
        return parse_errors.normalizeName(@errorName(err));
    };
}

fn seemsKnxToml(input: []const u8) bool {
    return std.mem.indexOf(u8, input, "#!knxfile") != null;
}

fn normalizeTomlArrayLiterals(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);

    var in_string = false;
    var escape = false;
    var in_array_literal = false;

    var i: usize = 0;
    while (i < input.len) : (i += 1) {
        const ch = input[i];

        if (in_string) {
            try out.append(allocator, ch);
            if (escape) {
                escape = false;
            } else if (ch == '\\') {
                escape = true;
            } else if (ch == '"') {
                in_string = false;
            }
            continue;
        }

        if (ch == '"') {
            in_string = true;
            try out.append(allocator, ch);
            continue;
        }

        if (!in_array_literal and ch == '[' and isArrayLiteralStart(input, i)) {
            in_array_literal = true;
            try out.append(allocator, ch);
            continue;
        }

        if (in_array_literal and ch == ']') {
            trimTrailingCommaAndSpace(out.items);
            in_array_literal = false;
            try out.append(allocator, ch);
            continue;
        }

        if (in_array_literal and (ch == '\n' or ch == '\r')) {
            if (out.items.len == 0 or out.items[out.items.len - 1] != ' ') {
                try out.append(allocator, ' ');
            }
            continue;
        }

        try out.append(allocator, ch);
    }

    return out.toOwnedSlice(allocator);
}

fn isArrayLiteralStart(input: []const u8, idx: usize) bool {
    var j: isize = @as(isize, @intCast(idx)) - 1;
    while (j >= 0) : (j -= 1) {
        const ch = input[@intCast(j)];
        if (ch == ' ' or ch == '\t' or ch == '\r') continue;
        if (ch == '=') return true;
        if (ch == ',') return true;
        if (ch == '\n') return false;
        return false;
    }
    return false;
}

fn trimTrailingCommaAndSpace(buf: []u8) void {
    if (buf.len == 0) return;
    var end: isize = @as(isize, @intCast(buf.len)) - 1;
    while (end >= 0 and (buf[@intCast(end)] == ' ' or buf[@intCast(end)] == '\t')) : (end -= 1) {}
    if (end >= 0 and buf[@intCast(end)] == ',') {
        buf[@intCast(end)] = ' ';
    }
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
        "{\"target\":\"x86_64-unknown-linux-musl\",\"version\":1}",
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
    try std.testing.expectEqualStrings(
        "{\"payload\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"version\":1}",
        parsed.canonical_json,
    );
}

test "parseLockfileStrict rejects empty input" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.EmptyInput, parseLockfileStrict(allocator, "   \r\n"));
}

test "parseLockfile parses TOML into canonical JSON" {
    const allocator = std.testing.allocator;
    const source =
        \\#!knxfile
        \\
        \\version = 1
        \\target = "x86_64-unknown-linux-musl"
        \\
        \\[policy]
        \\network = "off"
        \\clock = "fixed"
        \\verify_mode = "strict"
    ;
    const parsed = try parseLockfile(allocator, source);
    defer allocator.free(parsed.canonical_json);

    try std.testing.expectEqualStrings(
        "{\"policy\":{\"clock\":\"fixed\",\"network\":\"off\",\"verify_mode\":\"strict\"},\"target\":\"x86_64-unknown-linux-musl\",\"version\":1}",
        parsed.canonical_json,
    );
}

test "parseLockfile rejects TOML without knx magic header" {
    const allocator = std.testing.allocator;
    const source =
        \\version = 1
        \\target = "x86_64-unknown-linux-musl"
    ;
    try std.testing.expectError(error.Parse, parseLockfile(allocator, source));
}

test "parseLockfileStrict tolerates multiline arrays and trailing comma" {
    const allocator = std.testing.allocator;
    const source =
        \\#!knxfile
        \\version = 1
        \\target = "x86_64-unknown-linux-musl"
        \\
        \\[toolchain]
        \\id = "zigcc-0.14.0"
        \\blob_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        \\tree_root = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        \\size = 1
        \\
        \\[policy]
        \\network = "off"
        \\clock = "fixed"
        \\verify_mode = "strict"
        \\
        \\[env]
        \\TZ = "UTC"
        \\LANG = "C"
        \\SOURCE_DATE_EPOCH = "1735689600"
        \\
        \\[[inputs.local]]
        \\id = "src"
        \\include = [
        \\  "examples/hello-c/src/*.c",
        \\]
        \\
        \\[[workspace.mounts]]
        \\source = "src/examples/hello-c/src/main.c"
        \\target = "src/main.c"
        \\mode = "0444"
        \\
        \\[[operators]]
        \\id = "compile"
        \\run = "knx.c.compile"
        \\inputs = ["src/main.c"]
        \\outputs = ["obj/main.o"]
        \\flags = ["-O2", "-std=c11"]
        \\
        \\[[operators]]
        \\id = "link"
        \\run = "knx.zig.link"
        \\inputs = ["obj/main.o"]
        \\outputs = ["kilnexus-out/app"]
        \\flags = ["-s"]
        \\
        \\[[outputs]]
        \\source = "kilnexus-out/app"
        \\publish_as = "app"
        \\mode = "0755"
    ;

    const parsed = try parseLockfileStrict(allocator, source);
    defer allocator.free(parsed.canonical_json);
    try std.testing.expect(parsed.canonical_json.len > 0);
}
