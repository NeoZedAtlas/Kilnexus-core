const std = @import("std");
const error_names = @import("../errors/error_names.zig");

pub const ParseError = error{
    EmptyInput,
    Syntax,
    Schema,
    Canonicalization,
    MissingField,
    TypeMismatch,
    ValueInvalid,
    VersionUnsupported,
    OperatorDisallowed,
    OutputInvalid,
    LegacyBuildBlock,
    Internal,
};

const Alias = error_names.Alias;

pub fn normalizeName(err_name: []const u8) ParseError {
    return normalizeTo(ParseError, err_name, error_names.parse_aliases);
}

fn normalizeTo(comptime Target: type, err_name: []const u8, comptime aliases: []const Alias) Target {
    const resolved = error_names.resolveAlias(err_name, aliases);
    return errorFromName(Target, resolved) orelse error.Internal;
}

fn errorFromName(comptime Target: type, name: []const u8) ?Target {
    inline for (@typeInfo(Target).error_set.?) |field| {
        if (std.mem.eql(u8, name, field.name)) {
            return @field(Target, field.name);
        }
    }
    return null;
}

test "normalize maps parser and validator errors into canonical parse errors" {
    try std.testing.expect(normalizeName("Parse") == error.Syntax);
    try std.testing.expect(normalizeName("MissingVersion") == error.MissingField);
    try std.testing.expect(normalizeName("InvalidPolicyNetwork") == error.ValueInvalid);
    try std.testing.expect(normalizeName("InvalidMode") == error.OutputInvalid);
    try std.testing.expect(normalizeName("LegacyBuildBlock") == error.LegacyBuildBlock);
}
