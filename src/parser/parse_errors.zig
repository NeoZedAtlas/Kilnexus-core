const std = @import("std");

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

const Alias = struct {
    from: []const u8,
    to: []const u8,
};

const parse_aliases: []const Alias = &.{
    .{ .from = "Parse", .to = "Syntax" },
    .{ .from = "UnsupportedFloatInCanonicalization", .to = "Canonicalization" },
    .{ .from = "InvalidCanonicalObject", .to = "Canonicalization" },
    .{ .from = "MissingRequiredField", .to = "MissingField" },
    .{ .from = "MissingVersion", .to = "MissingField" },
    .{ .from = "ExpectedObject", .to = "TypeMismatch" },
    .{ .from = "ExpectedArray", .to = "TypeMismatch" },
    .{ .from = "ExpectedString", .to = "TypeMismatch" },
    .{ .from = "ExpectedInteger", .to = "TypeMismatch" },
    .{ .from = "InvalidHexLength", .to = "ValueInvalid" },
    .{ .from = "InvalidHexChar", .to = "ValueInvalid" },
    .{ .from = "InvalidPositiveInt", .to = "ValueInvalid" },
    .{ .from = "InvalidPolicyNetwork", .to = "ValueInvalid" },
    .{ .from = "InvalidPolicyClock", .to = "ValueInvalid" },
    .{ .from = "InvalidEnvTZ", .to = "ValueInvalid" },
    .{ .from = "InvalidEnvLang", .to = "ValueInvalid" },
    .{ .from = "InvalidDigits", .to = "ValueInvalid" },
    .{ .from = "InvalidVerifyMode", .to = "ValueInvalid" },
    .{ .from = "EmptyString", .to = "ValueInvalid" },
    .{ .from = "InvalidBuildGraph", .to = "ValueInvalid" },
    .{ .from = "UnsupportedVersion", .to = "VersionUnsupported" },
    .{ .from = "OperatorNotAllowed", .to = "OperatorDisallowed" },
    .{ .from = "OutputsEmpty", .to = "OutputInvalid" },
    .{ .from = "InvalidOutputPath", .to = "OutputInvalid" },
    .{ .from = "InvalidMode", .to = "OutputInvalid" },
};

pub fn normalizeName(err_name: []const u8) ParseError {
    return normalizeTo(ParseError, err_name, parse_aliases);
}

fn normalizeTo(comptime Target: type, err_name: []const u8, comptime aliases: []const Alias) Target {
    const resolved = resolveAliasName(err_name, aliases);
    return errorFromName(Target, resolved) orelse error.Internal;
}

fn resolveAliasName(name: []const u8, comptime aliases: []const Alias) []const u8 {
    inline for (aliases) |alias| {
        if (std.mem.eql(u8, name, alias.from)) return alias.to;
    }
    return name;
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
