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
    Internal,
};

pub fn normalize(err: anyerror) ParseError {
    if (err == error.EmptyInput) return error.EmptyInput;
    if (err == error.Syntax or err == error.Parse) return error.Syntax;
    if (err == error.Schema) return error.Schema;

    if (err == error.Canonicalization or err == error.UnsupportedFloatInCanonicalization or err == error.InvalidCanonicalObject) {
        return error.Canonicalization;
    }

    if (err == error.MissingField or err == error.MissingRequiredField or err == error.MissingVersion) {
        return error.MissingField;
    }

    if (err == error.TypeMismatch or err == error.ExpectedObject or err == error.ExpectedArray or err == error.ExpectedString or err == error.ExpectedInteger) {
        return error.TypeMismatch;
    }

    if (err == error.ValueInvalid or err == error.InvalidHexLength or err == error.InvalidHexChar or err == error.InvalidPositiveInt or err == error.InvalidPolicyNetwork or err == error.InvalidPolicyClock or err == error.InvalidEnvTZ or err == error.InvalidEnvLang or err == error.InvalidDigits or err == error.InvalidVerifyMode or err == error.EmptyString) {
        return error.ValueInvalid;
    }

    if (err == error.VersionUnsupported or err == error.UnsupportedVersion) {
        return error.VersionUnsupported;
    }

    if (err == error.OperatorDisallowed or err == error.OperatorNotAllowed) {
        return error.OperatorDisallowed;
    }

    if (err == error.OutputInvalid or err == error.OutputsEmpty or err == error.InvalidOutputPath or err == error.InvalidMode) {
        return error.OutputInvalid;
    }

    return error.Internal;
}

test "normalize maps parser and validator errors into canonical parse errors" {
    try std.testing.expect(normalize(error.Parse) == error.Syntax);
    try std.testing.expect(normalize(error.MissingVersion) == error.MissingField);
    try std.testing.expect(normalize(error.InvalidPolicyNetwork) == error.ValueInvalid);
    try std.testing.expect(normalize(error.InvalidMode) == error.OutputInvalid);
}
