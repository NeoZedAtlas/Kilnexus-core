const std = @import("std");
const keys = @import("keys.zig");
const model = @import("model.zig");
const helpers = @import("json_helpers.zig");
const parse_build = @import("parse_build.zig");

pub fn validateCanonicalJson(allocator: std.mem.Allocator, canonical_json: []const u8) !model.ValidationSummary {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, canonical_json, .{});
    defer parsed.deinit();

    const root = try helpers.expectObject(parsed.value, "root");
    try helpers.expectVersion(root);
    if (root.get("build") != null) return error.LegacyBuildBlock;
    _ = try helpers.expectNonEmptyString(root, "target");

    const toolchain = try helpers.expectObjectField(root, "toolchain");
    _ = try helpers.expectNonEmptyString(toolchain, "id");
    try helpers.expectHex64(toolchain, "blob_sha256");
    try helpers.expectHex64(toolchain, "tree_root");
    try helpers.expectPositiveInt(toolchain, "size");

    const policy = try helpers.expectObjectField(root, "policy");
    const network = try helpers.expectNonEmptyString(policy, "network");
    if (!std.mem.eql(u8, network, "off")) return error.InvalidPolicyNetwork;
    const verify_mode = try helpers.parseVerifyMode(policy);
    const clock = try helpers.expectNonEmptyString(policy, "clock");
    if (!std.mem.eql(u8, clock, "fixed")) return error.InvalidPolicyClock;

    const env = try helpers.expectObjectField(root, "env");
    const tz = try helpers.expectNonEmptyString(env, "TZ");
    if (!std.mem.eql(u8, tz, "UTC")) return error.InvalidEnvTZ;
    const lang = try helpers.expectNonEmptyString(env, "LANG");
    if (!std.mem.eql(u8, lang, "C")) return error.InvalidEnvLang;
    const source_date_epoch = try helpers.expectNonEmptyString(env, "SOURCE_DATE_EPOCH");
    try helpers.expectAsciiDigits(source_date_epoch, "SOURCE_DATE_EPOCH");

    const outputs = try helpers.expectArrayField(root, "outputs");
    if (outputs.items.len == 0) return error.OutputsEmpty;
    for (outputs.items) |entry| {
        const output = try helpers.expectObject(entry, "output");
        try helpers.ensureOnlyKeys(output, keys.output_entry_keys[0..]);
        const source = try helpers.expectNonEmptyString(output, "source");
        try helpers.validateWorkspaceRelativePath(source);
        const publish_as = try helpers.expectNonEmptyString(output, "publish_as");
        try helpers.validatePublishName(publish_as);
        const mode = try helpers.expectNonEmptyString(output, "mode");
        try helpers.expectModeString(mode);
        if (output.get("sha256")) |_| {
            try helpers.expectHex64(output, "sha256");
        }
    }

    const operators_value = root.get("operators") orelse return error.MissingRequiredField;
    switch (operators_value) {
        .array => |operators| {
            for (operators.items) |op_value| {
                const op_obj = try helpers.expectObject(op_value, "operator");
                const op_id = try helpers.expectNonEmptyString(op_obj, "id");
                try helpers.validateOperatorId(op_id);
                const op = try helpers.expectNonEmptyString(op_obj, "run");
                if (!helpers.isAllowedOperator(op)) return error.OperatorNotAllowed;
                try parse_build.ensureOperatorKeys(op_obj, op, true);
            }
        },
        .object => |operators_map| {
            var it = operators_map.iterator();
            while (it.next()) |entry| {
                const op_id = entry.key_ptr.*;
                try helpers.validateOperatorId(op_id);
                const op_obj = try helpers.expectObject(entry.value_ptr.*, "operator");
                if (op_obj.get("id") != null) return error.ValueInvalid;
                const op = try helpers.expectNonEmptyString(op_obj, "run");
                if (!helpers.isAllowedOperator(op)) return error.OperatorNotAllowed;
                try parse_build.ensureOperatorKeys(op_obj, op, false);
            }
        },
        else => return error.ExpectedArray,
    }

    return .{ .verify_mode = verify_mode };
}
