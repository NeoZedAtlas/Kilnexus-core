const std = @import("std");
const model = @import("model.zig");
const keys = @import("keys.zig");
const helpers = @import("json_helpers.zig");

pub fn parseOutputSpec(allocator: std.mem.Allocator, canonical_json: []const u8) !model.OutputSpec {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, canonical_json, .{});
    defer parsed.deinit();

    const root = try helpers.expectObject(parsed.value, "root");
    const outputs = try helpers.expectArrayField(root, "outputs");
    if (outputs.items.len == 0) return error.OutputsEmpty;

    var entries: std.ArrayList(model.OutputEntry) = .empty;
    errdefer {
        for (entries.items) |*entry| entry.deinit(allocator);
        entries.deinit(allocator);
    }

    for (outputs.items) |item| {
        const obj = try helpers.expectObject(item, "output");
        try helpers.ensureOnlyKeys(obj, keys.output_entry_keys[0..]);
        const mode_text = try helpers.expectNonEmptyString(obj, "mode");
        const mode = try helpers.parseOutputMode(mode_text);
        const sha256 = if (obj.get("sha256")) |sha_value| blk: {
            const sha_text = try helpers.expectString(sha_value, "sha256");
            break :blk try helpers.parseHexFixed(32, sha_text);
        } else null;
        var path: ?[]u8 = null;
        var source_path: ?[]u8 = null;
        var publish_as: ?[]u8 = null;
        errdefer {
            if (path) |value| allocator.free(value);
            if (source_path) |value| allocator.free(value);
            if (publish_as) |value| allocator.free(value);
        }
        const source_text = try helpers.expectNonEmptyString(obj, "source");
        const publish_text = try helpers.expectNonEmptyString(obj, "publish_as");
        try helpers.validateWorkspaceRelativePath(source_text);
        try helpers.validatePublishName(publish_text);
        path = try allocator.dupe(u8, source_text);
        source_path = try allocator.dupe(u8, source_text);
        publish_as = try allocator.dupe(u8, publish_text);

        try entries.append(allocator, .{
            .path = path.?,
            .source_path = source_path,
            .publish_as = publish_as,
            .mode = mode,
            .sha256 = sha256,
        });
    }

    return .{
        .entries = try entries.toOwnedSlice(allocator),
    };
}
