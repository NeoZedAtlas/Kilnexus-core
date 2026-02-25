const std = @import("std");
const model = @import("model.zig");
const helpers = @import("json_helpers.zig");

pub fn parseToolchainSpec(allocator: std.mem.Allocator, canonical_json: []const u8) !model.ToolchainSpec {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, canonical_json, .{});
    defer parsed.deinit();

    const root = try helpers.expectObject(parsed.value, "root");
    const toolchain = try helpers.expectObjectField(root, "toolchain");

    const id_text = try helpers.expectNonEmptyString(toolchain, "id");
    const id = try allocator.dupe(u8, id_text);
    errdefer allocator.free(id);

    const blob_sha_text = try helpers.expectNonEmptyString(toolchain, "blob_sha256");
    const tree_root_text = try helpers.expectNonEmptyString(toolchain, "tree_root");
    const size_u64 = try helpers.parsePositiveU64(toolchain, "size");

    var source_copy: ?[]u8 = null;
    errdefer if (source_copy) |source| allocator.free(source);
    if (toolchain.get("source")) |source_value| {
        const source_text = try helpers.expectString(source_value, "source");
        if (source_text.len == 0) return error.EmptyString;
        source_copy = try allocator.dupe(u8, source_text);
    }

    return .{
        .id = id,
        .source = source_copy,
        .blob_sha256 = try helpers.parseHexFixed(32, blob_sha_text),
        .tree_root = try helpers.parseHexFixed(32, tree_root_text),
        .size = size_u64,
    };
}
