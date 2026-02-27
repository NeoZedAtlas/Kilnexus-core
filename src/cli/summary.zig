const std = @import("std");
const abi_parser = @import("../parser/abi_parser.zig");
const parse_errors = @import("../parser/parse_errors.zig");
const validator = @import("../knx/validator.zig");
const args = @import("args.zig");
const types = @import("types.zig");

pub fn loadKnxSummary(allocator: std.mem.Allocator, path: []const u8) !types.KnxSummary {
    try args.validateKnxfileCliPath(path);
    const source = try std.fs.cwd().readFileAlloc(allocator, path, types.max_knxfile_bytes);
    defer allocator.free(source);

    const parsed = try abi_parser.parseLockfileStrict(allocator, source);
    defer allocator.free(parsed.canonical_json);
    return loadKnxSummaryFromCanonicalJson(allocator, parsed.canonical_json);
}

pub fn loadKnxSummaryFromCanonicalJson(allocator: std.mem.Allocator, canonical_json: []const u8) !types.KnxSummary {
    const canonical_copy = try allocator.dupe(u8, canonical_json);
    errdefer allocator.free(canonical_copy);

    const validation = try validator.validateCanonicalJsonStrict(allocator, canonical_copy);

    var toolchain_spec = try validator.parseToolchainSpecStrict(allocator, canonical_copy);
    errdefer toolchain_spec.deinit(allocator);

    var workspace_spec = try validator.parseWorkspaceSpecStrict(allocator, canonical_copy);
    errdefer workspace_spec.deinit(allocator);

    var build_spec = try validator.parseBuildSpecStrict(allocator, canonical_copy);
    errdefer build_spec.deinit(allocator);

    validator.validateBuildWriteIsolation(&workspace_spec, &build_spec) catch |err| {
        return parse_errors.normalizeName(@errorName(err));
    };

    var output_spec = try validator.parseOutputSpecStrict(allocator, canonical_copy);
    errdefer output_spec.deinit(allocator);

    const knx_digest_hex = validator.computeKnxDigestHex(canonical_copy);
    return .{
        .canonical_json = canonical_copy,
        .validation = validation,
        .toolchain_spec = toolchain_spec,
        .workspace_spec = workspace_spec,
        .build_spec = build_spec,
        .output_spec = output_spec,
        .knx_digest_hex = knx_digest_hex,
    };
}

pub fn countOptionalSlice(comptime T: type, value: ?[]T) usize {
    return if (value) |items| items.len else 0;
}
