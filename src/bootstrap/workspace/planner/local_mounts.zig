const std = @import("std");
const validator = @import("../../../knx/validator.zig");
const workspace_types = @import("../types.zig");
const path_utils = @import("../path_utils.zig");
const glob_utils = @import("../glob.zig");
const common = @import("common.zig");

const VirtualMapping = workspace_types.VirtualMapping;

pub const SourceRef = struct {
    input_id: []const u8,
    sub_path: ?[]const u8,
};

pub fn parseMountSource(source: []const u8) !SourceRef {
    if (source.len == 0) return error.PathTraversalDetected;
    if (std.fs.path.isAbsolute(source)) return error.PathTraversalDetected;
    if (std.mem.indexOfScalar(u8, source, '\\') != null) return error.PathTraversalDetected;
    if (std.mem.indexOfScalar(u8, source, ':') != null) return error.PathTraversalDetected;

    const slash = std.mem.indexOfScalar(u8, source, '/');
    if (slash == null) return .{ .input_id = source, .sub_path = null };
    const first = slash.?;
    if (first == 0) return error.PathTraversalDetected;

    const id = source[0..first];
    const rest = source[first + 1 ..];
    if (rest.len == 0) return .{ .input_id = id, .sub_path = null };
    try path_utils.validateMountPath(rest);
    return .{ .input_id = id, .sub_path = rest };
}

pub fn findLocalInput(local_inputs_opt: ?[]validator.LocalInputSpec, id: []const u8) ?validator.LocalInputSpec {
    const local_inputs = local_inputs_opt orelse return null;
    for (local_inputs) |input| {
        if (std.mem.eql(u8, input.id, id)) return input;
    }
    return null;
}

pub fn appendLocalMappingsForMount(
    allocator: std.mem.Allocator,
    mappings: *std.ArrayList(VirtualMapping),
    seen_mounts: *std.StringHashMap(void),
    mount: validator.WorkspaceMountSpec,
    source_ref: SourceRef,
    local_input: validator.LocalInputSpec,
) !void {
    const files = try glob_utils.expandLocalInputMatches(allocator, local_input);
    defer common.freeOwnedStrings(allocator, files);

    if (source_ref.sub_path) |sub_path| {
        if (mount.strip_prefix != null) return error.InvalidBuildGraph;
        if (!glob_utils.containsString(files, sub_path)) return error.FileNotFound;
        const source_abs_path = try std.fs.cwd().realpathAlloc(allocator, sub_path);
        errdefer allocator.free(source_abs_path);
        const mount_path = try allocator.dupe(u8, mount.target);
        errdefer allocator.free(mount_path);
        try common.appendMappingChecked(allocator, mappings, seen_mounts, mount_path, source_abs_path, false);
        return;
    }

    for (files) |rel_path| {
        const source_abs_path = try std.fs.cwd().realpathAlloc(allocator, rel_path);
        errdefer allocator.free(source_abs_path);
        const projected_rel = try common.applyMountStripPrefix(allocator, rel_path, mount.strip_prefix);
        defer allocator.free(projected_rel);
        const mount_path = try path_utils.joinPosix(allocator, mount.target, projected_rel);
        errdefer allocator.free(mount_path);
        try common.appendMappingChecked(allocator, mappings, seen_mounts, mount_path, source_abs_path, false);
    }
}
