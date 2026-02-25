const std = @import("std");
const model = @import("model.zig");
const keys = @import("keys.zig");
const helpers = @import("json_helpers.zig");

const OperatorDecl = struct {
    id: []u8,
    run: []u8,
    inputs: [][]u8,
    outputs: [][]u8,
    flags: [][]u8,
    archive_format: model.ArchiveFormat = .tar,

    fn deinit(self: *OperatorDecl, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.run);
        helpers.freeOwnedStrings(allocator, self.inputs);
        helpers.freeOwnedStrings(allocator, self.outputs);
        helpers.freeOwnedStrings(allocator, self.flags);
        self.* = undefined;
    }
};

pub fn parseBuildSpec(allocator: std.mem.Allocator, canonical_json: []const u8) !model.BuildSpec {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, canonical_json, .{});
    defer parsed.deinit();

    const root = try helpers.expectObject(parsed.value, "root");
    if (root.get("build") != null) return error.LegacyBuildBlock;
    const operators_value = root.get("operators") orelse return error.MissingRequiredField;
    return switch (operators_value) {
        .array => |operators| parseOperatorsBuildSpec(allocator, operators),
        .object => |operators_map| parseOperatorsObjectBuildSpec(allocator, operators_map),
        else => error.ExpectedArray,
    };
}

pub fn ensureOperatorKeys(op_obj: std.json.ObjectMap, run_text: []const u8, expect_id_field: bool) !void {
    if (std.mem.eql(u8, run_text, "knx.fs.copy")) {
        if (expect_id_field) {
            try helpers.ensureOnlyKeys(op_obj, keys.operator_fs_copy_keys[0..]);
        } else {
            try helpers.ensureOnlyKeys(op_obj, keys.operator_map_fs_copy_keys[0..]);
        }
        return;
    }
    if (std.mem.eql(u8, run_text, "knx.c.compile")) {
        if (expect_id_field) {
            try helpers.ensureOnlyKeys(op_obj, keys.operator_c_compile_keys[0..]);
        } else {
            try helpers.ensureOnlyKeys(op_obj, keys.operator_map_c_compile_keys[0..]);
        }
        return;
    }
    if (std.mem.eql(u8, run_text, "knx.zig.link")) {
        if (expect_id_field) {
            try helpers.ensureOnlyKeys(op_obj, keys.operator_zig_link_keys[0..]);
        } else {
            try helpers.ensureOnlyKeys(op_obj, keys.operator_map_zig_link_keys[0..]);
        }
        return;
    }
    if (std.mem.eql(u8, run_text, "knx.archive.pack")) {
        if (expect_id_field) {
            try helpers.ensureOnlyKeys(op_obj, keys.operator_archive_pack_keys[0..]);
        } else {
            try helpers.ensureOnlyKeys(op_obj, keys.operator_map_archive_pack_keys[0..]);
        }
        return;
    }
    return error.OperatorNotAllowed;
}

fn parseOperatorsBuildSpec(allocator: std.mem.Allocator, operators: std.json.Array) !model.BuildSpec {
    var decls: std.ArrayList(OperatorDecl) = .empty;
    defer {
        for (decls.items) |*decl| decl.deinit(allocator);
        decls.deinit(allocator);
    }
    var seen_ids: std.StringHashMap(void) = .init(allocator);
    defer seen_ids.deinit();

    for (operators.items) |item| {
        const obj = try helpers.expectObject(item, "operator");
        const id_text = try helpers.expectNonEmptyString(obj, "id");
        const id_slot = try seen_ids.getOrPut(id_text);
        if (id_slot.found_existing) return error.InvalidBuildGraph;
        id_slot.value_ptr.* = {};
        var decl = try parseOperatorDecl(allocator, id_text, obj, true);
        errdefer decl.deinit(allocator);
        try decls.append(allocator, decl);
    }

    return buildSpecFromDecls(allocator, decls.items);
}

fn parseOperatorsObjectBuildSpec(allocator: std.mem.Allocator, operators_map: std.json.ObjectMap) !model.BuildSpec {
    var decls: std.ArrayList(OperatorDecl) = .empty;
    defer {
        for (decls.items) |*decl| decl.deinit(allocator);
        decls.deinit(allocator);
    }

    var ids: std.ArrayList([]const u8) = .empty;
    defer ids.deinit(allocator);
    var it = operators_map.iterator();
    while (it.next()) |entry| {
        try ids.append(allocator, entry.key_ptr.*);
    }
    std.mem.sort([]const u8, ids.items, {}, lessThanString);

    for (ids.items) |id_text| {
        const op_value = operators_map.get(id_text) orelse unreachable;
        const obj = try helpers.expectObject(op_value, "operator");
        if (obj.get("id") != null) return error.ValueInvalid;
        var decl = try parseOperatorDecl(allocator, id_text, obj, false);
        errdefer decl.deinit(allocator);
        try decls.append(allocator, decl);
    }

    return buildSpecFromDecls(allocator, decls.items);
}

fn parseOperatorDecl(
    allocator: std.mem.Allocator,
    id_text: []const u8,
    obj: std.json.ObjectMap,
    expect_id_field: bool,
) !OperatorDecl {
    try helpers.validateOperatorId(id_text);
    const run_text = try helpers.expectNonEmptyString(obj, "run");
    if (!helpers.isAllowedOperator(run_text)) return error.OperatorNotAllowed;
    try ensureOperatorKeys(obj, run_text, expect_id_field);

    const inputs = try helpers.parseStringArrayField(allocator, obj, "inputs");
    errdefer helpers.freeOwnedStrings(allocator, inputs);
    const outputs = try helpers.parseStringArrayField(allocator, obj, "outputs");
    errdefer helpers.freeOwnedStrings(allocator, outputs);
    const flags = if (obj.get("flags")) |_| try helpers.parseStringArrayField(allocator, obj, "flags") else try allocator.alloc([]u8, 0);
    errdefer helpers.freeOwnedStrings(allocator, flags);

    for (inputs) |path| try helpers.validateWorkspaceRelativePath(path);
    for (outputs) |path| try helpers.validateWorkspaceRelativePath(path);

    var archive_format: model.ArchiveFormat = .tar;
    if (std.mem.eql(u8, run_text, "knx.archive.pack")) {
        if (obj.get("format")) |format_value| {
            const format_text = try helpers.expectString(format_value, "archive format");
            archive_format = helpers.parseArchiveFormat(format_text) orelse return error.ValueInvalid;
        }
    }

    if (std.mem.eql(u8, run_text, "knx.fs.copy")) {
        if (inputs.len != 1 or outputs.len != 1) return error.InvalidBuildGraph;
        if (flags.len != 0) return error.ValueInvalid;
    } else if (std.mem.eql(u8, run_text, "knx.c.compile")) {
        if (inputs.len < 1 or outputs.len != 1) return error.InvalidBuildGraph;
        for (flags) |flag| {
            if (!helpers.isAllowedCompileArg(flag)) return error.ValueInvalid;
        }
    } else if (std.mem.eql(u8, run_text, "knx.zig.link")) {
        if (inputs.len < 1 or outputs.len != 1) return error.InvalidBuildGraph;
        for (flags) |flag| {
            if (!helpers.isAllowedLinkArg(flag)) return error.ValueInvalid;
        }
    } else if (std.mem.eql(u8, run_text, "knx.archive.pack")) {
        if (inputs.len < 1 or outputs.len != 1) return error.InvalidBuildGraph;
        if (flags.len != 0) return error.ValueInvalid;
    } else {
        return error.OperatorNotAllowed;
    }

    return .{
        .id = try allocator.dupe(u8, id_text),
        .run = try allocator.dupe(u8, run_text),
        .inputs = inputs,
        .outputs = outputs,
        .flags = flags,
        .archive_format = archive_format,
    };
}

fn buildSpecFromDecls(allocator: std.mem.Allocator, decls: []const OperatorDecl) !model.BuildSpec {
    var output_producers: std.StringHashMap(usize) = .init(allocator);
    defer output_producers.deinit();
    for (decls, 0..) |decl, idx| {
        for (decl.outputs) |output_path| {
            const gop = try output_producers.getOrPut(output_path);
            if (gop.found_existing) return error.InvalidBuildGraph;
            gop.value_ptr.* = idx;
        }
    }

    const count = decls.len;
    var adjacency = try allocator.alloc(std.ArrayList(usize), count);
    defer {
        for (adjacency) |*edges| edges.deinit(allocator);
        allocator.free(adjacency);
    }
    for (adjacency) |*edges| edges.* = .empty;

    var indegree = try allocator.alloc(usize, count);
    defer allocator.free(indegree);
    @memset(indegree, 0);

    for (decls, 0..) |decl, idx| {
        for (decl.inputs) |input_path| {
            const producer = output_producers.get(input_path) orelse continue;
            if (producer == idx) return error.InvalidBuildGraph;
            if (!helpers.containsIndex(adjacency[producer].items, idx)) {
                try adjacency[producer].append(allocator, idx);
                indegree[idx] += 1;
            }
        }
    }

    var queue: std.ArrayList(usize) = .empty;
    defer queue.deinit(allocator);
    for (indegree, 0..) |deg, idx| {
        if (deg == 0) try queue.append(allocator, idx);
    }

    var ordered: std.ArrayList(usize) = .empty;
    defer ordered.deinit(allocator);
    var head: usize = 0;
    while (head < queue.items.len) : (head += 1) {
        const idx = queue.items[head];
        try ordered.append(allocator, idx);
        for (adjacency[idx].items) |next_idx| {
            indegree[next_idx] -= 1;
            if (indegree[next_idx] == 0) {
                try queue.append(allocator, next_idx);
            }
        }
    }
    if (ordered.items.len != count) return error.InvalidBuildGraph;

    var ops: std.ArrayList(model.BuildOp) = .empty;
    errdefer {
        for (ops.items) |*op| op.deinit(allocator);
        ops.deinit(allocator);
    }

    for (ordered.items) |idx| {
        const decl = decls[idx];
        if (std.mem.eql(u8, decl.run, "knx.fs.copy")) {
            try ops.append(allocator, .{
                .fs_copy = .{
                    .from_path = try allocator.dupe(u8, decl.inputs[0]),
                    .to_path = try allocator.dupe(u8, decl.outputs[0]),
                },
            });
            continue;
        }
        if (std.mem.eql(u8, decl.run, "knx.c.compile")) {
            try ops.append(allocator, .{
                .c_compile = .{
                    .src_path = try allocator.dupe(u8, decl.inputs[0]),
                    .out_path = try allocator.dupe(u8, decl.outputs[0]),
                    .args = try helpers.dupeStringSlice(allocator, decl.flags),
                },
            });
            continue;
        }
        if (std.mem.eql(u8, decl.run, "knx.zig.link")) {
            try ops.append(allocator, .{
                .zig_link = .{
                    .object_paths = try helpers.dupeStringSlice(allocator, decl.inputs),
                    .out_path = try allocator.dupe(u8, decl.outputs[0]),
                    .args = try helpers.dupeStringSlice(allocator, decl.flags),
                },
            });
            continue;
        }
        if (std.mem.eql(u8, decl.run, "knx.archive.pack")) {
            try ops.append(allocator, .{
                .archive_pack = .{
                    .input_paths = try helpers.dupeStringSlice(allocator, decl.inputs),
                    .out_path = try allocator.dupe(u8, decl.outputs[0]),
                    .format = decl.archive_format,
                },
            });
            continue;
        }
        return error.OperatorNotAllowed;
    }

    return .{
        .ops = try ops.toOwnedSlice(allocator),
    };
}

fn lessThanString(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.lessThan(u8, a, b);
}
