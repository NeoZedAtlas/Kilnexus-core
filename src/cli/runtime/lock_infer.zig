const std = @import("std");
const parse_errors = @import("../../parser/parse_errors.zig");
const abi_parser = @import("../../parser/abi_parser.zig");
const validator = @import("../../knx/validator.zig");
const glob = @import("../../bootstrap/workspace/glob.zig");

const CompileUnit = struct {
    id: []u8,
    source_path: []u8,
    object_path: []u8,

    fn deinit(self: *CompileUnit, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.source_path);
        allocator.free(self.object_path);
        self.* = undefined;
    }
};

const OutputIntent = struct {
    source: []const u8,
    publish_as: []const u8,
    mode: []const u8,
};

const Profile = enum {
    c_app,
    c_lib,
    c_shared,
};

const FieldError = error{
    MissingField,
    TypeMismatch,
    ValueInvalid,
    VersionUnsupported,
    OperatorDisallowed,
    OutputInvalid,
    Internal,
};

pub const current_intent_version: i64 = 1;

pub fn inferLockCanonicalJsonFromIntentCanonical(
    allocator: std.mem.Allocator,
    canonical_intent: []const u8,
) parse_errors.ParseError![]u8 {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, canonical_intent, .{}) catch |err| {
        return parse_errors.normalizeName(@errorName(err));
    };
    defer parsed.deinit();

    const root = expectObject(parsed.value) catch |err| return mapFieldError(err);
    const version = expectIntegerField(root, "version") catch |err| return mapFieldError(err);
    if (version != current_intent_version) return error.VersionUnsupported;

    const profile_text = expectStringField(root, "profile") catch |err| return mapFieldError(err);
    const profile = parseProfile(profile_text) catch |err| return mapFieldError(err);

    const target = expectStringField(root, "target") catch |err| return mapFieldError(err);
    const toolchain = expectObjectField(root, "toolchain") catch |err| return mapFieldError(err);
    const policy = expectObjectField(root, "policy") catch |err| return mapFieldError(err);
    const env = expectObjectField(root, "env") catch |err| return mapFieldError(err);
    const sources = expectObjectField(root, "sources") catch |err| return mapFieldError(err);
    const build = expectObjectField(root, "build") catch |err| return mapFieldError(err);

    const toolchain_id = expectStringField(toolchain, "id") catch |err| return mapFieldError(err);
    const toolchain_source = expectStringField(toolchain, "source") catch |err| return mapFieldError(err);
    const toolchain_blob = expectStringField(toolchain, "blob_sha256") catch |err| return mapFieldError(err);
    const toolchain_tree = expectStringField(toolchain, "tree_root") catch |err| return mapFieldError(err);
    const toolchain_size = expectIntegerField(toolchain, "size") catch |err| return mapFieldError(err);
    if (toolchain_size <= 0) return error.ValueInvalid;

    const policy_network = expectStringField(policy, "network") catch |err| return mapFieldError(err);
    const policy_verify_mode = expectStringField(policy, "verify_mode") catch |err| return mapFieldError(err);
    const policy_clock = expectStringField(policy, "clock") catch |err| return mapFieldError(err);
    const env_tz = expectStringField(env, "TZ") catch |err| return mapFieldError(err);
    const env_lang = expectStringField(env, "LANG") catch |err| return mapFieldError(err);
    const env_source_date_epoch = expectStringField(env, "SOURCE_DATE_EPOCH") catch |err| return mapFieldError(err);

    const include_patterns = parseStringArrayDup(allocator, sources, "include") catch |err| return mapFieldError(err);
    defer freeOwnedStrings(allocator, include_patterns);
    if (include_patterns.len == 0) return error.MissingField;
    ensureOnlyKeys(sources, &.{ "include", "exclude" }) catch |err| return mapFieldError(err);

    const exclude_patterns = parseOptionalStringArrayDup(allocator, sources, "exclude") catch |err| return mapFieldError(err);
    defer freeOwnedStrings(allocator, exclude_patterns);
    validateBuildFieldSet(profile, build) catch |err| return mapFieldError(err);

    const entry_host_path = switch (profile) {
        .c_app => blk: {
            const path = expectStringField(build, "entry") catch |err| return mapFieldError(err);
            if (!std.mem.endsWith(u8, path, ".c")) return error.ValueInvalid;
            if (!isValidWorkspacePath(path)) return error.ValueInvalid;
            break :blk path;
        },
        .c_lib, .c_shared => null,
    };

    const c_std = if (build.get("c_std")) |value| blk: {
        const text = expectString(value) catch |err| return mapFieldError(err);
        if (!isAllowedCStd(text)) return error.ValueInvalid;
        break :blk text;
    } else "c11";

    const opt = if (build.get("opt")) |value| blk: {
        const text = expectString(value) catch |err| return mapFieldError(err);
        if (!isAllowedOpt(text)) return error.ValueInvalid;
        break :blk text;
    } else "O2";

    var defines = parseOptionalStringArrayBorrow(allocator, build, "defines") catch |err| return mapFieldError(err);
    defer defines.deinit(allocator);
    var include_dirs = parseOptionalStringArrayBorrow(allocator, build, "include_dirs") catch |err| return mapFieldError(err);
    defer include_dirs.deinit(allocator);
    var link_flags = parseOptionalStringArrayBorrow(allocator, build, "link") catch |err| return mapFieldError(err);
    defer link_flags.deinit(allocator);
    const archive_format = if (build.get("archive_format")) |value| blk: {
        const text = expectString(value) catch |err| return mapFieldError(err);
        if (!std.mem.eql(u8, text, "tar") and !std.mem.eql(u8, text, "tar.gz")) return error.ValueInvalid;
        break :blk text;
    } else "tar";

    switch (profile) {
        .c_app => {},
        .c_lib => if (link_flags.items.len != 0) return error.ValueInvalid,
        .c_shared => {},
    }

    for (defines.items) |define| {
        if (!isValidDefine(define)) return error.ValueInvalid;
        const flag = std.fmt.allocPrint(allocator, "-D{s}", .{define}) catch return error.Internal;
        defer allocator.free(flag);
        if (!validatorHelperIsAllowedCompileArg(flag)) return error.ValueInvalid;
    }
    for (include_dirs.items) |include_dir| {
        if (!isValidWorkspacePath(include_dir)) return error.ValueInvalid;
        const flag = std.fmt.allocPrint(allocator, "-Isrc/{s}", .{include_dir}) catch return error.Internal;
        defer allocator.free(flag);
        if (!validatorHelperIsAllowedCompileArg(flag)) return error.ValueInvalid;
    }
    for (link_flags.items) |flag| {
        if (!isAllowedLinkArg(flag)) return error.ValueInvalid;
    }

    const outputs_array = expectArrayField(root, "outputs") catch |err| return mapFieldError(err);
    if (outputs_array.items.len == 0) return error.OutputInvalid;
    var outputs: std.ArrayList(OutputIntent) = .empty;
    defer outputs.deinit(allocator);
    for (outputs_array.items) |item| {
        const obj = expectObject(item) catch |err| return mapFieldError(err);
        const source = expectStringField(obj, "source") catch |err| return mapFieldError(err);
        const publish_as = expectStringField(obj, "publish_as") catch |err| return mapFieldError(err);
        const mode = expectStringField(obj, "mode") catch |err| return mapFieldError(err);
        if (!isValidWorkspacePath(source)) return error.OutputInvalid;
        if (!isValidPublishName(publish_as)) return error.OutputInvalid;
        if (!isValidMode(mode)) return error.OutputInvalid;
        outputs.append(allocator, .{ .source = source, .publish_as = publish_as, .mode = mode }) catch return error.Internal;
    }

    // Expand sources through the existing workspace glob expander.
    const local_input: validator.LocalInputSpec = .{
        .id = allocator.dupe(u8, "knx-src") catch return error.Internal,
        .include = include_patterns,
        .exclude = exclude_patterns,
    };
    defer allocator.free(local_input.id);
    const expanded_files = glob.expandLocalInputMatches(allocator, local_input) catch |err| {
        return parse_errors.normalizeName(@errorName(err));
    };
    defer freeOwnedStrings(allocator, expanded_files);
    if (expanded_files.len == 0) return error.ValueInvalid;

    var compile_units: std.ArrayList(CompileUnit) = .empty;
    defer {
        for (compile_units.items) |*unit| unit.deinit(allocator);
        compile_units.deinit(allocator);
    }

    var entry_found = false;
    for (expanded_files, 0..) |host_rel_path, idx| {
        if (entry_host_path) |entry| {
            if (std.mem.eql(u8, host_rel_path, entry)) entry_found = true;
        }
        if (!std.mem.endsWith(u8, host_rel_path, ".c")) continue;

        const source_path = std.fmt.allocPrint(allocator, "src/{s}", .{host_rel_path}) catch return error.Internal;
        errdefer allocator.free(source_path);
        const object_name = objectNameFromPath(allocator, host_rel_path) catch return error.Internal;
        defer allocator.free(object_name);
        const object_path = std.fmt.allocPrint(allocator, "obj/{s}.o", .{object_name}) catch return error.Internal;
        errdefer allocator.free(object_path);
        const op_id = std.fmt.allocPrint(allocator, "compile-{d}", .{idx + 1}) catch return error.Internal;
        errdefer allocator.free(op_id);

        compile_units.append(allocator, .{
            .id = op_id,
            .source_path = source_path,
            .object_path = object_path,
        }) catch return error.Internal;
    }

    if (compile_units.items.len == 0) return error.ValueInvalid;
    if (profile == .c_app and !entry_found) return error.ValueInvalid;

    const generated_lock_json = buildV1LockJson(allocator, .{
        .profile = profile,
        .target = target,
        .toolchain_id = toolchain_id,
        .toolchain_source = toolchain_source,
        .toolchain_blob = toolchain_blob,
        .toolchain_tree = toolchain_tree,
        .toolchain_size = @intCast(toolchain_size),
        .policy_network = policy_network,
        .policy_verify_mode = policy_verify_mode,
        .policy_clock = policy_clock,
        .env_tz = env_tz,
        .env_lang = env_lang,
        .env_source_date_epoch = env_source_date_epoch,
        .include_patterns = include_patterns,
        .exclude_patterns = exclude_patterns,
        .expanded_files = expanded_files,
        .compile_opt = opt,
        .compile_std = c_std,
        .defines = defines.items,
        .include_dirs = include_dirs.items,
        .link_flags = link_flags.items,
        .archive_format = archive_format,
        .compile_units = compile_units.items,
        .outputs = outputs.items,
    }) catch |err| return parse_errors.normalizeName(@errorName(err));
    defer allocator.free(generated_lock_json);

    const parsed_lock = abi_parser.parseLockfileStrict(allocator, generated_lock_json) catch |err| return err;
    return parsed_lock.canonical_json;
}

const BuildV1Input = struct {
    profile: Profile,
    target: []const u8,
    toolchain_id: []const u8,
    toolchain_source: []const u8,
    toolchain_blob: []const u8,
    toolchain_tree: []const u8,
    toolchain_size: u64,
    policy_network: []const u8,
    policy_verify_mode: []const u8,
    policy_clock: []const u8,
    env_tz: []const u8,
    env_lang: []const u8,
    env_source_date_epoch: []const u8,
    include_patterns: [][]u8,
    exclude_patterns: [][]u8,
    expanded_files: [][]u8,
    compile_opt: []const u8,
    compile_std: []const u8,
    defines: []const []const u8,
    include_dirs: []const []const u8,
    link_flags: []const []const u8,
    archive_format: []const u8,
    compile_units: []const CompileUnit,
    outputs: []const OutputIntent,
};

fn buildV1LockJson(allocator: std.mem.Allocator, input: BuildV1Input) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    var out_writer = out.writer(allocator);
    var out_buffer: [32 * 1024]u8 = undefined;
    var out_adapter = out_writer.adaptToNewApi(&out_buffer);
    const writer = &out_adapter.new_interface;

    try writer.writeAll("{\"version\":1");

    try writer.writeAll(",\"target\":");
    try std.json.Stringify.encodeJsonString(input.target, .{}, writer);

    try writer.writeAll(",\"toolchain\":{");
    try writer.writeAll("\"id\":");
    try std.json.Stringify.encodeJsonString(input.toolchain_id, .{}, writer);
    try writer.writeAll(",\"source\":");
    try std.json.Stringify.encodeJsonString(input.toolchain_source, .{}, writer);
    try writer.writeAll(",\"blob_sha256\":");
    try std.json.Stringify.encodeJsonString(input.toolchain_blob, .{}, writer);
    try writer.writeAll(",\"tree_root\":");
    try std.json.Stringify.encodeJsonString(input.toolchain_tree, .{}, writer);
    try writer.writeAll(",\"size\":");
    try writer.print("{d}", .{input.toolchain_size});
    try writer.writeAll("}");

    try writer.writeAll(",\"policy\":{");
    try writer.writeAll("\"network\":");
    try std.json.Stringify.encodeJsonString(input.policy_network, .{}, writer);
    try writer.writeAll(",\"verify_mode\":");
    try std.json.Stringify.encodeJsonString(input.policy_verify_mode, .{}, writer);
    try writer.writeAll(",\"clock\":");
    try std.json.Stringify.encodeJsonString(input.policy_clock, .{}, writer);
    try writer.writeAll("}");

    try writer.writeAll(",\"env\":{");
    try writer.writeAll("\"TZ\":");
    try std.json.Stringify.encodeJsonString(input.env_tz, .{}, writer);
    try writer.writeAll(",\"LANG\":");
    try std.json.Stringify.encodeJsonString(input.env_lang, .{}, writer);
    try writer.writeAll(",\"SOURCE_DATE_EPOCH\":");
    try std.json.Stringify.encodeJsonString(input.env_source_date_epoch, .{}, writer);
    try writer.writeAll("}");

    try writer.writeAll(",\"inputs\":{\"local\":[{\"id\":\"knx-src\",\"include\":[");
    for (input.include_patterns, 0..) |pattern, i| {
        if (i != 0) try writer.writeAll(",");
        try std.json.Stringify.encodeJsonString(pattern, .{}, writer);
    }
    try writer.writeAll("]");
    if (input.exclude_patterns.len > 0) {
        try writer.writeAll(",\"exclude\":[");
        for (input.exclude_patterns, 0..) |pattern, i| {
            if (i != 0) try writer.writeAll(",");
            try std.json.Stringify.encodeJsonString(pattern, .{}, writer);
        }
        try writer.writeAll("]");
    }
    try writer.writeAll("}]}");

    try writer.writeAll(",\"workspace\":{\"mounts\":[");
    for (input.expanded_files, 0..) |host_rel, i| {
        if (i != 0) try writer.writeAll(",");
        const source_ref = try std.fmt.allocPrint(allocator, "knx-src/{s}", .{host_rel});
        defer allocator.free(source_ref);
        const target_ref = try std.fmt.allocPrint(allocator, "src/{s}", .{host_rel});
        defer allocator.free(target_ref);
        try writer.writeAll("{\"source\":");
        try std.json.Stringify.encodeJsonString(source_ref, .{}, writer);
        try writer.writeAll(",\"target\":");
        try std.json.Stringify.encodeJsonString(target_ref, .{}, writer);
        try writer.writeAll(",\"mode\":\"0444\"}");
    }
    try writer.writeAll("]}");

    try writer.writeAll(",\"operators\":[");
    for (input.compile_units, 0..) |unit, i| {
        if (i != 0) try writer.writeAll(",");
        try writer.writeAll("{\"id\":");
        try std.json.Stringify.encodeJsonString(unit.id, .{}, writer);
        try writer.writeAll(",\"run\":\"knx.c.compile\",\"inputs\":[");
        try std.json.Stringify.encodeJsonString(unit.source_path, .{}, writer);
        try writer.writeAll("],\"outputs\":[");
        try std.json.Stringify.encodeJsonString(unit.object_path, .{}, writer);
        try writer.writeAll("],\"flags\":[");

        const opt_flag = try std.fmt.allocPrint(allocator, "-{s}", .{input.compile_opt});
        defer allocator.free(opt_flag);
        const std_flag = try std.fmt.allocPrint(allocator, "-std={s}", .{input.compile_std});
        defer allocator.free(std_flag);

        try std.json.Stringify.encodeJsonString(opt_flag, .{}, writer);
        try writer.writeAll(",");
        try std.json.Stringify.encodeJsonString(std_flag, .{}, writer);

        for (input.defines) |define| {
            const define_flag = try std.fmt.allocPrint(allocator, "-D{s}", .{define});
            defer allocator.free(define_flag);
            try writer.writeAll(",");
            try std.json.Stringify.encodeJsonString(define_flag, .{}, writer);
        }
        for (input.include_dirs) |include_dir| {
            const include_flag = try std.fmt.allocPrint(allocator, "-Isrc/{s}", .{include_dir});
            defer allocator.free(include_flag);
            try writer.writeAll(",");
            try std.json.Stringify.encodeJsonString(include_flag, .{}, writer);
        }
        try writer.writeAll("]}");
    }

    try writer.writeAll(",");
    switch (input.profile) {
        .c_app => {
            try writer.writeAll("{\"id\":\"link-final\",\"run\":\"knx.zig.link\",\"inputs\":[");
            for (input.compile_units, 0..) |unit, i| {
                if (i != 0) try writer.writeAll(",");
                try std.json.Stringify.encodeJsonString(unit.object_path, .{}, writer);
            }
            try writer.writeAll("],\"outputs\":[");
            try std.json.Stringify.encodeJsonString(input.outputs[0].source, .{}, writer);
            try writer.writeAll("]");
            if (input.link_flags.len > 0) {
                try writer.writeAll(",\"flags\":[");
                for (input.link_flags, 0..) |flag, i| {
                    if (i != 0) try writer.writeAll(",");
                    try std.json.Stringify.encodeJsonString(flag, .{}, writer);
                }
                try writer.writeAll("]");
            }
            try writer.writeAll("}");
        },
        .c_lib => {
            try writer.writeAll("{\"id\":\"archive-final\",\"run\":\"knx.archive.pack\",\"inputs\":[");
            for (input.compile_units, 0..) |unit, i| {
                if (i != 0) try writer.writeAll(",");
                try std.json.Stringify.encodeJsonString(unit.object_path, .{}, writer);
            }
            try writer.writeAll("],\"outputs\":[");
            try std.json.Stringify.encodeJsonString(input.outputs[0].source, .{}, writer);
            try writer.writeAll("]");
            if (!std.mem.eql(u8, input.archive_format, "tar")) {
                try writer.writeAll(",\"format\":");
                try std.json.Stringify.encodeJsonString(input.archive_format, .{}, writer);
            }
            try writer.writeAll("}");
        },
        .c_shared => {
            try writer.writeAll("{\"id\":\"link-shared\",\"run\":\"knx.zig.link\",\"inputs\":[");
            for (input.compile_units, 0..) |unit, i| {
                if (i != 0) try writer.writeAll(",");
                try std.json.Stringify.encodeJsonString(unit.object_path, .{}, writer);
            }
            try writer.writeAll("],\"outputs\":[");
            try std.json.Stringify.encodeJsonString(input.outputs[0].source, .{}, writer);
            try writer.writeAll("],\"flags\":[");
            try std.json.Stringify.encodeJsonString("-shared", .{}, writer);
            for (input.link_flags) |flag| {
                try writer.writeAll(",");
                try std.json.Stringify.encodeJsonString(flag, .{}, writer);
            }
            try writer.writeAll("]}");
        },
    }

    for (input.outputs[1..], 0..) |entry, copy_idx| {
        if (std.mem.eql(u8, entry.source, input.outputs[0].source)) continue;
        try writer.writeAll(",{\"id\":");
        const copy_id = try std.fmt.allocPrint(allocator, "copy-output-{d}", .{copy_idx + 1});
        defer allocator.free(copy_id);
        try std.json.Stringify.encodeJsonString(copy_id, .{}, writer);
        try writer.writeAll(",\"run\":\"knx.fs.copy\",\"inputs\":[");
        try std.json.Stringify.encodeJsonString(input.outputs[0].source, .{}, writer);
        try writer.writeAll("],\"outputs\":[");
        try std.json.Stringify.encodeJsonString(entry.source, .{}, writer);
        try writer.writeAll("]}");
    }
    try writer.writeAll("]");

    try writer.writeAll(",\"outputs\":[");
    for (input.outputs, 0..) |entry, i| {
        if (i != 0) try writer.writeAll(",");
        try writer.writeAll("{\"source\":");
        try std.json.Stringify.encodeJsonString(entry.source, .{}, writer);
        try writer.writeAll(",\"publish_as\":");
        try std.json.Stringify.encodeJsonString(entry.publish_as, .{}, writer);
        try writer.writeAll(",\"mode\":");
        try std.json.Stringify.encodeJsonString(entry.mode, .{}, writer);
        try writer.writeAll("}");
    }
    try writer.writeAll("]}");

    try writer.flush();
    return out.toOwnedSlice(allocator);
}

fn parseStringArrayDup(allocator: std.mem.Allocator, object: std.json.ObjectMap, key: []const u8) FieldError![][]u8 {
    const array = expectArrayField(object, key) catch return error.MissingField;
    var out: std.ArrayList([]u8) = .empty;
    errdefer {
        for (out.items) |item| allocator.free(item);
        out.deinit(allocator);
    }
    for (array.items) |item| {
        const text = expectString(item) catch return error.TypeMismatch;
        if (text.len == 0) return error.ValueInvalid;
        const dup = allocator.dupe(u8, text) catch return error.Internal;
        out.append(allocator, dup) catch return error.Internal;
    }
    return out.toOwnedSlice(allocator) catch return error.Internal;
}

fn parseOptionalStringArrayDup(allocator: std.mem.Allocator, object: std.json.ObjectMap, key: []const u8) FieldError![][]u8 {
    const value = object.get(key) orelse {
        return allocator.alloc([]u8, 0) catch return error.Internal;
    };
    const array = expectArray(value) catch return error.TypeMismatch;
    var out: std.ArrayList([]u8) = .empty;
    errdefer {
        for (out.items) |item| allocator.free(item);
        out.deinit(allocator);
    }
    for (array.items) |item| {
        const text = expectString(item) catch return error.TypeMismatch;
        if (text.len == 0) return error.ValueInvalid;
        const dup = allocator.dupe(u8, text) catch return error.Internal;
        out.append(allocator, dup) catch return error.Internal;
    }
    return out.toOwnedSlice(allocator) catch return error.Internal;
}

fn parseOptionalStringArrayBorrow(allocator: std.mem.Allocator, object: std.json.ObjectMap, key: []const u8) FieldError!std.ArrayList([]const u8) {
    const value = object.get(key) orelse return .empty;
    const array = expectArray(value) catch return error.TypeMismatch;
    var out: std.ArrayList([]const u8) = .empty;
    errdefer out.deinit(allocator);
    for (array.items) |item| {
        const text = expectString(item) catch return error.TypeMismatch;
        if (text.len == 0) return error.ValueInvalid;
        out.append(allocator, text) catch return error.Internal;
    }
    return out;
}

fn objectNameFromPath(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(path, &digest, .{});
    const hex = std.fmt.bytesToHex(digest[0..8], .lower);
    return allocator.dupe(u8, &hex);
}

fn freeOwnedStrings(allocator: std.mem.Allocator, items: [][]u8) void {
    for (items) |item| allocator.free(item);
    allocator.free(items);
}

fn expectObjectField(object: std.json.ObjectMap, key: []const u8) FieldError!std.json.ObjectMap {
    const value = object.get(key) orelse return error.MissingField;
    return expectObject(value);
}

fn expectArrayField(object: std.json.ObjectMap, key: []const u8) FieldError!std.json.Array {
    const value = object.get(key) orelse return error.MissingField;
    return expectArray(value);
}

fn expectObject(value: std.json.Value) FieldError!std.json.ObjectMap {
    return switch (value) {
        .object => |obj| obj,
        else => error.TypeMismatch,
    };
}

fn expectArray(value: std.json.Value) FieldError!std.json.Array {
    return switch (value) {
        .array => |arr| arr,
        else => error.TypeMismatch,
    };
}

fn expectString(value: std.json.Value) FieldError![]const u8 {
    return switch (value) {
        .string => |text| text,
        else => error.TypeMismatch,
    };
}

fn expectStringField(object: std.json.ObjectMap, key: []const u8) FieldError![]const u8 {
    const value = object.get(key) orelse return error.MissingField;
    const text = try expectString(value);
    if (text.len == 0) return error.ValueInvalid;
    return text;
}

fn expectIntegerField(object: std.json.ObjectMap, key: []const u8) FieldError!i64 {
    const value = object.get(key) orelse return error.MissingField;
    return switch (value) {
        .integer => |num| num,
        else => error.TypeMismatch,
    };
}

fn isAllowedCStd(value: []const u8) bool {
    return std.mem.eql(u8, value, "c89") or
        std.mem.eql(u8, value, "c99") or
        std.mem.eql(u8, value, "c11") or
        std.mem.eql(u8, value, "c17");
}

fn isAllowedOpt(value: []const u8) bool {
    return std.mem.eql(u8, value, "O0") or
        std.mem.eql(u8, value, "O1") or
        std.mem.eql(u8, value, "O2") or
        std.mem.eql(u8, value, "O3") or
        std.mem.eql(u8, value, "Os") or
        std.mem.eql(u8, value, "Oz");
}

fn isAllowedLinkArg(arg: []const u8) bool {
    const allowed = [_][]const u8{
        "-shared",
        "-static",
        "-s",
        "-Wl,--gc-sections",
        "-Wl,--strip-all",
    };
    for (allowed) |item| {
        if (std.mem.eql(u8, arg, item)) return true;
    }
    if (std.mem.startsWith(u8, arg, "-Wl,-soname,")) {
        const soname = arg["-Wl,-soname,".len..];
        return isValidPublishName(soname);
    }
    return false;
}

fn validatorHelperIsAllowedCompileArg(arg: []const u8) bool {
    // Mirror validator behavior to fail fast before writing lock.
    const exact = [_][]const u8{
        "-O0",      "-O1",      "-O2",      "-O3",     "-Os",     "-Oz",
        "-g",       "-g0",      "-Wall",    "-Wextra", "-Werror", "-std=c89",
        "-std=c99", "-std=c11", "-std=c17",
    };
    for (exact) |item| if (std.mem.eql(u8, arg, item)) return true;
    if (std.mem.startsWith(u8, arg, "-D")) return isValidDefine(arg[2..]);
    if (std.mem.startsWith(u8, arg, "-I")) return isValidWorkspacePath(arg[2..]);
    return false;
}

fn isValidDefine(value: []const u8) bool {
    if (value.len == 0) return false;
    for (value) |ch| {
        if (std.ascii.isAlphanumeric(ch)) continue;
        switch (ch) {
            '_', '=', '.', '-', ':' => continue,
            else => return false,
        }
    }
    return true;
}

fn isValidWorkspacePath(path: []const u8) bool {
    if (path.len == 0) return false;
    if (std.fs.path.isAbsolute(path)) return false;
    if (std.mem.indexOfScalar(u8, path, '\\') != null) return false;
    if (std.mem.indexOfScalar(u8, path, ':') != null) return false;
    var it = std.mem.splitScalar(u8, path, '/');
    while (it.next()) |segment| {
        if (segment.len == 0 or std.mem.eql(u8, segment, ".") or std.mem.eql(u8, segment, "..")) return false;
    }
    return true;
}

fn isValidPublishName(path: []const u8) bool {
    if (path.len == 0) return false;
    if (std.fs.path.isAbsolute(path)) return false;
    if (std.mem.indexOfScalar(u8, path, '\\') != null) return false;
    if (std.mem.indexOfScalar(u8, path, ':') != null) return false;
    var it = std.mem.splitScalar(u8, path, '/');
    while (it.next()) |segment| {
        if (segment.len == 0 or std.mem.eql(u8, segment, ".") or std.mem.eql(u8, segment, "..")) return false;
    }
    return true;
}

fn isValidMode(mode: []const u8) bool {
    if (mode.len != 4) return false;
    if (mode[0] != '0') return false;
    for (mode[1..]) |ch| {
        if (ch < '0' or ch > '7') return false;
    }
    return true;
}

fn mapFieldError(err: anyerror) parse_errors.ParseError {
    return parse_errors.normalizeName(@errorName(err));
}

fn parseProfile(text: []const u8) FieldError!Profile {
    if (std.mem.eql(u8, text, "c.app")) return .c_app;
    if (std.mem.eql(u8, text, "c.lib")) return .c_lib;
    if (std.mem.eql(u8, text, "c.shared")) return .c_shared;
    return error.OperatorDisallowed;
}

fn validateBuildFieldSet(profile: Profile, build: std.json.ObjectMap) FieldError!void {
    const keys_c_app = [_][]const u8{ "entry", "c_std", "opt", "defines", "include_dirs", "link" };
    const keys_c_lib = [_][]const u8{ "c_std", "opt", "defines", "include_dirs", "archive_format" };
    const keys_c_shared = [_][]const u8{ "c_std", "opt", "defines", "include_dirs", "link" };
    const allowed: []const []const u8 = switch (profile) {
        .c_app => keys_c_app[0..],
        .c_lib => keys_c_lib[0..],
        .c_shared => keys_c_shared[0..],
    };
    try ensureOnlyKeys(build, allowed);
}

fn ensureOnlyKeys(object: std.json.ObjectMap, allowed: []const []const u8) FieldError!void {
    var it = object.iterator();
    while (it.next()) |entry| {
        var found = false;
        for (allowed) |key| {
            if (std.mem.eql(u8, entry.key_ptr.*, key)) {
                found = true;
                break;
            }
        }
        if (!found) return error.ValueInvalid;
    }
}

test "inferLockCanonicalJsonFromIntentCanonical builds v1 lock for c.app" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("proj/src");
    try tmp.dir.makePath("proj/include");
    try tmp.dir.writeFile(.{ .sub_path = "proj/src/main.c", .data = "int main(void){return 0;}\n" });
    try tmp.dir.writeFile(.{ .sub_path = "proj/src/util.c", .data = "int util(void){return 1;}\n" });
    try tmp.dir.writeFile(.{ .sub_path = "proj/include/util.h", .data = "#pragma once\n" });

    const include_pat = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/proj/src/*.c", .{tmp.sub_path[0..]});
    defer allocator.free(include_pat);
    const main_rel = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/proj/src/main.c", .{tmp.sub_path[0..]});
    defer allocator.free(main_rel);

    const source_intent = try std.fmt.allocPrint(
        allocator,
        \\#!knxfile
        \\version = 1
        \\profile = "c.app"
        \\target = "x86_64-windows-gnu"
        \\
        \\[toolchain]
        \\id = "zigcc-0.15.2-win64"
        \\source = "examples/real-c/toolchain/zig-win-0.15.2.tar.gz"
        \\blob_sha256 = "7672ea8ee561a77a1d69bd716562be8ae594a97c5f053bac05ac4c6d73e1f1da"
        \\tree_root = "dec4aa4dbe7ccaec0bac913f77e69350a53d46096c6529912e987cde018ee1fc"
        \\size = 83562220
        \\
        \\[policy]
        \\network = "off"
        \\verify_mode = "strict"
        \\clock = "fixed"
        \\
        \\[env]
        \\TZ = "UTC"
        \\LANG = "C"
        \\SOURCE_DATE_EPOCH = "1735689600"
        \\
        \\[sources]
        \\include = ["{s}"]
        \\
        \\[build]
        \\entry = "{s}"
        \\c_std = "c11"
        \\opt = "O2"
        \\link = ["-s"]
        \\
        \\[[outputs]]
        \\source = "bin/app.exe"
        \\publish_as = "app.exe"
        \\mode = "0755"
    ,
        .{ include_pat, main_rel },
    );
    defer allocator.free(source_intent);

    const parsed_intent = try abi_parser.parseLockfileStrict(allocator, source_intent);
    defer allocator.free(parsed_intent.canonical_json);

    const lock_json = try inferLockCanonicalJsonFromIntentCanonical(allocator, parsed_intent.canonical_json);
    defer allocator.free(lock_json);

    _ = try validator.validateCanonicalJsonStrict(allocator, lock_json);
    var build_spec = try validator.parseBuildSpecStrict(allocator, lock_json);
    defer build_spec.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 3), build_spec.ops.len);
}

test "inferLockCanonicalJsonFromIntentCanonical builds v1 lock for c.lib" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("proj/src");
    try tmp.dir.writeFile(.{ .sub_path = "proj/src/liba.c", .data = "int a(void){return 1;}\n" });
    try tmp.dir.writeFile(.{ .sub_path = "proj/src/libb.c", .data = "int b(void){return 2;}\n" });

    const include_pat = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/proj/src/*.c", .{tmp.sub_path[0..]});
    defer allocator.free(include_pat);

    const source_intent = try std.fmt.allocPrint(
        allocator,
        \\#!knxfile
        \\version = 1
        \\profile = "c.lib"
        \\target = "x86_64-windows-gnu"
        \\
        \\[toolchain]
        \\id = "zigcc-0.15.2-win64"
        \\source = "examples/real-c/toolchain/zig-win-0.15.2.tar.gz"
        \\blob_sha256 = "7672ea8ee561a77a1d69bd716562be8ae594a97c5f053bac05ac4c6d73e1f1da"
        \\tree_root = "dec4aa4dbe7ccaec0bac913f77e69350a53d46096c6529912e987cde018ee1fc"
        \\size = 83562220
        \\
        \\[policy]
        \\network = "off"
        \\verify_mode = "strict"
        \\clock = "fixed"
        \\
        \\[env]
        \\TZ = "UTC"
        \\LANG = "C"
        \\SOURCE_DATE_EPOCH = "1735689600"
        \\
        \\[sources]
        \\include = ["{s}"]
        \\
        \\[build]
        \\c_std = "c11"
        \\opt = "O2"
        \\archive_format = "tar.gz"
        \\
        \\[[outputs]]
        \\source = "bin/libbundle.tar.gz"
        \\publish_as = "libbundle.tar.gz"
        \\mode = "0644"
    ,
        .{include_pat},
    );
    defer allocator.free(source_intent);

    const parsed_intent = try abi_parser.parseLockfileStrict(allocator, source_intent);
    defer allocator.free(parsed_intent.canonical_json);
    const lock_json = try inferLockCanonicalJsonFromIntentCanonical(allocator, parsed_intent.canonical_json);
    defer allocator.free(lock_json);

    _ = try validator.validateCanonicalJsonStrict(allocator, lock_json);
    var build_spec = try validator.parseBuildSpecStrict(allocator, lock_json);
    defer build_spec.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 3), build_spec.ops.len);
    switch (build_spec.ops[2]) {
        .archive_pack => |pack| try std.testing.expect(pack.format == .tar_gz),
        else => return error.TestUnexpectedResult,
    }
}

test "inferLockCanonicalJsonFromIntentCanonical supports multiple outputs via fs.copy fanout" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("proj/src");
    try tmp.dir.writeFile(.{ .sub_path = "proj/src/main.c", .data = "int main(void){return 0;}\n" });

    const include_pat = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/proj/src/*.c", .{tmp.sub_path[0..]});
    defer allocator.free(include_pat);
    const main_rel = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/proj/src/main.c", .{tmp.sub_path[0..]});
    defer allocator.free(main_rel);

    const source_intent = try std.fmt.allocPrint(
        allocator,
        \\#!knxfile
        \\version = 1
        \\profile = "c.app"
        \\target = "x86_64-windows-gnu"
        \\
        \\[toolchain]
        \\id = "zigcc-0.15.2-win64"
        \\source = "examples/real-c/toolchain/zig-win-0.15.2.tar.gz"
        \\blob_sha256 = "7672ea8ee561a77a1d69bd716562be8ae594a97c5f053bac05ac4c6d73e1f1da"
        \\tree_root = "dec4aa4dbe7ccaec0bac913f77e69350a53d46096c6529912e987cde018ee1fc"
        \\size = 83562220
        \\
        \\[policy]
        \\network = "off"
        \\verify_mode = "strict"
        \\clock = "fixed"
        \\
        \\[env]
        \\TZ = "UTC"
        \\LANG = "C"
        \\SOURCE_DATE_EPOCH = "1735689600"
        \\
        \\[sources]
        \\include = ["{s}"]
        \\
        \\[build]
        \\entry = "{s}"
        \\c_std = "c11"
        \\opt = "O2"
        \\
        \\[[outputs]]
        \\source = "bin/app.exe"
        \\publish_as = "app.exe"
        \\mode = "0755"
        \\
        \\[[outputs]]
        \\source = "dist/app-copy.exe"
        \\publish_as = "app-copy.exe"
        \\mode = "0755"
    ,
        .{ include_pat, main_rel },
    );
    defer allocator.free(source_intent);

    const parsed_intent = try abi_parser.parseLockfileStrict(allocator, source_intent);
    defer allocator.free(parsed_intent.canonical_json);
    const lock_json = try inferLockCanonicalJsonFromIntentCanonical(allocator, parsed_intent.canonical_json);
    defer allocator.free(lock_json);

    _ = try validator.validateCanonicalJsonStrict(allocator, lock_json);
    var build_spec = try validator.parseBuildSpecStrict(allocator, lock_json);
    defer build_spec.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 3), build_spec.ops.len);
    switch (build_spec.ops[2]) {
        .fs_copy => |copy| {
            try std.testing.expectEqualStrings("bin/app.exe", copy.from_path);
            try std.testing.expectEqualStrings("dist/app-copy.exe", copy.to_path);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "inferLockCanonicalJsonFromIntentCanonical builds v1 lock for c.shared" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("proj/src");
    try tmp.dir.writeFile(.{ .sub_path = "proj/src/liba.c", .data = "int a(void){return 1;}\n" });

    const include_pat = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/proj/src/*.c", .{tmp.sub_path[0..]});
    defer allocator.free(include_pat);

    const source_intent = try std.fmt.allocPrint(
        allocator,
        \\#!knxfile
        \\version = 1
        \\profile = "c.shared"
        \\target = "x86_64-windows-gnu"
        \\
        \\[toolchain]
        \\id = "zigcc-0.15.2-win64"
        \\source = "examples/real-c/toolchain/zig-win-0.15.2.tar.gz"
        \\blob_sha256 = "7672ea8ee561a77a1d69bd716562be8ae594a97c5f053bac05ac4c6d73e1f1da"
        \\tree_root = "dec4aa4dbe7ccaec0bac913f77e69350a53d46096c6529912e987cde018ee1fc"
        \\size = 83562220
        \\
        \\[policy]
        \\network = "off"
        \\verify_mode = "strict"
        \\clock = "fixed"
        \\
        \\[env]
        \\TZ = "UTC"
        \\LANG = "C"
        \\SOURCE_DATE_EPOCH = "1735689600"
        \\
        \\[sources]
        \\include = ["{s}"]
        \\
        \\[build]
        \\c_std = "c11"
        \\opt = "O2"
        \\link = ["-Wl,-soname,libdemo.so"]
        \\
        \\[[outputs]]
        \\source = "bin/libdemo.so"
        \\publish_as = "libdemo.so"
        \\mode = "0755"
    ,
        .{include_pat},
    );
    defer allocator.free(source_intent);

    const parsed_intent = try abi_parser.parseLockfileStrict(allocator, source_intent);
    defer allocator.free(parsed_intent.canonical_json);
    const lock_json = try inferLockCanonicalJsonFromIntentCanonical(allocator, parsed_intent.canonical_json);
    defer allocator.free(lock_json);

    _ = try validator.validateCanonicalJsonStrict(allocator, lock_json);
    var build_spec = try validator.parseBuildSpecStrict(allocator, lock_json);
    defer build_spec.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), build_spec.ops.len);
    switch (build_spec.ops[1]) {
        .zig_link => |link| {
            var found_shared = false;
            for (link.args) |arg| {
                if (std.mem.eql(u8, arg, "-shared")) found_shared = true;
            }
            try std.testing.expect(found_shared);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "inferLockCanonicalJsonFromIntentCanonical rejects profile-incompatible build fields" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("proj/src");
    try tmp.dir.writeFile(.{ .sub_path = "proj/src/liba.c", .data = "int a(void){return 1;}\n" });

    const include_pat = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/proj/src/*.c", .{tmp.sub_path[0..]});
    defer allocator.free(include_pat);

    const source_intent = try std.fmt.allocPrint(
        allocator,
        \\#!knxfile
        \\version = 1
        \\profile = "c.lib"
        \\target = "x86_64-windows-gnu"
        \\
        \\[toolchain]
        \\id = "zigcc-0.15.2-win64"
        \\source = "examples/real-c/toolchain/zig-win-0.15.2.tar.gz"
        \\blob_sha256 = "7672ea8ee561a77a1d69bd716562be8ae594a97c5f053bac05ac4c6d73e1f1da"
        \\tree_root = "dec4aa4dbe7ccaec0bac913f77e69350a53d46096c6529912e987cde018ee1fc"
        \\size = 83562220
        \\
        \\[policy]
        \\network = "off"
        \\verify_mode = "strict"
        \\clock = "fixed"
        \\
        \\[env]
        \\TZ = "UTC"
        \\LANG = "C"
        \\SOURCE_DATE_EPOCH = "1735689600"
        \\
        \\[sources]
        \\include = ["{s}"]
        \\
        \\[build]
        \\entry = "src/main.c"
        \\c_std = "c11"
        \\opt = "O2"
        \\
        \\[[outputs]]
        \\source = "bin/libbundle.tar"
        \\publish_as = "libbundle.tar"
        \\mode = "0644"
    ,
        .{include_pat},
    );
    defer allocator.free(source_intent);

    const parsed_intent = try abi_parser.parseLockfileStrict(allocator, source_intent);
    defer allocator.free(parsed_intent.canonical_json);
    try std.testing.expectError(error.ValueInvalid, inferLockCanonicalJsonFromIntentCanonical(allocator, parsed_intent.canonical_json));
}
