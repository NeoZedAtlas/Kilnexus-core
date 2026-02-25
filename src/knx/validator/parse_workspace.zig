const std = @import("std");
const model = @import("model.zig");
const keys = @import("keys.zig");
const helpers = @import("json_helpers.zig");

pub fn parseWorkspaceSpec(allocator: std.mem.Allocator, canonical_json: []const u8) !model.WorkspaceSpec {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, canonical_json, .{});
    defer parsed.deinit();

    const root = try helpers.expectObject(parsed.value, "root");

    var entries: std.ArrayList(model.WorkspaceEntry) = .empty;
    errdefer {
        for (entries.items) |*entry| entry.deinit(allocator);
        entries.deinit(allocator);
    }

    var local_inputs: std.ArrayList(model.LocalInputSpec) = .empty;
    errdefer {
        for (local_inputs.items) |*input| input.deinit(allocator);
        local_inputs.deinit(allocator);
    }

    var remote_inputs: std.ArrayList(model.RemoteInputSpec) = .empty;
    errdefer {
        for (remote_inputs.items) |*input| input.deinit(allocator);
        remote_inputs.deinit(allocator);
    }

    var mounts: std.ArrayList(model.WorkspaceMountSpec) = .empty;
    errdefer {
        for (mounts.items) |*mount| mount.deinit(allocator);
        mounts.deinit(allocator);
    }

    if (root.get("inputs")) |inputs_value| {
        switch (inputs_value) {
            .array => |inputs| {
                try parseWorkspaceEntries(allocator, &entries, inputs, false);
            },
            .object => |inputs_obj| {
                if (inputs_obj.get("local")) |locals_value| {
                    const locals = try helpers.expectArray(locals_value, "inputs.local");
                    try parseLocalInputs(allocator, &local_inputs, locals);
                }
                if (inputs_obj.get("remote")) |remotes_value| {
                    const remotes = try helpers.expectArray(remotes_value, "inputs.remote");
                    try parseRemoteInputs(allocator, &remote_inputs, remotes);
                }
            },
            else => return error.ExpectedArray,
        }
    }
    if (root.get("deps")) |deps_value| {
        const deps = try helpers.expectArray(deps_value, "deps");
        try parseWorkspaceEntries(allocator, &entries, deps, true);
    }
    if (root.get("workspace")) |workspace_value| {
        const workspace = try helpers.expectObject(workspace_value, "workspace");
        if (workspace.get("mounts")) |mounts_value| {
            const mounts_array = try helpers.expectArray(mounts_value, "workspace.mounts");
            try parseWorkspaceMounts(allocator, &mounts, mounts_array);
        }
    }

    return .{
        .entries = try entries.toOwnedSlice(allocator),
        .local_inputs = try local_inputs.toOwnedSlice(allocator),
        .remote_inputs = try remote_inputs.toOwnedSlice(allocator),
        .mounts = try mounts.toOwnedSlice(allocator),
    };
}

fn parseWorkspaceEntries(
    allocator: std.mem.Allocator,
    entries: *std.ArrayList(model.WorkspaceEntry),
    items: std.json.Array,
    is_dependency: bool,
) !void {
    for (items.items) |item| {
        const obj = try helpers.expectObject(item, "workspace entry");
        const mount_path_text = try helpers.expectNonEmptyString(obj, "path");
        const mount_path = try allocator.dupe(u8, mount_path_text);
        errdefer allocator.free(mount_path);

        var entry: model.WorkspaceEntry = .{
            .mount_path = mount_path,
            .is_dependency = is_dependency,
        };
        errdefer entry.deinit(allocator);

        const has_source = obj.get("source") != null;
        const has_cas = obj.get("cas_sha256") != null;
        if (has_source == has_cas) {
            return error.ValueInvalid;
        }

        if (has_source) {
            const source_text = try helpers.expectNonEmptyString(obj, "source");
            entry.host_source = try allocator.dupe(u8, source_text);
        } else {
            const cas_text = try helpers.expectNonEmptyString(obj, "cas_sha256");
            entry.cas_sha256 = try helpers.parseHexFixed(32, cas_text);

            if (obj.get("cas_domain")) |domain_value| {
                const domain_text = try helpers.expectString(domain_value, "cas_domain");
                entry.cas_domain = helpers.parseCasDomain(domain_text) orelse return error.ValueInvalid;
            }
        }

        try entries.append(allocator, entry);
    }
}

fn parseLocalInputs(
    allocator: std.mem.Allocator,
    locals: *std.ArrayList(model.LocalInputSpec),
    items: std.json.Array,
) !void {
    for (items.items) |item| {
        const obj = try helpers.expectObject(item, "local input");
        try helpers.ensureOnlyKeys(obj, keys.local_input_keys[0..]);
        const id_text = try helpers.expectNonEmptyString(obj, "id");
        const include_array = try helpers.expectArrayField(obj, "include");

        var include_patterns: std.ArrayList([]u8) = .empty;
        errdefer {
            for (include_patterns.items) |pattern| allocator.free(pattern);
            include_patterns.deinit(allocator);
        }
        for (include_array.items) |entry| {
            const pattern = try helpers.expectString(entry, "include pattern");
            if (pattern.len == 0) return error.ValueInvalid;
            try include_patterns.append(allocator, try allocator.dupe(u8, pattern));
        }
        if (include_patterns.items.len == 0) return error.ValueInvalid;

        var exclude_patterns: std.ArrayList([]u8) = .empty;
        errdefer {
            for (exclude_patterns.items) |pattern| allocator.free(pattern);
            exclude_patterns.deinit(allocator);
        }
        if (obj.get("exclude")) |exclude_value| {
            const exclude_array = try helpers.expectArray(exclude_value, "exclude");
            for (exclude_array.items) |entry| {
                const pattern = try helpers.expectString(entry, "exclude pattern");
                if (pattern.len == 0) return error.ValueInvalid;
                try exclude_patterns.append(allocator, try allocator.dupe(u8, pattern));
            }
        }

        const id = try allocator.dupe(u8, id_text);
        errdefer allocator.free(id);

        try locals.append(allocator, .{
            .id = id,
            .include = try include_patterns.toOwnedSlice(allocator),
            .exclude = try exclude_patterns.toOwnedSlice(allocator),
        });
    }
}

fn parseRemoteInputs(
    allocator: std.mem.Allocator,
    remotes: *std.ArrayList(model.RemoteInputSpec),
    items: std.json.Array,
) !void {
    for (items.items) |item| {
        const obj = try helpers.expectObject(item, "remote input");
        try helpers.ensureOnlyKeys(obj, keys.remote_input_keys[0..]);
        const id_text = try helpers.expectNonEmptyString(obj, "id");
        const url_text = try helpers.expectNonEmptyString(obj, "url");
        const blob_text = try helpers.expectNonEmptyString(obj, "blob_sha256");
        const tree_root = if (obj.get("tree_root")) |tree_value| blk: {
            const tree_text = try helpers.expectString(tree_value, "tree_root");
            break :blk try helpers.parseHexFixed(32, tree_text);
        } else null;

        const extract = if (obj.get("extract")) |extract_value| try helpers.expectBool(extract_value, "extract") else false;
        if (extract and tree_root == null) return error.MissingRequiredField;

        const id = try allocator.dupe(u8, id_text);
        errdefer allocator.free(id);
        const url = try allocator.dupe(u8, url_text);
        errdefer allocator.free(url);

        try remotes.append(allocator, .{
            .id = id,
            .url = url,
            .blob_sha256 = try helpers.parseHexFixed(32, blob_text),
            .tree_root = tree_root,
            .extract = extract,
        });
    }
}

fn parseWorkspaceMounts(
    allocator: std.mem.Allocator,
    mounts: *std.ArrayList(model.WorkspaceMountSpec),
    items: std.json.Array,
) !void {
    for (items.items) |item| {
        const obj = try helpers.expectObject(item, "workspace mount");
        try helpers.ensureOnlyKeys(obj, keys.workspace_mount_keys[0..]);
        const source_text = try helpers.expectNonEmptyString(obj, "source");
        const target_text = try helpers.expectNonEmptyString(obj, "target");
        const mode_text = try helpers.expectNonEmptyString(obj, "mode");
        const normalized_target = helpers.trimTrailingSlash(target_text);
        try helpers.validateWorkspaceRelativePath(normalized_target);
        const mode = try helpers.parseOutputMode(mode_text);
        if (mode & 0o222 != 0) return error.ValueInvalid;

        const source = try allocator.dupe(u8, source_text);
        errdefer allocator.free(source);
        const target = try allocator.dupe(u8, normalized_target);
        errdefer allocator.free(target);
        const strip_prefix = if (obj.get("strip_prefix")) |strip_value| blk: {
            const strip_text = try helpers.expectString(strip_value, "strip_prefix");
            if (strip_text.len == 0) return error.ValueInvalid;
            const normalized_strip = helpers.trimTrailingSlash(strip_text);
            try helpers.validateWorkspaceRelativePath(normalized_strip);
            break :blk try allocator.dupe(u8, normalized_strip);
        } else null;
        errdefer if (strip_prefix) |value| allocator.free(value);

        try mounts.append(allocator, .{
            .source = source,
            .target = target,
            .mode = mode,
            .strip_prefix = strip_prefix,
        });
    }
}
