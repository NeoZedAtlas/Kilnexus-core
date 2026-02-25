const std = @import("std");
const validator = @import("../../knx/validator.zig");
const workspace_types = @import("types.zig");
const path_utils = @import("path_utils.zig");
const glob_utils = @import("glob.zig");
const remote_utils = @import("remote.zig");
const tree_hash = @import("tree_hash.zig");

const ProjectOptions = workspace_types.ProjectOptions;
const VirtualMapping = workspace_types.VirtualMapping;
const WorkspacePlan = workspace_types.WorkspacePlan;

const MountSourceRef = struct {
    input_id: []const u8,
    sub_path: ?[]const u8,
};

pub fn planWorkspace(
    allocator: std.mem.Allocator,
    workspace_spec: *const validator.WorkspaceSpec,
    options: ProjectOptions,
) !WorkspacePlan {
    var mappings: std.ArrayList(VirtualMapping) = .empty;
    var seen_mounts: std.StringHashMap(void) = .init(allocator);
    errdefer {
        for (mappings.items) |*mapping| mapping.deinit(allocator);
        mappings.deinit(allocator);
    }
    defer seen_mounts.deinit();

    for (workspace_spec.entries) |entry| {
        try path_utils.validateMountPath(entry.mount_path);
        if (seen_mounts.contains(entry.mount_path)) return error.DuplicateMountPath;
        try seen_mounts.put(entry.mount_path, {});
    }

    for (workspace_spec.entries) |entry| {
        const mount_path = try allocator.dupe(u8, entry.mount_path);
        errdefer allocator.free(mount_path);

        const source_abs_path = try resolveSourceAbsolutePath(allocator, entry, options.cache_root);
        errdefer allocator.free(source_abs_path);

        try mappings.append(allocator, .{
            .mount_path = mount_path,
            .source_abs_path = source_abs_path,
            .is_dependency = entry.is_dependency,
        });
    }

    const prepared_remotes = try remote_utils.prepareRemoteInputs(allocator, workspace_spec, options);
    defer {
        for (prepared_remotes) |remote| allocator.free(remote.root_abs_path);
        allocator.free(prepared_remotes);
    }

    if (workspace_spec.mounts) |mounts| {
        for (mounts) |mount| {
            const source_ref = try parseMountSource(mount.source);
            if (findLocalInput(workspace_spec.local_inputs, source_ref.input_id)) |local_input| {
                const files = try glob_utils.expandLocalInputMatches(allocator, local_input);
                defer freeOwnedStrings(allocator, files);

                if (source_ref.sub_path) |sub_path| {
                    if (mount.strip_prefix != null) return error.InvalidBuildGraph;
                    if (!glob_utils.containsString(files, sub_path)) return error.FileNotFound;
                    const source_abs_path = try std.fs.cwd().realpathAlloc(allocator, sub_path);
                    errdefer allocator.free(source_abs_path);
                    const mount_path = try allocator.dupe(u8, mount.target);
                    errdefer allocator.free(mount_path);
                    try appendMappingChecked(allocator, &mappings, &seen_mounts, mount_path, source_abs_path, false);
                } else {
                    for (files) |rel_path| {
                        const source_abs_path = try std.fs.cwd().realpathAlloc(allocator, rel_path);
                        errdefer allocator.free(source_abs_path);
                        const projected_rel = try applyMountStripPrefix(allocator, rel_path, mount.strip_prefix);
                        defer allocator.free(projected_rel);
                        const mount_path = try path_utils.joinPosix(allocator, mount.target, projected_rel);
                        errdefer allocator.free(mount_path);
                        try appendMappingChecked(allocator, &mappings, &seen_mounts, mount_path, source_abs_path, false);
                    }
                }
                continue;
            }

            if (remote_utils.findPreparedRemote(prepared_remotes, source_ref.input_id)) |remote| {
                try appendRemoteMappingsForMount(allocator, &mappings, &seen_mounts, mount, source_ref, remote);
                continue;
            }

            return error.FileNotFound;
        }
    }

    return .{
        .mappings = try mappings.toOwnedSlice(allocator),
    };
}

fn parseMountSource(source: []const u8) !MountSourceRef {
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

fn appendMappingChecked(
    allocator: std.mem.Allocator,
    mappings: *std.ArrayList(VirtualMapping),
    seen_mounts: *std.StringHashMap(void),
    mount_path: []u8,
    source_abs_path: []u8,
    is_dependency: bool,
) !void {
    try path_utils.validateMountPath(mount_path);
    if (seen_mounts.contains(mount_path)) return error.DuplicateMountPath;
    try seen_mounts.put(mount_path, {});
    try mappings.append(allocator, .{
        .mount_path = mount_path,
        .source_abs_path = source_abs_path,
        .is_dependency = is_dependency,
    });
}

fn findLocalInput(local_inputs_opt: ?[]validator.LocalInputSpec, id: []const u8) ?validator.LocalInputSpec {
    const local_inputs = local_inputs_opt orelse return null;
    for (local_inputs) |input| {
        if (std.mem.eql(u8, input.id, id)) return input;
    }
    return null;
}

fn appendRemoteMappingsForMount(
    allocator: std.mem.Allocator,
    mappings: *std.ArrayList(VirtualMapping),
    seen_mounts: *std.StringHashMap(void),
    mount: validator.WorkspaceMountSpec,
    source_ref: MountSourceRef,
    remote: remote_utils.Prepared,
) !void {
    if (!remote.is_tree) {
        if (mount.strip_prefix != null) return error.InvalidBuildGraph;
        if (source_ref.sub_path != null) return error.InvalidBuildGraph;
        const mount_path = try allocator.dupe(u8, mount.target);
        errdefer allocator.free(mount_path);
        const source_abs = try allocator.dupe(u8, remote.root_abs_path);
        errdefer allocator.free(source_abs);
        try appendMappingChecked(allocator, mappings, seen_mounts, mount_path, source_abs, true);
        return;
    }

    const selected_root_abs = if (source_ref.sub_path) |sub_path| blk: {
        const joined = try std.fs.path.join(allocator, &.{ remote.root_abs_path, sub_path });
        defer allocator.free(joined);
        const abs = try std.fs.cwd().realpathAlloc(allocator, joined);
        errdefer allocator.free(abs);
        try path_utils.ensurePathWithinRoot(abs, remote.root_abs_path);
        break :blk abs;
    } else try allocator.dupe(u8, remote.root_abs_path);
    defer allocator.free(selected_root_abs);

    if (try pathIsFile(selected_root_abs)) {
        if (mount.strip_prefix != null) return error.InvalidBuildGraph;
        const mount_path = try allocator.dupe(u8, mount.target);
        errdefer allocator.free(mount_path);
        const source_abs = try allocator.dupe(u8, selected_root_abs);
        errdefer allocator.free(source_abs);
        try appendMappingChecked(allocator, mappings, seen_mounts, mount_path, source_abs, true);
        return;
    }

    if (!(try pathIsDirectory(selected_root_abs))) return error.FileNotFound;
    const files = try listFilesRelativeTo(allocator, selected_root_abs);
    defer freeOwnedStrings(allocator, files);

    for (files) |rel| {
        const source_abs = try std.fs.path.join(allocator, &.{ selected_root_abs, rel });
        errdefer allocator.free(source_abs);
        const source_abs_real = try std.fs.cwd().realpathAlloc(allocator, source_abs);
        allocator.free(source_abs);
        errdefer allocator.free(source_abs_real);
        const projected_rel = try applyMountStripPrefix(allocator, rel, mount.strip_prefix);
        defer allocator.free(projected_rel);
        const mount_path = try path_utils.joinPosix(allocator, mount.target, projected_rel);
        errdefer allocator.free(mount_path);
        try appendMappingChecked(allocator, mappings, seen_mounts, mount_path, source_abs_real, true);
    }
}

fn listFilesRelativeTo(allocator: std.mem.Allocator, root_abs: []const u8) ![][]u8 {
    var root_dir = try std.fs.cwd().openDir(root_abs, .{ .iterate = true });
    defer root_dir.close();

    var walker = try root_dir.walk(allocator);
    defer walker.deinit();

    var files: std.ArrayList([]u8) = .empty;
    errdefer {
        for (files.items) |item| allocator.free(item);
        files.deinit(allocator);
    }

    while (try walker.next()) |entry| {
        if (entry.kind != .file) continue;
        const rel = try glob_utils.normalizePathOwned(allocator, entry.path);
        try files.append(allocator, rel);
    }
    std.sort.pdq([]u8, files.items, {}, struct {
        fn lessThan(_: void, lhs: []u8, rhs: []u8) bool {
            return std.mem.order(u8, lhs, rhs) == .lt;
        }
    }.lessThan);
    return files.toOwnedSlice(allocator);
}

fn applyMountStripPrefix(
    allocator: std.mem.Allocator,
    rel_path: []const u8,
    strip_prefix_opt: ?[]u8,
) ![]u8 {
    const strip_prefix = strip_prefix_opt orelse return allocator.dupe(u8, rel_path);
    if (std.mem.eql(u8, rel_path, strip_prefix)) return error.InvalidBuildGraph;
    if (!std.mem.startsWith(u8, rel_path, strip_prefix)) return error.InvalidBuildGraph;
    if (rel_path.len <= strip_prefix.len or rel_path[strip_prefix.len] != '/') {
        return error.InvalidBuildGraph;
    }
    const trimmed = rel_path[strip_prefix.len + 1 ..];
    if (trimmed.len == 0) return error.InvalidBuildGraph;
    try path_utils.validateMountPath(trimmed);
    return allocator.dupe(u8, trimmed);
}

fn freeOwnedStrings(allocator: std.mem.Allocator, items: [][]u8) void {
    for (items) |item| allocator.free(item);
    allocator.free(items);
}

fn resolveSourceAbsolutePath(
    allocator: std.mem.Allocator,
    entry: validator.WorkspaceEntry,
    cache_root: []const u8,
) ![]u8 {
    if (entry.host_source) |host_source| {
        return std.fs.cwd().realpathAlloc(allocator, host_source);
    }

    const cas_digest = entry.cas_sha256 orelse return error.FileNotFound;
    const digest_hex = std.fmt.bytesToHex(cas_digest, .lower);
    const domain_name = switch (entry.cas_domain) {
        .official => "official",
        .third_party => "third_party",
        .local => "local",
    };
    const cas_path = try std.fs.path.join(allocator, &.{
        cache_root,
        "cas",
        domain_name,
        "blob",
        digest_hex[0..],
        "blob.bin",
    });
    defer allocator.free(cas_path);
    return std.fs.cwd().realpathAlloc(allocator, cas_path);
}

fn pathIsDirectory(path: []const u8) !bool {
    var dir = std.fs.cwd().openDir(path, .{}) catch |err| switch (err) {
        error.FileNotFound, error.NotDir => return false,
        else => return err,
    };
    dir.close();
    return true;
}

fn pathIsFile(path: []const u8) !bool {
    var file = std.fs.cwd().openFile(path, .{}) catch |err| switch (err) {
        error.FileNotFound, error.NotDir, error.IsDir => return false,
        else => return err,
    };
    file.close();
    return true;
}

test "planWorkspace rejects duplicate mount path" {
    const allocator = std.testing.allocator;

    var entries = try allocator.alloc(validator.WorkspaceEntry, 2);
    entries[0] = .{
        .mount_path = try allocator.dupe(u8, "src/main.c"),
        .host_source = try allocator.dupe(u8, "src/main.c"),
    };
    entries[1] = .{
        .mount_path = try allocator.dupe(u8, "src/main.c"),
        .host_source = try allocator.dupe(u8, "src/other.c"),
    };
    var spec: validator.WorkspaceSpec = .{ .entries = entries };
    defer spec.deinit(allocator);

    try std.testing.expectError(error.DuplicateMountPath, planWorkspace(allocator, &spec, .{}));
}

test "planWorkspace materializes remote file input and mounts blob" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(.{
        .sub_path = "remote.bin",
        .data = "remote-bytes\n",
    });

    const sub = tmp.sub_path[0..];
    const remote_rel = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/remote.bin", .{sub});
    defer allocator.free(remote_rel);
    const cache_root = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/cache", .{sub});
    defer allocator.free(cache_root);

    const digest = try tree_hash.hashFileAtPath(remote_rel);
    const remote_url = try std.fmt.allocPrint(allocator, "file://{s}", .{remote_rel});
    defer allocator.free(remote_url);

    var mounts = try allocator.alloc(validator.WorkspaceMountSpec, 1);
    mounts[0] = .{
        .source = try allocator.dupe(u8, "remote-lib"),
        .target = try allocator.dupe(u8, "deps/lib.bin"),
        .mode = 0o444,
    };
    var remotes = try allocator.alloc(validator.RemoteInputSpec, 1);
    remotes[0] = .{
        .id = try allocator.dupe(u8, "remote-lib"),
        .url = try allocator.dupe(u8, remote_url),
        .blob_sha256 = digest.digest,
        .extract = false,
    };
    var spec: validator.WorkspaceSpec = .{
        .entries = try allocator.alloc(validator.WorkspaceEntry, 0),
        .remote_inputs = remotes,
        .mounts = mounts,
    };
    defer spec.deinit(allocator);

    var plan = try planWorkspace(allocator, &spec, .{
        .cache_root = cache_root,
    });
    defer plan.deinit(allocator);

    const projected_abs = try std.fs.path.join(allocator, &.{ cache_root, "cas", "third_party", "blob" });
    defer allocator.free(projected_abs);
    try std.testing.expect(try pathIsDirectory(projected_abs));
}

test "planWorkspace materializes remote tar input and mounts extracted file" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var out: std.Io.Writer.Allocating = .init(allocator);
    defer out.deinit();
    var tar_writer: std.tar.Writer = .{
        .underlying_writer = &out.writer,
    };
    try tar_writer.writeFileBytes("pkg/a.txt", "from-archive\n", .{});
    try tar_writer.finishPedantically();
    const tar_bytes = try out.toOwnedSlice();
    defer allocator.free(tar_bytes);

    try tmp.dir.writeFile(.{
        .sub_path = "remote.tar",
        .data = tar_bytes,
    });

    const sub = tmp.sub_path[0..];
    const remote_rel = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/remote.tar", .{sub});
    defer allocator.free(remote_rel);
    const remote_url = try std.fmt.allocPrint(allocator, "file://{s}", .{remote_rel});
    defer allocator.free(remote_url);
    const cache_root = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/cache", .{sub});
    defer allocator.free(cache_root);
    const digest = try tree_hash.hashFileAtPath(remote_rel);
    try tmp.dir.makePath("expected/pkg");
    try tmp.dir.writeFile(.{
        .sub_path = "expected/pkg/a.txt",
        .data = "from-archive\n",
    });
    const expected_tree_rel = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/expected", .{sub});
    defer allocator.free(expected_tree_rel);
    const expected_tree_root = try tree_hash.computeTreeRootForDir(allocator, expected_tree_rel);

    var mounts = try allocator.alloc(validator.WorkspaceMountSpec, 1);
    mounts[0] = .{
        .source = try allocator.dupe(u8, "remote-src/pkg/a.txt"),
        .target = try allocator.dupe(u8, "src/a.txt"),
        .mode = 0o444,
    };
    var remotes = try allocator.alloc(validator.RemoteInputSpec, 1);
    remotes[0] = .{
        .id = try allocator.dupe(u8, "remote-src"),
        .url = try allocator.dupe(u8, remote_url),
        .blob_sha256 = digest.digest,
        .tree_root = expected_tree_root,
        .extract = true,
    };
    var spec: validator.WorkspaceSpec = .{
        .entries = try allocator.alloc(validator.WorkspaceEntry, 0),
        .remote_inputs = remotes,
        .mounts = mounts,
    };
    defer spec.deinit(allocator);

    var plan = try planWorkspace(allocator, &spec, .{
        .cache_root = cache_root,
    });
    defer plan.deinit(allocator);

    try std.testing.expect(plan.mappings.len == 1);
}

test "planWorkspace rejects remote extract when tree_root mismatches" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var out: std.Io.Writer.Allocating = .init(allocator);
    defer out.deinit();
    var tar_writer: std.tar.Writer = .{
        .underlying_writer = &out.writer,
    };
    try tar_writer.writeFileBytes("pkg/a.txt", "from-archive\n", .{});
    try tar_writer.finishPedantically();
    const tar_bytes = try out.toOwnedSlice();
    defer allocator.free(tar_bytes);

    try tmp.dir.writeFile(.{
        .sub_path = "remote.tar",
        .data = tar_bytes,
    });

    const sub = tmp.sub_path[0..];
    const remote_rel = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/remote.tar", .{sub});
    defer allocator.free(remote_rel);
    const remote_url = try std.fmt.allocPrint(allocator, "file://{s}", .{remote_rel});
    defer allocator.free(remote_url);
    const cache_root = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/cache", .{sub});
    defer allocator.free(cache_root);
    const digest = try tree_hash.hashFileAtPath(remote_rel);

    var mounts = try allocator.alloc(validator.WorkspaceMountSpec, 1);
    mounts[0] = .{
        .source = try allocator.dupe(u8, "remote-src/pkg/a.txt"),
        .target = try allocator.dupe(u8, "src/a.txt"),
        .mode = 0o444,
    };
    var remotes = try allocator.alloc(validator.RemoteInputSpec, 1);
    remotes[0] = .{
        .id = try allocator.dupe(u8, "remote-src"),
        .url = try allocator.dupe(u8, remote_url),
        .blob_sha256 = digest.digest,
        .tree_root = [_]u8{0xaa} ** 32,
        .extract = true,
    };
    var spec: validator.WorkspaceSpec = .{
        .entries = try allocator.alloc(validator.WorkspaceEntry, 0),
        .remote_inputs = remotes,
        .mounts = mounts,
    };
    defer spec.deinit(allocator);

    try std.testing.expectError(error.TreeRootMismatch, planWorkspace(allocator, &spec, .{
        .cache_root = cache_root,
    }));
}

test "planWorkspace applies strip_prefix for local directory mount projection" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("project/src");
    try tmp.dir.writeFile(.{
        .sub_path = "project/src/a.c",
        .data = "int a;\n",
    });

    const sub = tmp.sub_path[0..];
    const include_pat = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/project/src/*.c", .{sub});
    defer allocator.free(include_pat);
    const strip_prefix = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/project", .{sub});
    defer allocator.free(strip_prefix);
    const cache_root = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/cache", .{sub});
    defer allocator.free(cache_root);

    var locals = try allocator.alloc(validator.LocalInputSpec, 1);
    locals[0] = .{
        .id = try allocator.dupe(u8, "local-src"),
        .include = blk: {
            var arr = try allocator.alloc([]u8, 1);
            arr[0] = try allocator.dupe(u8, include_pat);
            break :blk arr;
        },
        .exclude = try allocator.alloc([]u8, 0),
    };
    var mounts = try allocator.alloc(validator.WorkspaceMountSpec, 1);
    mounts[0] = .{
        .source = try allocator.dupe(u8, "local-src"),
        .target = try allocator.dupe(u8, "mirror"),
        .mode = 0o444,
        .strip_prefix = try allocator.dupe(u8, strip_prefix),
    };
    var spec: validator.WorkspaceSpec = .{
        .entries = try allocator.alloc(validator.WorkspaceEntry, 0),
        .local_inputs = locals,
        .mounts = mounts,
    };
    defer spec.deinit(allocator);

    var plan = try planWorkspace(allocator, &spec, .{
        .cache_root = cache_root,
    });
    defer plan.deinit(allocator);

    try std.testing.expect(plan.mappings.len == 1);
    try std.testing.expectEqualStrings("mirror/src/a.c", plan.mappings[0].mount_path);
}

test "planWorkspace rejects mount when strip_prefix does not match projected file path" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("project/src");
    try tmp.dir.writeFile(.{
        .sub_path = "project/src/a.c",
        .data = "int a;\n",
    });

    const sub = tmp.sub_path[0..];
    const include_pat = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/project/src/*.c", .{sub});
    defer allocator.free(include_pat);
    const cache_root = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/cache", .{sub});
    defer allocator.free(cache_root);

    var locals = try allocator.alloc(validator.LocalInputSpec, 1);
    locals[0] = .{
        .id = try allocator.dupe(u8, "local-src"),
        .include = blk: {
            var arr = try allocator.alloc([]u8, 1);
            arr[0] = try allocator.dupe(u8, include_pat);
            break :blk arr;
        },
        .exclude = try allocator.alloc([]u8, 0),
    };
    var mounts = try allocator.alloc(validator.WorkspaceMountSpec, 1);
    mounts[0] = .{
        .source = try allocator.dupe(u8, "local-src"),
        .target = try allocator.dupe(u8, "mirror"),
        .mode = 0o444,
        .strip_prefix = try allocator.dupe(u8, "does/not/match"),
    };
    var spec: validator.WorkspaceSpec = .{
        .entries = try allocator.alloc(validator.WorkspaceEntry, 0),
        .local_inputs = locals,
        .mounts = mounts,
    };
    defer spec.deinit(allocator);

    try std.testing.expectError(error.InvalidBuildGraph, planWorkspace(allocator, &spec, .{
        .cache_root = cache_root,
    }));
}
