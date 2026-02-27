const std = @import("std");
const validator = @import("../../knx/validator.zig");
const workspace_types = @import("types.zig");
const path_utils = @import("path_utils.zig");
const remote_utils = @import("remote.zig");
const tree_hash = @import("tree_hash.zig");
const common = @import("planner/common.zig");
const local_mounts = @import("planner/local_mounts.zig");
const remote_mounts = @import("planner/remote_mounts.zig");
const cas_resolver = @import("planner/cas_resolver.zig");

const ProjectOptions = workspace_types.ProjectOptions;
const VirtualMapping = workspace_types.VirtualMapping;
const WorkspacePlan = workspace_types.WorkspacePlan;

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

        const source_abs_path = try cas_resolver.resolveSourceAbsolutePath(allocator, entry, options.cache_root);
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
            const source_ref = try local_mounts.parseMountSource(mount.source);
            if (local_mounts.findLocalInput(workspace_spec.local_inputs, source_ref.input_id)) |local_input| {
                try local_mounts.appendLocalMappingsForMount(
                    allocator,
                    &mappings,
                    &seen_mounts,
                    mount,
                    source_ref,
                    local_input,
                );
                continue;
            }

            if (remote_utils.findPreparedRemote(prepared_remotes, source_ref.input_id)) |remote| {
                try remote_mounts.appendRemoteMappingsForMount(
                    allocator,
                    &mappings,
                    &seen_mounts,
                    mount,
                    source_ref,
                    remote,
                );
                continue;
            }

            return error.FileNotFound;
        }
    }

    return .{
        .mappings = try mappings.toOwnedSlice(allocator),
    };
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
    try std.testing.expect(try common.pathIsDirectory(projected_abs));
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

test "planWorkspace materializes remote raw input with extract=true and mounts blob file" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const raw_bytes = "raw-payload\n";
    try tmp.dir.writeFile(.{
        .sub_path = "remote.raw",
        .data = raw_bytes,
    });
    try tmp.dir.makePath("expected");
    try tmp.dir.writeFile(.{
        .sub_path = "expected/blob.bin",
        .data = raw_bytes,
    });

    const sub = tmp.sub_path[0..];
    const remote_rel = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/remote.raw", .{sub});
    defer allocator.free(remote_rel);
    const remote_url = try std.fmt.allocPrint(allocator, "file://{s}", .{remote_rel});
    defer allocator.free(remote_url);
    const cache_root = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/cache", .{sub});
    defer allocator.free(cache_root);
    const digest = try tree_hash.hashFileAtPath(remote_rel);
    const expected_tree_rel = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/expected", .{sub});
    defer allocator.free(expected_tree_rel);
    const expected_tree_root = try tree_hash.computeTreeRootForDir(allocator, expected_tree_rel);

    var mounts = try allocator.alloc(validator.WorkspaceMountSpec, 1);
    mounts[0] = .{
        .source = try allocator.dupe(u8, "remote-src/blob.bin"),
        .target = try allocator.dupe(u8, "src/blob.bin"),
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

    try std.testing.expectEqual(@as(usize, 1), plan.mappings.len);
    try std.testing.expectEqualStrings("src/blob.bin", plan.mappings[0].mount_path);
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
