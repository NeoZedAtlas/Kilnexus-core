const std = @import("std");
const validator = @import("../knx/validator.zig");
const workspace_types = @import("workspace/types.zig");
const planner_impl = @import("workspace/planner.zig");
const projector_impl = @import("workspace/projector.zig");
const tree_hash = @import("workspace/tree_hash.zig");

pub const LinkMode = workspace_types.LinkMode;
pub const ProjectOptions = workspace_types.ProjectOptions;
pub const VirtualMapping = workspace_types.VirtualMapping;
pub const WorkspacePlan = workspace_types.WorkspacePlan;

pub fn computeTreeRootHexForDir(allocator: std.mem.Allocator, dir_path: []const u8) ![64]u8 {
    return tree_hash.computeTreeRootHexForDir(allocator, dir_path);
}

pub fn planWorkspace(
    allocator: std.mem.Allocator,
    workspace_spec: *const validator.WorkspaceSpec,
    options: ProjectOptions,
) !WorkspacePlan {
    return planner_impl.planWorkspace(allocator, workspace_spec, options);
}

pub fn projectWorkspace(
    allocator: std.mem.Allocator,
    plan: *const WorkspacePlan,
    build_id: []const u8,
    options: ProjectOptions,
) ![]u8 {
    return projector_impl.projectWorkspace(allocator, plan, build_id, options);
}

test "plan and project workspace with host and cas mappings" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("project/src");
    try tmp.dir.writeFile(.{
        .sub_path = "project/src/main.c",
        .data = "int main(){return 0;}\n",
    });

    const cas_digest = [_]u8{0xdd} ** 32;
    const digest_hex = std.fmt.bytesToHex(cas_digest, .lower);
    const cas_blob_rel = try std.fmt.allocPrint(
        allocator,
        ".zig-cache/tmp/{s}/cache/cas/local/blob/{s}/blob.bin",
        .{ tmp.sub_path[0..], digest_hex[0..] },
    );
    defer allocator.free(cas_blob_rel);
    if (std.fs.path.dirname(cas_blob_rel)) |parent| {
        try std.fs.cwd().makePath(parent);
    }
    try std.fs.cwd().writeFile(.{
        .sub_path = cas_blob_rel,
        .data = "cached-bytes\n",
    });

    const host_source_rel = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/project/src/main.c", .{tmp.sub_path[0..]});
    defer allocator.free(host_source_rel);
    const cache_root_rel = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/cache", .{tmp.sub_path[0..]});
    defer allocator.free(cache_root_rel);

    var entries = try allocator.alloc(validator.WorkspaceEntry, 2);
    entries[0] = .{
        .mount_path = try allocator.dupe(u8, "src/main.c"),
        .host_source = try allocator.dupe(u8, host_source_rel),
        .is_dependency = false,
    };
    entries[1] = .{
        .mount_path = try allocator.dupe(u8, "deps/libc.a"),
        .cas_sha256 = cas_digest,
        .cas_domain = .local,
        .is_dependency = true,
    };
    var spec: validator.WorkspaceSpec = .{ .entries = entries };
    defer spec.deinit(allocator);

    var plan = try planWorkspace(allocator, &spec, .{
        .cache_root = cache_root_rel,
    });
    defer plan.deinit(allocator);

    const workspace_root = try projectWorkspace(allocator, &plan, "test-build", .{
        .cache_root = cache_root_rel,
    });
    defer allocator.free(workspace_root);

    const projected_host = try std.fs.path.join(allocator, &.{ workspace_root, "src/main.c" });
    defer allocator.free(projected_host);
    const projected_dep = try std.fs.path.join(allocator, &.{ workspace_root, "deps/libc.a" });
    defer allocator.free(projected_dep);

    const host_contents = try std.fs.cwd().readFileAlloc(allocator, projected_host, 1024);
    defer allocator.free(host_contents);
    const dep_contents = try std.fs.cwd().readFileAlloc(allocator, projected_dep, 1024);
    defer allocator.free(dep_contents);

    try std.testing.expectEqualStrings("int main(){return 0;}\n", host_contents);
    try std.testing.expectEqualStrings("cached-bytes\n", dep_contents);
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

    const workspace_root = try projectWorkspace(allocator, &plan, "remote-file", .{
        .cache_root = cache_root,
    });
    defer allocator.free(workspace_root);

    const projected = try std.fs.path.join(allocator, &.{ workspace_root, "deps/lib.bin" });
    defer allocator.free(projected);
    const bytes = try std.fs.cwd().readFileAlloc(allocator, projected, 1024);
    defer allocator.free(bytes);
    try std.testing.expectEqualStrings("remote-bytes\n", bytes);
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

    const workspace_root = try projectWorkspace(allocator, &plan, "remote-tar", .{
        .cache_root = cache_root,
    });
    defer allocator.free(workspace_root);

    const projected = try std.fs.path.join(allocator, &.{ workspace_root, "src/a.txt" });
    defer allocator.free(projected);
    const bytes = try std.fs.cwd().readFileAlloc(allocator, projected, 1024);
    defer allocator.free(bytes);
    try std.testing.expectEqualStrings("from-archive\n", bytes);
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

    const workspace_root = try projectWorkspace(allocator, &plan, "strip-prefix-local", .{
        .cache_root = cache_root,
    });
    defer allocator.free(workspace_root);

    const projected = try std.fs.path.join(allocator, &.{ workspace_root, "mirror/src/a.c" });
    defer allocator.free(projected);
    const bytes = try std.fs.cwd().readFileAlloc(allocator, projected, 1024);
    defer allocator.free(bytes);
    try std.testing.expectEqualStrings("int a;\n", bytes);
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
