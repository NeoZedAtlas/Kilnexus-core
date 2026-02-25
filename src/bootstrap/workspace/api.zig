const std = @import("std");
const validator = @import("../../knx/validator.zig");
const types = @import("types.zig");
const planner = @import("planner.zig");
const projector = @import("projector.zig");
const tree_hash = @import("tree_hash.zig");

pub const LinkMode = types.LinkMode;
pub const ProjectOptions = types.ProjectOptions;
pub const VirtualMapping = types.VirtualMapping;
pub const WorkspacePlan = types.WorkspacePlan;

pub const computeTreeRootHexForDir = tree_hash.computeTreeRootHexForDir;
pub const planWorkspace = planner.planWorkspace;
pub const projectWorkspace = projector.projectWorkspace;

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
