const std = @import("std");
const validator = @import("../knx/validator.zig");

pub const LinkMode = enum {
    hardlink_then_symlink,
    symlink_only,
};

pub const ProjectOptions = struct {
    cache_root: []const u8 = ".kilnexus-cache",
    link_mode: LinkMode = .hardlink_then_symlink,
};

pub const VirtualMapping = struct {
    mount_path: []u8,
    source_abs_path: []u8,
    is_dependency: bool,

    pub fn deinit(self: *VirtualMapping, allocator: std.mem.Allocator) void {
        allocator.free(self.mount_path);
        allocator.free(self.source_abs_path);
        self.* = undefined;
    }
};

pub const WorkspacePlan = struct {
    mappings: []VirtualMapping,

    pub fn deinit(self: *WorkspacePlan, allocator: std.mem.Allocator) void {
        for (self.mappings) |*mapping| mapping.deinit(allocator);
        allocator.free(self.mappings);
        self.* = undefined;
    }
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
        try validateMountPath(entry.mount_path);
        if (seen_mounts.contains(entry.mount_path)) return error.DuplicateMountPath;
        try seen_mounts.put(entry.mount_path, {});

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

    return .{
        .mappings = try mappings.toOwnedSlice(allocator),
    };
}

pub fn projectWorkspace(
    allocator: std.mem.Allocator,
    plan: *const WorkspacePlan,
    build_id: []const u8,
    options: ProjectOptions,
) ![]u8 {
    const work_root = try std.fs.path.join(allocator, &.{ options.cache_root, "work", build_id });
    defer allocator.free(work_root);
    const workspace_root = try std.fs.path.join(allocator, &.{ work_root, "workspace" });
    errdefer allocator.free(workspace_root);

    if (try pathIsDirectory(work_root)) {
        try std.fs.cwd().deleteTree(work_root);
    }
    try std.fs.cwd().makePath(workspace_root);

    for (plan.mappings) |mapping| {
        const target_path = try std.fs.path.join(allocator, &.{ workspace_root, mapping.mount_path });
        defer allocator.free(target_path);

        if (std.fs.path.dirname(target_path)) |parent| {
            try std.fs.cwd().makePath(parent);
        }

        try projectMapping(mapping.source_abs_path, target_path, options.link_mode);
    }

    return workspace_root;
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

fn validateMountPath(path: []const u8) !void {
    if (path.len == 0) return error.PathTraversalDetected;
    if (std.fs.path.isAbsolute(path)) return error.PathTraversalDetected;
    if (std.mem.indexOfScalar(u8, path, '\\') != null) return error.PathTraversalDetected;
    if (std.mem.indexOfScalar(u8, path, ':') != null) return error.PathTraversalDetected;

    var it = std.mem.splitScalar(u8, path, '/');
    while (it.next()) |segment| {
        if (segment.len == 0 or std.mem.eql(u8, segment, ".") or std.mem.eql(u8, segment, "..")) {
            return error.PathTraversalDetected;
        }
    }
}

fn projectMapping(source_abs_path: []const u8, target_path: []const u8, link_mode: LinkMode) !void {
    if (@import("builtin").os.tag == .windows) {
        // On mingw targets, libc hardlink symbol resolution is unreliable.
        // Keep projection functional with symlink-first and safe file-copy fallback.
        return projectWindows(source_abs_path, target_path, link_mode);
    }

    switch (link_mode) {
        .symlink_only => try std.fs.cwd().symLink(source_abs_path, target_path, .{}),
        .hardlink_then_symlink => {
            std.posix.link(source_abs_path, target_path) catch |err| {
                if (!shouldFallbackToSymlink(err)) return err;
                try std.fs.cwd().symLink(source_abs_path, target_path, .{});
            };
        },
    }
}

fn projectWindows(source_abs_path: []const u8, target_path: []const u8, link_mode: LinkMode) !void {
    switch (link_mode) {
        .symlink_only, .hardlink_then_symlink => {
            std.fs.cwd().symLink(source_abs_path, target_path, .{}) catch {
                // Windows symlink availability depends on privilege/policy.
                // Fall back to byte copy to keep projection deterministic.
                try std.fs.cwd().copyFile(source_abs_path, std.fs.cwd(), target_path, .{});
            };
        },
    }
}

fn shouldFallbackToSymlink(err: anyerror) bool {
    return err == error.NotSameFileSystem or
        err == error.AccessDenied or
        err == error.PermissionDenied or
        err == error.FileSystem or
        err == error.ReadOnlyFileSystem or
        err == error.LinkQuotaExceeded;
}

fn pathIsDirectory(path: []const u8) !bool {
    var dir = std.fs.cwd().openDir(path, .{}) catch |err| switch (err) {
        error.FileNotFound, error.NotDir => return false,
        else => return err,
    };
    dir.close();
    return true;
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
