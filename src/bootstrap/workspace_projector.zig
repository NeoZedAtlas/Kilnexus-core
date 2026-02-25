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

    if (workspace_spec.mounts) |mounts| {
        for (mounts) |mount| {
            const source_ref = try parseMountSource(mount.source);
            if (containsRemoteInput(workspace_spec.remote_inputs, source_ref.input_id)) {
                return error.NotImplemented;
            }

            const local_input = findLocalInput(workspace_spec.local_inputs, source_ref.input_id) orelse return error.FileNotFound;
            const files = try expandLocalInputMatches(allocator, local_input);
            defer freeOwnedStrings(allocator, files);

            if (source_ref.sub_path) |sub_path| {
                if (!containsString(files, sub_path)) return error.FileNotFound;
                const source_abs_path = try std.fs.cwd().realpathAlloc(allocator, sub_path);
                errdefer allocator.free(source_abs_path);
                const mount_path = try allocator.dupe(u8, mount.target);
                errdefer allocator.free(mount_path);
                try appendMappingChecked(allocator, &mappings, &seen_mounts, mount_path, source_abs_path, false);
            } else {
                for (files) |rel_path| {
                    const source_abs_path = try std.fs.cwd().realpathAlloc(allocator, rel_path);
                    errdefer allocator.free(source_abs_path);
                    const mount_path = try joinPosix(allocator, mount.target, rel_path);
                    errdefer allocator.free(mount_path);
                    try appendMappingChecked(allocator, &mappings, &seen_mounts, mount_path, source_abs_path, false);
                }
            }
        }
    }

    return .{
        .mappings = try mappings.toOwnedSlice(allocator),
    };
}

const MountSourceRef = struct {
    input_id: []const u8,
    sub_path: ?[]const u8,
};

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
    try validateMountPath(rest);
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
    try validateMountPath(mount_path);
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

fn containsRemoteInput(remote_inputs_opt: ?[]validator.RemoteInputSpec, id: []const u8) bool {
    const remote_inputs = remote_inputs_opt orelse return false;
    for (remote_inputs) |input| {
        if (std.mem.eql(u8, input.id, id)) return true;
    }
    return false;
}

fn expandLocalInputMatches(allocator: std.mem.Allocator, input: validator.LocalInputSpec) ![][]u8 {
    var matches: std.ArrayList([]u8) = .empty;
    errdefer {
        for (matches.items) |item| allocator.free(item);
        matches.deinit(allocator);
    }

    for (input.include) |pattern| {
        try collectPatternMatches(allocator, &matches, pattern);
    }

    for (input.exclude) |pattern| {
        var i: usize = 0;
        while (i < matches.items.len) {
            if (globMatchPath(pattern, matches.items[i])) {
                allocator.free(matches.items[i]);
                _ = matches.orderedRemove(i);
            } else {
                i += 1;
            }
        }
    }
    std.sort.pdq([]u8, matches.items, {}, struct {
        fn lessThan(_: void, lhs: []u8, rhs: []u8) bool {
            return std.mem.order(u8, lhs, rhs) == .lt;
        }
    }.lessThan);
    return matches.toOwnedSlice(allocator);
}

fn collectPatternMatches(
    allocator: std.mem.Allocator,
    matches: *std.ArrayList([]u8),
    pattern_raw: []const u8,
) !void {
    const pattern = try normalizePathOwned(allocator, pattern_raw);
    defer allocator.free(pattern);
    try validatePatternPath(pattern);

    if (!hasGlobWildcard(pattern)) {
        if (try pathIsFile(pattern)) {
            if (!containsStringConst(matches.items, pattern)) {
                try matches.append(allocator, try allocator.dupe(u8, pattern));
            }
        }
        return;
    }

    const root = patternRoot(pattern);
    var root_dir = std.fs.cwd().openDir(root, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound, error.NotDir => return,
        else => return err,
    };
    defer root_dir.close();

    var walker = try root_dir.walk(allocator);
    defer walker.deinit();

    while (try walker.next()) |entry| {
        if (entry.kind != .file) continue;
        const rel = if (std.mem.eql(u8, root, ".")) blk: {
            break :blk try normalizePathOwned(allocator, entry.path);
        } else blk: {
            const joined = try std.fs.path.join(allocator, &.{ root, entry.path });
            defer allocator.free(joined);
            break :blk try normalizePathOwned(allocator, joined);
        };
        defer allocator.free(rel);
        if (globMatchPath(pattern, rel)) {
            if (!containsStringConst(matches.items, rel)) {
                try matches.append(allocator, try allocator.dupe(u8, rel));
            }
        }
    }
}

fn normalizePathOwned(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    return std.mem.replaceOwned(u8, allocator, path, "\\", "/");
}

fn hasGlobWildcard(pattern: []const u8) bool {
    return std.mem.indexOfAny(u8, pattern, "*?[") != null;
}

fn patternRoot(pattern: []const u8) []const u8 {
    const wildcard = std.mem.indexOfAny(u8, pattern, "*?[") orelse {
        return std.fs.path.dirname(pattern) orelse ".";
    };
    const prefix = pattern[0..wildcard];
    const slash = std.mem.lastIndexOfScalar(u8, prefix, '/') orelse return ".";
    if (slash == 0) return ".";
    return pattern[0..slash];
}

fn validatePatternPath(path: []const u8) !void {
    if (path.len == 0) return error.PathTraversalDetected;
    if (std.fs.path.isAbsolute(path)) return error.PathTraversalDetected;
    if (std.mem.indexOfScalar(u8, path, ':') != null) return error.PathTraversalDetected;
    if (std.mem.indexOfScalar(u8, path, '\\') != null) return error.PathTraversalDetected;

    var it = std.mem.splitScalar(u8, path, '/');
    while (it.next()) |segment| {
        if (segment.len == 0) continue;
        if (std.mem.eql(u8, segment, ".") or std.mem.eql(u8, segment, "..")) {
            return error.PathTraversalDetected;
        }
    }
}

fn globMatchPath(pattern: []const u8, path: []const u8) bool {
    var pattern_parts = std.mem.splitScalar(u8, pattern, '/');
    var path_parts = std.mem.splitScalar(u8, path, '/');

    var p_items: std.ArrayList([]const u8) = .empty;
    defer p_items.deinit(std.heap.page_allocator);
    while (pattern_parts.next()) |part| {
        if (part.len == 0) continue;
        p_items.append(std.heap.page_allocator, part) catch return false;
    }

    var t_items: std.ArrayList([]const u8) = .empty;
    defer t_items.deinit(std.heap.page_allocator);
    while (path_parts.next()) |part| {
        if (part.len == 0) continue;
        t_items.append(std.heap.page_allocator, part) catch return false;
    }

    return matchPathParts(p_items.items, t_items.items);
}

fn matchPathParts(pattern_parts: []const []const u8, path_parts: []const []const u8) bool {
    return matchPathPartsRec(pattern_parts, path_parts, 0, 0);
}

fn matchPathPartsRec(pattern_parts: []const []const u8, path_parts: []const []const u8, p_idx: usize, t_idx: usize) bool {
    if (p_idx == pattern_parts.len) return t_idx == path_parts.len;
    const part = pattern_parts[p_idx];
    if (std.mem.eql(u8, part, "**")) {
        var consume = t_idx;
        while (consume <= path_parts.len) : (consume += 1) {
            if (matchPathPartsRec(pattern_parts, path_parts, p_idx + 1, consume)) return true;
        }
        return false;
    }
    if (t_idx >= path_parts.len) return false;
    if (!matchSegment(part, path_parts[t_idx])) return false;
    return matchPathPartsRec(pattern_parts, path_parts, p_idx + 1, t_idx + 1);
}

fn matchSegment(pattern: []const u8, text: []const u8) bool {
    var dp: std.ArrayList(bool) = .empty;
    defer dp.deinit(std.heap.page_allocator);
    var next: std.ArrayList(bool) = .empty;
    defer next.deinit(std.heap.page_allocator);

    dp.resize(std.heap.page_allocator, text.len + 1) catch return false;
    @memset(dp.items, false);
    dp.items[0] = true;

    for (pattern) |ch| {
        next.resize(std.heap.page_allocator, text.len + 1) catch return false;
        @memset(next.items, false);
        if (ch == '*') {
            var any = false;
            for (0..text.len + 1) |i| {
                any = any or dp.items[i];
                if (any) next.items[i] = true;
            }
        } else {
            for (1..text.len + 1) |i| {
                if (dp.items[i - 1] and (ch == '?' or ch == text[i - 1])) {
                    next.items[i] = true;
                }
            }
        }
        std.mem.swap(std.ArrayList(bool), &dp, &next);
    }

    return dp.items[text.len];
}

fn containsString(items: [][]u8, needle: []const u8) bool {
    for (items) |item| {
        if (std.mem.eql(u8, item, needle)) return true;
    }
    return false;
}

fn containsStringConst(items: []const []u8, needle: []const u8) bool {
    for (items) |item| {
        if (std.mem.eql(u8, item, needle)) return true;
    }
    return false;
}

fn joinPosix(allocator: std.mem.Allocator, base: []const u8, tail: []const u8) ![]u8 {
    if (base.len == 0) return allocator.dupe(u8, tail);
    if (tail.len == 0) return allocator.dupe(u8, base);
    return std.fmt.allocPrint(allocator, "{s}/{s}", .{ trimTrailingSlash(base), trimLeadingSlash(tail) });
}

fn trimTrailingSlash(path: []const u8) []const u8 {
    var out = path;
    while (out.len > 0 and out[out.len - 1] == '/') out = out[0 .. out.len - 1];
    return out;
}

fn trimLeadingSlash(path: []const u8) []const u8 {
    var out = path;
    while (out.len > 0 and out[0] == '/') out = out[1..];
    return out;
}

fn freeOwnedStrings(allocator: std.mem.Allocator, items: [][]u8) void {
    for (items) |item| allocator.free(item);
    allocator.free(items);
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

fn pathIsFile(path: []const u8) !bool {
    var file = std.fs.cwd().openFile(path, .{}) catch |err| switch (err) {
        error.FileNotFound, error.NotDir, error.IsDir => return false,
        else => return err,
    };
    file.close();
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
