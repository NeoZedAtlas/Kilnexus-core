const std = @import("std");
const builtin = @import("builtin");
const cli_types = @import("../types.zig");
const current_pointer = @import("../render/current_pointer.zig");

const CandidateScope = enum {
    work,
    staging,
    local,
    third_party,
    official,
    releases,
    toolchain,
};

pub const CleanOptions = struct {
    cache_root: []const u8,
    output_root: []const u8,
    scopes: cli_types.CleanScopeSet,
    older_than_secs: u64,
    toolchain_tree_root: ?[]const u8,
    apply: bool,
};

pub const CleanReport = struct {
    dry_run: bool,
    planned_objects: usize = 0,
    planned_bytes: u64 = 0,
    deleted_objects: usize = 0,
    deleted_bytes: u64 = 0,
    skipped_in_use: usize = 0,
    skipped_locked: usize = 0,
    errors: usize = 0,
};

const Candidate = struct {
    path: []u8,
    scope: CandidateScope,
    is_dir: bool,
    bytes: u64,

    fn deinit(self: *Candidate, allocator: std.mem.Allocator) void {
        allocator.free(self.path);
        self.* = undefined;
    }
};

const CurrentRefs = struct {
    toolchain_tree_root: ?[]u8 = null,
    release_rel: ?[]u8 = null,

    fn deinit(self: *CurrentRefs, allocator: std.mem.Allocator) void {
        if (self.toolchain_tree_root) |value| allocator.free(value);
        if (self.release_rel) |value| allocator.free(value);
        self.* = undefined;
    }
};

const LockGuard = struct {
    path: []u8,

    fn release(self: *LockGuard, allocator: std.mem.Allocator) void {
        std.fs.cwd().deleteTree(self.path) catch {};
        allocator.free(self.path);
        self.* = undefined;
    }
};

pub fn runClean(allocator: std.mem.Allocator, options: CleanOptions) !CleanReport {
    var report: CleanReport = .{
        .dry_run = !options.apply,
    };

    var refs = try readCurrentRefs(allocator, options.output_root);
    defer refs.deinit(allocator);

    var lock: ?LockGuard = null;
    if (options.apply) {
        lock = try acquireCleanLock(allocator, options.cache_root);
        defer {
            if (lock) |*held| held.release(allocator);
        }
    }

    var candidates: std.ArrayList(Candidate) = .empty;
    defer {
        for (candidates.items) |*candidate| candidate.deinit(allocator);
        candidates.deinit(allocator);
    }

    const now_secs: i64 = @intCast(std.time.timestamp());
    const threshold_secs: i64 = if (options.older_than_secs > @as(u64, @intCast(now_secs))) 0 else now_secs - @as(i64, @intCast(options.older_than_secs));

    if (options.scopes.work) try addScopeCandidates(allocator, &candidates, options.cache_root, "work", .work, threshold_secs);
    if (options.scopes.staging) try addScopeCandidates(allocator, &candidates, options.cache_root, "staging", .staging, threshold_secs);
    if (options.scopes.local) {
        try addScopeCandidates(allocator, &candidates, options.cache_root, "cas/local/tree", .local, threshold_secs);
        try addScopeCandidates(allocator, &candidates, options.cache_root, "cas/local/blob", .local, threshold_secs);
    }
    if (options.scopes.third_party) {
        try addScopeCandidates(allocator, &candidates, options.cache_root, "cas/third_party/tree", .third_party, threshold_secs);
        try addScopeCandidates(allocator, &candidates, options.cache_root, "cas/third_party/blob", .third_party, threshold_secs);
    }
    if (options.scopes.official) {
        try addScopeCandidates(allocator, &candidates, options.cache_root, "cas/official/tree", .official, threshold_secs);
        try addScopeCandidates(allocator, &candidates, options.cache_root, "cas/official/blob", .official, threshold_secs);
    }
    if (options.scopes.releases) {
        try addReleaseCandidates(allocator, &candidates, options.output_root, threshold_secs);
    }
    if (options.toolchain_tree_root) |tree_root| {
        try addExplicitToolchainCandidate(allocator, &candidates, options.cache_root, tree_root);
    }

    var seen_paths: std.StringHashMap(void) = .init(allocator);
    defer seen_paths.deinit();

    for (candidates.items) |candidate| {
        const gop = try seen_paths.getOrPut(candidate.path);
        if (gop.found_existing) continue;
        gop.value_ptr.* = {};

        if (try isProtectedByCurrentRefs(allocator, candidate, options, &refs)) {
            report.skipped_in_use += 1;
            continue;
        }

        report.planned_objects += 1;
        report.planned_bytes += candidate.bytes;

        if (!options.apply) continue;

        const trash_root_base = if (candidate.scope == .releases) options.output_root else options.cache_root;
        const moved = moveToTrash(allocator, trash_root_base, candidate.path) catch |err| switch (err) {
            error.AccessDenied, error.PermissionDenied, error.SharingViolation => {
                report.skipped_locked += 1;
                continue;
            },
            else => {
                report.errors += 1;
                continue;
            },
        };
        defer allocator.free(moved);

        deleteMovedPath(moved, candidate.is_dir) catch {
            report.errors += 1;
            continue;
        };
        report.deleted_objects += 1;
        report.deleted_bytes += candidate.bytes;
    }

    return report;
}

fn addReleaseCandidates(
    allocator: std.mem.Allocator,
    candidates: *std.ArrayList(Candidate),
    output_root: []const u8,
    threshold_secs: i64,
) !void {
    const base = try std.fs.path.join(allocator, &.{ output_root, "releases" });
    defer allocator.free(base);
    try addDirectChildren(allocator, candidates, base, .releases, threshold_secs);
}

fn addScopeCandidates(
    allocator: std.mem.Allocator,
    candidates: *std.ArrayList(Candidate),
    cache_root: []const u8,
    rel: []const u8,
    scope: CandidateScope,
    threshold_secs: i64,
) !void {
    const base = try std.fs.path.join(allocator, &.{ cache_root, rel });
    defer allocator.free(base);
    try addDirectChildren(allocator, candidates, base, scope, threshold_secs);
}

fn addExplicitToolchainCandidate(
    allocator: std.mem.Allocator,
    candidates: *std.ArrayList(Candidate),
    cache_root: []const u8,
    tree_root: []const u8,
) !void {
    const path = try std.fs.path.join(allocator, &.{ cache_root, "cas", "official", "tree", tree_root });
    defer allocator.free(path);
    const exists = pathExists(path);
    if (!exists) return;

    const bytes = try computePathBytes(allocator, path, true);
    try candidates.append(allocator, .{
        .path = try allocator.dupe(u8, path),
        .scope = .toolchain,
        .is_dir = true,
        .bytes = bytes,
    });
}

fn addDirectChildren(
    allocator: std.mem.Allocator,
    candidates: *std.ArrayList(Candidate),
    base_path: []const u8,
    scope: CandidateScope,
    threshold_secs: i64,
) !void {
    var dir = std.fs.cwd().openDir(base_path, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    defer dir.close();

    var iter = dir.iterate();
    while (try iter.next()) |entry| {
        if (entry.kind != .directory and entry.kind != .file) continue;

        const child_path = try std.fs.path.join(allocator, &.{ base_path, entry.name });
        defer allocator.free(child_path);
        const is_dir = entry.kind == .directory;
        const mtime_secs = try getPathMtimeSeconds(child_path, is_dir);
        if (mtime_secs > threshold_secs) continue;

        const bytes = try computePathBytes(allocator, child_path, is_dir);
        try candidates.append(allocator, .{
            .path = try allocator.dupe(u8, child_path),
            .scope = scope,
            .is_dir = is_dir,
            .bytes = bytes,
        });
    }
}

fn readCurrentRefs(allocator: std.mem.Allocator, output_root: []const u8) !CurrentRefs {
    var refs: CurrentRefs = .{};
    var summary = current_pointer.readCurrentPointerSummary(allocator, output_root) catch return refs;
    defer summary.deinit(allocator);

    if (summary.toolchain_tree_root) |value| {
        refs.toolchain_tree_root = try allocator.dupe(u8, value);
    }
    refs.release_rel = try allocator.dupe(u8, summary.release_rel);
    return refs;
}

fn isProtectedByCurrentRefs(
    allocator: std.mem.Allocator,
    candidate: Candidate,
    options: CleanOptions,
    refs: *const CurrentRefs,
) !bool {
    if (refs.toolchain_tree_root) |tree_root| {
        const protected_toolchain_path = try std.fs.path.join(allocator, &.{ options.cache_root, "cas", "official", "tree", tree_root });
        defer allocator.free(protected_toolchain_path);
        if (pathsEqual(protected_toolchain_path, candidate.path)) return true;
    }
    if (refs.release_rel) |release_rel| {
        const protected_release_path = try std.fs.path.join(allocator, &.{ options.output_root, release_rel });
        defer allocator.free(protected_release_path);
        if (pathsEqual(protected_release_path, candidate.path)) return true;
    }
    return false;
}

fn pathsEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ca_raw, cb_raw| {
        const ca = normalizePathChar(ca_raw);
        const cb = normalizePathChar(cb_raw);
        if (ca != cb) return false;
    }
    return true;
}

fn normalizePathChar(ch: u8) u8 {
    const slash_normalized = if (ch == '\\') '/' else ch;
    if (builtin.os.tag == .windows) {
        return std.ascii.toLower(slash_normalized);
    }
    return slash_normalized;
}

fn pathExists(path: []const u8) bool {
    std.fs.cwd().access(path, .{}) catch return false;
    return true;
}

fn getPathMtimeSeconds(path: []const u8, is_dir: bool) !i64 {
    if (is_dir) {
        var dir = try std.fs.cwd().openDir(path, .{});
        defer dir.close();
        const stat = try dir.stat();
        return @intCast(@divFloor(stat.mtime, std.time.ns_per_s));
    }
    const stat = try std.fs.cwd().statFile(path);
    return @intCast(@divFloor(stat.mtime, std.time.ns_per_s));
}

fn computePathBytes(allocator: std.mem.Allocator, path: []const u8, is_dir: bool) !u64 {
    if (!is_dir) {
        const stat = try std.fs.cwd().statFile(path);
        return stat.size;
    }

    var dir = try std.fs.cwd().openDir(path, .{ .iterate = true });
    defer dir.close();
    var walker = try dir.walk(allocator);
    defer walker.deinit();
    var total: u64 = 0;
    while (try walker.next()) |entry| {
        if (entry.kind != .file) continue;
        const file = try dir.openFile(entry.path, .{});
        defer file.close();
        const stat = try file.stat();
        total += stat.size;
    }
    return total;
}

fn acquireCleanLock(allocator: std.mem.Allocator, cache_root: []const u8) !LockGuard {
    const lock_dir = try std.fs.path.join(allocator, &.{ cache_root, ".locks" });
    defer allocator.free(lock_dir);
    try std.fs.cwd().makePath(lock_dir);

    const lock_path = try std.fs.path.join(allocator, &.{ cache_root, ".locks", "clean.lock" });
    errdefer allocator.free(lock_path);
    std.fs.cwd().makeDir(lock_path) catch |err| switch (err) {
        error.PathAlreadyExists => return error.CleanLocked,
        else => return err,
    };

    return .{
        .path = lock_path,
    };
}

fn moveToTrash(allocator: std.mem.Allocator, root: []const u8, source_path: []const u8) ![]u8 {
    const trash_root = try std.fs.path.join(allocator, &.{ root, ".trash" });
    defer allocator.free(trash_root);
    try std.fs.cwd().makePath(trash_root);

    const base = std.fs.path.basename(source_path);
    const stamp = std.time.microTimestamp();
    const trash_name = try std.fmt.allocPrint(allocator, "{s}-{d}", .{ base, stamp });
    defer allocator.free(trash_name);
    const trash_path = try std.fs.path.join(allocator, &.{ trash_root, trash_name });

    try std.fs.cwd().rename(source_path, trash_path);
    return trash_path;
}

fn deleteMovedPath(path: []const u8, is_dir: bool) !void {
    if (is_dir) {
        try std.fs.cwd().deleteTree(path);
    } else {
        try std.fs.cwd().deleteFile(path);
    }
}
