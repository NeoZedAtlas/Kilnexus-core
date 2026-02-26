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
    toolchain_prune: bool,
    keep_last: usize,
    official_max_bytes: ?u64,
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
    error_items: []CleanError,
    skipped_items: []CleanSkipItem,

    pub fn deinit(self: *CleanReport, allocator: std.mem.Allocator) void {
        for (self.error_items) |*item| item.deinit(allocator);
        allocator.free(self.error_items);
        for (self.skipped_items) |*item| item.deinit(allocator);
        allocator.free(self.skipped_items);
        self.* = undefined;
    }
};

pub const ErrorPhase = enum {
    move_to_trash,
    delete_moved,
};

pub const CleanError = struct {
    path: []u8,
    phase: ErrorPhase,
    reason: []u8,

    fn deinit(self: *CleanError, allocator: std.mem.Allocator) void {
        allocator.free(self.path);
        allocator.free(self.reason);
        self.* = undefined;
    }
};

pub const SkipReason = enum {
    in_use,
    locked,
};

pub const CleanSkipItem = struct {
    path: []u8,
    reason: SkipReason,

    fn deinit(self: *CleanSkipItem, allocator: std.mem.Allocator) void {
        allocator.free(self.path);
        self.* = undefined;
    }
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

const ToolchainTreeEntry = struct {
    tree_root: []u8,
    path: []u8,
    mtime_secs: i64,
    bytes: u64,

    fn deinit(self: *ToolchainTreeEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.tree_root);
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
        .error_items = &[_]CleanError{},
        .skipped_items = &[_]CleanSkipItem{},
    };
    var error_items: std.ArrayList(CleanError) = .empty;
    var skipped_items: std.ArrayList(CleanSkipItem) = .empty;
    var transferred_errors = false;
    var transferred_skipped = false;
    defer {
        if (!transferred_errors) {
            for (error_items.items) |*item| item.deinit(allocator);
            error_items.deinit(allocator);
        }
        if (!transferred_skipped) {
            for (skipped_items.items) |*item| item.deinit(allocator);
            skipped_items.deinit(allocator);
        }
    }

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
    if (options.toolchain_prune or options.official_max_bytes != null) {
        try addAutomaticToolchainGcCandidates(allocator, &candidates, options, threshold_secs, &refs);
    }

    var seen_paths: std.StringHashMap(void) = .init(allocator);
    defer seen_paths.deinit();

    for (candidates.items) |candidate| {
        const gop = try seen_paths.getOrPut(candidate.path);
        if (gop.found_existing) continue;
        gop.value_ptr.* = {};

        if (try isProtectedByCurrentRefs(allocator, candidate, options, &refs)) {
            report.skipped_in_use += 1;
            try appendSkipItem(allocator, &skipped_items, candidate.path, .in_use);
            continue;
        }

        report.planned_objects += 1;
        report.planned_bytes += candidate.bytes;

        if (!options.apply) continue;

        const trash_root_base = if (candidate.scope == .releases) options.output_root else options.cache_root;
        const moved = moveToTrash(allocator, trash_root_base, candidate.path) catch |err| switch (err) {
            error.AccessDenied, error.PermissionDenied, error.SharingViolation => {
                report.skipped_locked += 1;
                try appendSkipItem(allocator, &skipped_items, candidate.path, .locked);
                continue;
            },
            else => {
                try appendErrorItem(allocator, &error_items, candidate.path, .move_to_trash, err);
                report.errors = error_items.items.len;
                continue;
            },
        };
        defer allocator.free(moved);

        deleteMovedPath(moved, candidate.is_dir) catch |err| {
            try appendErrorItem(allocator, &error_items, moved, .delete_moved, err);
            report.errors = error_items.items.len;
            continue;
        };
        report.deleted_objects += 1;
        report.deleted_bytes += candidate.bytes;
    }

    report.error_items = try error_items.toOwnedSlice(allocator);
    transferred_errors = true;
    report.skipped_items = try skipped_items.toOwnedSlice(allocator);
    transferred_skipped = true;
    report.errors = report.error_items.len;
    return report;
}

fn appendErrorItem(
    allocator: std.mem.Allocator,
    error_items: *std.ArrayList(CleanError),
    path: []const u8,
    phase: ErrorPhase,
    err: anyerror,
) !void {
    try error_items.append(allocator, .{
        .path = try allocator.dupe(u8, path),
        .phase = phase,
        .reason = try allocator.dupe(u8, @errorName(err)),
    });
}

fn appendSkipItem(
    allocator: std.mem.Allocator,
    skipped_items: *std.ArrayList(CleanSkipItem),
    path: []const u8,
    reason: SkipReason,
) !void {
    try skipped_items.append(allocator, .{
        .path = try allocator.dupe(u8, path),
        .reason = reason,
    });
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

fn addAutomaticToolchainGcCandidates(
    allocator: std.mem.Allocator,
    candidates: *std.ArrayList(Candidate),
    options: CleanOptions,
    threshold_secs: i64,
    refs: *const CurrentRefs,
) !void {
    var entries = try listOfficialToolchainTrees(allocator, options.cache_root, threshold_secs);
    defer {
        for (entries.items) |*entry| entry.deinit(allocator);
        entries.deinit(allocator);
    }

    if (entries.items.len == 0) return;

    std.mem.sort(ToolchainTreeEntry, entries.items, {}, lessByNewestMtime);

    var kept: std.ArrayList(bool) = try std.ArrayList(bool).initCapacity(allocator, entries.items.len);
    defer kept.deinit(allocator);
    try kept.resize(allocator, entries.items.len);
    @memset(kept.items, false);

    if (refs.toolchain_tree_root) |current_tree_root| {
        for (entries.items, 0..) |entry, idx| {
            if (std.mem.eql(u8, entry.tree_root, current_tree_root)) {
                kept.items[idx] = true;
            }
        }
    }

    var keep_budget = options.keep_last;
    for (entries.items, 0..) |_, idx| {
        if (keep_budget == 0) break;
        if (kept.items[idx]) continue;
        kept.items[idx] = true;
        keep_budget -= 1;
    }

    if (options.toolchain_prune) {
        for (entries.items, 0..) |entry, idx| {
            if (kept.items[idx]) continue;
            try candidates.append(allocator, .{
                .path = try allocator.dupe(u8, entry.path),
                .scope = .toolchain,
                .is_dir = true,
                .bytes = entry.bytes,
            });
        }
    }

    if (options.official_max_bytes) |max_bytes| {
        var total_bytes: u64 = 0;
        for (entries.items) |entry| total_bytes += entry.bytes;
        if (total_bytes <= max_bytes) return;

        var oldest: std.ArrayList(usize) = .empty;
        defer oldest.deinit(allocator);
        for (entries.items, 0..) |_, idx| {
            if (!kept.items[idx]) try oldest.append(allocator, idx);
        }
        std.mem.sort(usize, oldest.items, entries.items, lessIndexByOldestMtime);

        for (oldest.items) |idx| {
            if (total_bytes <= max_bytes) break;
            const entry = entries.items[idx];
            try candidates.append(allocator, .{
                .path = try allocator.dupe(u8, entry.path),
                .scope = .toolchain,
                .is_dir = true,
                .bytes = entry.bytes,
            });
            total_bytes = if (entry.bytes > total_bytes) 0 else total_bytes - entry.bytes;
        }
    }
}

fn listOfficialToolchainTrees(allocator: std.mem.Allocator, cache_root: []const u8, threshold_secs: i64) !std.ArrayList(ToolchainTreeEntry) {
    var entries: std.ArrayList(ToolchainTreeEntry) = .empty;
    errdefer {
        for (entries.items) |*entry| entry.deinit(allocator);
        entries.deinit(allocator);
    }

    const base = try std.fs.path.join(allocator, &.{ cache_root, "cas", "official", "tree" });
    defer allocator.free(base);

    var dir = std.fs.cwd().openDir(base, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => return entries,
        else => return err,
    };
    defer dir.close();

    var iter = dir.iterate();
    while (try iter.next()) |entry| {
        if (entry.kind != .directory) continue;
        if (entry.name.len != 64) continue;
        if (!isHex64(entry.name)) continue;

        const path = try std.fs.path.join(allocator, &.{ base, entry.name });
        errdefer allocator.free(path);
        const mtime_secs = try getPathMtimeSeconds(path, true);
        if (mtime_secs > threshold_secs) {
            allocator.free(path);
            continue;
        }
        const bytes = try computePathBytes(allocator, path, true);
        try entries.append(allocator, .{
            .tree_root = try allocator.dupe(u8, entry.name),
            .path = path,
            .mtime_secs = mtime_secs,
            .bytes = bytes,
        });
    }

    return entries;
}

fn isHex64(text: []const u8) bool {
    if (text.len != 64) return false;
    for (text) |ch| {
        if (!std.ascii.isHex(ch)) return false;
    }
    return true;
}

fn lessByNewestMtime(_: void, a: ToolchainTreeEntry, b: ToolchainTreeEntry) bool {
    if (a.mtime_secs == b.mtime_secs) return std.mem.lessThan(u8, a.tree_root, b.tree_root);
    return a.mtime_secs > b.mtime_secs;
}

fn lessIndexByOldestMtime(entries: []const ToolchainTreeEntry, a: usize, b: usize) bool {
    const ea = entries[a];
    const eb = entries[b];
    if (ea.mtime_secs == eb.mtime_secs) return std.mem.lessThan(u8, ea.tree_root, eb.tree_root);
    return ea.mtime_secs < eb.mtime_secs;
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

test "runClean reports in-use skipped items for current toolchain and release" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const cache_root = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/cache", .{tmp.sub_path});
    defer allocator.free(cache_root);
    const output_root = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/out", .{tmp.sub_path});
    defer allocator.free(output_root);

    try std.fs.cwd().makePath(cache_root);
    try std.fs.cwd().makePath(output_root);

    const work_file = try std.fs.path.join(allocator, &.{ cache_root, "work", "build-1", "file.txt" });
    defer allocator.free(work_file);
    if (std.fs.path.dirname(work_file)) |parent| try std.fs.cwd().makePath(parent);
    try std.fs.cwd().writeFile(.{ .sub_path = work_file, .data = "x" });

    const tree_root = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const toolchain_file = try std.fs.path.join(allocator, &.{ cache_root, "cas", "official", "tree", tree_root, "zig.exe" });
    defer allocator.free(toolchain_file);
    if (std.fs.path.dirname(toolchain_file)) |parent| try std.fs.cwd().makePath(parent);
    try std.fs.cwd().writeFile(.{ .sub_path = toolchain_file, .data = "x" });

    const release_file = try std.fs.path.join(allocator, &.{ output_root, "releases", "build-1", "app.exe" });
    defer allocator.free(release_file);
    if (std.fs.path.dirname(release_file)) |parent| try std.fs.cwd().makePath(parent);
    try std.fs.cwd().writeFile(.{ .sub_path = release_file, .data = "x" });

    const pointer_path = try std.fmt.allocPrint(allocator, "{s}.current", .{output_root});
    defer allocator.free(pointer_path);
    const pointer_json = try std.fmt.allocPrint(
        allocator,
        "{{\"version\":2,\"build_id\":\"build-1\",\"release_rel\":\"releases/build-1\",\"verify_mode\":\"strict\",\"toolchain_tree_root\":\"{s}\"}}",
        .{tree_root},
    );
    defer allocator.free(pointer_json);
    try std.fs.cwd().writeFile(.{ .sub_path = pointer_path, .data = pointer_json });

    var report = try runClean(allocator, .{
        .cache_root = cache_root,
        .output_root = output_root,
        .scopes = cli_types.CleanScopeSet.all(),
        .older_than_secs = 0,
        .toolchain_tree_root = null,
        .toolchain_prune = false,
        .keep_last = 1,
        .official_max_bytes = null,
        .apply = false,
    });
    defer report.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 2), report.skipped_in_use);
    try std.testing.expectEqual(@as(usize, 2), report.skipped_items.len);
    try std.testing.expectEqual(@as(usize, 1), report.planned_objects);
    try std.testing.expectEqual(@as(usize, 0), report.errors);

    var saw_toolchain = false;
    var saw_release = false;
    for (report.skipped_items) |item| {
        try std.testing.expectEqual(SkipReason.in_use, item.reason);
        if (std.mem.indexOf(u8, item.path, tree_root) != null) saw_toolchain = true;
        if (std.mem.indexOf(u8, item.path, "releases") != null) saw_release = true;
    }
    try std.testing.expect(saw_toolchain);
    try std.testing.expect(saw_release);
}

test "runClean returns CleanLocked when lock already exists" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const cache_root = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/cache", .{tmp.sub_path});
    defer allocator.free(cache_root);
    const output_root = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/out", .{tmp.sub_path});
    defer allocator.free(output_root);

    const lock_path = try std.fs.path.join(allocator, &.{ cache_root, ".locks", "clean.lock" });
    defer allocator.free(lock_path);
    try std.fs.cwd().makePath(lock_path);

    try std.testing.expectError(error.CleanLocked, runClean(allocator, .{
        .cache_root = cache_root,
        .output_root = output_root,
        .scopes = cli_types.CleanScopeSet.default(),
        .older_than_secs = 0,
        .toolchain_tree_root = null,
        .toolchain_prune = false,
        .keep_last = 1,
        .official_max_bytes = null,
        .apply = true,
    }));
}

test "runClean records error_items when move_to_trash fails" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const cache_root = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/cache", .{tmp.sub_path});
    defer allocator.free(cache_root);
    const output_root = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/out", .{tmp.sub_path});
    defer allocator.free(output_root);

    const work_file = try std.fs.path.join(allocator, &.{ cache_root, "work", "build-1", "file.txt" });
    defer allocator.free(work_file);
    if (std.fs.path.dirname(work_file)) |parent| try std.fs.cwd().makePath(parent);
    try std.fs.cwd().writeFile(.{ .sub_path = work_file, .data = "x" });

    // Force moveToTrash(makePath) to fail by occupying ".trash" with a file.
    const trash_file = try std.fs.path.join(allocator, &.{ cache_root, ".trash" });
    defer allocator.free(trash_file);
    if (std.fs.path.dirname(trash_file)) |parent| try std.fs.cwd().makePath(parent);
    try std.fs.cwd().writeFile(.{ .sub_path = trash_file, .data = "not-a-dir" });

    var report = try runClean(allocator, .{
        .cache_root = cache_root,
        .output_root = output_root,
        .scopes = cli_types.CleanScopeSet.default(),
        .older_than_secs = 0,
        .toolchain_tree_root = null,
        .toolchain_prune = false,
        .keep_last = 1,
        .official_max_bytes = null,
        .apply = true,
    });
    defer report.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), report.planned_objects);
    try std.testing.expectEqual(@as(usize, 0), report.deleted_objects);
    try std.testing.expectEqual(@as(usize, 1), report.errors);
    try std.testing.expectEqual(@as(usize, 1), report.error_items.len);
    try std.testing.expectEqual(ErrorPhase.move_to_trash, report.error_items[0].phase);
}
