const builtin = @import("builtin");
const std = @import("std");
const validator = @import("../knx/validator.zig");

pub const InstallOptions = struct {
    cache_root: []const u8 = ".kilnexus-cache",
    verify_mode: validator.VerifyMode = .strict,
};

pub const InstallSession = struct {
    allocator: std.mem.Allocator,
    spec: *const validator.ToolchainSpec,
    verify_mode: validator.VerifyMode,
    cache_root: []u8,
    blob_path: []u8,
    tree_path: []u8,
    staging_path: []u8,
    computed_tree_root: ?[32]u8 = null,
    cache_hit: bool = false,

    pub fn init(
        allocator: std.mem.Allocator,
        spec: *const validator.ToolchainSpec,
        options: InstallOptions,
    ) !InstallSession {
        const cache_root = try allocator.dupe(u8, options.cache_root);
        errdefer allocator.free(cache_root);

        const blob_hex = std.fmt.bytesToHex(spec.blob_sha256, .lower);
        const tree_hex = std.fmt.bytesToHex(spec.tree_root, .lower);
        const blob_path = try std.fs.path.join(allocator, &.{ cache_root, "cas", "official", "blob", blob_hex[0..], "blob.bin" });
        errdefer allocator.free(blob_path);
        const tree_path = try std.fs.path.join(allocator, &.{ cache_root, "cas", "official", "tree", tree_hex[0..] });
        errdefer allocator.free(tree_path);

        const sanitized_id = try sanitizeId(allocator, spec.id);
        defer allocator.free(sanitized_id);
        const nonce = std.time.microTimestamp();
        const staging_tag = try std.fmt.allocPrint(allocator, "{s}-{d}", .{ sanitized_id, nonce });
        defer allocator.free(staging_tag);
        const staging_path = try std.fs.path.join(allocator, &.{ cache_root, "staging", staging_tag });
        errdefer allocator.free(staging_path);

        return .{
            .allocator = allocator,
            .spec = spec,
            .verify_mode = options.verify_mode,
            .cache_root = cache_root,
            .blob_path = blob_path,
            .tree_path = tree_path,
            .staging_path = staging_path,
        };
    }

    pub fn deinit(self: *InstallSession) void {
        self.allocator.free(self.cache_root);
        self.allocator.free(self.blob_path);
        self.allocator.free(self.tree_path);
        self.allocator.free(self.staging_path);
        self.* = undefined;
    }

    pub fn resolveToolchain(self: *InstallSession) !void {
        if (!try pathIsDirectory(self.tree_path)) return;

        if (self.verify_mode == .strict) {
            const digest = try computeTreeRootForDir(self.allocator, self.tree_path);
            if (!std.mem.eql(u8, &digest, &self.spec.tree_root)) {
                return error.TreeRootMismatch;
            }
        }

        self.cache_hit = true;
        self.computed_tree_root = self.spec.tree_root;
    }

    pub fn downloadBlob(self: *InstallSession) !void {
        if (self.cache_hit) return;
        if (try pathIsFile(self.blob_path)) return;

        const source = self.spec.source orelse return error.FileNotFound;
        const source_path = try resolveSourcePath(source);

        if (std.fs.path.dirname(self.blob_path)) |parent| {
            try std.fs.cwd().makePath(parent);
        }

        try std.fs.cwd().copyFile(source_path, std.fs.cwd(), self.blob_path, .{});
    }

    pub fn verifyBlob(self: *InstallSession) !void {
        if (self.cache_hit) return;

        const blob_info = try hashFileAtPath(self.blob_path);
        if (blob_info.size != self.spec.size) return error.SizeMismatch;
        if (!std.mem.eql(u8, &blob_info.digest, &self.spec.blob_sha256)) {
            return error.BlobHashMismatch;
        }
    }

    pub fn unpackStaging(self: *InstallSession) !void {
        if (self.cache_hit) return;

        if (try pathIsDirectory(self.staging_path)) {
            try std.fs.cwd().deleteTree(self.staging_path);
        }
        try std.fs.cwd().makePath(self.staging_path);

        const staged_blob = try std.fs.path.join(self.allocator, &.{ self.staging_path, "toolchain.blob" });
        defer self.allocator.free(staged_blob);
        try std.fs.cwd().copyFile(self.blob_path, std.fs.cwd(), staged_blob, .{});
    }

    pub fn computeTreeRoot(self: *InstallSession) !void {
        if (self.cache_hit) {
            self.computed_tree_root = self.spec.tree_root;
            return;
        }
        self.computed_tree_root = try computeTreeRootForDir(self.allocator, self.staging_path);
    }

    pub fn verifyTreeRoot(self: *InstallSession) !void {
        if (self.cache_hit) return;
        const digest = self.computed_tree_root orelse return error.TreeRootMismatch;
        if (!std.mem.eql(u8, &digest, &self.spec.tree_root)) {
            return error.TreeRootMismatch;
        }
    }

    pub fn sealCacheObject(self: *InstallSession) !void {
        if (self.cache_hit) return;

        if (std.fs.path.dirname(self.tree_path)) |parent| {
            try std.fs.cwd().makePath(parent);
        }

        std.fs.cwd().rename(self.staging_path, self.tree_path) catch |err| switch (err) {
            error.PathAlreadyExists => {
                std.fs.cwd().deleteTree(self.staging_path) catch {};
                self.cache_hit = true;
                return;
            },
            else => return err,
        };

        try makeReadOnlyRecursively(self.allocator, self.tree_path);
        self.cache_hit = true;
    }
};

pub fn computeTreeRootHexForDir(allocator: std.mem.Allocator, dir_path: []const u8) ![64]u8 {
    const digest = try computeTreeRootForDir(allocator, dir_path);
    return std.fmt.bytesToHex(digest, .lower);
}

fn resolveSourcePath(source: []const u8) ![]const u8 {
    if (std.mem.startsWith(u8, source, "file://")) {
        return source["file://".len..];
    }
    if (std.mem.indexOf(u8, source, "://") != null) {
        return error.BadPathName;
    }
    return source;
}

fn sanitizeId(allocator: std.mem.Allocator, text: []const u8) ![]u8 {
    var out = try allocator.alloc(u8, text.len);
    for (text, 0..) |ch, idx| {
        out[idx] = switch (ch) {
            'a'...'z', 'A'...'Z', '0'...'9', '-', '_', '.' => ch,
            else => '_',
        };
    }
    return out;
}

const FileDigest = struct {
    digest: [32]u8,
    size: u64,
};

fn hashFileAtPath(path: []const u8) !FileDigest {
    var file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    return hashFile(&file);
}

fn hashFile(file: *std.fs.File) !FileDigest {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var buffer: [64 * 1024]u8 = undefined;
    var size: u64 = 0;

    while (true) {
        const read_len = try file.read(&buffer);
        if (read_len == 0) break;
        hasher.update(buffer[0..read_len]);
        size += read_len;
    }

    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    return .{
        .digest = digest,
        .size = size,
    };
}

const TreeEntryDigest = struct {
    path: []u8,
    digest: [32]u8,
};

fn computeTreeRootForDir(allocator: std.mem.Allocator, dir_path: []const u8) ![32]u8 {
    var root_dir = try std.fs.cwd().openDir(dir_path, .{ .iterate = true });
    defer root_dir.close();

    var walker = try root_dir.walk(allocator);
    defer walker.deinit();

    var entries: std.ArrayList(TreeEntryDigest) = .empty;
    defer {
        for (entries.items) |entry| allocator.free(entry.path);
        entries.deinit(allocator);
    }

    while (try walker.next()) |entry| {
        switch (entry.kind) {
            .directory => continue,
            .sym_link => return error.SymlinkPolicyViolation,
            .file => {
                var file = try entry.dir.openFile(entry.basename, .{});
                defer file.close();
                const digest = (try hashFile(&file)).digest;
                try entries.append(allocator, .{
                    .path = try allocator.dupe(u8, entry.path),
                    .digest = digest,
                });
            },
            else => return error.SymlinkPolicyViolation,
        }
    }

    std.sort.pdq(TreeEntryDigest, entries.items, {}, struct {
        fn lessThan(_: void, lhs: TreeEntryDigest, rhs: TreeEntryDigest) bool {
            return std.mem.order(u8, lhs.path, rhs.path) == .lt;
        }
    }.lessThan);

    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    for (entries.items) |entry| {
        hasher.update(entry.path);
        hasher.update(&[_]u8{0});
        hasher.update(&entry.digest);
    }
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    return digest;
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
        error.FileNotFound, error.NotDir => return false,
        else => return err,
    };
    file.close();
    return true;
}

fn makeReadOnlyRecursively(allocator: std.mem.Allocator, root_path: []const u8) !void {
    if (builtin.os.tag == .windows) return;

    var root = try std.fs.cwd().openDir(root_path, .{ .iterate = true });
    defer root.close();

    var walker = try root.walk(allocator);
    defer walker.deinit();

    while (try walker.next()) |entry| {
        switch (entry.kind) {
            .directory => {
                var dir = try entry.dir.openDir(entry.basename, .{ .iterate = true });
                defer dir.close();
                dir.chmod(0o555) catch {};
            },
            .file => {
                var file = try entry.dir.openFile(entry.basename, .{});
                defer file.close();
                file.chmod(0o555) catch {};
            },
            else => {},
        }
    }

    root.chmod(0o555) catch {};
}

test "install session materializes and seals local blob source" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(.{
        .sub_path = "source.blob",
        .data = "toolchain-bytes-v1",
    });
    try tmp.dir.makePath("expected");
    try tmp.dir.copyFile("source.blob", tmp.dir, "expected/toolchain.blob", .{});

    const sub = tmp.sub_path[0..];
    const source_rel = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/source.blob", .{sub});
    defer allocator.free(source_rel);
    const expected_rel = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/expected", .{sub});
    defer allocator.free(expected_rel);
    const cache_root = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/cache", .{sub});
    defer allocator.free(cache_root);

    const blob_info = try hashFileAtPath(source_rel);
    const tree_root = try computeTreeRootForDir(allocator, expected_rel);

    var spec: validator.ToolchainSpec = .{
        .id = try allocator.dupe(u8, "zigcc-test"),
        .source = try allocator.dupe(u8, source_rel),
        .blob_sha256 = blob_info.digest,
        .tree_root = tree_root,
        .size = blob_info.size,
    };
    defer spec.deinit(allocator);

    var session = try InstallSession.init(allocator, &spec, .{
        .cache_root = cache_root,
        .verify_mode = .strict,
    });
    defer session.deinit();

    try session.resolveToolchain();
    try session.downloadBlob();
    try session.verifyBlob();
    try session.unpackStaging();
    try session.computeTreeRoot();
    try session.verifyTreeRoot();
    try session.sealCacheObject();

    const root_hex = std.fmt.bytesToHex(spec.tree_root, .lower);
    const installed_tree = try std.fmt.allocPrint(allocator, "{s}/cas/official/tree/{s}", .{ cache_root, root_hex[0..] });
    defer allocator.free(installed_tree);
    const installed_blob = try std.fmt.allocPrint(allocator, "{s}/cas/official/tree/{s}/toolchain.blob", .{ cache_root, root_hex[0..] });
    defer allocator.free(installed_blob);

    try std.testing.expect(try pathIsDirectory(installed_tree));
    try std.testing.expect(try pathIsFile(installed_blob));
}
