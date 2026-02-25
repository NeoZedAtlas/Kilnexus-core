const builtin = @import("builtin");
const std = @import("std");
const validator = @import("../knx/validator.zig");

pub const InstallOptions = struct {
    cache_root: []const u8 = ".kilnexus-cache",
    verify_mode: validator.VerifyMode = .strict,
    download_attempts: u8 = 3,
    download_timeout_ms: u64 = 30_000,
    download_max_bytes: u64 = 1024 * 1024 * 1024,
    allow_insecure_http_source: bool = false,
};

pub const InstallSession = struct {
    allocator: std.mem.Allocator,
    spec: *const validator.ToolchainSpec,
    verify_mode: validator.VerifyMode,
    download_attempts: u8,
    download_timeout_ms: u64,
    download_max_bytes: u64,
    allow_insecure_http_source: bool,
    cache_root: []u8,
    blob_path: []u8,
    tree_path: []u8,
    fast_manifest_path: []u8,
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
        const fast_name = try std.fmt.allocPrint(allocator, "{s}.json", .{tree_hex[0..]});
        defer allocator.free(fast_name);
        const fast_manifest_path = try std.fs.path.join(allocator, &.{ cache_root, "cas", "official", "fast", "tree", fast_name });
        errdefer allocator.free(fast_manifest_path);

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
            .download_attempts = if (options.download_attempts == 0) 1 else options.download_attempts,
            .download_timeout_ms = options.download_timeout_ms,
            .download_max_bytes = options.download_max_bytes,
            .allow_insecure_http_source = options.allow_insecure_http_source,
            .cache_root = cache_root,
            .blob_path = blob_path,
            .tree_path = tree_path,
            .fast_manifest_path = fast_manifest_path,
            .staging_path = staging_path,
        };
    }

    pub fn deinit(self: *InstallSession) void {
        self.allocator.free(self.cache_root);
        self.allocator.free(self.blob_path);
        self.allocator.free(self.tree_path);
        self.allocator.free(self.fast_manifest_path);
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
        } else {
            verifyFastManifest(self.allocator, self.tree_path, self.fast_manifest_path) catch |err| switch (err) {
                error.FileNotFound => {
                    // Backward-compatible fallback: validate once in strict mode and mint fast manifest.
                    const digest = try computeTreeRootForDir(self.allocator, self.tree_path);
                    if (!std.mem.eql(u8, &digest, &self.spec.tree_root)) {
                        return error.TreeRootMismatch;
                    }
                    try writeFastManifest(self.allocator, self.tree_path, self.fast_manifest_path);
                },
                else => return err,
            };
        }

        self.cache_hit = true;
        self.computed_tree_root = self.spec.tree_root;
    }

    pub fn downloadBlob(self: *InstallSession) !void {
        if (self.cache_hit) return;
        if (try pathIsFile(self.blob_path)) return;

        const source = self.spec.source orelse return error.FileNotFound;
        const hard_cap = @min(self.download_max_bytes, self.spec.size);
        if (hard_cap < self.spec.size) return error.NoSpaceLeft;

        switch (try parseSource(source)) {
            .file_path => |source_path| {
                if (std.fs.path.dirname(self.blob_path)) |parent| {
                    try std.fs.cwd().makePath(parent);
                }
                try std.fs.cwd().copyFile(source_path, std.fs.cwd(), self.blob_path, .{});
            },
            .https_url => |url| try downloadHttpWithRetries(self, url, hard_cap),
            .http_url => |url| {
                if (!self.allow_insecure_http_source) return error.AccessDenied;
                try downloadHttpWithRetries(self, url, hard_cap);
            },
        }
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

        var blob_file = try std.fs.cwd().openFile(self.blob_path, .{});
        defer blob_file.close();
        const format = try detectBlobFormat(&blob_file);
        try blob_file.seekTo(0);

        var staging_dir = try std.fs.cwd().openDir(self.staging_path, .{});
        defer staging_dir.close();

        switch (format) {
            .raw_blob => {
                const staged_blob = try std.fs.path.join(self.allocator, &.{ self.staging_path, "toolchain.blob" });
                defer self.allocator.free(staged_blob);
                try std.fs.cwd().copyFile(self.blob_path, std.fs.cwd(), staged_blob, .{});
            },
            .tar => {
                var read_buffer: [64 * 1024]u8 = undefined;
                var file_reader = blob_file.reader(&read_buffer);
                try extractTarArchive(&staging_dir, &file_reader.interface);
            },
            .tar_gzip => {
                var read_buffer: [64 * 1024]u8 = undefined;
                var file_reader = blob_file.reader(&read_buffer);
                var window: [std.compress.flate.max_window_len]u8 = undefined;
                var decompress = std.compress.flate.Decompress.init(&file_reader.interface, .gzip, &window);
                try extractTarArchive(&staging_dir, &decompress.reader);
            },
        }
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

        try writeFastManifest(self.allocator, self.tree_path, self.fast_manifest_path);
        try makeReadOnlyRecursively(self.allocator, self.tree_path);
        self.cache_hit = true;
    }
};

pub fn computeTreeRootHexForDir(allocator: std.mem.Allocator, dir_path: []const u8) ![64]u8 {
    const digest = try computeTreeRootForDir(allocator, dir_path);
    return std.fmt.bytesToHex(digest, .lower);
}

const Source = union(enum) {
    file_path: []const u8,
    http_url: []const u8,
    https_url: []const u8,
};

fn parseSource(source: []const u8) !Source {
    if (std.mem.startsWith(u8, source, "file://")) {
        return .{ .file_path = source["file://".len..] };
    }
    if (std.mem.startsWith(u8, source, "https://")) {
        return .{ .https_url = source };
    }
    if (std.mem.startsWith(u8, source, "http://")) {
        return .{ .http_url = source };
    }
    if (std.mem.indexOf(u8, source, "://") != null) {
        return error.BadPathName;
    }
    return .{ .file_path = source };
}

fn downloadHttpWithRetries(self: *InstallSession, url: []const u8, hard_cap: u64) !void {
    var attempt: u8 = 0;
    while (attempt < self.download_attempts) : (attempt += 1) {
        downloadHttpAttempt(self, url, hard_cap) catch |err| {
            if (attempt + 1 >= self.download_attempts or !isRetryableDownloadError(err)) {
                return err;
            }
            const backoff_ms = @as(u64, 200) * (@as(u64, attempt) + 1);
            std.Thread.sleep(backoff_ms * std.time.ns_per_ms);
            continue;
        };
        return;
    }
}

fn downloadHttpAttempt(self: *InstallSession, url: []const u8, hard_cap: u64) !void {
    const uri = try std.Uri.parse(url);
    if (uri.user != null or uri.password != null) return error.AccessDenied;

    const deadline_ms = computeDeadlineMs(self.download_timeout_ms);
    try enforceDeadline(deadline_ms);

    var client: std.http.Client = .{ .allocator = self.allocator };
    defer client.deinit();

    var request = try client.request(.GET, uri, .{
        .redirect_behavior = .not_allowed,
        .keep_alive = false,
    });
    defer request.deinit();

    try enforceDeadline(deadline_ms);
    try request.sendBodiless();
    var redirect_buffer: [1]u8 = undefined;
    var response = try request.receiveHead(&redirect_buffer);
    try enforceDeadline(deadline_ms);

    if (response.head.status.class() != .success) {
        return mapHttpStatusToError(response.head.status);
    }
    if (response.head.content_length) |len| {
        if (len > hard_cap) return error.NoSpaceLeft;
    }

    var write_buffer: [8 * 1024]u8 = undefined;
    var atomic_file = try std.fs.cwd().atomicFile(self.blob_path, .{
        .mode = 0o644,
        .make_path = true,
        .write_buffer = &write_buffer,
    });
    defer atomic_file.deinit();

    var body_buffer: [32 * 1024]u8 = undefined;
    var chunk: [16 * 1024]u8 = undefined;
    const body_reader = response.reader(&body_buffer);

    var total_bytes: u64 = 0;
    while (true) {
        try enforceDeadline(deadline_ms);
        const read_len = body_reader.readSliceShort(&chunk) catch |err| switch (err) {
            error.ReadFailed => return response.bodyErr() orelse err,
        };
        if (read_len == 0) break;

        const next_total = total_bytes + read_len;
        if (next_total > hard_cap) return error.NoSpaceLeft;
        total_bytes = next_total;

        try atomic_file.file_writer.interface.writeAll(chunk[0..read_len]);
    }

    try atomic_file.finish();
}

fn mapHttpStatusToError(status: std.http.Status) anyerror {
    return switch (status) {
        .not_found => error.FileNotFound,
        .unauthorized, .forbidden => error.AccessDenied,
        .request_timeout, .too_many_requests, .bad_gateway, .service_unavailable, .gateway_timeout => error.ConnectionTimedOut,
        else => switch (status.class()) {
            .server_error => error.ConnectionResetByPeer,
            .client_error => error.AccessDenied,
            else => error.Unexpected,
        },
    };
}

fn computeDeadlineMs(timeout_ms: u64) ?u64 {
    if (timeout_ms == 0) return null;
    return nowMs() + timeout_ms;
}

fn nowMs() u64 {
    const now = std.time.milliTimestamp();
    if (now <= 0) return 0;
    return @intCast(now);
}

fn enforceDeadline(deadline_ms: ?u64) !void {
    if (deadline_ms) |deadline| {
        if (nowMs() > deadline) return error.ConnectionTimedOut;
    }
}

fn isRetryableDownloadError(err: anyerror) bool {
    return err == error.ConnectionTimedOut or
        err == error.ConnectionResetByPeer or
        err == error.ConnectionRefused or
        err == error.NetworkUnreachable or
        err == error.TemporaryNameServerFailure or
        err == error.NameServerFailure or
        err == error.HttpHeadersInvalid or
        err == error.HttpHeadersOversize or
        err == error.HttpChunkInvalid or
        err == error.HttpChunkTruncated or
        err == error.ReadFailed or
        err == error.WriteFailed;
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

const BlobFormat = enum {
    raw_blob,
    tar,
    tar_gzip,
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

fn detectBlobFormat(blob_file: *std.fs.File) !BlobFormat {
    var probe: [512]u8 = undefined;
    const read_len = try blob_file.read(&probe);
    if (read_len >= 2 and probe[0] == 0x1f and probe[1] == 0x8b) {
        return .tar_gzip;
    }
    if (read_len >= 512 and isTarHeader(probe[0..512])) {
        return .tar;
    }
    return .raw_blob;
}

fn isTarHeader(bytes: []const u8) bool {
    if (bytes.len < 263) return false;
    return std.mem.eql(u8, bytes[257..262], "ustar");
}

fn extractTarArchive(dir: *std.fs.Dir, reader: *std.Io.Reader) !void {
    var file_name_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var link_name_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var file_contents_buffer: [8 * 1024]u8 = undefined;
    var it: std.tar.Iterator = .init(reader, .{
        .file_name_buffer = &file_name_buffer,
        .link_name_buffer = &link_name_buffer,
    });

    while (try it.next()) |entry| {
        try validateArchivePath(entry.name);

        switch (entry.kind) {
            .directory => {
                if (entry.name.len > 0) {
                    try dir.makePath(entry.name);
                }
            },
            .sym_link => return error.SymlinkPolicyViolation,
            .file => {
                var output = try createDirAndFileSafe(dir.*, entry.name, tarFileMode(entry.mode));
                defer output.close();
                var writer = output.writer(&file_contents_buffer);
                try it.streamRemaining(entry, &writer.interface);
                try writer.interface.flush();
            },
        }
    }
}

fn createDirAndFileSafe(dir: std.fs.Dir, file_name: []const u8, mode: std.fs.File.Mode) !std.fs.File {
    const file = dir.createFile(file_name, .{
        .exclusive = true,
        .mode = mode,
    }) catch |err| {
        if (err == error.FileNotFound) {
            if (std.fs.path.dirname(file_name)) |dir_name| {
                try dir.makePath(dir_name);
                return try dir.createFile(file_name, .{
                    .exclusive = true,
                    .mode = mode,
                });
            }
        }
        return err;
    };
    return file;
}

fn tarFileMode(tar_mode: u32) std.fs.File.Mode {
    if (std.fs.has_executable_bit and (tar_mode & 0o111) != 0) {
        return 0o755;
    }
    return 0o644;
}

fn validateArchivePath(path: []const u8) !void {
    if (path.len == 0) return error.PathTraversalDetected;
    if (path[0] == '/' or path[0] == '\\') return error.PathTraversalDetected;
    if (std.mem.indexOfScalar(u8, path, '\\') != null) return error.PathTraversalDetected;
    if (std.mem.indexOfScalar(u8, path, ':')) |idx| {
        if (idx <= 1) return error.PathTraversalDetected;
    }

    var it = std.mem.splitScalar(u8, path, '/');
    while (it.next()) |segment| {
        if (segment.len == 0 or std.mem.eql(u8, segment, ".")) continue;
        if (std.mem.eql(u8, segment, "..")) return error.PathTraversalDetected;
    }
}

const TreeEntryDigest = struct {
    path: []u8,
    kind: u8,
    mode: u32,
    size: u64,
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
                const file_digest = try hashFile(&file);
                const stat = try file.stat();
                try entries.append(allocator, .{
                    .path = try allocator.dupe(u8, entry.path),
                    .kind = 1, // file
                    .mode = normalizeTreeEntryMode(stat.mode),
                    .size = file_digest.size,
                    .digest = file_digest.digest,
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
        var mode_bytes: [4]u8 = undefined;
        var size_bytes: [8]u8 = undefined;
        hasher.update(entry.path);
        hasher.update(&[_]u8{0});
        hasher.update(&[_]u8{entry.kind});
        std.mem.writeInt(u32, &mode_bytes, entry.mode, .little);
        hasher.update(&mode_bytes);
        std.mem.writeInt(u64, &size_bytes, entry.size, .little);
        hasher.update(&size_bytes);
        hasher.update(&entry.digest);
    }
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    return digest;
}

fn normalizeTreeEntryMode(mode: std.fs.File.Mode) u32 {
    if (std.fs.has_executable_bit and (mode & 0o111) != 0) {
        return 0o755;
    }
    return 0o644;
}

const FastCheck = struct {
    path: []u8,
    digest: [32]u8,
    size: u64,
    mode: u32,
};

fn writeFastManifest(allocator: std.mem.Allocator, tree_path: []const u8, manifest_path: []const u8) !void {
    const checks = try collectFastChecks(allocator, tree_path);
    defer {
        for (checks) |check| allocator.free(check.path);
        allocator.free(checks);
    }

    var write_buffer: [8 * 1024]u8 = undefined;
    var atomic_file = try std.fs.cwd().atomicFile(manifest_path, .{
        .mode = 0o644,
        .make_path = true,
        .write_buffer = &write_buffer,
    });
    defer atomic_file.deinit();

    var writer = &atomic_file.file_writer.interface;
    try writer.writeAll("{\"version\":1,\"checks\":[");
    for (checks, 0..) |check, idx| {
        if (idx != 0) try writer.writeAll(",");
        try writer.writeAll("{\"path\":");
        try std.json.Stringify.encodeJsonString(check.path, .{}, writer);
        try writer.writeAll(",\"sha256\":\"");
        const digest_hex = std.fmt.bytesToHex(check.digest, .lower);
        try writer.writeAll(digest_hex[0..]);
        try writer.print("\",\"size\":{d},\"mode\":{d}", .{
            check.size,
            check.mode,
        });
        try writer.writeAll("}");
    }
    try writer.writeAll("]}");
    try atomic_file.finish();
}

fn verifyFastManifest(allocator: std.mem.Allocator, tree_path: []const u8, manifest_path: []const u8) !void {
    const raw = try std.fs.cwd().readFileAlloc(allocator, manifest_path, 1024 * 1024);
    defer allocator.free(raw);

    const parsed = std.json.parseFromSlice(std.json.Value, allocator, raw, .{}) catch return error.TreeRootMismatch;
    defer parsed.deinit();

    const root = expectObject(parsed.value) catch return error.TreeRootMismatch;
    const version = expectIntegerField(root, "version") catch return error.TreeRootMismatch;
    if (version != 1) return error.TreeRootMismatch;
    const checks_array = expectArrayField(root, "checks") catch return error.TreeRootMismatch;
    if (checks_array.items.len == 0) return error.TreeRootMismatch;

    for (checks_array.items) |item| {
        const obj = expectObject(item) catch return error.TreeRootMismatch;
        const rel_path = expectStringField(obj, "path") catch return error.TreeRootMismatch;
        if (!isValidFastRelativePath(rel_path)) return error.TreeRootMismatch;
        const expected_hex = expectStringField(obj, "sha256") catch return error.TreeRootMismatch;
        const expected = parseHexFixed32(expected_hex) catch return error.TreeRootMismatch;
        const expected_size_i64 = expectIntegerField(obj, "size") catch return error.TreeRootMismatch;
        if (expected_size_i64 < 0) return error.TreeRootMismatch;
        const expected_size: u64 = @intCast(expected_size_i64);
        const expected_mode_i64 = expectIntegerField(obj, "mode") catch return error.TreeRootMismatch;
        if (expected_mode_i64 < 0) return error.TreeRootMismatch;
        const expected_mode: u32 = @intCast(expected_mode_i64);

        const abs_path = try std.fs.path.join(allocator, &.{ tree_path, rel_path });
        defer allocator.free(abs_path);
        const actual = hashFileAtPath(abs_path) catch return error.TreeRootMismatch;
        if (!std.mem.eql(u8, &actual.digest, &expected)) return error.TreeRootMismatch;
        if (actual.size != expected_size) return error.TreeRootMismatch;

        var file = std.fs.cwd().openFile(abs_path, .{}) catch return error.TreeRootMismatch;
        defer file.close();
        const stat = file.stat() catch return error.TreeRootMismatch;
        if (normalizeTreeEntryMode(stat.mode) != expected_mode) return error.TreeRootMismatch;
    }
}

fn collectFastChecks(allocator: std.mem.Allocator, tree_path: []const u8) ![]FastCheck {
    const prefer_windows = builtin.os.tag == .windows;
    const preferred = if (prefer_windows)
        [_][]const u8{ "zig.exe", "bin/zig.exe" }
    else
        [_][]const u8{ "zig", "bin/zig" };
    const additional_candidates = if (prefer_windows)
        [_][]const u8{
            "bin/clang.exe",
            "bin/lld-link.exe",
            "lib/libc/include/stdio.h",
            "lib/libc/include/stddef.h",
        }
    else
        [_][]const u8{
            "bin/clang",
            "bin/ld.lld",
            "lib/libc/include/stdio.h",
            "lib/libc/include/stddef.h",
        };

    var checks: std.ArrayList(FastCheck) = .empty;
    var seen: std.StringHashMap(void) = .init(allocator);
    errdefer {
        for (checks.items) |item| allocator.free(item.path);
        checks.deinit(allocator);
    }
    defer seen.deinit();

    for (preferred) |rel| {
        try appendFastCheckIfExists(allocator, tree_path, rel, &checks, &seen);
    }
    for (additional_candidates) |rel| {
        try appendFastCheckIfExists(allocator, tree_path, rel, &checks, &seen);
    }
    if (checks.items.len > 0) {
        return checks.toOwnedSlice(allocator);
    }

    var root_dir = try std.fs.cwd().openDir(tree_path, .{ .iterate = true });
    defer root_dir.close();
    var walker = try root_dir.walk(allocator);
    defer walker.deinit();

    var first_rel: ?[]u8 = null;
    defer if (first_rel) |path| allocator.free(path);

    while (try walker.next()) |entry| {
        if (entry.kind != .file) continue;
        if (first_rel == null or std.mem.order(u8, entry.path, first_rel.?) == .lt) {
            if (first_rel) |old| allocator.free(old);
            first_rel = try allocator.dupe(u8, entry.path);
        }
    }

    const rel = first_rel orelse return error.FileNotFound;
    try appendFastCheck(allocator, tree_path, rel, &checks, &seen);
    return checks.toOwnedSlice(allocator);
}

fn appendFastCheckIfExists(
    allocator: std.mem.Allocator,
    tree_path: []const u8,
    rel: []const u8,
    checks: *std.ArrayList(FastCheck),
    seen: *std.StringHashMap(void),
) !void {
    const abs = try std.fs.path.join(allocator, &.{ tree_path, rel });
    defer allocator.free(abs);
    if (!(try pathIsFile(abs))) return;
    try appendFastCheck(allocator, tree_path, rel, checks, seen);
}

fn appendFastCheck(
    allocator: std.mem.Allocator,
    tree_path: []const u8,
    rel: []const u8,
    checks: *std.ArrayList(FastCheck),
    seen: *std.StringHashMap(void),
) !void {
    if (seen.contains(rel)) return;
    try seen.put(rel, {});

    const abs = try std.fs.path.join(allocator, &.{ tree_path, rel });
    defer allocator.free(abs);
    const info = try hashFileAtPath(abs);
    var file = try std.fs.cwd().openFile(abs, .{});
    defer file.close();
    const stat = try file.stat();
    try checks.append(allocator, .{
        .path = try allocator.dupe(u8, rel),
        .digest = info.digest,
        .size = info.size,
        .mode = normalizeTreeEntryMode(stat.mode),
    });
}

fn parseHexFixed32(text: []const u8) ![32]u8 {
    if (text.len != 64) return error.InvalidHexLength;
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, text) catch return error.InvalidHexChar;
    return out;
}

fn isValidFastRelativePath(path: []const u8) bool {
    if (path.len == 0) return false;
    if (std.fs.path.isAbsolute(path)) return false;
    if (std.mem.indexOfScalar(u8, path, '\\') != null) return false;
    if (std.mem.indexOfScalar(u8, path, ':') != null) return false;

    var it = std.mem.splitScalar(u8, path, '/');
    while (it.next()) |segment| {
        if (segment.len == 0 or std.mem.eql(u8, segment, ".") or std.mem.eql(u8, segment, "..")) return false;
    }
    return true;
}

fn expectObject(value: std.json.Value) !std.json.ObjectMap {
    return switch (value) {
        .object => |obj| obj,
        else => error.ExpectedObject,
    };
}

fn expectArrayField(object: std.json.ObjectMap, key: []const u8) !std.json.Array {
    const value = object.get(key) orelse return error.MissingRequiredField;
    return switch (value) {
        .array => |arr| arr,
        else => error.ExpectedArray,
    };
}

fn expectStringField(object: std.json.ObjectMap, key: []const u8) ![]const u8 {
    const value = object.get(key) orelse return error.MissingRequiredField;
    return switch (value) {
        .string => |str| str,
        else => error.ExpectedString,
    };
}

fn expectIntegerField(object: std.json.ObjectMap, key: []const u8) !i64 {
    const value = object.get(key) orelse return error.MissingRequiredField;
    return switch (value) {
        .integer => |number| number,
        else => error.ExpectedInteger,
    };
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
    if (builtin.os.tag == .windows) {
        try tightenWindowsAcl(allocator, root_path);
        return;
    }

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

fn tightenWindowsAcl(allocator: std.mem.Allocator, root_path: []const u8) !void {
    const icacls_exe = try resolveIcaclsPath(allocator);
    defer allocator.free(icacls_exe);

    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{
            icacls_exe,
            root_path,
            "/inheritance:r",
            "/grant:r",
            "*S-1-5-18:(RX)",
            "*S-1-5-32-544:(RX)",
            "*S-1-5-11:(RX)",
            "/grant",
            "*S-1-5-18:(OI)(CI)(RX)",
            "*S-1-5-32-544:(OI)(CI)(RX)",
            "*S-1-5-11:(OI)(CI)(RX)",
            "/T",
            "/C",
            "/Q",
        },
        .max_output_bytes = 64 * 1024,
    }) catch |err| switch (err) {
        error.FileNotFound => return error.FileNotFound,
        error.AccessDenied => return error.AccessDenied,
        else => return error.Unexpected,
    };
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    switch (result.term) {
        .Exited => |code| {
            if (code != 0) return error.AccessDenied;
        },
        else => return error.AccessDenied,
    }
}

fn resolveIcaclsPath(allocator: std.mem.Allocator) ![]u8 {
    const win_dir = std.process.getEnvVarOwned(allocator, "WINDIR") catch {
        return allocator.dupe(u8, "icacls");
    };
    defer allocator.free(win_dir);

    const candidate = try std.fs.path.join(allocator, &.{ win_dir, "System32", "icacls.exe" });
    if (pathIsFile(candidate) catch false) {
        return candidate;
    }
    allocator.free(candidate);
    return allocator.dupe(u8, "icacls");
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
    const fast_manifest = try std.fmt.allocPrint(allocator, "{s}/cas/official/fast/tree/{s}.json", .{ cache_root, root_hex[0..] });
    defer allocator.free(fast_manifest);

    try std.testing.expect(try pathIsDirectory(installed_tree));
    if (builtin.os.tag == .windows) {
        std.fs.cwd().access(installed_blob, .{}) catch |err| switch (err) {
            error.AccessDenied => {},
            else => return err,
        };
    } else {
        try std.testing.expect(try pathIsFile(installed_blob));
    }
    try std.testing.expect(try pathIsFile(fast_manifest));
}

test "resolveToolchain fast detects sidecar hash mismatch" {
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
    const cache_root = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/cache-fast", .{sub});
    defer allocator.free(cache_root);

    const blob_info = try hashFileAtPath(source_rel);
    const tree_root = try computeTreeRootForDir(allocator, expected_rel);

    var spec: validator.ToolchainSpec = .{
        .id = try allocator.dupe(u8, "zigcc-fast"),
        .source = try allocator.dupe(u8, source_rel),
        .blob_sha256 = blob_info.digest,
        .tree_root = tree_root,
        .size = blob_info.size,
    };
    defer spec.deinit(allocator);

    var strict_session = try InstallSession.init(allocator, &spec, .{
        .cache_root = cache_root,
        .verify_mode = .strict,
    });
    defer strict_session.deinit();

    try strict_session.resolveToolchain();
    try strict_session.downloadBlob();
    try strict_session.verifyBlob();
    try strict_session.unpackStaging();
    try strict_session.computeTreeRoot();
    try strict_session.verifyTreeRoot();
    try strict_session.sealCacheObject();

    const root_hex = std.fmt.bytesToHex(spec.tree_root, .lower);
    const fast_manifest = try std.fmt.allocPrint(allocator, "{s}/cas/official/fast/tree/{s}.json", .{ cache_root, root_hex[0..] });
    defer allocator.free(fast_manifest);
    try std.fs.cwd().writeFile(.{
        .sub_path = fast_manifest,
        .data = "{\"version\":1,\"checks\":[{\"path\":\"toolchain.blob\",\"sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}]}",
    });

    var fast_session = try InstallSession.init(allocator, &spec, .{
        .cache_root = cache_root,
        .verify_mode = .fast,
    });
    defer fast_session.deinit();

    try std.testing.expectError(error.TreeRootMismatch, fast_session.resolveToolchain());
}

test "verifyFastManifest fails when checked file content changes" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("tree");
    try tmp.dir.writeFile(.{
        .sub_path = "tree/toolchain.blob",
        .data = "v1\n",
    });

    const tree_rel = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/tree", .{tmp.sub_path[0..]});
    defer allocator.free(tree_rel);
    const manifest_rel = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/manifest.json", .{tmp.sub_path[0..]});
    defer allocator.free(manifest_rel);

    try writeFastManifest(allocator, tree_rel, manifest_rel);

    try tmp.dir.writeFile(.{
        .sub_path = "tree/toolchain.blob",
        .data = "v2\n",
    });

    try std.testing.expectError(error.TreeRootMismatch, verifyFastManifest(allocator, tree_rel, manifest_rel));
}

test "resolveToolchain fast falls back to strict when sidecar missing" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const cache_root = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/cache-fast-fallback", .{tmp.sub_path[0..]});
    defer allocator.free(cache_root);

    const tree_seed = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/seed-tree", .{tmp.sub_path[0..]});
    defer allocator.free(tree_seed);
    try std.fs.cwd().makePath(tree_seed);
    const seed_blob = try std.fs.path.join(allocator, &.{ tree_seed, "toolchain.blob" });
    defer allocator.free(seed_blob);
    try std.fs.cwd().writeFile(.{
        .sub_path = seed_blob,
        .data = "seed\n",
    });

    const tree_root = try computeTreeRootForDir(allocator, tree_seed);
    const tree_hex = std.fmt.bytesToHex(tree_root, .lower);
    const installed_tree = try std.fmt.allocPrint(allocator, "{s}/cas/official/tree/{s}", .{ cache_root, tree_hex[0..] });
    defer allocator.free(installed_tree);
    try std.fs.cwd().makePath(installed_tree);
    const installed_blob = try std.fs.path.join(allocator, &.{ installed_tree, "toolchain.blob" });
    defer allocator.free(installed_blob);
    try std.fs.cwd().writeFile(.{
        .sub_path = installed_blob,
        .data = "seed\n",
    });

    var spec: validator.ToolchainSpec = .{
        .id = try allocator.dupe(u8, "zigcc-fast-fallback"),
        .source = null,
        .blob_sha256 = [_]u8{0xaa} ** 32,
        .tree_root = tree_root,
        .size = 0,
    };
    defer spec.deinit(allocator);

    var session = try InstallSession.init(allocator, &spec, .{
        .cache_root = cache_root,
        .verify_mode = .fast,
    });
    defer session.deinit();

    try session.resolveToolchain();
    try std.testing.expect(session.cache_hit);

    const sidecar = try std.fmt.allocPrint(allocator, "{s}/cas/official/fast/tree/{s}.json", .{ cache_root, tree_hex[0..] });
    defer allocator.free(sidecar);
    try std.testing.expect(try pathIsFile(sidecar));
}

test "downloadBlob rejects insecure http source by default" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const sub = tmp.sub_path[0..];
    const cache_root = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/cache-http", .{sub});
    defer allocator.free(cache_root);

    var spec: validator.ToolchainSpec = .{
        .id = try allocator.dupe(u8, "zigcc-http"),
        .source = try allocator.dupe(u8, "http://example.invalid/toolchain.blob"),
        .blob_sha256 = [_]u8{0xaa} ** 32,
        .tree_root = [_]u8{0xbb} ** 32,
        .size = 16,
    };
    defer spec.deinit(allocator);

    var session = try InstallSession.init(allocator, &spec, .{
        .cache_root = cache_root,
    });
    defer session.deinit();

    try std.testing.expectError(error.AccessDenied, session.downloadBlob());
}

test "unpackStaging rejects tar path traversal entries" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var out: std.Io.Writer.Allocating = .init(allocator);
    defer out.deinit();
    var tar_writer: std.tar.Writer = .{
        .underlying_writer = &out.writer,
    };
    try tar_writer.writeFileBytes("../escape.bin", "bad", .{});
    try tar_writer.finishPedantically();
    const tar_bytes = try out.toOwnedSlice();
    defer allocator.free(tar_bytes);

    try tmp.dir.writeFile(.{
        .sub_path = "source.tar",
        .data = tar_bytes,
    });

    const sub = tmp.sub_path[0..];
    const source_rel = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/source.tar", .{sub});
    defer allocator.free(source_rel);
    const cache_root = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/cache-tar", .{sub});
    defer allocator.free(cache_root);

    const blob_info = try hashFileAtPath(source_rel);
    var spec: validator.ToolchainSpec = .{
        .id = try allocator.dupe(u8, "zigcc-tar"),
        .source = try allocator.dupe(u8, source_rel),
        .blob_sha256 = blob_info.digest,
        .tree_root = [_]u8{0xcc} ** 32,
        .size = blob_info.size,
    };
    defer spec.deinit(allocator);

    var session = try InstallSession.init(allocator, &spec, .{
        .cache_root = cache_root,
    });
    defer session.deinit();

    try session.downloadBlob();
    try std.testing.expectError(error.PathTraversalDetected, session.unpackStaging());
}

test "computeTreeRootForDir includes normalized mode bits" {
    if (!std.fs.has_executable_bit) return;

    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("tree-a/bin");
    try tmp.dir.writeFile(.{
        .sub_path = "tree-a/bin/tool",
        .data = "same-bytes\n",
    });
    try tmp.dir.makePath("tree-b/bin");
    try tmp.dir.writeFile(.{
        .sub_path = "tree-b/bin/tool",
        .data = "same-bytes\n",
    });

    var non_exec = try tmp.dir.openFile("tree-a/bin/tool", .{});
    defer non_exec.close();
    try non_exec.chmod(0o644);

    var exec = try tmp.dir.openFile("tree-b/bin/tool", .{});
    defer exec.close();
    try exec.chmod(0o755);

    const root_a = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/tree-a", .{tmp.sub_path[0..]});
    defer allocator.free(root_a);
    const root_b = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/tree-b", .{tmp.sub_path[0..]});
    defer allocator.free(root_b);

    const digest_a = try computeTreeRootForDir(allocator, root_a);
    const digest_b = try computeTreeRootForDir(allocator, root_b);

    try std.testing.expect(!std.mem.eql(u8, &digest_a, &digest_b));
}
