const builtin = @import("builtin");
const std = @import("std");
const validator = @import("../../knx/validator.zig");
const workspace_types = @import("types.zig");
const tree_hash = @import("tree_hash.zig");

const ProjectOptions = workspace_types.ProjectOptions;

pub const Prepared = struct {
    id: []const u8,
    root_abs_path: []u8,
    is_tree: bool,
    tree_root: ?[32]u8 = null,
};

const Source = union(enum) {
    file_path: []const u8,
    http_url: []const u8,
    https_url: []const u8,
};

const BlobFormat = enum {
    raw,
    tar,
    tar_gzip,
    zip,
};

pub fn prepareRemoteInputs(
    allocator: std.mem.Allocator,
    workspace_spec: *const validator.WorkspaceSpec,
    options: ProjectOptions,
) ![]Prepared {
    const remote_inputs = workspace_spec.remote_inputs orelse return try allocator.alloc(Prepared, 0);

    var prepared: std.ArrayList(Prepared) = .empty;
    errdefer {
        for (prepared.items) |item| allocator.free(item.root_abs_path);
        prepared.deinit(allocator);
    }

    var seen_ids: std.StringHashMap(void) = .init(allocator);
    defer seen_ids.deinit();

    for (remote_inputs) |remote| {
        const gop = try seen_ids.getOrPut(remote.id);
        if (gop.found_existing) return error.InvalidBuildGraph;

        const blob_hex = std.fmt.bytesToHex(remote.blob_sha256, .lower);
        const blob_path = try std.fs.path.join(allocator, &.{
            options.cache_root,
            "cas",
            "third_party",
            "blob",
            blob_hex[0..],
            "blob.bin",
        });
        defer allocator.free(blob_path);

        try ensureRemoteBlob(allocator, blob_path, remote, options);
        const blob_abs = try std.fs.cwd().realpathAlloc(allocator, blob_path);

        if (!remote.extract) {
            errdefer allocator.free(blob_abs);
            try prepared.append(allocator, .{
                .id = remote.id,
                .root_abs_path = blob_abs,
                .is_tree = false,
                .tree_root = null,
            });
            continue;
        }

        const expected_tree_root = remote.tree_root orelse return error.MissingRequiredField;
        allocator.free(blob_abs);
        const tree_hex = std.fmt.bytesToHex(expected_tree_root, .lower);
        const tree_path = try std.fs.path.join(allocator, &.{
            options.cache_root,
            "cas",
            "third_party",
            "tree",
            tree_hex[0..],
        });
        defer allocator.free(tree_path);

        try ensureRemoteExtractedTree(allocator, blob_path, tree_path, expected_tree_root, remote.id, options);
        const tree_abs = try std.fs.cwd().realpathAlloc(allocator, tree_path);
        errdefer allocator.free(tree_abs);

        try prepared.append(allocator, .{
            .id = remote.id,
            .root_abs_path = tree_abs,
            .is_tree = true,
            .tree_root = expected_tree_root,
        });
    }

    return prepared.toOwnedSlice(allocator);
}

pub fn findPreparedRemote(prepared: []const Prepared, id: []const u8) ?Prepared {
    for (prepared) |item| {
        if (std.mem.eql(u8, item.id, id)) return item;
    }
    return null;
}

fn ensureRemoteBlob(
    allocator: std.mem.Allocator,
    blob_path: []const u8,
    remote: validator.RemoteInputSpec,
    options: ProjectOptions,
) !void {
    if (try pathIsFile(blob_path)) {
        const digest = try tree_hash.hashFileAtPath(blob_path);
        if (!std.mem.eql(u8, &digest.digest, &remote.blob_sha256)) {
            return error.BlobHashMismatch;
        }
        return;
    }

    const source = try parseRemoteSource(remote.url);
    switch (source) {
        .file_path => |source_path| {
            if (std.fs.path.dirname(blob_path)) |parent| {
                try std.fs.cwd().makePath(parent);
            }
            try std.fs.cwd().copyFile(source_path, std.fs.cwd(), blob_path, .{});
        },
        .https_url => |url| {
            try downloadRemoteHttpWithRetries(allocator, url, blob_path, options);
        },
        .http_url => |url| {
            if (!options.allow_insecure_http_source) return error.AccessDenied;
            try downloadRemoteHttpWithRetries(allocator, url, blob_path, options);
        },
    }

    const digest = try tree_hash.hashFileAtPath(blob_path);
    if (!std.mem.eql(u8, &digest.digest, &remote.blob_sha256)) {
        return error.BlobHashMismatch;
    }
}

fn parseRemoteSource(source: []const u8) !Source {
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

fn downloadRemoteHttpWithRetries(
    allocator: std.mem.Allocator,
    url: []const u8,
    blob_path: []const u8,
    options: ProjectOptions,
) !void {
    const attempts = if (options.remote_download_attempts == 0) 1 else options.remote_download_attempts;
    var attempt: u8 = 0;
    while (attempt < attempts) : (attempt += 1) {
        downloadRemoteHttpAttempt(allocator, url, blob_path, options) catch |err| {
            if (attempt + 1 >= attempts or !isRetryableDownloadError(err)) return err;
            const backoff_ms = @as(u64, 200) * (@as(u64, attempt) + 1);
            std.Thread.sleep(backoff_ms * std.time.ns_per_ms);
            continue;
        };
        return;
    }
}

fn downloadRemoteHttpAttempt(
    allocator: std.mem.Allocator,
    url: []const u8,
    blob_path: []const u8,
    options: ProjectOptions,
) !void {
    const uri = try std.Uri.parse(url);
    if (uri.user != null or uri.password != null) return error.AccessDenied;

    const deadline_ms = computeDeadlineMs(options.remote_download_timeout_ms);
    try enforceDeadline(deadline_ms);

    var client: std.http.Client = .{ .allocator = allocator };
    defer client.deinit();

    var request = try client.request(.GET, uri, .{
        .redirect_behavior = .not_allowed,
        .keep_alive = false,
    });
    defer request.deinit();

    try request.sendBodiless();
    var redirect_buffer: [1]u8 = undefined;
    var response = try request.receiveHead(&redirect_buffer);
    if (response.head.status.class() != .success) return mapHttpStatusToError(response.head.status);

    if (response.head.content_length) |len| {
        if (len > options.remote_download_max_bytes) return error.NoSpaceLeft;
    }

    var write_buffer: [8 * 1024]u8 = undefined;
    var atomic_file = try std.fs.cwd().atomicFile(blob_path, .{
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
        total_bytes += read_len;
        if (total_bytes > options.remote_download_max_bytes) return error.NoSpaceLeft;
        try atomic_file.file_writer.interface.writeAll(chunk[0..read_len]);
    }
    try atomic_file.finish();
}

fn ensureRemoteExtractedTree(
    allocator: std.mem.Allocator,
    blob_path: []const u8,
    tree_path: []const u8,
    expected_tree_root: [32]u8,
    remote_id: []const u8,
    options: ProjectOptions,
) !void {
    if (try pathIsDirectory(tree_path)) {
        const existing_root = try tree_hash.computeTreeRootForDir(allocator, tree_path);
        if (!std.mem.eql(u8, &existing_root, &expected_tree_root)) {
            return error.TreeRootMismatch;
        }
        return;
    }

    const staging_tag = try std.fmt.allocPrint(allocator, "remote-{s}-{d}", .{ remote_id, std.time.microTimestamp() });
    defer allocator.free(staging_tag);
    const staging_path = try std.fs.path.join(allocator, &.{ options.cache_root, "staging", staging_tag });
    defer allocator.free(staging_path);

    if (try pathIsDirectory(staging_path)) {
        try std.fs.cwd().deleteTree(staging_path);
    }
    try std.fs.cwd().makePath(staging_path);
    errdefer std.fs.cwd().deleteTree(staging_path) catch {};

    try extractBlobToDirectory(blob_path, staging_path);
    const computed_root = try tree_hash.computeTreeRootForDir(allocator, staging_path);
    if (!std.mem.eql(u8, &computed_root, &expected_tree_root)) {
        return error.TreeRootMismatch;
    }

    if (std.fs.path.dirname(tree_path)) |parent| {
        try std.fs.cwd().makePath(parent);
    }
    std.fs.cwd().rename(staging_path, tree_path) catch |err| switch (err) {
        error.PathAlreadyExists => {
            std.fs.cwd().deleteTree(staging_path) catch {};
            return;
        },
        else => return err,
    };
    try makeReadOnlyRecursively(allocator, tree_path);
}

fn extractBlobToDirectory(blob_path: []const u8, output_dir: []const u8) !void {
    var blob_file = try std.fs.cwd().openFile(blob_path, .{});
    defer blob_file.close();
    const format = try detectBlobFormat(&blob_file);
    try blob_file.seekTo(0);

    var out_dir = try std.fs.cwd().openDir(output_dir, .{});
    defer out_dir.close();

    switch (format) {
        .zip => {
            var read_buffer: [64 * 1024]u8 = undefined;
            var file_reader = blob_file.reader(&read_buffer);
            try std.zip.extract(out_dir, &file_reader, .{});
        },
        .tar => {
            var read_buffer: [64 * 1024]u8 = undefined;
            var file_reader = blob_file.reader(&read_buffer);
            try extractTarArchive(&out_dir, &file_reader.interface);
        },
        .tar_gzip => {
            var read_buffer: [64 * 1024]u8 = undefined;
            var file_reader = blob_file.reader(&read_buffer);
            var window: [std.compress.flate.max_window_len]u8 = undefined;
            var decompress = std.compress.flate.Decompress.init(&file_reader.interface, .gzip, &window);
            try extractTarArchive(&out_dir, &decompress.reader);
        },
        .raw => return error.NotImplemented,
    }
}

fn detectBlobFormat(blob_file: *std.fs.File) !BlobFormat {
    var probe: [512]u8 = undefined;
    const read_len = try blob_file.read(&probe);
    if (read_len >= 4 and std.mem.eql(u8, probe[0..4], "PK\x03\x04")) return .zip;
    if (read_len >= 2 and probe[0] == 0x1f and probe[1] == 0x8b) return .tar_gzip;
    if (read_len >= 512 and isTarHeader(probe[0..512])) return .tar;
    return .raw;
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
