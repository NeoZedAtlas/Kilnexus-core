const std = @import("std");
const validator = @import("../knx/validator.zig");

pub const LinkMode = enum {
    hardlink_then_symlink,
    symlink_only,
};

pub const ProjectOptions = struct {
    cache_root: []const u8 = ".kilnexus-cache",
    link_mode: LinkMode = .hardlink_then_symlink,
    remote_download_attempts: u8 = 3,
    remote_download_timeout_ms: u64 = 30_000,
    remote_download_max_bytes: u64 = 1024 * 1024 * 1024,
    allow_insecure_http_source: bool = false,
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

    const prepared_remotes = try prepareRemoteInputs(allocator, workspace_spec, options);
    defer {
        for (prepared_remotes) |remote| allocator.free(remote.root_abs_path);
        allocator.free(prepared_remotes);
    }

    if (workspace_spec.mounts) |mounts| {
        for (mounts) |mount| {
            const source_ref = try parseMountSource(mount.source);
            if (findLocalInput(workspace_spec.local_inputs, source_ref.input_id)) |local_input| {
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
                continue;
            }

            if (findPreparedRemote(prepared_remotes, source_ref.input_id)) |remote| {
                try appendRemoteMappingsForMount(allocator, &mappings, &seen_mounts, mount, source_ref, remote);
                continue;
            }

            return error.FileNotFound;
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

const RemotePrepared = struct {
    id: []const u8,
    root_abs_path: []u8,
    is_tree: bool,
};

const RemoteSource = union(enum) {
    file_path: []const u8,
    http_url: []const u8,
    https_url: []const u8,
};

fn prepareRemoteInputs(
    allocator: std.mem.Allocator,
    workspace_spec: *const validator.WorkspaceSpec,
    options: ProjectOptions,
) ![]RemotePrepared {
    const remote_inputs = workspace_spec.remote_inputs orelse return try allocator.alloc(RemotePrepared, 0);

    var prepared: std.ArrayList(RemotePrepared) = .empty;
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
        errdefer allocator.free(blob_abs);

        if (!remote.extract) {
            try prepared.append(allocator, .{
                .id = remote.id,
                .root_abs_path = blob_abs,
                .is_tree = false,
            });
            continue;
        }

        allocator.free(blob_abs);
        const tree_path = try std.fs.path.join(allocator, &.{
            options.cache_root,
            "cas",
            "third_party",
            "tree",
            blob_hex[0..],
        });
        defer allocator.free(tree_path);

        try ensureRemoteExtractedTree(allocator, blob_path, tree_path, remote.id, options);
        const tree_abs = try std.fs.cwd().realpathAlloc(allocator, tree_path);
        errdefer allocator.free(tree_abs);

        try prepared.append(allocator, .{
            .id = remote.id,
            .root_abs_path = tree_abs,
            .is_tree = true,
        });
    }

    return prepared.toOwnedSlice(allocator);
}

fn findPreparedRemote(prepared: []const RemotePrepared, id: []const u8) ?RemotePrepared {
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
        const digest = try hashFileAtPath(blob_path);
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

    const digest = try hashFileAtPath(blob_path);
    if (!std.mem.eql(u8, &digest.digest, &remote.blob_sha256)) {
        return error.BlobHashMismatch;
    }
}

fn parseRemoteSource(source: []const u8) !RemoteSource {
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
    remote_id: []const u8,
    options: ProjectOptions,
) !void {
    if (try pathIsDirectory(tree_path)) return;

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

const BlobFormat = enum {
    raw,
    tar,
    tar_gzip,
    zip,
};

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
    if (@import("builtin").os.tag == .windows) return;

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

fn appendRemoteMappingsForMount(
    allocator: std.mem.Allocator,
    mappings: *std.ArrayList(VirtualMapping),
    seen_mounts: *std.StringHashMap(void),
    mount: validator.WorkspaceMountSpec,
    source_ref: MountSourceRef,
    remote: RemotePrepared,
) !void {
    if (!remote.is_tree) {
        if (source_ref.sub_path != null) return error.InvalidBuildGraph;
        const mount_path = try allocator.dupe(u8, mount.target);
        errdefer allocator.free(mount_path);
        const source_abs = try allocator.dupe(u8, remote.root_abs_path);
        errdefer allocator.free(source_abs);
        try appendMappingChecked(allocator, mappings, seen_mounts, mount_path, source_abs, true);
        return;
    }

    const selected_root_abs = if (source_ref.sub_path) |sub_path| blk: {
        const joined = try std.fs.path.join(allocator, &.{ remote.root_abs_path, sub_path });
        defer allocator.free(joined);
        const abs = try std.fs.cwd().realpathAlloc(allocator, joined);
        errdefer allocator.free(abs);
        try ensurePathWithinRoot(abs, remote.root_abs_path);
        break :blk abs;
    } else try allocator.dupe(u8, remote.root_abs_path);
    defer allocator.free(selected_root_abs);

    if (try pathIsFile(selected_root_abs)) {
        const mount_path = try allocator.dupe(u8, mount.target);
        errdefer allocator.free(mount_path);
        const source_abs = try allocator.dupe(u8, selected_root_abs);
        errdefer allocator.free(source_abs);
        try appendMappingChecked(allocator, mappings, seen_mounts, mount_path, source_abs, true);
        return;
    }

    if (!(try pathIsDirectory(selected_root_abs))) return error.FileNotFound;
    const files = try listFilesRelativeTo(allocator, selected_root_abs);
    defer freeOwnedStrings(allocator, files);

    for (files) |rel| {
        const source_abs = try std.fs.path.join(allocator, &.{ selected_root_abs, rel });
        errdefer allocator.free(source_abs);
        const source_abs_real = try std.fs.cwd().realpathAlloc(allocator, source_abs);
        allocator.free(source_abs);
        errdefer allocator.free(source_abs_real);
        const mount_path = try joinPosix(allocator, mount.target, rel);
        errdefer allocator.free(mount_path);
        try appendMappingChecked(allocator, mappings, seen_mounts, mount_path, source_abs_real, true);
    }
}

fn ensurePathWithinRoot(path_abs: []const u8, root_abs: []const u8) !void {
    const normalized_root = trimTrailingSeparator(root_abs);
    if (std.mem.eql(u8, path_abs, normalized_root)) return;
    if (path_abs.len <= normalized_root.len) return error.PathTraversalDetected;
    if (!std.mem.startsWith(u8, path_abs, normalized_root)) return error.PathTraversalDetected;
    const sep = path_abs[normalized_root.len];
    if (sep != '/' and sep != '\\') return error.PathTraversalDetected;
}

fn trimTrailingSeparator(path: []const u8) []const u8 {
    var out = path;
    while (out.len > 0 and (out[out.len - 1] == '/' or out[out.len - 1] == '\\')) {
        out = out[0 .. out.len - 1];
    }
    return out;
}

fn listFilesRelativeTo(allocator: std.mem.Allocator, root_abs: []const u8) ![][]u8 {
    var root_dir = try std.fs.cwd().openDir(root_abs, .{ .iterate = true });
    defer root_dir.close();

    var walker = try root_dir.walk(allocator);
    defer walker.deinit();

    var files: std.ArrayList([]u8) = .empty;
    errdefer {
        for (files.items) |item| allocator.free(item);
        files.deinit(allocator);
    }

    while (try walker.next()) |entry| {
        if (entry.kind != .file) continue;
        const rel = try normalizePathOwned(allocator, entry.path);
        try files.append(allocator, rel);
    }
    std.sort.pdq([]u8, files.items, {}, struct {
        fn lessThan(_: void, lhs: []u8, rhs: []u8) bool {
            return std.mem.order(u8, lhs, rhs) == .lt;
        }
    }.lessThan);
    return files.toOwnedSlice(allocator);
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

    const digest = try hashFileAtPath(remote_rel);
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
    const digest = try hashFileAtPath(remote_rel);

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
