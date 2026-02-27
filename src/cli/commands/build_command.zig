const std = @import("std");
const bootstrap = @import("../../bootstrap/state_machine.zig");
const abi_parser = @import("../../parser/abi_parser.zig");
const validator = @import("../../knx/validator.zig");
const kx_error = @import("../../errors/kx_error.zig");
const v2_infer = @import("../runtime/v2_lock_infer.zig");
const lock_metadata = @import("../runtime/lock_metadata.zig");
const cli_args = @import("../args.zig");
const cli_output = @import("../output.zig");

const DriftCategory = enum {
    none,
    sources,
    build,
    outputs,
    toolchain,
    metadata,
    unknown,
};

pub fn run(allocator: std.mem.Allocator, args: []const []const u8) !void {
    const cli = cli_args.parseBootstrapCliArgs(args) catch |err| {
        if (err == error.HelpRequested) {
            cli_output.printUsage();
            return;
        }
        cli_output.printUsage();
        return error.InvalidCommand;
    };

    var drift_category: DriftCategory = .none;
    runWithCli(allocator, cli, &drift_category) catch |err| {
        if (cli.json_output) {
            if (err == error.LockDrift) {
                try printBuildFailureJsonWithCategory(allocator, @errorName(err), driftCategoryName(drift_category));
            } else {
                try cli_output.printSimpleFailureJson(allocator, "build", @errorName(err));
            }
        } else {
            if (err == error.LockMissing) {
                std.debug.print("Lockfile missing for {s}. Run `knx freeze --knxfile {s}` first.\n", .{ cli.path, cli.path });
            } else if (err == error.LockDrift) {
                std.debug.print("Lock drift detected for {s}. Re-run `knx freeze --knxfile {s}`.\n", .{ cli.path, cli.path });
                std.debug.print("Drift category: {s}\n", .{driftCategoryName(drift_category)});
            } else if (err == error.AllowUnlockedForbidden) {
                std.debug.print("CI is enabled; refusing --allow-unlocked for {s}.\n", .{cli.path});
            } else if (err == error.CiLockfileRequired) {
                std.debug.print("CI strict mode requires explicit .lock path. Use `knx build {s}.lock`.\n", .{cli.path});
            }
            cli_output.printSimpleFailureHuman("build", @errorName(err));
        }
        return err;
    };
}

fn runWithCli(allocator: std.mem.Allocator, cli: @import("../types.zig").BootstrapCliArgs, drift_category_out: *DriftCategory) !void {
    const ci = isCiEnvironment();
    if (ci and !hasLockSuffixIgnoreCase(cli.path)) {
        return error.CiLockfileRequired;
    }
    if (cli.allow_unlocked and ci and !isAllowUnlockedCiOverrideEnabled()) {
        return error.AllowUnlockedForbidden;
    }

    const resolved = try resolveBuildPathWithLockPolicy(allocator, cli.path, cli.allow_unlocked);
    defer if (resolved.needs_free) allocator.free(resolved.path);

    if (resolved.using_lock and !hasLockSuffixIgnoreCase(cli.path)) {
        try validateLockDrift(allocator, cli.path, resolved.path, drift_category_out);
    } else if (!resolved.using_lock and !cli.json_output) {
        std.debug.print("Warning: building unlocked from {s}; reproducibility lock is bypassed.\n", .{cli.path});
    }

    var attempt = bootstrap.attemptRunFromPathWithOptions(allocator, resolved.path, .{
        .trust_metadata_dir = cli.trust_dir,
        .trust_state_path = if (cli.trust_dir == null) null else cli.trust_state_path,
        .cache_root = cli.cache_root,
        .output_root = cli.output_root,
    });

    switch (attempt) {
        .success => |*run_result| {
            defer run_result.deinit(allocator);
            if (cli.json_output) {
                try cli_output.printSuccessJson(allocator, run_result, &cli);
            } else {
                cli_output.printSuccessHuman(allocator, run_result, &cli);
            }
        },
        .failure => |failure| {
            if (cli.json_output) {
                try cli_output.printFailureJson(allocator, failure);
            } else {
                cli_output.printFailureHuman(failure);
            }
            return error.BootstrapFailed;
        },
    }
}

const BuildPathResolution = struct {
    path: []const u8,
    using_lock: bool,
    needs_free: bool,
};

fn resolveBuildPathWithLockPolicy(allocator: std.mem.Allocator, path: []const u8, allow_unlocked: bool) !BuildPathResolution {
    if (hasLockSuffixIgnoreCase(path)) {
        return .{ .path = path, .using_lock = true, .needs_free = false };
    }

    const lock_path = try std.fmt.allocPrint(allocator, "{s}.lock", .{path});
    if (try pathExists(lock_path)) {
        return .{ .path = lock_path, .using_lock = true, .needs_free = true };
    }

    allocator.free(lock_path);
    if (allow_unlocked) {
        return .{ .path = path, .using_lock = false, .needs_free = false };
    }
    return error.LockMissing;
}

fn validateLockDrift(allocator: std.mem.Allocator, knx_path: []const u8, lock_path: []const u8, drift_category_out: *DriftCategory) !void {
    if (!try pathExists(knx_path)) return;

    const expected = try computeExpectedLockCanonicalFromKnxPath(allocator, knx_path);
    defer allocator.free(expected);
    const lock_canonical = try loadCanonicalFromPath(allocator, lock_path);
    defer allocator.free(lock_canonical);

    const expected_digest = validator.computeKnxDigestHex(expected);
    const lock_digest = validator.computeKnxDigestHex(lock_canonical);
    if (!std.mem.eql(u8, expected_digest[0..], lock_digest[0..])) {
        // Backward compatibility: legacy lock files generated before source metadata.
        const legacy = try computeExpectedLegacyLockCanonicalFromKnxPath(allocator, knx_path);
        defer allocator.free(legacy);
        const legacy_digest = validator.computeKnxDigestHex(legacy);
        if (std.mem.eql(u8, legacy_digest[0..], lock_digest[0..])) {
            drift_category_out.* = .none;
            return;
        }

        drift_category_out.* = classifyDriftCategory(allocator, expected, lock_canonical) catch .unknown;
        return error.LockDrift;
    }
    drift_category_out.* = .none;
}

fn computeExpectedLockCanonicalFromKnxPath(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    const source = try std.fs.cwd().readFileAlloc(allocator, path, @import("../types.zig").max_knxfile_bytes);
    defer allocator.free(source);
    const parsed = try abi_parser.parseLockfileStrict(allocator, source);
    defer allocator.free(parsed.canonical_json);

    const base_lock = switch (try parseVersion(parsed.canonical_json)) {
        1 => try allocator.dupe(u8, parsed.canonical_json),
        2 => try v2_infer.inferLockCanonicalJsonFromV2Canonical(allocator, parsed.canonical_json),
        else => return error.VersionUnsupported,
    };
    defer allocator.free(base_lock);

    return lock_metadata.canonicalizeWithSourceMetadata(allocator, base_lock, parsed.canonical_json);
}

fn computeExpectedLegacyLockCanonicalFromKnxPath(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    const source = try std.fs.cwd().readFileAlloc(allocator, path, @import("../types.zig").max_knxfile_bytes);
    defer allocator.free(source);
    const parsed = try abi_parser.parseLockfileStrict(allocator, source);
    defer allocator.free(parsed.canonical_json);

    return switch (try parseVersion(parsed.canonical_json)) {
        1 => allocator.dupe(u8, parsed.canonical_json),
        2 => v2_infer.inferLockCanonicalJsonFromV2Canonical(allocator, parsed.canonical_json),
        else => error.VersionUnsupported,
    };
}

fn loadCanonicalFromPath(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    const source = try std.fs.cwd().readFileAlloc(allocator, path, @import("../types.zig").max_knxfile_bytes);
    defer allocator.free(source);
    const parsed = try abi_parser.parseLockfileStrict(allocator, source);
    return parsed.canonical_json;
}

fn classifyDriftCategory(allocator: std.mem.Allocator, expected: []const u8, actual: []const u8) !DriftCategory {
    var exp_toolchain = try validator.parseToolchainSpecStrict(allocator, expected);
    defer exp_toolchain.deinit(allocator);
    var act_toolchain = try validator.parseToolchainSpecStrict(allocator, actual);
    defer act_toolchain.deinit(allocator);
    if (!equalToolchainSpec(exp_toolchain, act_toolchain)) return .toolchain;

    var exp_workspace = try validator.parseWorkspaceSpecStrict(allocator, expected);
    defer exp_workspace.deinit(allocator);
    var act_workspace = try validator.parseWorkspaceSpecStrict(allocator, actual);
    defer act_workspace.deinit(allocator);
    if (!equalWorkspaceSpec(exp_workspace, act_workspace)) return .sources;

    var exp_build = try validator.parseBuildSpecStrict(allocator, expected);
    defer exp_build.deinit(allocator);
    var act_build = try validator.parseBuildSpecStrict(allocator, actual);
    defer act_build.deinit(allocator);
    if (!equalBuildSpec(exp_build, act_build)) return .build;

    var exp_output = try validator.parseOutputSpecStrict(allocator, expected);
    defer exp_output.deinit(allocator);
    var act_output = try validator.parseOutputSpecStrict(allocator, actual);
    defer act_output.deinit(allocator);
    if (!equalOutputSpec(exp_output, act_output)) return .outputs;

    if (!equalSourceMetadataDigest(allocator, expected, actual)) return .metadata;
    return .unknown;
}

fn equalToolchainSpec(a: validator.ToolchainSpec, b: validator.ToolchainSpec) bool {
    return std.mem.eql(u8, a.id, b.id) and
        std.meta.eql(a.blob_sha256, b.blob_sha256) and
        std.meta.eql(a.tree_root, b.tree_root) and
        a.size == b.size and
        equalOptionalString(a.source, b.source);
}

fn equalWorkspaceSpec(a: validator.WorkspaceSpec, b: validator.WorkspaceSpec) bool {
    if (a.entries.len != b.entries.len) return false;
    for (a.entries, b.entries) |lhs, rhs| {
        if (!std.mem.eql(u8, lhs.mount_path, rhs.mount_path)) return false;
        if (!equalOptionalString(lhs.host_source, rhs.host_source)) return false;
        if (!std.meta.eql(lhs.cas_sha256, rhs.cas_sha256)) return false;
        if (lhs.cas_domain != rhs.cas_domain) return false;
        if (lhs.is_dependency != rhs.is_dependency) return false;
    }
    if (!equalMountSlice(a.mounts, b.mounts)) return false;
    if (!equalLocalInputSlice(a.local_inputs, b.local_inputs)) return false;
    if (!equalRemoteInputSlice(a.remote_inputs, b.remote_inputs)) return false;
    return true;
}

fn equalBuildSpec(a: validator.BuildSpec, b: validator.BuildSpec) bool {
    if (a.ops.len != b.ops.len) return false;
    for (a.ops, b.ops) |lhs, rhs| {
        switch (lhs) {
            .fs_copy => |l| switch (rhs) {
                .fs_copy => |r| {
                    if (!std.mem.eql(u8, l.from_path, r.from_path) or !std.mem.eql(u8, l.to_path, r.to_path)) return false;
                },
                else => return false,
            },
            .c_compile => |l| switch (rhs) {
                .c_compile => |r| {
                    if (!std.mem.eql(u8, l.src_path, r.src_path) or !std.mem.eql(u8, l.out_path, r.out_path)) return false;
                    if (!equalStringSlices(l.args, r.args)) return false;
                },
                else => return false,
            },
            .zig_link => |l| switch (rhs) {
                .zig_link => |r| {
                    if (!std.mem.eql(u8, l.out_path, r.out_path)) return false;
                    if (!equalStringSlices(l.object_paths, r.object_paths)) return false;
                    if (!equalStringSlices(l.args, r.args)) return false;
                },
                else => return false,
            },
            .archive_pack => |l| switch (rhs) {
                .archive_pack => |r| {
                    if (l.format != r.format) return false;
                    if (!std.mem.eql(u8, l.out_path, r.out_path)) return false;
                    if (!equalStringSlices(l.input_paths, r.input_paths)) return false;
                },
                else => return false,
            },
        }
    }
    return true;
}

fn equalOutputSpec(a: validator.OutputSpec, b: validator.OutputSpec) bool {
    if (a.entries.len != b.entries.len) return false;
    for (a.entries, b.entries) |lhs, rhs| {
        if (!std.mem.eql(u8, lhs.path, rhs.path)) return false;
        if (!equalOptionalString(lhs.source_path, rhs.source_path)) return false;
        if (!equalOptionalString(lhs.publish_as, rhs.publish_as)) return false;
        if (lhs.mode != rhs.mode) return false;
        if (!std.meta.eql(lhs.sha256, rhs.sha256)) return false;
    }
    return true;
}

fn equalMountSlice(a_opt: ?[]validator.WorkspaceMountSpec, b_opt: ?[]validator.WorkspaceMountSpec) bool {
    if (a_opt == null and b_opt == null) return true;
    if (a_opt == null or b_opt == null) return false;
    const a = a_opt.?;
    const b = b_opt.?;
    if (a.len != b.len) return false;
    for (a, b) |lhs, rhs| {
        if (!std.mem.eql(u8, lhs.source, rhs.source)) return false;
        if (!std.mem.eql(u8, lhs.target, rhs.target)) return false;
        if (lhs.mode != rhs.mode) return false;
        if (!equalOptionalString(lhs.strip_prefix, rhs.strip_prefix)) return false;
    }
    return true;
}

fn equalLocalInputSlice(a_opt: ?[]validator.LocalInputSpec, b_opt: ?[]validator.LocalInputSpec) bool {
    if (a_opt == null and b_opt == null) return true;
    if (a_opt == null or b_opt == null) return false;
    const a = a_opt.?;
    const b = b_opt.?;
    if (a.len != b.len) return false;
    for (a, b) |lhs, rhs| {
        if (!std.mem.eql(u8, lhs.id, rhs.id)) return false;
        if (!equalStringSlices(lhs.include, rhs.include)) return false;
        if (!equalStringSlices(lhs.exclude, rhs.exclude)) return false;
    }
    return true;
}

fn equalRemoteInputSlice(a_opt: ?[]validator.RemoteInputSpec, b_opt: ?[]validator.RemoteInputSpec) bool {
    if (a_opt == null and b_opt == null) return true;
    if (a_opt == null or b_opt == null) return false;
    const a = a_opt.?;
    const b = b_opt.?;
    if (a.len != b.len) return false;
    for (a, b) |lhs, rhs| {
        if (!std.mem.eql(u8, lhs.id, rhs.id)) return false;
        if (!std.mem.eql(u8, lhs.url, rhs.url)) return false;
        if (!std.meta.eql(lhs.blob_sha256, rhs.blob_sha256)) return false;
        if (!std.meta.eql(lhs.tree_root, rhs.tree_root)) return false;
        if (lhs.extract != rhs.extract) return false;
    }
    return true;
}

fn equalStringSlices(a: []const []u8, b: []const []u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |lhs, rhs| {
        if (!std.mem.eql(u8, lhs, rhs)) return false;
    }
    return true;
}

fn equalOptionalString(a: ?[]u8, b: ?[]u8) bool {
    if (a == null and b == null) return true;
    if (a == null or b == null) return false;
    return std.mem.eql(u8, a.?, b.?);
}

fn equalSourceMetadataDigest(allocator: std.mem.Allocator, expected: []const u8, actual: []const u8) bool {
    const exp = std.json.parseFromSlice(std.json.Value, allocator, expected, .{}) catch return false;
    defer exp.deinit();
    const act = std.json.parseFromSlice(std.json.Value, allocator, actual, .{}) catch return false;
    defer act.deinit();

    const exp_obj = switch (exp.value) {
        .object => |obj| obj,
        else => return false,
    };
    const act_obj = switch (act.value) {
        .object => |obj| obj,
        else => return false,
    };
    const exp_source = exp_obj.get("source") orelse return false;
    const act_source = act_obj.get("source") orelse return false;
    const exp_source_obj = switch (exp_source) {
        .object => |obj| obj,
        else => return false,
    };
    const act_source_obj = switch (act_source) {
        .object => |obj| obj,
        else => return false,
    };
    const exp_digest = exp_source_obj.get("knxfile_digest_sha256") orelse return false;
    const act_digest = act_source_obj.get("knxfile_digest_sha256") orelse return false;
    const exp_text = switch (exp_digest) {
        .string => |text| text,
        else => return false,
    };
    const act_text = switch (act_digest) {
        .string => |text| text,
        else => return false,
    };
    return std.mem.eql(u8, exp_text, act_text);
}

fn driftCategoryName(category: DriftCategory) []const u8 {
    return @tagName(category);
}

fn printBuildFailureJsonWithCategory(allocator: std.mem.Allocator, err_name: []const u8, category: []const u8) !void {
    const code = kx_error.classifyBuild(error.LockDrift);
    const descriptor = kx_error.describe(code);
    var error_id_buf: [128]u8 = undefined;
    const error_id = kx_error.buildErrorId(&error_id_buf, code, "build", err_name);

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    var out_writer = out.writer(allocator);
    var out_buffer: [1024]u8 = undefined;
    var out_adapter = out_writer.adaptToNewApi(&out_buffer);
    const writer = &out_adapter.new_interface;

    try writer.writeAll("{\"status\":\"failed\",\"command\":\"build\",\"error_id\":");
    try std.json.Stringify.encodeJsonString(error_id, .{}, writer);
    try writer.writeAll(",\"code\":");
    try std.json.Stringify.encodeJsonString(@tagName(code), .{}, writer);
    try writer.writeAll(",\"code_num\":");
    try writer.print("{d}", .{@intFromEnum(code)});
    try writer.writeAll(",\"family\":");
    try std.json.Stringify.encodeJsonString(@tagName(descriptor.family), .{}, writer);
    try writer.writeAll(",\"summary\":");
    try std.json.Stringify.encodeJsonString(descriptor.summary, .{}, writer);
    try writer.writeAll(",\"cause\":");
    try std.json.Stringify.encodeJsonString(err_name, .{}, writer);
    try writer.writeAll(",\"drift_category\":");
    try std.json.Stringify.encodeJsonString(category, .{}, writer);
    try writer.writeAll("}\n");
    try writer.flush();
    std.debug.print("{s}", .{out.items});
}

fn parseVersion(canonical_json: []const u8) !i64 {
    const parsed = try std.json.parseFromSlice(std.json.Value, std.heap.page_allocator, canonical_json, .{});
    defer parsed.deinit();
    const root = switch (parsed.value) {
        .object => |obj| obj,
        else => return error.TypeMismatch,
    };
    const version_value = root.get("version") orelse return error.MissingField;
    return switch (version_value) {
        .integer => |num| num,
        else => error.TypeMismatch,
    };
}

fn pathExists(path: []const u8) !bool {
    var file = std.fs.cwd().openFile(path, .{}) catch |err| switch (err) {
        error.FileNotFound, error.PathAlreadyExists, error.NotDir, error.NameTooLong, error.BadPathName => return false,
        else => return err,
    };
    file.close();
    return true;
}

fn hasLockSuffixIgnoreCase(path: []const u8) bool {
    return path.len >= 5 and std.ascii.eqlIgnoreCase(path[path.len - 5 ..], ".lock");
}

fn isCiEnvironment() bool {
    return std.process.hasEnvVarConstant("CI") or std.process.hasEnvVarConstant("GITHUB_ACTIONS") or std.process.hasEnvVarConstant("BUILD_BUILDID");
}

fn isAllowUnlockedCiOverrideEnabled() bool {
    const enabled = std.process.getEnvVarOwned(std.heap.page_allocator, "KNX_ALLOW_UNLOCKED_IN_CI") catch return false;
    defer std.heap.page_allocator.free(enabled);
    return std.mem.eql(u8, enabled, "1") or std.ascii.eqlIgnoreCase(enabled, "true");
}

test "ci strict path requirement enforces .lock suffix check" {
    try std.testing.expect(hasLockSuffixIgnoreCase("Knxfile.lock"));
    try std.testing.expect(!hasLockSuffixIgnoreCase("Knxfile"));
}
