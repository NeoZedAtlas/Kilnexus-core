const std = @import("std");
const bootstrap = @import("../../bootstrap/state_machine.zig");
const abi_parser = @import("../../parser/abi_parser.zig");
const validator = @import("../../knx/validator.zig");
const v2_infer = @import("../runtime/v2_lock_infer.zig");
const cli_args = @import("../args.zig");
const cli_output = @import("../output.zig");

pub fn run(allocator: std.mem.Allocator, args: []const []const u8) !void {
    const cli = cli_args.parseBootstrapCliArgs(args) catch |err| {
        if (err == error.HelpRequested) {
            cli_output.printUsage();
            return;
        }
        cli_output.printUsage();
        return error.InvalidCommand;
    };

    runWithCli(allocator, cli) catch |err| {
        if (cli.json_output) {
            try cli_output.printSimpleFailureJson(allocator, "build", @errorName(err));
        } else {
            if (err == error.LockMissing) {
                std.debug.print("Lockfile missing for {s}. Run `knx freeze --knxfile {s}` first.\n", .{ cli.path, cli.path });
            } else if (err == error.LockDrift) {
                std.debug.print("Lock drift detected for {s}. Re-run `knx freeze --knxfile {s}`.\n", .{ cli.path, cli.path });
            }
            cli_output.printSimpleFailureHuman("build", @errorName(err));
        }
        return err;
    };
}

fn runWithCli(allocator: std.mem.Allocator, cli: @import("../types.zig").BootstrapCliArgs) !void {
    const resolved = try resolveBuildPathWithLockPolicy(allocator, cli.path, cli.allow_unlocked);
    defer if (resolved.needs_free) allocator.free(resolved.path);

    if (resolved.using_lock and !hasLockSuffixIgnoreCase(cli.path)) {
        try validateLockDrift(allocator, cli.path, resolved.path);
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
        return .{
            .path = path,
            .using_lock = true,
            .needs_free = false,
        };
    }

    const lock_path = try std.fmt.allocPrint(allocator, "{s}.lock", .{path});
    if (try pathExists(lock_path)) {
        return .{
            .path = lock_path,
            .using_lock = true,
            .needs_free = true,
        };
    }

    allocator.free(lock_path);
    if (allow_unlocked) {
        return .{
            .path = path,
            .using_lock = false,
            .needs_free = false,
        };
    }
    return error.LockMissing;
}

fn validateLockDrift(allocator: std.mem.Allocator, knx_path: []const u8, lock_path: []const u8) !void {
    if (!try pathExists(knx_path)) return;
    const knx_digest = try computeExpectedLockDigestHexFromKnxPath(allocator, knx_path);
    const lock_digest = try computeCanonicalDigestHexFromPath(allocator, lock_path);
    if (!std.mem.eql(u8, knx_digest[0..], lock_digest[0..])) {
        return error.LockDrift;
    }
}

fn computeExpectedLockDigestHexFromKnxPath(allocator: std.mem.Allocator, path: []const u8) ![64]u8 {
    const source = try std.fs.cwd().readFileAlloc(allocator, path, @import("../types.zig").max_knxfile_bytes);
    defer allocator.free(source);
    const parsed = try abi_parser.parseLockfileStrict(allocator, source);
    defer allocator.free(parsed.canonical_json);

    const version = try parseVersion(parsed.canonical_json);
    switch (version) {
        1 => return validator.computeKnxDigestHex(parsed.canonical_json),
        2 => {
            const inferred = try v2_infer.inferLockCanonicalJsonFromV2Canonical(allocator, parsed.canonical_json);
            defer allocator.free(inferred);
            return validator.computeKnxDigestHex(inferred);
        },
        else => return error.VersionUnsupported,
    }
}

fn computeCanonicalDigestHexFromPath(allocator: std.mem.Allocator, path: []const u8) ![64]u8 {
    const source = try std.fs.cwd().readFileAlloc(allocator, path, @import("../types.zig").max_knxfile_bytes);
    defer allocator.free(source);
    const parsed = try abi_parser.parseLockfileStrict(allocator, source);
    defer allocator.free(parsed.canonical_json);
    return validator.computeKnxDigestHex(parsed.canonical_json);
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
