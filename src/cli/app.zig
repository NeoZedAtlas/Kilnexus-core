const std = @import("std");
const bootstrap = @import("../bootstrap/state_machine.zig");
const kx_error = @import("../errors/kx_error.zig");
const abi_parser = @import("../parser/abi_parser.zig");
const parse_errors = @import("../parser/parse_errors.zig");
const validator = @import("../knx/validator.zig");
const max_knxfile_bytes: usize = 4 * 1024 * 1024;

const CurrentPointerSummary = struct {
    build_id: []u8,
    release_rel: []u8,
    verify_mode: ?[]u8,
    toolchain_tree_root: ?[]u8,

    fn deinit(self: *CurrentPointerSummary, allocator: std.mem.Allocator) void {
        allocator.free(self.build_id);
        allocator.free(self.release_rel);
        if (self.verify_mode) |verify_mode| allocator.free(verify_mode);
        if (self.toolchain_tree_root) |tree_root| allocator.free(tree_root);
        self.* = undefined;
    }
};

const BootstrapCliArgs = struct {
    path: []const u8 = "Knxfile",
    trust_dir: ?[]const u8 = "trust",
    trust_state_path: ?[]const u8 = ".kilnexus-trust-state.json",
    cache_root: []const u8 = ".kilnexus-cache",
    output_root: []const u8 = "kilnexus-out",
    json_output: bool = false,
};

const ParseOnlyCliArgs = struct {
    path: []const u8 = "Knxfile",
    json_output: bool = false,
};

const CliCommand = enum {
    build,
    validate,
    plan,
};

const CommandSelection = struct {
    command: CliCommand,
    args: []const []const u8,
};

const KnxSummary = struct {
    canonical_json: []u8,
    validation: validator.ValidationSummary,
    toolchain_spec: validator.ToolchainSpec,
    workspace_spec: validator.WorkspaceSpec,
    build_spec: validator.BuildSpec,
    output_spec: validator.OutputSpec,
    knx_digest_hex: [64]u8,

    fn deinit(self: *KnxSummary, allocator: std.mem.Allocator) void {
        allocator.free(self.canonical_json);
        self.toolchain_spec.deinit(allocator);
        self.workspace_spec.deinit(allocator);
        self.build_spec.deinit(allocator);
        self.output_spec.deinit(allocator);
        self.* = undefined;
    }
};

pub fn runMain() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();

    var cli_tokens: std.ArrayList([]const u8) = .empty;
    defer cli_tokens.deinit(allocator);
    _ = args.next();
    while (args.next()) |arg| {
        try cli_tokens.append(allocator, arg);
    }

    const selection = selectCommand(cli_tokens.items) catch |err| {
        if (err == error.HelpRequested) {
            printUsage();
            return;
        }
        if (cli_tokens.items.len > 0) {
            std.debug.print("Unknown command: {s}\n", .{cli_tokens.items[0]});
        } else {
            std.debug.print("Invalid command\n", .{});
        }
        printUsage();
        return error.InvalidCommand;
    };

    switch (selection.command) {
        .build => try runBuildCommand(allocator, selection.args),
        .validate => try runValidateCommand(allocator, selection.args),
        .plan => try runPlanCommand(allocator, selection.args),
    }
}

fn printUsage() void {
    std.debug.print(
        "Usage: Kilnexus_core [knx] <build|validate|plan> [args]\n",
        .{},
    );
    std.debug.print("Or: Kilnexus_core [Knxfile] (defaults to build)\n", .{});
    std.debug.print("Knxfile path must be extensionless (no .toml).\n", .{});
    std.debug.print("build positional: [Knxfile] [trust-dir] [cache-root] [output-root]\n", .{});
    std.debug.print(
        "build options: --knxfile <path> --trust-off --trust-dir <dir> --trust-state <path|off> --cache-root <dir> --output-root <dir> --json --help\n",
        .{},
    );
    std.debug.print("validate options: [Knxfile] --knxfile <path> --json --help\n", .{});
    std.debug.print("plan options: [Knxfile] --knxfile <path> --json --help\n", .{});
}

fn runBuildCommand(allocator: std.mem.Allocator, args: []const []const u8) !void {
    const cli = parseBootstrapCliArgs(args) catch |err| {
        if (err == error.HelpRequested) {
            printUsage();
            return;
        }
        printUsage();
        return error.InvalidCommand;
    };

    var attempt = bootstrap.attemptRunFromPathWithOptions(allocator, cli.path, .{
        .trust_metadata_dir = cli.trust_dir,
        .trust_state_path = if (cli.trust_dir == null) null else cli.trust_state_path,
        .cache_root = cli.cache_root,
        .output_root = cli.output_root,
    });

    switch (attempt) {
        .success => |*run_result| {
            defer run_result.deinit(allocator);
            if (cli.json_output) {
                try printSuccessJson(allocator, run_result, &cli);
            } else {
                printSuccessHuman(allocator, run_result, &cli);
            }
        },
        .failure => |failure| {
            if (cli.json_output) {
                try printFailureJson(allocator, failure);
            } else {
                printFailureHuman(failure);
            }
            return error.BootstrapFailed;
        },
    }
}

fn runValidateCommand(allocator: std.mem.Allocator, args: []const []const u8) !void {
    const cli = parseParseOnlyCliArgs(args) catch |err| {
        if (err == error.HelpRequested) {
            printUsage();
            return;
        }
        printUsage();
        return error.InvalidCommand;
    };

    var summary = loadKnxSummary(allocator, cli.path) catch |err| {
        if (cli.json_output) {
            try printSimpleFailureJson(allocator, "validate", err);
        } else {
            printSimpleFailureHuman("validate", err);
        }
        return error.InvalidCommand;
    };
    defer summary.deinit(allocator);

    if (cli.json_output) {
        try printValidateJson(allocator, &summary);
    } else {
        printValidateHuman(&summary);
    }
}

fn runPlanCommand(allocator: std.mem.Allocator, args: []const []const u8) !void {
    const cli = parseParseOnlyCliArgs(args) catch |err| {
        if (err == error.HelpRequested) {
            printUsage();
            return;
        }
        printUsage();
        return error.InvalidCommand;
    };

    var summary = loadKnxSummary(allocator, cli.path) catch |err| {
        if (cli.json_output) {
            try printSimpleFailureJson(allocator, "plan", err);
        } else {
            printSimpleFailureHuman("plan", err);
        }
        return error.InvalidCommand;
    };
    defer summary.deinit(allocator);

    if (cli.json_output) {
        try printPlanJson(allocator, &summary);
    } else {
        printPlanHuman(&summary);
    }
}

fn selectCommand(tokens: []const []const u8) !CommandSelection {
    if (tokens.len == 0) {
        return .{ .command = .build, .args = tokens };
    }

    if (std.mem.eql(u8, tokens[0], "--help") or std.mem.eql(u8, tokens[0], "-h")) {
        return error.HelpRequested;
    }

    if (std.mem.eql(u8, tokens[0], "knx")) {
        if (tokens.len == 1) {
            return .{ .command = .build, .args = tokens[1..] };
        }
        return parseNamedCommand(tokens[1], tokens[2..]);
    }

    if (isKnownCommand(tokens[0])) {
        return parseNamedCommand(tokens[0], tokens[1..]);
    }

    if (std.mem.startsWith(u8, tokens[0], "--")) {
        return .{ .command = .build, .args = tokens };
    }

    // Treat unknown first token as knxfile path for build convenience.
    return .{ .command = .build, .args = tokens };
}

fn isKnownCommand(token: []const u8) bool {
    return std.mem.eql(u8, token, "build") or
        std.mem.eql(u8, token, "bootstrap") or
        std.mem.eql(u8, token, "validate") or
        std.mem.eql(u8, token, "plan");
}

fn parseNamedCommand(token: []const u8, args: []const []const u8) !CommandSelection {
    if (std.mem.eql(u8, token, "build") or std.mem.eql(u8, token, "bootstrap")) {
        return .{ .command = .build, .args = args };
    }
    if (std.mem.eql(u8, token, "validate")) {
        return .{ .command = .validate, .args = args };
    }
    if (std.mem.eql(u8, token, "plan")) {
        return .{ .command = .plan, .args = args };
    }
    return error.InvalidCommand;
}

fn parseParseOnlyCliArgs(args: []const []const u8) !ParseOnlyCliArgs {
    var output: ParseOnlyCliArgs = .{};
    var positional_index: usize = 0;
    var path_set = false;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            return error.HelpRequested;
        }

        if (std.mem.startsWith(u8, arg, "--")) {
            if (std.mem.eql(u8, arg, "--json")) {
                output.json_output = true;
                continue;
            }
            if (std.mem.eql(u8, arg, "--knxfile")) {
                output.path = try nextOptionValue(args, &i);
                path_set = true;
                continue;
            }
            return error.InvalidCommand;
        }

        if (positional_index > 0 or path_set) return error.InvalidCommand;
        output.path = arg;
        positional_index += 1;
    }

    try validateKnxfileCliPath(output.path);
    return output;
}

fn parseBootstrapCliArgs(args: []const []const u8) !BootstrapCliArgs {
    var output: BootstrapCliArgs = .{};
    var positional_index: usize = 0;
    var path_set = false;
    var trust_set = false;
    var cache_set = false;
    var output_set = false;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            return error.HelpRequested;
        }

        if (std.mem.startsWith(u8, arg, "--")) {
            if (std.mem.eql(u8, arg, "--json")) {
                output.json_output = true;
                continue;
            }
            if (std.mem.eql(u8, arg, "--knxfile")) {
                output.path = try nextOptionValue(args, &i);
                path_set = true;
                continue;
            }
            if (std.mem.eql(u8, arg, "--trust-off")) {
                output.trust_dir = null;
                output.trust_state_path = null;
                trust_set = true;
                continue;
            }
            if (std.mem.eql(u8, arg, "--trust-dir")) {
                const value = try nextOptionValue(args, &i);
                output.trust_dir = value;
                if (output.trust_state_path == null) {
                    output.trust_state_path = ".kilnexus-trust-state.json";
                }
                trust_set = true;
                continue;
            }
            if (std.mem.eql(u8, arg, "--trust-state")) {
                const value = try nextOptionValue(args, &i);
                if (std.mem.eql(u8, value, "off")) {
                    output.trust_state_path = null;
                } else {
                    output.trust_state_path = value;
                }
                continue;
            }
            if (std.mem.eql(u8, arg, "--cache-root")) {
                output.cache_root = try nextOptionValue(args, &i);
                cache_set = true;
                continue;
            }
            if (std.mem.eql(u8, arg, "--output-root")) {
                output.output_root = try nextOptionValue(args, &i);
                output_set = true;
                continue;
            }
            return error.InvalidCommand;
        }

        switch (positional_index) {
            0 => {
                if (path_set) return error.InvalidCommand;
                output.path = arg;
            },
            1 => {
                if (trust_set) return error.InvalidCommand;
                output.trust_dir = arg;
                trust_set = true;
            },
            2 => {
                if (cache_set) return error.InvalidCommand;
                output.cache_root = arg;
                cache_set = true;
            },
            3 => {
                if (output_set) return error.InvalidCommand;
                output.output_root = arg;
                output_set = true;
            },
            else => return error.InvalidCommand,
        }
        positional_index += 1;
    }

    try validateKnxfileCliPath(output.path);
    return output;
}

fn validateKnxfileCliPath(path: []const u8) !void {
    if (hasSuffixIgnoreCase(path, ".toml")) return error.InvalidCommand;
}

fn hasSuffixIgnoreCase(text: []const u8, suffix: []const u8) bool {
    if (text.len < suffix.len) return false;
    return std.ascii.eqlIgnoreCase(text[text.len - suffix.len ..], suffix);
}

fn nextOptionValue(args: []const []const u8, index: *usize) ![]const u8 {
    index.* += 1;
    if (index.* >= args.len) return error.InvalidCommand;
    const value = args[index.*];
    if (std.mem.startsWith(u8, value, "--")) return error.InvalidCommand;
    return value;
}

fn loadKnxSummary(allocator: std.mem.Allocator, path: []const u8) !KnxSummary {
    try validateKnxfileCliPath(path);
    const source = try std.fs.cwd().readFileAlloc(allocator, path, max_knxfile_bytes);
    defer allocator.free(source);

    const parsed = try abi_parser.parseLockfileStrict(allocator, source);
    errdefer allocator.free(parsed.canonical_json);

    const validation = try validator.validateCanonicalJsonStrict(allocator, parsed.canonical_json);

    var toolchain_spec = try validator.parseToolchainSpecStrict(allocator, parsed.canonical_json);
    errdefer toolchain_spec.deinit(allocator);

    var workspace_spec = try validator.parseWorkspaceSpecStrict(allocator, parsed.canonical_json);
    errdefer workspace_spec.deinit(allocator);

    var build_spec = try validator.parseBuildSpecStrict(allocator, parsed.canonical_json);
    errdefer build_spec.deinit(allocator);

    validator.validateBuildWriteIsolation(&workspace_spec, &build_spec) catch |err| {
        return parse_errors.normalize(err);
    };

    var output_spec = try validator.parseOutputSpecStrict(allocator, parsed.canonical_json);
    errdefer output_spec.deinit(allocator);

    const knx_digest_hex = validator.computeKnxDigestHex(parsed.canonical_json);
    return .{
        .canonical_json = parsed.canonical_json,
        .validation = validation,
        .toolchain_spec = toolchain_spec,
        .workspace_spec = workspace_spec,
        .build_spec = build_spec,
        .output_spec = output_spec,
        .knx_digest_hex = knx_digest_hex,
    };
}

fn countOptionalSlice(comptime T: type, value: ?[]T) usize {
    return if (value) |items| items.len else 0;
}

fn printSimpleFailureHuman(command: []const u8, err: anyerror) void {
    std.debug.print("{s} failed: {s}\n", .{ command, @errorName(err) });
}

fn printSimpleFailureJson(allocator: std.mem.Allocator, command: []const u8, err: anyerror) !void {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    var out_writer = out.writer(allocator);
    var out_buffer: [512]u8 = undefined;
    var out_adapter = out_writer.adaptToNewApi(&out_buffer);
    const writer = &out_adapter.new_interface;

    try writer.writeAll("{\"status\":\"failed\",\"command\":");
    try std.json.Stringify.encodeJsonString(command, .{}, writer);
    try writer.writeAll(",\"error\":");
    try std.json.Stringify.encodeJsonString(@errorName(err), .{}, writer);
    try writer.writeAll("}\n");
    try writer.flush();
    std.debug.print("{s}", .{out.items});
}

fn printValidateHuman(summary: *const KnxSummary) void {
    std.debug.print("Validation passed\n", .{});
    std.debug.print("Verify mode: {s}\n", .{@tagName(summary.validation.verify_mode)});
    std.debug.print("Knx digest: {s}\n", .{summary.knx_digest_hex[0..]});
    std.debug.print("Toolchain id: {s}\n", .{summary.toolchain_spec.id});
    std.debug.print(
        "Workspace entries/local/remote/mounts: {d}/{d}/{d}/{d}\n",
        .{
            summary.workspace_spec.entries.len,
            countOptionalSlice(validator.LocalInputSpec, summary.workspace_spec.local_inputs),
            countOptionalSlice(validator.RemoteInputSpec, summary.workspace_spec.remote_inputs),
            countOptionalSlice(validator.WorkspaceMountSpec, summary.workspace_spec.mounts),
        },
    );
    std.debug.print("Operators: {d}\n", .{summary.build_spec.ops.len});
    std.debug.print("Outputs: {d}\n", .{summary.output_spec.entries.len});
}

fn printValidateJson(allocator: std.mem.Allocator, summary: *const KnxSummary) !void {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    var out_writer = out.writer(allocator);
    var out_buffer: [2048]u8 = undefined;
    var out_adapter = out_writer.adaptToNewApi(&out_buffer);
    const writer = &out_adapter.new_interface;

    try writer.writeAll("{\"status\":\"ok\",\"command\":\"validate\",\"verify_mode\":");
    try std.json.Stringify.encodeJsonString(@tagName(summary.validation.verify_mode), .{}, writer);
    try writer.writeAll(",\"knx_digest\":");
    try std.json.Stringify.encodeJsonString(summary.knx_digest_hex[0..], .{}, writer);
    try writer.writeAll(",\"toolchain_id\":");
    try std.json.Stringify.encodeJsonString(summary.toolchain_spec.id, .{}, writer);
    try writer.writeAll(",\"stats\":{\"workspace_entries\":");
    try writer.print("{d}", .{summary.workspace_spec.entries.len});
    try writer.writeAll(",\"local_inputs\":");
    try writer.print("{d}", .{countOptionalSlice(validator.LocalInputSpec, summary.workspace_spec.local_inputs)});
    try writer.writeAll(",\"remote_inputs\":");
    try writer.print("{d}", .{countOptionalSlice(validator.RemoteInputSpec, summary.workspace_spec.remote_inputs)});
    try writer.writeAll(",\"mounts\":");
    try writer.print("{d}", .{countOptionalSlice(validator.WorkspaceMountSpec, summary.workspace_spec.mounts)});
    try writer.writeAll(",\"operators\":");
    try writer.print("{d}", .{summary.build_spec.ops.len});
    try writer.writeAll(",\"outputs\":");
    try writer.print("{d}", .{summary.output_spec.entries.len});
    try writer.writeAll("}}\n");
    try writer.flush();
    std.debug.print("{s}", .{out.items});
}

fn printPlanHuman(summary: *const KnxSummary) void {
    std.debug.print("Plan generated\n", .{});
    std.debug.print("Verify mode: {s}\n", .{@tagName(summary.validation.verify_mode)});
    std.debug.print("Knx digest: {s}\n", .{summary.knx_digest_hex[0..]});
    std.debug.print("Operators ({d}):\n", .{summary.build_spec.ops.len});
    for (summary.build_spec.ops, 0..) |op, idx| {
        switch (op) {
            .fs_copy => |copy| {
                std.debug.print(" {d}. knx.fs.copy {s} -> {s}\n", .{ idx + 1, copy.from_path, copy.to_path });
            },
            .c_compile => |compile| {
                std.debug.print(" {d}. knx.c.compile {s} -> {s} (flags:{d})\n", .{ idx + 1, compile.src_path, compile.out_path, compile.args.len });
            },
            .zig_link => |link| {
                std.debug.print(" {d}. knx.zig.link objs:{d} -> {s} (flags:{d})\n", .{ idx + 1, link.object_paths.len, link.out_path, link.args.len });
            },
            .archive_pack => |pack| {
                std.debug.print(" {d}. knx.archive.pack inputs:{d} -> {s} ({s})\n", .{ idx + 1, pack.input_paths.len, pack.out_path, @tagName(pack.format) });
            },
        }
    }
    std.debug.print("Publish outputs ({d}):\n", .{summary.output_spec.entries.len});
    for (summary.output_spec.entries) |entry| {
        const source = entry.source_path orelse entry.path;
        const publish_as = entry.publish_as orelse entry.path;
        std.debug.print(" - {s} => {s} (mode {o})\n", .{ source, publish_as, entry.mode });
    }
}

fn printPlanJson(allocator: std.mem.Allocator, summary: *const KnxSummary) !void {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    var out_writer = out.writer(allocator);
    var out_buffer: [8 * 1024]u8 = undefined;
    var out_adapter = out_writer.adaptToNewApi(&out_buffer);
    const writer = &out_adapter.new_interface;

    try writer.writeAll("{\"status\":\"ok\",\"command\":\"plan\",\"verify_mode\":");
    try std.json.Stringify.encodeJsonString(@tagName(summary.validation.verify_mode), .{}, writer);
    try writer.writeAll(",\"knx_digest\":");
    try std.json.Stringify.encodeJsonString(summary.knx_digest_hex[0..], .{}, writer);
    try writer.writeAll(",\"operators\":[");
    for (summary.build_spec.ops, 0..) |op, idx| {
        if (idx != 0) try writer.writeAll(",");
        switch (op) {
            .fs_copy => |copy| {
                try writer.writeAll("{\"run\":\"knx.fs.copy\",\"inputs\":[");
                try std.json.Stringify.encodeJsonString(copy.from_path, .{}, writer);
                try writer.writeAll("],\"outputs\":[");
                try std.json.Stringify.encodeJsonString(copy.to_path, .{}, writer);
                try writer.writeAll("]}");
            },
            .c_compile => |compile| {
                try writer.writeAll("{\"run\":\"knx.c.compile\",\"inputs\":[");
                try std.json.Stringify.encodeJsonString(compile.src_path, .{}, writer);
                try writer.writeAll("],\"outputs\":[");
                try std.json.Stringify.encodeJsonString(compile.out_path, .{}, writer);
                try writer.writeAll("],\"flags\":[");
                for (compile.args, 0..) |arg, i| {
                    if (i != 0) try writer.writeAll(",");
                    try std.json.Stringify.encodeJsonString(arg, .{}, writer);
                }
                try writer.writeAll("]}");
            },
            .zig_link => |link| {
                try writer.writeAll("{\"run\":\"knx.zig.link\",\"inputs\":[");
                for (link.object_paths, 0..) |obj, i| {
                    if (i != 0) try writer.writeAll(",");
                    try std.json.Stringify.encodeJsonString(obj, .{}, writer);
                }
                try writer.writeAll("],\"outputs\":[");
                try std.json.Stringify.encodeJsonString(link.out_path, .{}, writer);
                try writer.writeAll("],\"flags\":[");
                for (link.args, 0..) |arg, i| {
                    if (i != 0) try writer.writeAll(",");
                    try std.json.Stringify.encodeJsonString(arg, .{}, writer);
                }
                try writer.writeAll("]}");
            },
            .archive_pack => |pack| {
                try writer.writeAll("{\"run\":\"knx.archive.pack\",\"inputs\":[");
                for (pack.input_paths, 0..) |in_path, i| {
                    if (i != 0) try writer.writeAll(",");
                    try std.json.Stringify.encodeJsonString(in_path, .{}, writer);
                }
                try writer.writeAll("],\"outputs\":[");
                try std.json.Stringify.encodeJsonString(pack.out_path, .{}, writer);
                try writer.writeAll("],\"format\":");
                try std.json.Stringify.encodeJsonString(@tagName(pack.format), .{}, writer);
                try writer.writeAll("}");
            },
        }
    }
    try writer.writeAll("],\"outputs\":[");
    for (summary.output_spec.entries, 0..) |entry, idx| {
        if (idx != 0) try writer.writeAll(",");
        const source = entry.source_path orelse entry.path;
        const publish_as = entry.publish_as orelse entry.path;
        try writer.writeAll("{\"source\":");
        try std.json.Stringify.encodeJsonString(source, .{}, writer);
        try writer.writeAll(",\"publish_as\":");
        try std.json.Stringify.encodeJsonString(publish_as, .{}, writer);
        try writer.writeAll(",\"mode\":");
        try writer.print("{d}", .{entry.mode});
        try writer.writeAll("}");
    }
    try writer.writeAll("]}\n");
    try writer.flush();
    std.debug.print("{s}", .{out.items});
}

fn printSuccessHuman(allocator: std.mem.Allocator, run_result: *const bootstrap.RunResult, cli: *const BootstrapCliArgs) void {
    std.debug.print("Bootstrap completed with state: {s}\n", .{@tagName(run_result.final_state)});
    std.debug.print(
        "Trust versions root/timestamp/snapshot/targets: {d}/{d}/{d}/{d}\n",
        .{
            run_result.trust.root_version,
            run_result.trust.timestamp_version,
            run_result.trust.snapshot_version,
            run_result.trust.targets_version,
        },
    );
    std.debug.print("Verify mode: {s}\n", .{@tagName(run_result.verify_mode)});
    std.debug.print("Knx digest: {s}\n", .{run_result.knx_digest_hex[0..]});
    std.debug.print("Workspace cwd: {s}\n", .{run_result.workspace_cwd});
    std.debug.print("Canonical lockfile bytes: {d}\n", .{run_result.canonical_json.len});
    printCurrentPointerSummary(allocator, cli.output_root) catch |err| {
        std.debug.print("Current pointer read failed: {s}\n", .{@errorName(err)});
    };

    for (run_result.trace.items) |state| {
        std.debug.print(" - {s}\n", .{@tagName(state)});
    }
}

fn printFailureHuman(failure: bootstrap.RunFailure) void {
    const descriptor = kx_error.describe(failure.code);
    var error_id_buf: [128]u8 = undefined;
    const error_id = kx_error.buildErrorId(
        &error_id_buf,
        failure.code,
        @tagName(failure.at),
        @errorName(failure.cause),
    );

    std.debug.print("Bootstrap failed\n", .{});
    std.debug.print("Error id: {s}\n", .{error_id});
    std.debug.print("Code: {s} ({d})\n", .{ @tagName(failure.code), @intFromEnum(failure.code) });
    std.debug.print("Family: {s}\n", .{@tagName(descriptor.family)});
    std.debug.print("State: {s}\n", .{@tagName(failure.at)});
    std.debug.print("Cause: {s}\n", .{@errorName(failure.cause)});
    std.debug.print("Summary: {s}\n", .{descriptor.summary});
}

fn printFailureJson(allocator: std.mem.Allocator, failure: bootstrap.RunFailure) !void {
    const output = try buildFailureJsonLine(allocator, failure);
    defer allocator.free(output);
    std.debug.print("{s}", .{output});
}

fn buildFailureJsonLine(allocator: std.mem.Allocator, failure: bootstrap.RunFailure) ![]u8 {
    const descriptor = kx_error.describe(failure.code);
    var error_id_buf: [128]u8 = undefined;
    const error_id = kx_error.buildErrorId(
        &error_id_buf,
        failure.code,
        @tagName(failure.at),
        @errorName(failure.cause),
    );

    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(allocator);
    var output_writer = output.writer(allocator);
    var output_buffer: [1024]u8 = undefined;
    var output_adapter = output_writer.adaptToNewApi(&output_buffer);
    const writer = &output_adapter.new_interface;

    try writer.writeAll("{\"status\":\"failed\",\"error_id\":");
    try std.json.Stringify.encodeJsonString(error_id, .{}, writer);
    try writer.writeAll(",\"code\":");
    try std.json.Stringify.encodeJsonString(@tagName(failure.code), .{}, writer);
    try writer.writeAll(",\"code_num\":");
    try writer.print("{d}", .{@intFromEnum(failure.code)});
    try writer.writeAll(",\"family\":");
    try std.json.Stringify.encodeJsonString(@tagName(descriptor.family), .{}, writer);
    try writer.writeAll(",\"state\":");
    try std.json.Stringify.encodeJsonString(@tagName(failure.at), .{}, writer);
    try writer.writeAll(",\"cause\":");
    try std.json.Stringify.encodeJsonString(@errorName(failure.cause), .{}, writer);
    try writer.writeAll(",\"summary\":");
    try std.json.Stringify.encodeJsonString(descriptor.summary, .{}, writer);
    try writer.writeAll("}\n");
    try writer.flush();

    return try output.toOwnedSlice(allocator);
}

fn printSuccessJson(
    allocator: std.mem.Allocator,
    run_result: *const bootstrap.RunResult,
    cli: *const BootstrapCliArgs,
) !void {
    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(allocator);
    var output_writer = output.writer(allocator);
    var output_buffer: [4096]u8 = undefined;
    var output_adapter = output_writer.adaptToNewApi(&output_buffer);
    const writer = &output_adapter.new_interface;

    try writer.writeAll("{\"status\":\"ok\",\"state\":");
    try std.json.Stringify.encodeJsonString(@tagName(run_result.final_state), .{}, writer);
    try writer.writeAll(",\"verify_mode\":");
    try std.json.Stringify.encodeJsonString(@tagName(run_result.verify_mode), .{}, writer);
    try writer.writeAll(",\"knx_digest\":");
    try std.json.Stringify.encodeJsonString(run_result.knx_digest_hex[0..], .{}, writer);
    try writer.writeAll(",\"workspace_cwd\":");
    try std.json.Stringify.encodeJsonString(run_result.workspace_cwd, .{}, writer);
    try writer.writeAll(",\"canonical_json_bytes\":");
    try writer.print("{d}", .{run_result.canonical_json.len});
    try writer.writeAll(",\"trust\":{\"root\":");
    try writer.print("{d}", .{run_result.trust.root_version});
    try writer.writeAll(",\"timestamp\":");
    try writer.print("{d}", .{run_result.trust.timestamp_version});
    try writer.writeAll(",\"snapshot\":");
    try writer.print("{d}", .{run_result.trust.snapshot_version});
    try writer.writeAll(",\"targets\":");
    try writer.print("{d}", .{run_result.trust.targets_version});
    try writer.writeAll("}");

    var pointer = readCurrentPointerSummary(allocator, cli.output_root) catch |err| {
        try writer.writeAll(",\"published_error\":");
        try std.json.Stringify.encodeJsonString(@errorName(err), .{}, writer);
        try writeTraceJson(writer, run_result);
        try writer.writeAll("}\n");
        try writer.flush();
        std.debug.print("{s}", .{output.items});
        return;
    };
    defer pointer.deinit(allocator);

    const release_abs = try std.fs.path.join(allocator, &.{ cli.output_root, pointer.release_rel });
    defer allocator.free(release_abs);
    try writer.writeAll(",\"published\":{\"build_id\":");
    try std.json.Stringify.encodeJsonString(pointer.build_id, .{}, writer);
    try writer.writeAll(",\"release_rel\":");
    try std.json.Stringify.encodeJsonString(pointer.release_rel, .{}, writer);
    try writer.writeAll(",\"release_path\":");
    try std.json.Stringify.encodeJsonString(release_abs, .{}, writer);
    if (pointer.verify_mode) |mode| {
        try writer.writeAll(",\"verify_mode\":");
        try std.json.Stringify.encodeJsonString(mode, .{}, writer);
    }
    if (pointer.toolchain_tree_root) |tree_root| {
        try writer.writeAll(",\"toolchain_tree_root\":");
        try std.json.Stringify.encodeJsonString(tree_root, .{}, writer);
    }
    try writer.writeAll("}");

    try writeTraceJson(writer, run_result);
    try writer.writeAll("}\n");
    try writer.flush();
    std.debug.print("{s}", .{output.items});
}

fn writeTraceJson(writer: *std.Io.Writer, run_result: *const bootstrap.RunResult) !void {
    try writer.writeAll(",\"trace\":[");
    for (run_result.trace.items, 0..) |state, idx| {
        if (idx != 0) try writer.writeAll(",");
        try std.json.Stringify.encodeJsonString(@tagName(state), .{}, writer);
    }
    try writer.writeAll("]");
}

fn printCurrentPointerSummary(allocator: std.mem.Allocator, output_root: []const u8) !void {
    var summary = try readCurrentPointerSummary(allocator, output_root);
    defer summary.deinit(allocator);
    const release_abs = try std.fs.path.join(allocator, &.{ output_root, summary.release_rel });
    defer allocator.free(release_abs);

    std.debug.print("Published build id: {s}\n", .{summary.build_id});
    std.debug.print("Published release path: {s}\n", .{release_abs});
    if (summary.verify_mode) |verify_mode| {
        std.debug.print("Published verify mode: {s}\n", .{verify_mode});
    }
    if (summary.toolchain_tree_root) |tree_root| {
        std.debug.print("Published toolchain tree root: {s}\n", .{tree_root});
    }
}

fn readCurrentPointerSummary(allocator: std.mem.Allocator, output_root: []const u8) !CurrentPointerSummary {
    const pointer_path = try std.fmt.allocPrint(allocator, "{s}.current", .{output_root});
    defer allocator.free(pointer_path);

    const raw = try std.fs.cwd().readFileAlloc(allocator, pointer_path, 1024 * 1024);
    defer allocator.free(raw);

    return parseCurrentPointerSummary(allocator, raw);
}

fn parseCurrentPointerSummary(allocator: std.mem.Allocator, raw: []const u8) !CurrentPointerSummary {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, raw, .{});
    defer parsed.deinit();

    const root = switch (parsed.value) {
        .object => |obj| obj,
        else => return error.InvalidCurrentPointer,
    };
    const build_id = try requireStringField(root, "build_id");
    const release_rel = try requireStringField(root, "release_rel");
    const verify_mode = optionalStringField(root, "verify_mode");
    const toolchain_tree_root = optionalStringField(root, "toolchain_tree_root");

    const out_build_id = try allocator.dupe(u8, build_id);
    errdefer allocator.free(out_build_id);
    const out_release_rel = try allocator.dupe(u8, release_rel);
    errdefer allocator.free(out_release_rel);
    const out_verify_mode = if (verify_mode) |value| try allocator.dupe(u8, value) else null;
    errdefer if (out_verify_mode) |value| allocator.free(value);
    const out_tree_root = if (toolchain_tree_root) |value| try allocator.dupe(u8, value) else null;
    errdefer if (out_tree_root) |value| allocator.free(value);

    return .{
        .build_id = out_build_id,
        .release_rel = out_release_rel,
        .verify_mode = out_verify_mode,
        .toolchain_tree_root = out_tree_root,
    };
}

fn requireStringField(object: std.json.ObjectMap, key: []const u8) ![]const u8 {
    const value = object.get(key) orelse return error.InvalidCurrentPointer;
    return switch (value) {
        .string => |text| text,
        else => error.InvalidCurrentPointer,
    };
}

fn optionalStringField(object: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const value = object.get(key) orelse return null;
    return switch (value) {
        .string => |text| text,
        else => null,
    };
}

test "parseCurrentPointerSummary parses required and optional fields" {
    const allocator = std.testing.allocator;
    const raw =
        \\{
        \\  "version": 2,
        \\  "build_id": "build-42",
        \\  "release_rel": "releases/build-42",
        \\  "verify_mode": "strict",
        \\  "toolchain_tree_root": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        \\}
    ;
    var summary = try parseCurrentPointerSummary(allocator, raw);
    defer summary.deinit(allocator);
    try std.testing.expectEqualStrings("build-42", summary.build_id);
    try std.testing.expectEqualStrings("releases/build-42", summary.release_rel);
    try std.testing.expect(summary.verify_mode != null);
    try std.testing.expect(summary.toolchain_tree_root != null);
    try std.testing.expectEqualStrings("strict", summary.verify_mode.?);
}

test "parseCurrentPointerSummary rejects missing required fields" {
    const allocator = std.testing.allocator;
    const raw =
        \\{
        \\  "version": 2,
        \\  "release_rel": "releases/build-42"
        \\}
    ;
    try std.testing.expectError(error.InvalidCurrentPointer, parseCurrentPointerSummary(allocator, raw));
}

test "parseBootstrapCliArgs applies defaults and optional overrides" {
    const defaults = try parseBootstrapCliArgs(&.{});
    try std.testing.expectEqualStrings("Knxfile", defaults.path);
    try std.testing.expect(defaults.trust_dir != null);
    try std.testing.expectEqualStrings("trust", defaults.trust_dir.?);
    try std.testing.expect(defaults.trust_state_path != null);
    try std.testing.expectEqualStrings(".kilnexus-trust-state.json", defaults.trust_state_path.?);
    try std.testing.expectEqualStrings(".kilnexus-cache", defaults.cache_root);
    try std.testing.expectEqualStrings("kilnexus-out", defaults.output_root);
    try std.testing.expect(!defaults.json_output);

    const custom = try parseBootstrapCliArgs(&.{
        "Custom.knx",
        "custom-trust",
        "cache-dir",
        "out-dir",
    });
    try std.testing.expectEqualStrings("Custom.knx", custom.path);
    try std.testing.expect(custom.trust_dir != null);
    try std.testing.expectEqualStrings("custom-trust", custom.trust_dir.?);
    try std.testing.expectEqualStrings("cache-dir", custom.cache_root);
    try std.testing.expectEqualStrings("out-dir", custom.output_root);
}

test "parseBootstrapCliArgs accepts --knxfile option" {
    const parsed = try parseBootstrapCliArgs(&.{
        "--knxfile",
        "Knxfile.prod",
        "--json",
    });
    try std.testing.expectEqualStrings("Knxfile.prod", parsed.path);
    try std.testing.expect(parsed.json_output);
}

test "parseParseOnlyCliArgs parses positional and named forms" {
    const positional = try parseParseOnlyCliArgs(&.{"Knxfile.plan"});
    try std.testing.expectEqualStrings("Knxfile.plan", positional.path);
    try std.testing.expect(!positional.json_output);

    const named = try parseParseOnlyCliArgs(&.{
        "--knxfile",
        "Knxfile.validate",
        "--json",
    });
    try std.testing.expectEqualStrings("Knxfile.validate", named.path);
    try std.testing.expect(named.json_output);
}

test "selectCommand supports knx prefix and defaults" {
    const prefixed = try selectCommand(&.{ "knx", "build", "Knxfile" });
    try std.testing.expectEqual(CliCommand.build, prefixed.command);
    try std.testing.expectEqual(@as(usize, 1), prefixed.args.len);
    try std.testing.expectEqualStrings("Knxfile", prefixed.args[0]);

    const validate_cmd = try selectCommand(&.{ "validate", "Knxfile" });
    try std.testing.expectEqual(CliCommand.validate, validate_cmd.command);
    try std.testing.expectEqual(@as(usize, 1), validate_cmd.args.len);

    const default_build = try selectCommand(&.{"Knxfile"});
    try std.testing.expectEqual(CliCommand.build, default_build.command);
    try std.testing.expectEqual(@as(usize, 1), default_build.args.len);
}

test "parseBootstrapCliArgs rejects too many positional arguments" {
    try std.testing.expectError(
        error.InvalidCommand,
        parseBootstrapCliArgs(&.{ "a", "b", "c", "d", "e" }),
    );
}

test "parseBootstrapCliArgs parses named options" {
    const parsed = try parseBootstrapCliArgs(&.{
        "Knxfile.prod",
        "--trust-dir",
        "trust-prod",
        "--trust-state",
        "trust-state-prod.json",
        "--cache-root",
        ".cache-prod",
        "--output-root",
        "out-prod",
        "--json",
    });
    try std.testing.expectEqualStrings("Knxfile.prod", parsed.path);
    try std.testing.expect(parsed.trust_dir != null);
    try std.testing.expectEqualStrings("trust-prod", parsed.trust_dir.?);
    try std.testing.expect(parsed.trust_state_path != null);
    try std.testing.expectEqualStrings("trust-state-prod.json", parsed.trust_state_path.?);
    try std.testing.expectEqualStrings(".cache-prod", parsed.cache_root);
    try std.testing.expectEqualStrings("out-prod", parsed.output_root);
    try std.testing.expect(parsed.json_output);
}

test "parseBootstrapCliArgs parses trust off and disabled trust state" {
    const parsed = try parseBootstrapCliArgs(&.{
        "--trust-off",
        "--trust-state",
        "off",
    });
    try std.testing.expect(parsed.trust_dir == null);
    try std.testing.expect(parsed.trust_state_path == null);
}

test "parseBootstrapCliArgs rejects conflict between trust option and trust positional" {
    try std.testing.expectError(
        error.InvalidCommand,
        parseBootstrapCliArgs(&.{ "Knxfile", "--trust-off", "trust-positional" }),
    );
}

test "parseBootstrapCliArgs returns help requested" {
    try std.testing.expectError(error.HelpRequested, parseBootstrapCliArgs(&.{"--help"}));
}

test "parseBootstrapCliArgs rejects toml lockfile suffix" {
    try std.testing.expectError(error.InvalidCommand, parseBootstrapCliArgs(&.{"Knxfile.toml"}));
    try std.testing.expectError(error.InvalidCommand, parseBootstrapCliArgs(&.{"Knxfile.TOML"}));
}

test "buildFailureJsonLine renders stable failure payload" {
    const allocator = std.testing.allocator;
    const failure: bootstrap.RunFailure = .{
        .at = .init,
        .code = .KX_IO_NOT_FOUND,
        .cause = error.IoNotFound,
    };

    const line = try buildFailureJsonLine(allocator, failure);
    defer allocator.free(line);
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, line, .{});
    defer parsed.deinit();
    const root = switch (parsed.value) {
        .object => |obj| obj,
        else => return error.TestUnexpectedResult,
    };

    const status = switch (root.get("status") orelse return error.TestUnexpectedResult) {
        .string => |text| text,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expectEqualStrings("failed", status);

    const code = switch (root.get("code") orelse return error.TestUnexpectedResult) {
        .string => |text| text,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expectEqualStrings("KX_IO_NOT_FOUND", code);

    const state = switch (root.get("state") orelse return error.TestUnexpectedResult) {
        .string => |text| text,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expectEqualStrings("init", state);
}
