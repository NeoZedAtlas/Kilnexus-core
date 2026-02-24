const std = @import("std");
const abi_parser = @import("../parser/abi_parser.zig");

pub const State = enum {
    init,
    load_trust_metadata,
    verify_metadata_chain,
    parse_knxfile,
    resolve_toolchain,
    download_blob,
    verify_blob,
    unpack_staging,
    compute_tree_root,
    verify_tree_root,
    seal_cache_object,
    execute_build_graph,
    verify_outputs,
    atomic_publish,
    done,
    failed,
};

pub const RunResult = struct {
    trace: std.ArrayList(State),
    canonical_json: []u8,
    final_state: State,

    pub fn deinit(self: *RunResult, allocator: std.mem.Allocator) void {
        self.trace.deinit(allocator);
        allocator.free(self.canonical_json);
        self.* = undefined;
    }
};

const max_knxfile_bytes: usize = 4 * 1024 * 1024;

pub fn runFromPath(allocator: std.mem.Allocator, path: []const u8) !RunResult {
    const source = try std.fs.cwd().readFileAlloc(allocator, path, max_knxfile_bytes);
    defer allocator.free(source);
    return run(allocator, source);
}

pub fn run(allocator: std.mem.Allocator, source: []const u8) !RunResult {
    var trace: std.ArrayList(State) = .empty;
    errdefer trace.deinit(allocator);

    try push(&trace, allocator, .init);
    try push(&trace, allocator, .load_trust_metadata);
    try push(&trace, allocator, .verify_metadata_chain);
    try push(&trace, allocator, .parse_knxfile);

    const parsed = abi_parser.parseLockfile(allocator, source) catch |err| {
        try push(&trace, allocator, .failed);
        return err;
    };
    errdefer allocator.free(parsed.canonical_json);

    try push(&trace, allocator, .resolve_toolchain);
    try push(&trace, allocator, .download_blob);
    try push(&trace, allocator, .verify_blob);
    try push(&trace, allocator, .unpack_staging);
    try push(&trace, allocator, .compute_tree_root);
    try push(&trace, allocator, .verify_tree_root);
    try push(&trace, allocator, .seal_cache_object);
    try push(&trace, allocator, .execute_build_graph);
    try push(&trace, allocator, .verify_outputs);
    try push(&trace, allocator, .atomic_publish);
    try push(&trace, allocator, .done);

    return .{
        .trace = trace,
        .canonical_json = parsed.canonical_json,
        .final_state = .done,
    };
}

fn push(trace: *std.ArrayList(State), allocator: std.mem.Allocator, state: State) !void {
    try trace.append(allocator, state);
}

test "run completes bootstrap happy path" {
    const allocator = std.testing.allocator;
    const source = "{\"version\":1}";

    var result = try run(allocator, source);
    defer result.deinit(allocator);

    try std.testing.expectEqual(State.done, result.final_state);
    try std.testing.expectEqual(@as(usize, 15), result.trace.items.len);
    try std.testing.expectEqual(State.parse_knxfile, result.trace.items[3]);
    try std.testing.expectEqual(State.done, result.trace.items[result.trace.items.len - 1]);
    try std.testing.expectEqualStrings("{\"version\":1}", result.canonical_json);
}

test "run fails on malformed lockfile" {
    const allocator = std.testing.allocator;
    const source = "version=1";

    try std.testing.expectError(error.Schema, run(allocator, source));
}
