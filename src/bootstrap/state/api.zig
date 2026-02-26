const std = @import("std");
const kx_error = @import("../../errors/kx_error.zig");
const boundary_map = @import("../../errors/boundary_map.zig");
const state_types = @import("types.zig");
const state_errors = @import("errors.zig");
const state_runner = @import("runner.zig");

pub const State = state_types.State;
pub const RunResult = state_types.RunResult;
pub const RunFailure = state_types.RunFailure;
pub const RunAttempt = state_types.RunAttempt;
pub const RunOptions = state_types.RunOptions;

const max_knxfile_bytes: usize = state_types.max_knxfile_bytes;

pub fn runFromPath(allocator: std.mem.Allocator, path: []const u8) !RunResult {
    return runFromPathWithOptions(allocator, path, .{});
}

pub fn runFromPathWithOptions(allocator: std.mem.Allocator, path: []const u8, options: RunOptions) !RunResult {
    const source = try std.fs.cwd().readFileAlloc(allocator, path, max_knxfile_bytes);
    defer allocator.free(source);
    var failed_at: State = .init;
    return state_runner.runWithOptionsCore(allocator, source, options, &failed_at);
}

pub fn run(allocator: std.mem.Allocator, source: []const u8) !RunResult {
    return runWithOptions(allocator, source, .{
        .trust_metadata_dir = null,
        .trust_state_path = null,
    });
}

pub fn runWithOptions(allocator: std.mem.Allocator, source: []const u8, options: RunOptions) !RunResult {
    var failed_at: State = .init;
    return state_runner.runWithOptionsCore(allocator, source, options, &failed_at);
}

pub fn attemptRunFromPathWithOptions(allocator: std.mem.Allocator, path: []const u8, options: RunOptions) RunAttempt {
    const source = std.fs.cwd().readFileAlloc(allocator, path, max_knxfile_bytes) catch |err| {
        const cause = boundary_map.mapIo(@errorName(err));
        return .{
            .failure = .{
                .at = .init,
                .code = kx_error.classifyIo(cause),
                .cause = .{ .io = cause },
            },
        };
    };
    defer allocator.free(source);
    return attemptRunWithOptions(allocator, source, options);
}

pub fn attemptRunWithOptions(allocator: std.mem.Allocator, source: []const u8, options: RunOptions) RunAttempt {
    var failed_at: State = .init;
    const result = state_runner.runWithOptionsCore(allocator, source, options, &failed_at) catch |err| {
        const cause = state_errors.translateCauseByState(failed_at, @errorName(err));
        return .{
            .failure = .{
                .at = failed_at,
                .code = state_errors.classifyByState(failed_at, cause),
                .cause = cause,
            },
        };
    };
    return .{ .success = result };
}
