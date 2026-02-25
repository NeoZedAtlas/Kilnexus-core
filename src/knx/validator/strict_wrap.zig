const std = @import("std");
const parse_errors = @import("../../parser/parse_errors.zig");
const model = @import("model.zig");
const validate_canonical = @import("validate_canonical.zig");
const parse_toolchain = @import("parse_toolchain.zig");
const parse_workspace = @import("parse_workspace.zig");
const parse_output = @import("parse_output.zig");
const parse_build = @import("parse_build.zig");

pub fn validateCanonicalJsonStrict(allocator: std.mem.Allocator, canonical_json: []const u8) parse_errors.ParseError!model.ValidationSummary {
    return validate_canonical.validateCanonicalJson(allocator, canonical_json) catch |err| return parse_errors.normalize(err);
}

pub fn parseToolchainSpecStrict(allocator: std.mem.Allocator, canonical_json: []const u8) parse_errors.ParseError!model.ToolchainSpec {
    return parse_toolchain.parseToolchainSpec(allocator, canonical_json) catch |err| return parse_errors.normalize(err);
}

pub fn parseWorkspaceSpecStrict(allocator: std.mem.Allocator, canonical_json: []const u8) parse_errors.ParseError!model.WorkspaceSpec {
    return parse_workspace.parseWorkspaceSpec(allocator, canonical_json) catch |err| return parse_errors.normalize(err);
}

pub fn parseOutputSpecStrict(allocator: std.mem.Allocator, canonical_json: []const u8) parse_errors.ParseError!model.OutputSpec {
    return parse_output.parseOutputSpec(allocator, canonical_json) catch |err| return parse_errors.normalize(err);
}

pub fn parseBuildSpecStrict(allocator: std.mem.Allocator, canonical_json: []const u8) parse_errors.ParseError!model.BuildSpec {
    return parse_build.parseBuildSpec(allocator, canonical_json) catch |err| return parse_errors.normalize(err);
}
