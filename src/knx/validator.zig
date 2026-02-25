const std = @import("std");
const parse_errors = @import("../parser/parse_errors.zig");

const model = @import("validator/model.zig");
const validate_canonical = @import("validator/validate_canonical.zig");
const parse_toolchain = @import("validator/parse_toolchain.zig");
const parse_workspace = @import("validator/parse_workspace.zig");
const parse_output = @import("validator/parse_output.zig");
const parse_build = @import("validator/parse_build.zig");
const validate_isolation = @import("validator/validate_isolation.zig");
const digest = @import("validator/digest.zig");
const strict_wrap = @import("validator/strict_wrap.zig");

pub const VerifyMode = model.VerifyMode;
pub const ValidationSummary = model.ValidationSummary;
pub const ToolchainSpec = model.ToolchainSpec;
pub const CasDomain = model.CasDomain;
pub const LocalInputSpec = model.LocalInputSpec;
pub const RemoteInputSpec = model.RemoteInputSpec;
pub const WorkspaceMountSpec = model.WorkspaceMountSpec;
pub const WorkspaceEntry = model.WorkspaceEntry;
pub const WorkspaceSpec = model.WorkspaceSpec;
pub const OutputEntry = model.OutputEntry;
pub const OutputSpec = model.OutputSpec;
pub const FsCopyOp = model.FsCopyOp;
pub const CCompileOp = model.CCompileOp;
pub const ZigLinkOp = model.ZigLinkOp;
pub const ArchivePackOp = model.ArchivePackOp;
pub const ArchiveFormat = model.ArchiveFormat;
pub const BuildOp = model.BuildOp;
pub const BuildSpec = model.BuildSpec;

pub fn validateCanonicalJson(allocator: std.mem.Allocator, canonical_json: []const u8) !ValidationSummary {
    return validate_canonical.validateCanonicalJson(allocator, canonical_json);
}

pub fn validateCanonicalJsonStrict(allocator: std.mem.Allocator, canonical_json: []const u8) parse_errors.ParseError!ValidationSummary {
    return strict_wrap.validateCanonicalJsonStrict(allocator, canonical_json);
}

pub fn parseToolchainSpec(allocator: std.mem.Allocator, canonical_json: []const u8) !ToolchainSpec {
    return parse_toolchain.parseToolchainSpec(allocator, canonical_json);
}

pub fn parseToolchainSpecStrict(allocator: std.mem.Allocator, canonical_json: []const u8) parse_errors.ParseError!ToolchainSpec {
    return strict_wrap.parseToolchainSpecStrict(allocator, canonical_json);
}

pub fn parseWorkspaceSpec(allocator: std.mem.Allocator, canonical_json: []const u8) !WorkspaceSpec {
    return parse_workspace.parseWorkspaceSpec(allocator, canonical_json);
}

pub fn parseWorkspaceSpecStrict(allocator: std.mem.Allocator, canonical_json: []const u8) parse_errors.ParseError!WorkspaceSpec {
    return strict_wrap.parseWorkspaceSpecStrict(allocator, canonical_json);
}

pub fn parseOutputSpec(allocator: std.mem.Allocator, canonical_json: []const u8) !OutputSpec {
    return parse_output.parseOutputSpec(allocator, canonical_json);
}

pub fn parseOutputSpecStrict(allocator: std.mem.Allocator, canonical_json: []const u8) parse_errors.ParseError!OutputSpec {
    return strict_wrap.parseOutputSpecStrict(allocator, canonical_json);
}

pub fn parseBuildSpec(allocator: std.mem.Allocator, canonical_json: []const u8) !BuildSpec {
    return parse_build.parseBuildSpec(allocator, canonical_json);
}

pub fn parseBuildSpecStrict(allocator: std.mem.Allocator, canonical_json: []const u8) parse_errors.ParseError!BuildSpec {
    return strict_wrap.parseBuildSpecStrict(allocator, canonical_json);
}

pub fn validateBuildWriteIsolation(workspace_spec: *const WorkspaceSpec, build_spec: *const BuildSpec) !void {
    return validate_isolation.validateBuildWriteIsolation(workspace_spec, build_spec);
}

pub fn computeKnxDigestHex(canonical_json: []const u8) [64]u8 {
    return digest.computeKnxDigestHex(canonical_json);
}

test {
    _ = @import("validator/tests.zig");
}
