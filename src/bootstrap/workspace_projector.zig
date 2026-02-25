const std = @import("std");
const validator = @import("../knx/validator.zig");
const workspace_types = @import("workspace/types.zig");
const planner_impl = @import("workspace/planner.zig");
const projector_impl = @import("workspace/projector.zig");
const tree_hash = @import("workspace/tree_hash.zig");

pub const LinkMode = workspace_types.LinkMode;
pub const ProjectOptions = workspace_types.ProjectOptions;
pub const VirtualMapping = workspace_types.VirtualMapping;
pub const WorkspacePlan = workspace_types.WorkspacePlan;

pub fn computeTreeRootHexForDir(allocator: std.mem.Allocator, dir_path: []const u8) ![64]u8 {
    return tree_hash.computeTreeRootHexForDir(allocator, dir_path);
}

pub fn planWorkspace(
    allocator: std.mem.Allocator,
    workspace_spec: *const validator.WorkspaceSpec,
    options: ProjectOptions,
) !WorkspacePlan {
    return planner_impl.planWorkspace(allocator, workspace_spec, options);
}

pub fn projectWorkspace(
    allocator: std.mem.Allocator,
    plan: *const WorkspacePlan,
    build_id: []const u8,
    options: ProjectOptions,
) ![]u8 {
    return projector_impl.projectWorkspace(allocator, plan, build_id, options);
}
