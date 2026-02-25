const legacy = @import("../workspace_projector.zig");
const types = @import("types.zig");

pub const LinkMode = types.LinkMode;
pub const ProjectOptions = types.ProjectOptions;
pub const VirtualMapping = types.VirtualMapping;
pub const WorkspacePlan = types.WorkspacePlan;

pub const computeTreeRootHexForDir = legacy.computeTreeRootHexForDir;
pub const planWorkspace = legacy.planWorkspace;
pub const projectWorkspace = legacy.projectWorkspace;
