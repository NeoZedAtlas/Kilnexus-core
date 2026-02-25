const model = @import("model.zig");
const helpers = @import("json_helpers.zig");

pub fn validateBuildWriteIsolation(workspace_spec: *const model.WorkspaceSpec, build_spec: *const model.BuildSpec) !void {
    for (build_spec.ops) |op| {
        const write_path = switch (op) {
            .fs_copy => |copy| copy.to_path,
            .c_compile => |compile| compile.out_path,
            .zig_link => |link| link.out_path,
            .archive_pack => |pack| pack.out_path,
        };
        for (workspace_spec.entries) |entry| {
            if (helpers.isEqualOrDescendant(write_path, entry.mount_path)) return error.ValueInvalid;
        }
        if (workspace_spec.mounts) |mounts| {
            for (mounts) |mount| {
                if (helpers.isEqualOrDescendant(write_path, mount.target)) return error.ValueInvalid;
            }
        }
    }
}
