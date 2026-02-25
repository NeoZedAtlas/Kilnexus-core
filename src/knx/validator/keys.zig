pub const allowed_operators = [_][]const u8{
    "knx.c.compile",
    "knx.zig.link",
    "knx.fs.copy",
    "knx.archive.pack",
};

pub const output_entry_keys = [_][]const u8{
    "source",
    "publish_as",
    "mode",
    "sha256",
};

pub const local_input_keys = [_][]const u8{
    "id",
    "include",
    "exclude",
};

pub const remote_input_keys = [_][]const u8{
    "id",
    "url",
    "blob_sha256",
    "tree_root",
    "extract",
};

pub const workspace_mount_keys = [_][]const u8{
    "source",
    "target",
    "mode",
    "strip_prefix",
};

pub const operator_fs_copy_keys = [_][]const u8{
    "id",
    "run",
    "inputs",
    "outputs",
};

pub const operator_c_compile_keys = [_][]const u8{
    "id",
    "run",
    "inputs",
    "outputs",
    "flags",
};

pub const operator_zig_link_keys = [_][]const u8{
    "id",
    "run",
    "inputs",
    "outputs",
    "flags",
};

pub const operator_archive_pack_keys = [_][]const u8{
    "id",
    "run",
    "inputs",
    "outputs",
    "format",
};

pub const operator_map_fs_copy_keys = [_][]const u8{
    "run",
    "inputs",
    "outputs",
};

pub const operator_map_c_compile_keys = [_][]const u8{
    "run",
    "inputs",
    "outputs",
    "flags",
};

pub const operator_map_zig_link_keys = [_][]const u8{
    "run",
    "inputs",
    "outputs",
    "flags",
};

pub const operator_map_archive_pack_keys = [_][]const u8{
    "run",
    "inputs",
    "outputs",
    "format",
};
