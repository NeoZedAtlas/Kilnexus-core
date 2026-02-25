const std = @import("std");

pub const VerifyMode = enum {
    strict,
    fast,
};

pub const ValidationSummary = struct {
    verify_mode: VerifyMode,
};

pub const ToolchainSpec = struct {
    id: []u8,
    source: ?[]u8,
    blob_sha256: [32]u8,
    tree_root: [32]u8,
    size: u64,

    pub fn deinit(self: *ToolchainSpec, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        if (self.source) |source| allocator.free(source);
        self.* = undefined;
    }
};

pub const CasDomain = enum {
    official,
    third_party,
    local,
};

pub const LocalInputSpec = struct {
    id: []u8,
    include: [][]u8,
    exclude: [][]u8,

    pub fn deinit(self: *LocalInputSpec, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        for (self.include) |pattern| allocator.free(pattern);
        allocator.free(self.include);
        for (self.exclude) |pattern| allocator.free(pattern);
        allocator.free(self.exclude);
        self.* = undefined;
    }
};

pub const RemoteInputSpec = struct {
    id: []u8,
    url: []u8,
    blob_sha256: [32]u8,
    tree_root: ?[32]u8 = null,
    extract: bool,

    pub fn deinit(self: *RemoteInputSpec, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.url);
        self.* = undefined;
    }
};

pub const WorkspaceMountSpec = struct {
    source: []u8,
    target: []u8,
    mode: u16,
    strip_prefix: ?[]u8 = null,

    pub fn deinit(self: *WorkspaceMountSpec, allocator: std.mem.Allocator) void {
        allocator.free(self.source);
        allocator.free(self.target);
        if (self.strip_prefix) |strip_prefix| allocator.free(strip_prefix);
        self.* = undefined;
    }
};

pub const WorkspaceEntry = struct {
    mount_path: []u8,
    host_source: ?[]u8 = null,
    cas_sha256: ?[32]u8 = null,
    cas_domain: CasDomain = .local,
    is_dependency: bool = false,

    pub fn deinit(self: *WorkspaceEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.mount_path);
        if (self.host_source) |source| allocator.free(source);
        self.* = undefined;
    }
};

pub const WorkspaceSpec = struct {
    entries: []WorkspaceEntry,
    local_inputs: ?[]LocalInputSpec = null,
    remote_inputs: ?[]RemoteInputSpec = null,
    mounts: ?[]WorkspaceMountSpec = null,

    pub fn deinit(self: *WorkspaceSpec, allocator: std.mem.Allocator) void {
        for (self.entries) |*entry| entry.deinit(allocator);
        allocator.free(self.entries);
        if (self.local_inputs) |inputs| {
            for (inputs) |*input| input.deinit(allocator);
            allocator.free(inputs);
        }
        if (self.remote_inputs) |inputs| {
            for (inputs) |*input| input.deinit(allocator);
            allocator.free(inputs);
        }
        if (self.mounts) |mounts| {
            for (mounts) |*mount| mount.deinit(allocator);
            allocator.free(mounts);
        }
        self.* = undefined;
    }
};

pub const OutputEntry = struct {
    path: []u8,
    source_path: ?[]u8 = null,
    publish_as: ?[]u8 = null,
    mode: u16,
    sha256: ?[32]u8 = null,

    pub fn deinit(self: *OutputEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.path);
        if (self.source_path) |path| allocator.free(path);
        if (self.publish_as) |name| allocator.free(name);
        self.* = undefined;
    }
};

pub const OutputSpec = struct {
    entries: []OutputEntry,

    pub fn deinit(self: *OutputSpec, allocator: std.mem.Allocator) void {
        for (self.entries) |*entry| entry.deinit(allocator);
        allocator.free(self.entries);
        self.* = undefined;
    }
};

pub const FsCopyOp = struct {
    from_path: []u8,
    to_path: []u8,

    pub fn deinit(self: *FsCopyOp, allocator: std.mem.Allocator) void {
        allocator.free(self.from_path);
        allocator.free(self.to_path);
        self.* = undefined;
    }
};

pub const CCompileOp = struct {
    src_path: []u8,
    out_path: []u8,
    args: [][]u8,

    pub fn deinit(self: *CCompileOp, allocator: std.mem.Allocator) void {
        allocator.free(self.src_path);
        allocator.free(self.out_path);
        for (self.args) |arg| allocator.free(arg);
        allocator.free(self.args);
        self.* = undefined;
    }
};

pub const ZigLinkOp = struct {
    object_paths: [][]u8,
    out_path: []u8,
    args: [][]u8,

    pub fn deinit(self: *ZigLinkOp, allocator: std.mem.Allocator) void {
        for (self.object_paths) |path| allocator.free(path);
        allocator.free(self.object_paths);
        allocator.free(self.out_path);
        for (self.args) |arg| allocator.free(arg);
        allocator.free(self.args);
        self.* = undefined;
    }
};

pub const ArchiveFormat = enum {
    tar,
    tar_gz,
};

pub const ArchivePackOp = struct {
    input_paths: [][]u8,
    out_path: []u8,
    format: ArchiveFormat = .tar,

    pub fn deinit(self: *ArchivePackOp, allocator: std.mem.Allocator) void {
        for (self.input_paths) |path| allocator.free(path);
        allocator.free(self.input_paths);
        allocator.free(self.out_path);
        self.* = undefined;
    }
};

pub const BuildOp = union(enum) {
    fs_copy: FsCopyOp,
    c_compile: CCompileOp,
    zig_link: ZigLinkOp,
    archive_pack: ArchivePackOp,

    pub fn deinit(self: *BuildOp, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .fs_copy => |*copy| copy.deinit(allocator),
            .c_compile => |*compile| compile.deinit(allocator),
            .zig_link => |*link| link.deinit(allocator),
            .archive_pack => |*pack| pack.deinit(allocator),
        }
        self.* = undefined;
    }
};

pub const BuildSpec = struct {
    ops: []BuildOp,

    pub fn deinit(self: *BuildSpec, allocator: std.mem.Allocator) void {
        for (self.ops) |*op| op.deinit(allocator);
        allocator.free(self.ops);
        self.* = undefined;
    }
};
