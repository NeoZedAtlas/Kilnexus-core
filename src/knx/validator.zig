const std = @import("std");
const parse_errors = @import("../parser/parse_errors.zig");

const allowed_operators = [_][]const u8{
    "knx.c.compile",
    "knx.zig.link",
    "knx.fs.copy",
    "knx.archive.pack",
};

const output_entry_keys = [_][]const u8{
    "source",
    "publish_as",
    "mode",
    "sha256",
};

const local_input_keys = [_][]const u8{
    "id",
    "include",
    "exclude",
};

const remote_input_keys = [_][]const u8{
    "id",
    "url",
    "blob_sha256",
    "tree_root",
    "extract",
};

const workspace_mount_keys = [_][]const u8{
    "source",
    "target",
    "mode",
    "strip_prefix",
};

const operator_fs_copy_keys = [_][]const u8{
    "id",
    "run",
    "inputs",
    "outputs",
};

const operator_c_compile_keys = [_][]const u8{
    "id",
    "run",
    "inputs",
    "outputs",
    "flags",
};

const operator_zig_link_keys = [_][]const u8{
    "id",
    "run",
    "inputs",
    "outputs",
    "flags",
};

const operator_archive_pack_keys = [_][]const u8{
    "id",
    "run",
    "inputs",
    "outputs",
    "format",
};

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

pub const ArchiveFormat = enum {
    tar,
    tar_gz,
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

pub fn validateCanonicalJson(allocator: std.mem.Allocator, canonical_json: []const u8) !ValidationSummary {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, canonical_json, .{});
    defer parsed.deinit();

    const root = try expectObject(parsed.value, "root");
    try expectVersion(root);
    if (root.get("build") != null) return error.LegacyBuildBlock;
    _ = try expectNonEmptyString(root, "target");

    const toolchain = try expectObjectField(root, "toolchain");
    _ = try expectNonEmptyString(toolchain, "id");
    try expectHex64(toolchain, "blob_sha256");
    try expectHex64(toolchain, "tree_root");
    try expectPositiveInt(toolchain, "size");

    const policy = try expectObjectField(root, "policy");
    const network = try expectNonEmptyString(policy, "network");
    if (!std.mem.eql(u8, network, "off")) return error.InvalidPolicyNetwork;
    const verify_mode = try parseVerifyMode(policy);
    const clock = try expectNonEmptyString(policy, "clock");
    if (!std.mem.eql(u8, clock, "fixed")) return error.InvalidPolicyClock;

    const env = try expectObjectField(root, "env");
    const tz = try expectNonEmptyString(env, "TZ");
    if (!std.mem.eql(u8, tz, "UTC")) return error.InvalidEnvTZ;
    const lang = try expectNonEmptyString(env, "LANG");
    if (!std.mem.eql(u8, lang, "C")) return error.InvalidEnvLang;
    const source_date_epoch = try expectNonEmptyString(env, "SOURCE_DATE_EPOCH");
    try expectAsciiDigits(source_date_epoch, "SOURCE_DATE_EPOCH");

    const outputs = try expectArrayField(root, "outputs");
    if (outputs.items.len == 0) return error.OutputsEmpty;
    for (outputs.items) |entry| {
        const output = try expectObject(entry, "output");
        try ensureOnlyKeys(output, output_entry_keys[0..]);
        const source = try expectNonEmptyString(output, "source");
        try validateWorkspaceRelativePath(source);
        const publish_as = try expectNonEmptyString(output, "publish_as");
        try validatePublishName(publish_as);
        const mode = try expectNonEmptyString(output, "mode");
        try expectModeString(mode);
        if (output.get("sha256")) |_| {
            try expectHex64(output, "sha256");
        }
    }

    const operators_value = root.get("operators") orelse return error.MissingRequiredField;
    const operators = try expectArray(operators_value, "operators");
    for (operators.items) |op_value| {
        const op_obj = try expectObject(op_value, "operator");
        const op_id = try expectNonEmptyString(op_obj, "id");
        try validateOperatorId(op_id);
        const op = try expectNonEmptyString(op_obj, "run");
        if (!isAllowedOperator(op)) return error.OperatorNotAllowed;
        if (std.mem.eql(u8, op, "knx.fs.copy")) {
            try ensureOnlyKeys(op_obj, operator_fs_copy_keys[0..]);
        } else if (std.mem.eql(u8, op, "knx.c.compile")) {
            try ensureOnlyKeys(op_obj, operator_c_compile_keys[0..]);
        } else if (std.mem.eql(u8, op, "knx.zig.link")) {
            try ensureOnlyKeys(op_obj, operator_zig_link_keys[0..]);
        } else if (std.mem.eql(u8, op, "knx.archive.pack")) {
            try ensureOnlyKeys(op_obj, operator_archive_pack_keys[0..]);
        } else {
            return error.OperatorNotAllowed;
        }
    }

    return .{ .verify_mode = verify_mode };
}

pub fn validateCanonicalJsonStrict(allocator: std.mem.Allocator, canonical_json: []const u8) parse_errors.ParseError!ValidationSummary {
    return validateCanonicalJson(allocator, canonical_json) catch |err| return parse_errors.normalize(err);
}

pub fn parseToolchainSpec(allocator: std.mem.Allocator, canonical_json: []const u8) !ToolchainSpec {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, canonical_json, .{});
    defer parsed.deinit();

    const root = try expectObject(parsed.value, "root");
    const toolchain = try expectObjectField(root, "toolchain");

    const id_text = try expectNonEmptyString(toolchain, "id");
    const id = try allocator.dupe(u8, id_text);
    errdefer allocator.free(id);

    const blob_sha_text = try expectNonEmptyString(toolchain, "blob_sha256");
    const tree_root_text = try expectNonEmptyString(toolchain, "tree_root");
    const size_u64 = try parsePositiveU64(toolchain, "size");

    var source_copy: ?[]u8 = null;
    errdefer if (source_copy) |source| allocator.free(source);
    if (toolchain.get("source")) |source_value| {
        const source_text = try expectString(source_value, "source");
        if (source_text.len == 0) return error.EmptyString;
        source_copy = try allocator.dupe(u8, source_text);
    }

    return .{
        .id = id,
        .source = source_copy,
        .blob_sha256 = try parseHexFixed(32, blob_sha_text),
        .tree_root = try parseHexFixed(32, tree_root_text),
        .size = size_u64,
    };
}

pub fn parseToolchainSpecStrict(allocator: std.mem.Allocator, canonical_json: []const u8) parse_errors.ParseError!ToolchainSpec {
    return parseToolchainSpec(allocator, canonical_json) catch |err| return parse_errors.normalize(err);
}

pub fn parseWorkspaceSpec(allocator: std.mem.Allocator, canonical_json: []const u8) !WorkspaceSpec {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, canonical_json, .{});
    defer parsed.deinit();

    const root = try expectObject(parsed.value, "root");

    var entries: std.ArrayList(WorkspaceEntry) = .empty;
    errdefer {
        for (entries.items) |*entry| entry.deinit(allocator);
        entries.deinit(allocator);
    }

    var local_inputs: std.ArrayList(LocalInputSpec) = .empty;
    errdefer {
        for (local_inputs.items) |*input| input.deinit(allocator);
        local_inputs.deinit(allocator);
    }

    var remote_inputs: std.ArrayList(RemoteInputSpec) = .empty;
    errdefer {
        for (remote_inputs.items) |*input| input.deinit(allocator);
        remote_inputs.deinit(allocator);
    }

    var mounts: std.ArrayList(WorkspaceMountSpec) = .empty;
    errdefer {
        for (mounts.items) |*mount| mount.deinit(allocator);
        mounts.deinit(allocator);
    }

    if (root.get("inputs")) |inputs_value| {
        switch (inputs_value) {
            .array => |inputs| {
                try parseWorkspaceEntries(allocator, &entries, inputs, false);
            },
            .object => |inputs_obj| {
                if (inputs_obj.get("local")) |locals_value| {
                    const locals = try expectArray(locals_value, "inputs.local");
                    try parseLocalInputs(allocator, &local_inputs, locals);
                }
                if (inputs_obj.get("remote")) |remotes_value| {
                    const remotes = try expectArray(remotes_value, "inputs.remote");
                    try parseRemoteInputs(allocator, &remote_inputs, remotes);
                }
            },
            else => return error.ExpectedArray,
        }
    }
    if (root.get("deps")) |deps_value| {
        const deps = try expectArray(deps_value, "deps");
        try parseWorkspaceEntries(allocator, &entries, deps, true);
    }
    if (root.get("workspace")) |workspace_value| {
        const workspace = try expectObject(workspace_value, "workspace");
        if (workspace.get("mounts")) |mounts_value| {
            const mounts_array = try expectArray(mounts_value, "workspace.mounts");
            try parseWorkspaceMounts(allocator, &mounts, mounts_array);
        }
    }

    return .{
        .entries = try entries.toOwnedSlice(allocator),
        .local_inputs = try local_inputs.toOwnedSlice(allocator),
        .remote_inputs = try remote_inputs.toOwnedSlice(allocator),
        .mounts = try mounts.toOwnedSlice(allocator),
    };
}

pub fn parseWorkspaceSpecStrict(allocator: std.mem.Allocator, canonical_json: []const u8) parse_errors.ParseError!WorkspaceSpec {
    return parseWorkspaceSpec(allocator, canonical_json) catch |err| return parse_errors.normalize(err);
}

pub fn parseOutputSpec(allocator: std.mem.Allocator, canonical_json: []const u8) !OutputSpec {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, canonical_json, .{});
    defer parsed.deinit();

    const root = try expectObject(parsed.value, "root");
    const outputs = try expectArrayField(root, "outputs");
    if (outputs.items.len == 0) return error.OutputsEmpty;

    var entries: std.ArrayList(OutputEntry) = .empty;
    errdefer {
        for (entries.items) |*entry| entry.deinit(allocator);
        entries.deinit(allocator);
    }

    for (outputs.items) |item| {
        const obj = try expectObject(item, "output");
        try ensureOnlyKeys(obj, output_entry_keys[0..]);
        const mode_text = try expectNonEmptyString(obj, "mode");
        const mode = try parseOutputMode(mode_text);
        const sha256 = if (obj.get("sha256")) |sha_value| blk: {
            const sha_text = try expectString(sha_value, "sha256");
            break :blk try parseHexFixed(32, sha_text);
        } else null;
        var path: ?[]u8 = null;
        var source_path: ?[]u8 = null;
        var publish_as: ?[]u8 = null;
        errdefer {
            if (path) |value| allocator.free(value);
            if (source_path) |value| allocator.free(value);
            if (publish_as) |value| allocator.free(value);
        }
        const source_text = try expectNonEmptyString(obj, "source");
        const publish_text = try expectNonEmptyString(obj, "publish_as");
        try validateWorkspaceRelativePath(source_text);
        try validatePublishName(publish_text);
        path = try allocator.dupe(u8, source_text);
        source_path = try allocator.dupe(u8, source_text);
        publish_as = try allocator.dupe(u8, publish_text);

        try entries.append(allocator, .{
            .path = path.?,
            .source_path = source_path,
            .publish_as = publish_as,
            .mode = mode,
            .sha256 = sha256,
        });
    }

    return .{
        .entries = try entries.toOwnedSlice(allocator),
    };
}

pub fn parseOutputSpecStrict(allocator: std.mem.Allocator, canonical_json: []const u8) parse_errors.ParseError!OutputSpec {
    return parseOutputSpec(allocator, canonical_json) catch |err| return parse_errors.normalize(err);
}

pub fn parseBuildSpec(allocator: std.mem.Allocator, canonical_json: []const u8) !BuildSpec {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, canonical_json, .{});
    defer parsed.deinit();

    const root = try expectObject(parsed.value, "root");
    if (root.get("build") != null) return error.LegacyBuildBlock;
    const operators_value = root.get("operators") orelse return error.MissingRequiredField;
    const operators = try expectArray(operators_value, "operators");
    return parseOperatorsBuildSpec(allocator, operators);
}

const OperatorDecl = struct {
    id: []u8,
    run: []u8,
    inputs: [][]u8,
    outputs: [][]u8,
    flags: [][]u8,
    archive_format: ArchiveFormat = .tar,

    fn deinit(self: *OperatorDecl, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.run);
        freeOwnedStrings(allocator, self.inputs);
        freeOwnedStrings(allocator, self.outputs);
        freeOwnedStrings(allocator, self.flags);
        self.* = undefined;
    }
};

fn parseOperatorsBuildSpec(allocator: std.mem.Allocator, operators: std.json.Array) !BuildSpec {
    var decls: std.ArrayList(OperatorDecl) = .empty;
    defer {
        for (decls.items) |*decl| decl.deinit(allocator);
        decls.deinit(allocator);
    }
    var seen_ids: std.StringHashMap(void) = .init(allocator);
    defer seen_ids.deinit();

    for (operators.items) |item| {
        const obj = try expectObject(item, "operator");
        const id_text = try expectNonEmptyString(obj, "id");
        try validateOperatorId(id_text);
        const id_slot = try seen_ids.getOrPut(id_text);
        if (id_slot.found_existing) return error.InvalidBuildGraph;
        id_slot.value_ptr.* = {};
        const run_text = try expectNonEmptyString(obj, "run");
        if (!isAllowedOperator(run_text)) return error.OperatorNotAllowed;
        if (std.mem.eql(u8, run_text, "knx.fs.copy")) {
            try ensureOnlyKeys(obj, operator_fs_copy_keys[0..]);
        } else if (std.mem.eql(u8, run_text, "knx.c.compile")) {
            try ensureOnlyKeys(obj, operator_c_compile_keys[0..]);
        } else if (std.mem.eql(u8, run_text, "knx.zig.link")) {
            try ensureOnlyKeys(obj, operator_zig_link_keys[0..]);
        } else if (std.mem.eql(u8, run_text, "knx.archive.pack")) {
            try ensureOnlyKeys(obj, operator_archive_pack_keys[0..]);
        } else {
            return error.OperatorNotAllowed;
        }

        const inputs = try parseStringArrayField(allocator, obj, "inputs");
        errdefer freeOwnedStrings(allocator, inputs);
        const outputs = try parseStringArrayField(allocator, obj, "outputs");
        errdefer freeOwnedStrings(allocator, outputs);
        const flags = if (obj.get("flags")) |_| try parseStringArrayField(allocator, obj, "flags") else try allocator.alloc([]u8, 0);
        errdefer freeOwnedStrings(allocator, flags);

        for (inputs) |path| try validateWorkspaceRelativePath(path);
        for (outputs) |path| try validateWorkspaceRelativePath(path);

        var archive_format: ArchiveFormat = .tar;
        if (std.mem.eql(u8, run_text, "knx.archive.pack")) {
            if (obj.get("format")) |format_value| {
                const format_text = try expectString(format_value, "archive format");
                archive_format = parseArchiveFormat(format_text) orelse return error.ValueInvalid;
            }
        }

        if (std.mem.eql(u8, run_text, "knx.fs.copy")) {
            if (inputs.len != 1 or outputs.len != 1) return error.InvalidBuildGraph;
            if (flags.len != 0) return error.ValueInvalid;
        } else if (std.mem.eql(u8, run_text, "knx.c.compile")) {
            if (inputs.len < 1 or outputs.len != 1) return error.InvalidBuildGraph;
            for (flags) |flag| {
                if (!isAllowedCompileArg(flag)) return error.ValueInvalid;
            }
        } else if (std.mem.eql(u8, run_text, "knx.zig.link")) {
            if (inputs.len < 1 or outputs.len != 1) return error.InvalidBuildGraph;
            for (flags) |flag| {
                if (!isAllowedLinkArg(flag)) return error.ValueInvalid;
            }
        } else if (std.mem.eql(u8, run_text, "knx.archive.pack")) {
            if (inputs.len < 1 or outputs.len != 1) return error.InvalidBuildGraph;
            if (flags.len != 0) return error.ValueInvalid;
        } else {
            return error.OperatorNotAllowed;
        }

        try decls.append(allocator, .{
            .id = try allocator.dupe(u8, id_text),
            .run = try allocator.dupe(u8, run_text),
            .inputs = inputs,
            .outputs = outputs,
            .flags = flags,
            .archive_format = archive_format,
        });
    }

    var output_producers: std.StringHashMap(usize) = .init(allocator);
    defer output_producers.deinit();
    for (decls.items, 0..) |decl, idx| {
        for (decl.outputs) |output_path| {
            const gop = try output_producers.getOrPut(output_path);
            if (gop.found_existing) return error.InvalidBuildGraph;
            gop.value_ptr.* = idx;
        }
    }

    const count = decls.items.len;
    var adjacency = try allocator.alloc(std.ArrayList(usize), count);
    defer {
        for (adjacency) |*edges| edges.deinit(allocator);
        allocator.free(adjacency);
    }
    for (adjacency) |*edges| edges.* = .empty;

    var indegree = try allocator.alloc(usize, count);
    defer allocator.free(indegree);
    @memset(indegree, 0);

    for (decls.items, 0..) |decl, idx| {
        for (decl.inputs) |input_path| {
            const producer = output_producers.get(input_path) orelse continue;
            if (producer == idx) return error.InvalidBuildGraph;
            if (!containsIndex(adjacency[producer].items, idx)) {
                try adjacency[producer].append(allocator, idx);
                indegree[idx] += 1;
            }
        }
    }

    var queue: std.ArrayList(usize) = .empty;
    defer queue.deinit(allocator);
    for (indegree, 0..) |deg, idx| {
        if (deg == 0) try queue.append(allocator, idx);
    }

    var ordered: std.ArrayList(usize) = .empty;
    defer ordered.deinit(allocator);
    var head: usize = 0;
    while (head < queue.items.len) : (head += 1) {
        const idx = queue.items[head];
        try ordered.append(allocator, idx);
        for (adjacency[idx].items) |next_idx| {
            indegree[next_idx] -= 1;
            if (indegree[next_idx] == 0) {
                try queue.append(allocator, next_idx);
            }
        }
    }
    if (ordered.items.len != count) return error.InvalidBuildGraph;

    var ops: std.ArrayList(BuildOp) = .empty;
    errdefer {
        for (ops.items) |*op| op.deinit(allocator);
        ops.deinit(allocator);
    }

    for (ordered.items) |idx| {
        const decl = decls.items[idx];
        if (std.mem.eql(u8, decl.run, "knx.fs.copy")) {
            try ops.append(allocator, .{
                .fs_copy = .{
                    .from_path = try allocator.dupe(u8, decl.inputs[0]),
                    .to_path = try allocator.dupe(u8, decl.outputs[0]),
                },
            });
            continue;
        }
        if (std.mem.eql(u8, decl.run, "knx.c.compile")) {
            try ops.append(allocator, .{
                .c_compile = .{
                    .src_path = try allocator.dupe(u8, decl.inputs[0]),
                    .out_path = try allocator.dupe(u8, decl.outputs[0]),
                    .args = try dupeStringSlice(allocator, decl.flags),
                },
            });
            continue;
        }
        if (std.mem.eql(u8, decl.run, "knx.zig.link")) {
            try ops.append(allocator, .{
                .zig_link = .{
                    .object_paths = try dupeStringSlice(allocator, decl.inputs),
                    .out_path = try allocator.dupe(u8, decl.outputs[0]),
                    .args = try dupeStringSlice(allocator, decl.flags),
                },
            });
            continue;
        }
        if (std.mem.eql(u8, decl.run, "knx.archive.pack")) {
            try ops.append(allocator, .{
                .archive_pack = .{
                    .input_paths = try dupeStringSlice(allocator, decl.inputs),
                    .out_path = try allocator.dupe(u8, decl.outputs[0]),
                    .format = decl.archive_format,
                },
            });
            continue;
        }
        return error.OperatorNotAllowed;
    }

    return .{
        .ops = try ops.toOwnedSlice(allocator),
    };
}

pub fn parseBuildSpecStrict(allocator: std.mem.Allocator, canonical_json: []const u8) parse_errors.ParseError!BuildSpec {
    return parseBuildSpec(allocator, canonical_json) catch |err| return parse_errors.normalize(err);
}

pub fn validateBuildWriteIsolation(workspace_spec: *const WorkspaceSpec, build_spec: *const BuildSpec) !void {
    for (build_spec.ops) |op| {
        const write_path = switch (op) {
            .fs_copy => |copy| copy.to_path,
            .c_compile => |compile| compile.out_path,
            .zig_link => |link| link.out_path,
            .archive_pack => |pack| pack.out_path,
        };
        for (workspace_spec.entries) |entry| {
            if (isEqualOrDescendant(write_path, entry.mount_path)) return error.ValueInvalid;
        }
        if (workspace_spec.mounts) |mounts| {
            for (mounts) |mount| {
                if (isEqualOrDescendant(write_path, mount.target)) return error.ValueInvalid;
            }
        }
    }
}

pub fn computeKnxDigestHex(canonical_json: []const u8) [64]u8 {
    var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(canonical_json, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

fn parseVerifyMode(policy: std.json.ObjectMap) !VerifyMode {
    const verify_mode_value = policy.get("verify_mode") orelse return .strict;
    const value = try expectString(verify_mode_value, "verify_mode");
    if (std.mem.eql(u8, value, "strict")) return .strict;
    if (std.mem.eql(u8, value, "fast")) return .fast;
    return error.InvalidVerifyMode;
}

fn parseWorkspaceEntries(
    allocator: std.mem.Allocator,
    entries: *std.ArrayList(WorkspaceEntry),
    items: std.json.Array,
    is_dependency: bool,
) !void {
    for (items.items) |item| {
        const obj = try expectObject(item, "workspace entry");
        const mount_path_text = try expectNonEmptyString(obj, "path");
        const mount_path = try allocator.dupe(u8, mount_path_text);
        errdefer allocator.free(mount_path);

        var entry: WorkspaceEntry = .{
            .mount_path = mount_path,
            .is_dependency = is_dependency,
        };
        errdefer entry.deinit(allocator);

        const has_source = obj.get("source") != null;
        const has_cas = obj.get("cas_sha256") != null;
        if (has_source == has_cas) {
            return error.ValueInvalid;
        }

        if (has_source) {
            const source_text = try expectNonEmptyString(obj, "source");
            entry.host_source = try allocator.dupe(u8, source_text);
        } else {
            const cas_text = try expectNonEmptyString(obj, "cas_sha256");
            entry.cas_sha256 = try parseHexFixed(32, cas_text);

            if (obj.get("cas_domain")) |domain_value| {
                const domain_text = try expectString(domain_value, "cas_domain");
                entry.cas_domain = parseCasDomain(domain_text) orelse return error.ValueInvalid;
            }
        }

        try entries.append(allocator, entry);
    }
}

fn parseLocalInputs(
    allocator: std.mem.Allocator,
    locals: *std.ArrayList(LocalInputSpec),
    items: std.json.Array,
) !void {
    for (items.items) |item| {
        const obj = try expectObject(item, "local input");
        try ensureOnlyKeys(obj, local_input_keys[0..]);
        const id_text = try expectNonEmptyString(obj, "id");
        const include_array = try expectArrayField(obj, "include");

        var include_patterns: std.ArrayList([]u8) = .empty;
        errdefer {
            for (include_patterns.items) |pattern| allocator.free(pattern);
            include_patterns.deinit(allocator);
        }
        for (include_array.items) |entry| {
            const pattern = try expectString(entry, "include pattern");
            if (pattern.len == 0) return error.ValueInvalid;
            try include_patterns.append(allocator, try allocator.dupe(u8, pattern));
        }
        if (include_patterns.items.len == 0) return error.ValueInvalid;

        var exclude_patterns: std.ArrayList([]u8) = .empty;
        errdefer {
            for (exclude_patterns.items) |pattern| allocator.free(pattern);
            exclude_patterns.deinit(allocator);
        }
        if (obj.get("exclude")) |exclude_value| {
            const exclude_array = try expectArray(exclude_value, "exclude");
            for (exclude_array.items) |entry| {
                const pattern = try expectString(entry, "exclude pattern");
                if (pattern.len == 0) return error.ValueInvalid;
                try exclude_patterns.append(allocator, try allocator.dupe(u8, pattern));
            }
        }

        const id = try allocator.dupe(u8, id_text);
        errdefer allocator.free(id);

        try locals.append(allocator, .{
            .id = id,
            .include = try include_patterns.toOwnedSlice(allocator),
            .exclude = try exclude_patterns.toOwnedSlice(allocator),
        });
    }
}

fn parseRemoteInputs(
    allocator: std.mem.Allocator,
    remotes: *std.ArrayList(RemoteInputSpec),
    items: std.json.Array,
) !void {
    for (items.items) |item| {
        const obj = try expectObject(item, "remote input");
        try ensureOnlyKeys(obj, remote_input_keys[0..]);
        const id_text = try expectNonEmptyString(obj, "id");
        const url_text = try expectNonEmptyString(obj, "url");
        const blob_text = try expectNonEmptyString(obj, "blob_sha256");
        const tree_root = if (obj.get("tree_root")) |tree_value| blk: {
            const tree_text = try expectString(tree_value, "tree_root");
            break :blk try parseHexFixed(32, tree_text);
        } else null;

        const extract = if (obj.get("extract")) |extract_value| try expectBool(extract_value, "extract") else false;
        if (extract and tree_root == null) return error.MissingRequiredField;

        const id = try allocator.dupe(u8, id_text);
        errdefer allocator.free(id);
        const url = try allocator.dupe(u8, url_text);
        errdefer allocator.free(url);

        try remotes.append(allocator, .{
            .id = id,
            .url = url,
            .blob_sha256 = try parseHexFixed(32, blob_text),
            .tree_root = tree_root,
            .extract = extract,
        });
    }
}

fn parseWorkspaceMounts(
    allocator: std.mem.Allocator,
    mounts: *std.ArrayList(WorkspaceMountSpec),
    items: std.json.Array,
) !void {
    for (items.items) |item| {
        const obj = try expectObject(item, "workspace mount");
        try ensureOnlyKeys(obj, workspace_mount_keys[0..]);
        const source_text = try expectNonEmptyString(obj, "source");
        const target_text = try expectNonEmptyString(obj, "target");
        const mode_text = try expectNonEmptyString(obj, "mode");
        const normalized_target = trimTrailingSlash(target_text);
        try validateWorkspaceRelativePath(normalized_target);
        const mode = try parseOutputMode(mode_text);
        if (mode & 0o222 != 0) return error.ValueInvalid;

        const source = try allocator.dupe(u8, source_text);
        errdefer allocator.free(source);
        const target = try allocator.dupe(u8, normalized_target);
        errdefer allocator.free(target);
        const strip_prefix = if (obj.get("strip_prefix")) |strip_value| blk: {
            const strip_text = try expectString(strip_value, "strip_prefix");
            if (strip_text.len == 0) return error.ValueInvalid;
            const normalized_strip = trimTrailingSlash(strip_text);
            try validateWorkspaceRelativePath(normalized_strip);
            break :blk try allocator.dupe(u8, normalized_strip);
        } else null;
        errdefer if (strip_prefix) |value| allocator.free(value);

        try mounts.append(allocator, .{
            .source = source,
            .target = target,
            .mode = mode,
            .strip_prefix = strip_prefix,
        });
    }
}

fn parseCasDomain(text: []const u8) ?CasDomain {
    if (std.mem.eql(u8, text, "official")) return .official;
    if (std.mem.eql(u8, text, "third_party")) return .third_party;
    if (std.mem.eql(u8, text, "local")) return .local;
    return null;
}

fn parseArchiveFormat(text: []const u8) ?ArchiveFormat {
    if (std.mem.eql(u8, text, "tar")) return .tar;
    if (std.mem.eql(u8, text, "tar.gz")) return .tar_gz;
    return null;
}

fn parseStringArrayField(
    allocator: std.mem.Allocator,
    object: std.json.ObjectMap,
    key: []const u8,
) ![][]u8 {
    const value = object.get(key) orelse return error.MissingRequiredField;
    const array = try expectArray(value, key);
    if (array.items.len == 0) return error.ValueInvalid;

    var out: std.ArrayList([]u8) = .empty;
    errdefer {
        for (out.items) |item| allocator.free(item);
        out.deinit(allocator);
    }
    for (array.items) |item| {
        const text = try expectString(item, key);
        if (text.len == 0) return error.ValueInvalid;
        try out.append(allocator, try allocator.dupe(u8, text));
    }
    return out.toOwnedSlice(allocator);
}

fn dupeStringSlice(allocator: std.mem.Allocator, items: [][]u8) ![][]u8 {
    var out: std.ArrayList([]u8) = .empty;
    errdefer {
        for (out.items) |item| allocator.free(item);
        out.deinit(allocator);
    }
    for (items) |item| {
        try out.append(allocator, try allocator.dupe(u8, item));
    }
    return out.toOwnedSlice(allocator);
}

fn containsIndex(items: []const usize, value: usize) bool {
    for (items) |item| {
        if (item == value) return true;
    }
    return false;
}

fn trimTrailingSlash(path: []const u8) []const u8 {
    var out = path;
    while (out.len > 0 and out[out.len - 1] == '/') {
        out = out[0 .. out.len - 1];
    }
    return out;
}

fn parsePositiveU64(object: std.json.ObjectMap, key: []const u8) !u64 {
    const value = object.get(key) orelse return error.MissingRequiredField;
    const number = try expectInteger(value, key);
    if (number <= 0) return error.InvalidPositiveInt;
    return @intCast(number);
}

fn expectVersion(root: std.json.ObjectMap) !void {
    const value = root.get("version") orelse return error.MissingVersion;
    const number = try expectInteger(value, "version");
    if (number != 1) return error.UnsupportedVersion;
}

fn expectHex64(object: std.json.ObjectMap, key: []const u8) !void {
    const value = try expectNonEmptyString(object, key);
    if (value.len != 64) return error.InvalidHexLength;
    for (value) |ch| {
        if (!std.ascii.isHex(ch)) return error.InvalidHexChar;
    }
}

fn expectPositiveInt(object: std.json.ObjectMap, key: []const u8) !void {
    const value = object.get(key) orelse return error.MissingRequiredField;
    const number = try expectInteger(value, key);
    if (number <= 0) return error.InvalidPositiveInt;
}

fn expectModeString(value: []const u8) !void {
    if (value.len != 4) return error.InvalidMode;
    if (value[0] != '0') return error.InvalidMode;
    for (value[1..]) |ch| {
        if (ch < '0' or ch > '7') return error.InvalidMode;
    }
}

fn parseOutputMode(text: []const u8) !u16 {
    try expectModeString(text);
    var mode: u16 = 0;
    for (text[1..]) |ch| {
        mode = (mode << 3) | @as(u16, ch - '0');
    }
    return mode;
}

fn validateOutputPath(path: []const u8) !void {
    const prefix = "kilnexus-out/";
    if (!std.mem.startsWith(u8, path, prefix)) return error.InvalidOutputPath;
    if (std.mem.indexOfScalar(u8, path, '\\') != null) return error.InvalidOutputPath;
    if (std.mem.indexOfScalar(u8, path, ':') != null) return error.InvalidOutputPath;

    const rel = path[prefix.len..];
    if (rel.len == 0) return error.InvalidOutputPath;

    var it = std.mem.splitScalar(u8, rel, '/');
    while (it.next()) |segment| {
        if (segment.len == 0 or std.mem.eql(u8, segment, ".") or std.mem.eql(u8, segment, "..")) {
            return error.InvalidOutputPath;
        }
    }
}

fn outputRelativePath(path: []const u8) ![]const u8 {
    const prefix = "kilnexus-out/";
    if (!std.mem.startsWith(u8, path, prefix)) return error.InvalidOutputPath;
    const rel = path[prefix.len..];
    if (rel.len == 0) return error.InvalidOutputPath;
    return rel;
}

fn validatePublishName(name: []const u8) !void {
    if (name.len == 0) return error.InvalidOutputPath;
    if (std.fs.path.isAbsolute(name)) return error.InvalidOutputPath;
    if (std.mem.indexOfScalar(u8, name, '\\') != null) return error.InvalidOutputPath;
    if (std.mem.indexOfScalar(u8, name, ':') != null) return error.InvalidOutputPath;

    var it = std.mem.splitScalar(u8, name, '/');
    while (it.next()) |segment| {
        if (segment.len == 0 or std.mem.eql(u8, segment, ".") or std.mem.eql(u8, segment, "..")) {
            return error.InvalidOutputPath;
        }
    }
}

fn parseOptionalArgs(
    allocator: std.mem.Allocator,
    object: std.json.ObjectMap,
    comptime allowed: fn ([]const u8) bool,
) ![][]u8 {
    const value = object.get("args") orelse return allocator.alloc([]u8, 0);
    const array = try expectArray(value, "args");

    var args: std.ArrayList([]u8) = .empty;
    errdefer {
        for (args.items) |arg| allocator.free(arg);
        args.deinit(allocator);
    }

    for (array.items) |arg_value| {
        const arg_text = try expectString(arg_value, "arg");
        if (arg_text.len == 0) return error.ValueInvalid;
        if (!allowed(arg_text)) return error.ValueInvalid;
        try args.append(allocator, try allocator.dupe(u8, arg_text));
    }
    return args.toOwnedSlice(allocator);
}

fn freeOwnedStrings(allocator: std.mem.Allocator, items: [][]u8) void {
    for (items) |item| allocator.free(item);
    allocator.free(items);
}

fn isAllowedCompileArg(arg: []const u8) bool {
    const allowed = [_][]const u8{
        "-O0",
        "-O1",
        "-O2",
        "-O3",
        "-Os",
        "-Oz",
        "-g",
        "-g0",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-std=c89",
        "-std=c99",
        "-std=c11",
        "-std=c17",
    };
    for (allowed) |item| {
        if (std.mem.eql(u8, arg, item)) return true;
    }
    return false;
}

fn isAllowedLinkArg(arg: []const u8) bool {
    const allowed = [_][]const u8{
        "-static",
        "-s",
        "-Wl,--gc-sections",
        "-Wl,--strip-all",
    };
    for (allowed) |item| {
        if (std.mem.eql(u8, arg, item)) return true;
    }
    return false;
}

fn validateWorkspaceRelativePath(path: []const u8) !void {
    if (path.len == 0) return error.ValueInvalid;
    if (std.fs.path.isAbsolute(path)) return error.ValueInvalid;
    if (std.mem.indexOfScalar(u8, path, '\\') != null) return error.ValueInvalid;
    if (std.mem.indexOfScalar(u8, path, ':') != null) return error.ValueInvalid;

    var it = std.mem.splitScalar(u8, path, '/');
    while (it.next()) |segment| {
        if (segment.len == 0 or std.mem.eql(u8, segment, ".") or std.mem.eql(u8, segment, "..")) {
            return error.ValueInvalid;
        }
    }
}

fn isEqualOrDescendant(path: []const u8, base: []const u8) bool {
    if (std.mem.eql(u8, path, base)) return true;
    if (path.len <= base.len) return false;
    if (!std.mem.startsWith(u8, path, base)) return false;
    return path[base.len] == '/';
}

fn expectAsciiDigits(value: []const u8, field: []const u8) !void {
    _ = field;
    for (value) |ch| {
        if (!std.ascii.isDigit(ch)) return error.InvalidDigits;
    }
}

fn isAllowedOperator(name: []const u8) bool {
    for (allowed_operators) |allowed| {
        if (std.mem.eql(u8, name, allowed)) return true;
    }
    return false;
}

fn validateOperatorId(id: []const u8) !void {
    if (id.len == 0) return error.ValueInvalid;
    for (id) |ch| {
        if (!std.ascii.isAlphanumeric(ch) and ch != '-' and ch != '_' and ch != '.') {
            return error.ValueInvalid;
        }
    }
}

fn ensureOnlyKeys(object: std.json.ObjectMap, allowed_keys: []const []const u8) !void {
    var it = object.iterator();
    while (it.next()) |entry| {
        if (!containsAllowedKey(entry.key_ptr.*, allowed_keys)) return error.ValueInvalid;
    }
}

fn containsAllowedKey(key: []const u8, allowed_keys: []const []const u8) bool {
    for (allowed_keys) |allowed| {
        if (std.mem.eql(u8, key, allowed)) return true;
    }
    return false;
}

fn expectObjectField(object: std.json.ObjectMap, key: []const u8) !std.json.ObjectMap {
    const value = object.get(key) orelse return error.MissingRequiredField;
    return expectObject(value, key);
}

fn expectArrayField(object: std.json.ObjectMap, key: []const u8) !std.json.Array {
    const value = object.get(key) orelse return error.MissingRequiredField;
    return expectArray(value, key);
}

fn expectObject(value: std.json.Value, _: []const u8) !std.json.ObjectMap {
    return switch (value) {
        .object => |object| object,
        else => error.ExpectedObject,
    };
}

fn expectArray(value: std.json.Value, _: []const u8) !std.json.Array {
    return switch (value) {
        .array => |array| array,
        else => error.ExpectedArray,
    };
}

fn expectString(value: std.json.Value, _: []const u8) ![]const u8 {
    return switch (value) {
        .string => |string| string,
        else => error.ExpectedString,
    };
}

fn expectInteger(value: std.json.Value, _: []const u8) !i64 {
    return switch (value) {
        .integer => |number| number,
        else => error.ExpectedInteger,
    };
}

fn expectBool(value: std.json.Value, _: []const u8) !bool {
    return switch (value) {
        .bool => |b| b,
        else => error.TypeMismatch,
    };
}

fn expectNonEmptyString(object: std.json.ObjectMap, key: []const u8) ![]const u8 {
    const value = object.get(key) orelse return error.MissingRequiredField;
    const string = try expectString(value, key);
    if (string.len == 0) return error.EmptyString;
    return string;
}

fn parseHexFixed(comptime byte_len: usize, text: []const u8) ![byte_len]u8 {
    if (text.len != byte_len * 2) return error.InvalidHexLength;
    var output: [byte_len]u8 = undefined;
    _ = std.fmt.hexToBytes(&output, text) catch |err| switch (err) {
        error.InvalidCharacter => return error.InvalidHexChar,
        error.InvalidLength => return error.InvalidHexLength,
        error.NoSpaceLeft => return error.InvalidHexLength,
    };
    return output;
}

test "validateCanonicalJson accepts minimal valid knxfile" {
    const allocator = std.testing.allocator;
    const json =
        \\{
        \\  "version": 1,
        \\  "target": "x86_64-unknown-linux-musl",
        \\  "toolchain": {
        \\    "id": "zigcc-0.14.0",
        \\    "blob_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\    "tree_root": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        \\    "size": 1
        \\  },
        \\  "policy": {
        \\    "network": "off",
        \\    "clock": "fixed"
        \\  },
        \\  "env": {
        \\    "TZ": "UTC",
        \\    "LANG": "C",
        \\    "SOURCE_DATE_EPOCH": "1735689600"
        \\  },
        \\  "outputs": [
        \\    { "source": "kilnexus-out/app", "publish_as": "app", "mode": "0755" }
        \\  ],
        \\  "operators": [
        \\    {
        \\      "id": "compile-main",
        \\      "run": "knx.c.compile",
        \\      "inputs": ["src/main.c"],
        \\      "outputs": ["obj/main.o"],
        \\      "flags": ["-O2"]
        \\    },
        \\    {
        \\      "id": "link-final",
        \\      "run": "knx.zig.link",
        \\      "inputs": ["obj/main.o"],
        \\      "outputs": ["kilnexus-out/app"],
        \\      "flags": ["-s"]
        \\    }
        \\  ]
        \\}
    ;

    const summary = try validateCanonicalJson(allocator, json);
    try std.testing.expectEqual(VerifyMode.strict, summary.verify_mode);
}

test "validateCanonicalJson rejects custom operator" {
    const allocator = std.testing.allocator;
    const json =
        \\{
        \\  "version": 1,
        \\  "target": "x86_64-unknown-linux-musl",
        \\  "toolchain": {
        \\    "id": "zigcc-0.14.0",
        \\    "blob_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\    "tree_root": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        \\    "size": 1
        \\  },
        \\  "policy": {
        \\    "network": "off",
        \\    "clock": "fixed",
        \\    "verify_mode": "strict"
        \\  },
        \\  "env": {
        \\    "TZ": "UTC",
        \\    "LANG": "C",
        \\    "SOURCE_DATE_EPOCH": "1735689600"
        \\  },
        \\  "outputs": [
        \\    { "source": "kilnexus-out/app", "publish_as": "app", "mode": "0755" }
        \\  ],
        \\  "operators": [
        \\    {
        \\      "id": "evil",
        \\      "run": "sh -c x",
        \\      "inputs": ["src/main.c"],
        \\      "outputs": ["obj/main.o"]
        \\    }
        \\  ]
        \\}
    ;

    try std.testing.expectError(error.OperatorNotAllowed, validateCanonicalJson(allocator, json));
}

test "computeKnxDigestHex is stable length" {
    const hex = computeKnxDigestHex("{\"version\":1}");
    try std.testing.expectEqual(@as(usize, 64), hex.len);
}

test "validateCanonicalJsonStrict normalizes policy errors" {
    const allocator = std.testing.allocator;
    const json =
        \\{
        \\  "version": 1,
        \\  "target": "x86_64-unknown-linux-musl",
        \\  "toolchain": {
        \\    "id": "zigcc-0.14.0",
        \\    "blob_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\    "tree_root": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        \\    "size": 1
        \\  },
        \\  "policy": {
        \\    "network": "on",
        \\    "clock": "fixed"
        \\  },
        \\  "env": {
        \\    "TZ": "UTC",
        \\    "LANG": "C",
        \\    "SOURCE_DATE_EPOCH": "1735689600"
        \\  },
        \\  "outputs": [
        \\    { "source": "kilnexus-out/app", "publish_as": "app", "mode": "0755" }
        \\  ]
        \\}
    ;

    try std.testing.expectError(error.ValueInvalid, validateCanonicalJsonStrict(allocator, json));
}

test "parseToolchainSpec extracts source and hashes" {
    const allocator = std.testing.allocator;
    const json =
        \\{
        \\  "version": 1,
        \\  "target": "x86_64-unknown-linux-musl",
        \\  "toolchain": {
        \\    "id": "zigcc-0.14.0",
        \\    "source": "file://tmp/toolchain.blob",
        \\    "blob_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\    "tree_root": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        \\    "size": 1
        \\  },
        \\  "policy": {
        \\    "network": "off",
        \\    "clock": "fixed"
        \\  },
        \\  "env": {
        \\    "TZ": "UTC",
        \\    "LANG": "C",
        \\    "SOURCE_DATE_EPOCH": "1735689600"
        \\  },
        \\  "outputs": [
        \\    { "source": "kilnexus-out/app", "publish_as": "app", "mode": "0755" }
        \\  ]
        \\}
    ;

    var spec = try parseToolchainSpec(allocator, json);
    defer spec.deinit(allocator);

    try std.testing.expectEqualStrings("zigcc-0.14.0", spec.id);
    try std.testing.expect(spec.source != null);
    try std.testing.expectEqualStrings("file://tmp/toolchain.blob", spec.source.?);
    try std.testing.expectEqual(@as(u64, 1), spec.size);
}

test "parseWorkspaceSpec parses inputs and deps entries" {
    const allocator = std.testing.allocator;
    const json =
        \\{
        \\  "version": 1,
        \\  "target": "x86_64-unknown-linux-musl",
        \\  "toolchain": {
        \\    "id": "zigcc-0.14.0",
        \\    "blob_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\    "tree_root": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        \\    "size": 1
        \\  },
        \\  "policy": {
        \\    "network": "off",
        \\    "clock": "fixed"
        \\  },
        \\  "env": {
        \\    "TZ": "UTC",
        \\    "LANG": "C",
        \\    "SOURCE_DATE_EPOCH": "1735689600"
        \\  },
        \\  "inputs": [
        \\    { "path": "src/main.c", "source": "project/src/main.c" }
        \\  ],
        \\  "deps": [
        \\    {
        \\      "path": "deps/libc.a",
        \\      "cas_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        \\      "cas_domain": "third_party"
        \\    }
        \\  ],
        \\  "outputs": [
        \\    { "source": "kilnexus-out/app", "publish_as": "app", "mode": "0755" }
        \\  ]
        \\}
    ;

    var spec = try parseWorkspaceSpec(allocator, json);
    defer spec.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 2), spec.entries.len);
    try std.testing.expectEqualStrings("src/main.c", spec.entries[0].mount_path);
    try std.testing.expect(spec.entries[0].host_source != null);
    try std.testing.expect(!spec.entries[0].is_dependency);
    try std.testing.expect(spec.entries[1].cas_sha256 != null);
    try std.testing.expectEqual(CasDomain.third_party, spec.entries[1].cas_domain);
    try std.testing.expect(spec.entries[1].is_dependency);
}

test "parseWorkspaceSpec requires remote tree_root when extract is true" {
    const allocator = std.testing.allocator;
    const json =
        \\{
        \\  "version": 1,
        \\  "target": "x86_64-unknown-linux-musl",
        \\  "toolchain": {
        \\    "id": "zigcc-0.14.0",
        \\    "blob_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\    "tree_root": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        \\    "size": 1
        \\  },
        \\  "policy": {
        \\    "network": "off",
        \\    "clock": "fixed"
        \\  },
        \\  "env": {
        \\    "TZ": "UTC",
        \\    "LANG": "C",
        \\    "SOURCE_DATE_EPOCH": "1735689600"
        \\  },
        \\  "inputs": {
        \\    "remote": [
        \\      {
        \\        "id": "remote-src",
        \\        "url": "file://tmp/remote.tar",
        \\        "blob_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        \\        "extract": true
        \\      }
        \\    ]
        \\  },
        \\  "workspace": {
        \\    "mounts": [
        \\      { "source": "remote-src/pkg/a.c", "target": "src/a.c", "mode": "0444" }
        \\    ]
        \\  },
        \\  "outputs": [
        \\    { "source": "kilnexus-out/app", "publish_as": "app", "mode": "0755" }
        \\  ]
        \\}
    ;

    try std.testing.expectError(error.MissingRequiredField, parseWorkspaceSpec(allocator, json));
}

test "parseWorkspaceSpec parses workspace mount strip_prefix" {
    const allocator = std.testing.allocator;
    const json =
        \\{
        \\  "version": 1,
        \\  "target": "x86_64-unknown-linux-musl",
        \\  "toolchain": {
        \\    "id": "zigcc-0.14.0",
        \\    "blob_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\    "tree_root": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        \\    "size": 1
        \\  },
        \\  "policy": {
        \\    "network": "off",
        \\    "clock": "fixed"
        \\  },
        \\  "env": {
        \\    "TZ": "UTC",
        \\    "LANG": "C",
        \\    "SOURCE_DATE_EPOCH": "1735689600"
        \\  },
        \\  "workspace": {
        \\    "mounts": [
        \\      {
        \\        "source": "local-src",
        \\        "target": "src",
        \\        "mode": "0444",
        \\        "strip_prefix": "examples/project"
        \\      }
        \\    ]
        \\  },
        \\  "outputs": [
        \\    { "source": "kilnexus-out/app", "publish_as": "app", "mode": "0755" }
        \\  ]
        \\}
    ;

    var spec = try parseWorkspaceSpec(allocator, json);
    defer spec.deinit(allocator);

    try std.testing.expect(spec.mounts != null);
    try std.testing.expectEqual(@as(usize, 1), spec.mounts.?.len);
    try std.testing.expect(spec.mounts.?[0].strip_prefix != null);
    try std.testing.expectEqualStrings("examples/project", spec.mounts.?[0].strip_prefix.?);
}

test "parseOutputSpec parses output entries" {
    const allocator = std.testing.allocator;
    const json =
        \\{
        \\  "version": 1,
        \\  "target": "x86_64-unknown-linux-musl",
        \\  "toolchain": {
        \\    "id": "zigcc-0.14.0",
        \\    "blob_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\    "tree_root": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        \\    "size": 1
        \\  },
        \\  "policy": {
        \\    "network": "off",
        \\    "clock": "fixed"
        \\  },
        \\  "env": {
        \\    "TZ": "UTC",
        \\    "LANG": "C",
        \\    "SOURCE_DATE_EPOCH": "1735689600"
        \\  },
        \\  "outputs": [
        \\    { "source": "kilnexus-out/app", "publish_as": "app", "mode": "0755" }
        \\  ]
        \\}
    ;

    var spec = try parseOutputSpec(allocator, json);
    defer spec.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), spec.entries.len);
    try std.testing.expectEqualStrings("kilnexus-out/app", spec.entries[0].path);
    try std.testing.expectEqual(@as(u16, 0o755), spec.entries[0].mode);
    try std.testing.expect(spec.entries[0].sha256 == null);
}

test "parseOutputSpec parses output sha256 when declared" {
    const allocator = std.testing.allocator;
    const json =
        \\{
        \\  "version": 1,
        \\  "target": "x86_64-unknown-linux-musl",
        \\  "toolchain": {
        \\    "id": "zigcc-0.14.0",
        \\    "blob_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\    "tree_root": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        \\    "size": 1
        \\  },
        \\  "policy": {
        \\    "network": "off",
        \\    "clock": "fixed"
        \\  },
        \\  "env": {
        \\    "TZ": "UTC",
        \\    "LANG": "C",
        \\    "SOURCE_DATE_EPOCH": "1735689600"
        \\  },
        \\  "outputs": [
        \\    {
        \\      "source": "kilnexus-out/app",
        \\      "publish_as": "app",
        \\      "mode": "0755",
        \\      "sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        \\    }
        \\  ]
        \\}
    ;

    var spec = try parseOutputSpec(allocator, json);
    defer spec.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), spec.entries.len);
    try std.testing.expect(spec.entries[0].sha256 != null);
    try std.testing.expectEqualSlices(u8, &([_]u8{0xcc} ** 32), &spec.entries[0].sha256.?);
}

test "parseBuildSpec parses fs.copy operation" {
    const allocator = std.testing.allocator;
    const json =
        \\{
        \\  "version": 1,
        \\  "target": "x86_64-unknown-linux-musl",
        \\  "toolchain": {
        \\    "id": "zigcc-0.14.0",
        \\    "blob_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\    "tree_root": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        \\    "size": 1
        \\  },
        \\  "policy": {
        \\    "network": "off",
        \\    "clock": "fixed"
        \\  },
        \\  "env": {
        \\    "TZ": "UTC",
        \\    "LANG": "C",
        \\    "SOURCE_DATE_EPOCH": "1735689600"
        \\  },
        \\  "operators": [
        \\    {
        \\      "id": "copy-main",
        \\      "run": "knx.fs.copy",
        \\      "inputs": ["src/main.c"],
        \\      "outputs": ["kilnexus-out/app"]
        \\    }
        \\  ],
        \\  "outputs": [
        \\    { "source": "kilnexus-out/app", "publish_as": "app", "mode": "0755" }
        \\  ]
        \\}
    ;

    var spec = try parseBuildSpec(allocator, json);
    defer spec.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), spec.ops.len);
    switch (spec.ops[0]) {
        .fs_copy => |copy| {
            try std.testing.expectEqualStrings("src/main.c", copy.from_path);
            try std.testing.expectEqualStrings("kilnexus-out/app", copy.to_path);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "parseBuildSpec parses c.compile and zig.link operations" {
    const allocator = std.testing.allocator;
    const json =
        \\{
        \\  "version": 1,
        \\  "target": "x86_64-unknown-linux-musl",
        \\  "toolchain": {
        \\    "id": "zigcc-0.14.0",
        \\    "blob_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\    "tree_root": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        \\    "size": 1
        \\  },
        \\  "policy": {
        \\    "network": "off",
        \\    "clock": "fixed"
        \\  },
        \\  "env": {
        \\    "TZ": "UTC",
        \\    "LANG": "C",
        \\    "SOURCE_DATE_EPOCH": "1735689600"
        \\  },
        \\  "operators": [
        \\    {
        \\      "id": "compile-main",
        \\      "run": "knx.c.compile",
        \\      "inputs": ["src/main.c"],
        \\      "outputs": ["obj/main.o"],
        \\      "flags": ["-O2", "-std=c11"]
        \\    },
        \\    {
        \\      "id": "link-final",
        \\      "run": "knx.zig.link",
        \\      "inputs": ["obj/main.o"],
        \\      "outputs": ["kilnexus-out/app"],
        \\      "flags": ["-static"]
        \\    }
        \\  ],
        \\  "outputs": [
        \\    { "source": "kilnexus-out/app", "publish_as": "app", "mode": "0755" }
        \\  ]
        \\}
    ;

    var spec = try parseBuildSpec(allocator, json);
    defer spec.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 2), spec.ops.len);
    switch (spec.ops[0]) {
        .c_compile => |compile| {
            try std.testing.expectEqualStrings("src/main.c", compile.src_path);
            try std.testing.expectEqualStrings("obj/main.o", compile.out_path);
            try std.testing.expectEqual(@as(usize, 2), compile.args.len);
            try std.testing.expectEqualStrings("-O2", compile.args[0]);
            try std.testing.expectEqualStrings("-std=c11", compile.args[1]);
        },
        else => return error.TestUnexpectedResult,
    }
    switch (spec.ops[1]) {
        .zig_link => |link| {
            try std.testing.expectEqual(@as(usize, 1), link.object_paths.len);
            try std.testing.expectEqualStrings("obj/main.o", link.object_paths[0]);
            try std.testing.expectEqualStrings("kilnexus-out/app", link.out_path);
            try std.testing.expectEqual(@as(usize, 1), link.args.len);
            try std.testing.expectEqualStrings("-static", link.args[0]);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "parseBuildSpec rejects disallowed compile arg" {
    const allocator = std.testing.allocator;
    const json =
        \\{
        \\  "version": 1,
        \\  "target": "x86_64-unknown-linux-musl",
        \\  "toolchain": {
        \\    "id": "zigcc-0.14.0",
        \\    "blob_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\    "tree_root": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        \\    "size": 1
        \\  },
        \\  "policy": {
        \\    "network": "off",
        \\    "clock": "fixed"
        \\  },
        \\  "env": {
        \\    "TZ": "UTC",
        \\    "LANG": "C",
        \\    "SOURCE_DATE_EPOCH": "1735689600"
        \\  },
        \\  "operators": [
        \\    {
        \\      "id": "compile-main",
        \\      "run": "knx.c.compile",
        \\      "inputs": ["src/main.c"],
        \\      "outputs": ["obj/main.o"],
        \\      "flags": ["-fplugin=evil.so"]
        \\    }
        \\  ],
        \\  "outputs": [
        \\    { "source": "kilnexus-out/app", "publish_as": "app", "mode": "0755" }
        \\  ]
        \\}
    ;

    try std.testing.expectError(error.ValueInvalid, parseBuildSpec(allocator, json));
}

test "parseBuildSpec parses archive.pack operation" {
    const allocator = std.testing.allocator;
    const json =
        \\{
        \\  "version": 1,
        \\  "target": "x86_64-unknown-linux-musl",
        \\  "toolchain": {
        \\    "id": "zigcc-0.14.0",
        \\    "blob_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\    "tree_root": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        \\    "size": 1
        \\  },
        \\  "policy": {
        \\    "network": "off",
        \\    "clock": "fixed"
        \\  },
        \\  "env": {
        \\    "TZ": "UTC",
        \\    "LANG": "C",
        \\    "SOURCE_DATE_EPOCH": "1735689600"
        \\  },
        \\  "operators": [
        \\    {
        \\      "id": "pack-objects",
        \\      "run": "knx.archive.pack",
        \\      "inputs": ["obj/a.o", "obj/b.o"],
        \\      "outputs": ["kilnexus-out/objects.tar"]
        \\    }
        \\  ],
        \\  "outputs": [
        \\    { "source": "kilnexus-out/objects.tar", "publish_as": "objects.tar", "mode": "0644" }
        \\  ]
        \\}
    ;

    var spec = try parseBuildSpec(allocator, json);
    defer spec.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), spec.ops.len);
    switch (spec.ops[0]) {
        .archive_pack => |pack| {
            try std.testing.expectEqual(@as(usize, 2), pack.input_paths.len);
            try std.testing.expectEqualStrings("obj/a.o", pack.input_paths[0]);
            try std.testing.expectEqualStrings("obj/b.o", pack.input_paths[1]);
            try std.testing.expectEqualStrings("kilnexus-out/objects.tar", pack.out_path);
            try std.testing.expectEqual(ArchiveFormat.tar, pack.format);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "parseBuildSpec parses archive.pack tar.gz format" {
    const allocator = std.testing.allocator;
    const json =
        \\{
        \\  "version": 1,
        \\  "target": "x86_64-unknown-linux-musl",
        \\  "toolchain": {
        \\    "id": "zigcc-0.14.0",
        \\    "blob_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\    "tree_root": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        \\    "size": 1
        \\  },
        \\  "policy": {
        \\    "network": "off",
        \\    "clock": "fixed"
        \\  },
        \\  "env": {
        \\    "TZ": "UTC",
        \\    "LANG": "C",
        \\    "SOURCE_DATE_EPOCH": "1735689600"
        \\  },
        \\  "operators": [
        \\    {
        \\      "id": "pack-objects",
        \\      "run": "knx.archive.pack",
        \\      "inputs": ["obj/a.o"],
        \\      "outputs": ["kilnexus-out/objects.tar.gz"],
        \\      "format": "tar.gz"
        \\    }
        \\  ],
        \\  "outputs": [
        \\    { "source": "kilnexus-out/objects.tar.gz", "publish_as": "objects.tar.gz", "mode": "0644" }
        \\  ]
        \\}
    ;

    var spec = try parseBuildSpec(allocator, json);
    defer spec.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), spec.ops.len);
    switch (spec.ops[0]) {
        .archive_pack => |pack| {
            try std.testing.expectEqual(ArchiveFormat.tar_gz, pack.format);
            try std.testing.expectEqualStrings("kilnexus-out/objects.tar.gz", pack.out_path);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "validateBuildWriteIsolation rejects write into mounted input path" {
    const allocator = std.testing.allocator;

    var workspace_entries = try allocator.alloc(WorkspaceEntry, 1);
    workspace_entries[0] = .{
        .mount_path = try allocator.dupe(u8, "src/main.c"),
        .host_source = try allocator.dupe(u8, "project/src/main.c"),
    };
    var workspace_spec: WorkspaceSpec = .{ .entries = workspace_entries };
    defer workspace_spec.deinit(allocator);

    var build_ops = try allocator.alloc(BuildOp, 1);
    build_ops[0] = .{
        .c_compile = .{
            .src_path = try allocator.dupe(u8, "src/main.c"),
            .out_path = try allocator.dupe(u8, "src/main.c"),
            .args = try allocator.alloc([]u8, 0),
        },
    };
    var build_spec: BuildSpec = .{ .ops = build_ops };
    defer build_spec.deinit(allocator);

    try std.testing.expectError(error.ValueInvalid, validateBuildWriteIsolation(&workspace_spec, &build_spec));
}

test "validateBuildWriteIsolation allows write outside mounted input paths" {
    const allocator = std.testing.allocator;

    var workspace_entries = try allocator.alloc(WorkspaceEntry, 1);
    workspace_entries[0] = .{
        .mount_path = try allocator.dupe(u8, "src/main.c"),
        .host_source = try allocator.dupe(u8, "project/src/main.c"),
    };
    var workspace_spec: WorkspaceSpec = .{ .entries = workspace_entries };
    defer workspace_spec.deinit(allocator);

    var build_ops = try allocator.alloc(BuildOp, 1);
    build_ops[0] = .{
        .c_compile = .{
            .src_path = try allocator.dupe(u8, "src/main.c"),
            .out_path = try allocator.dupe(u8, "obj/main.o"),
            .args = try allocator.alloc([]u8, 0),
        },
    };
    var build_spec: BuildSpec = .{ .ops = build_ops };
    defer build_spec.deinit(allocator);

    try validateBuildWriteIsolation(&workspace_spec, &build_spec);
}

test "parseOutputSpec rejects legacy path output field" {
    const allocator = std.testing.allocator;
    const json =
        \\{
        \\  "version": 1,
        \\  "target": "x86_64-unknown-linux-musl",
        \\  "toolchain": {
        \\    "id": "zigcc-0.14.0",
        \\    "blob_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\    "tree_root": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        \\    "size": 1
        \\  },
        \\  "policy": {
        \\    "network": "off",
        \\    "clock": "fixed"
        \\  },
        \\  "env": {
        \\    "TZ": "UTC",
        \\    "LANG": "C",
        \\    "SOURCE_DATE_EPOCH": "1735689600"
        \\  },
        \\  "outputs": [
        \\    { "path": "kilnexus-out/app", "mode": "0755" }
        \\  ]
        \\}
    ;

    try std.testing.expectError(error.ValueInvalid, parseOutputSpec(allocator, json));
}

test "parseBuildSpec rejects simultaneous operators and build blocks" {
    const allocator = std.testing.allocator;
    const json =
        \\{
        \\  "version": 1,
        \\  "target": "x86_64-unknown-linux-musl",
        \\  "toolchain": {
        \\    "id": "zigcc-0.14.0",
        \\    "blob_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\    "tree_root": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        \\    "size": 1
        \\  },
        \\  "policy": {
        \\    "network": "off",
        \\    "clock": "fixed"
        \\  },
        \\  "env": {
        \\    "TZ": "UTC",
        \\    "LANG": "C",
        \\    "SOURCE_DATE_EPOCH": "1735689600"
        \\  },
        \\  "operators": [
        \\    {
        \\      "id": "compile-main",
        \\      "run": "knx.c.compile",
        \\      "inputs": ["src/main.c"],
        \\      "outputs": ["obj/main.o"],
        \\      "flags": ["-O2"]
        \\    }
        \\  ],
        \\  "build": [
        \\    { "op": "knx.fs.copy", "from": "src/main.c", "to": "obj/main.c" }
        \\  ],
        \\  "outputs": [
        \\    { "source": "kilnexus-out/app", "publish_as": "app", "mode": "0755" }
        \\  ]
        \\}
    ;

    try std.testing.expectError(error.LegacyBuildBlock, parseBuildSpec(allocator, json));
}

test "parseBuildSpec rejects duplicate operator ids" {
    const allocator = std.testing.allocator;
    const json =
        \\{
        \\  "version": 1,
        \\  "target": "x86_64-unknown-linux-musl",
        \\  "toolchain": {
        \\    "id": "zigcc-0.14.0",
        \\    "blob_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\    "tree_root": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        \\    "size": 1
        \\  },
        \\  "policy": {
        \\    "network": "off",
        \\    "clock": "fixed"
        \\  },
        \\  "env": {
        \\    "TZ": "UTC",
        \\    "LANG": "C",
        \\    "SOURCE_DATE_EPOCH": "1735689600"
        \\  },
        \\  "operators": [
        \\    {
        \\      "id": "dup-id",
        \\      "run": "knx.c.compile",
        \\      "inputs": ["src/a.c"],
        \\      "outputs": ["obj/a.o"],
        \\      "flags": ["-O2"]
        \\    },
        \\    {
        \\      "id": "dup-id",
        \\      "run": "knx.zig.link",
        \\      "inputs": ["obj/a.o"],
        \\      "outputs": ["kilnexus-out/app"],
        \\      "flags": ["-s"]
        \\    }
        \\  ],
        \\  "outputs": [
        \\    { "source": "kilnexus-out/app", "publish_as": "app", "mode": "0755" }
        \\  ]
        \\}
    ;

    try std.testing.expectError(error.InvalidBuildGraph, parseBuildSpec(allocator, json));
}

test "parseWorkspaceSpec rejects unknown workspace mount key" {
    const allocator = std.testing.allocator;
    const json =
        \\{
        \\  "version": 1,
        \\  "target": "x86_64-unknown-linux-musl",
        \\  "toolchain": {
        \\    "id": "zigcc-0.14.0",
        \\    "blob_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\    "tree_root": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        \\    "size": 1
        \\  },
        \\  "policy": {
        \\    "network": "off",
        \\    "clock": "fixed"
        \\  },
        \\  "env": {
        \\    "TZ": "UTC",
        \\    "LANG": "C",
        \\    "SOURCE_DATE_EPOCH": "1735689600"
        \\  },
        \\  "workspace": {
        \\    "mounts": [
        \\      {
        \\        "source": "local-src",
        \\        "target": "src",
        \\        "mode": "0444",
        \\        "readonly": true
        \\      }
        \\    ]
        \\  },
        \\  "outputs": [
        \\    { "source": "kilnexus-out/app", "publish_as": "app", "mode": "0755" }
        \\  ]
        \\}
    ;

    try std.testing.expectError(error.ValueInvalid, parseWorkspaceSpec(allocator, json));
}

test "parseBuildSpec rejects legacy build block" {
    const allocator = std.testing.allocator;
    const json =
        \\{
        \\  "version": 1,
        \\  "target": "x86_64-unknown-linux-musl",
        \\  "toolchain": {
        \\    "id": "zigcc-0.14.0",
        \\    "blob_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\    "tree_root": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        \\    "size": 1
        \\  },
        \\  "policy": {
        \\    "network": "off",
        \\    "clock": "fixed"
        \\  },
        \\  "env": {
        \\    "TZ": "UTC",
        \\    "LANG": "C",
        \\    "SOURCE_DATE_EPOCH": "1735689600"
        \\  },
        \\  "build": [
        \\    { "op": "knx.fs.copy", "from": "src/a", "to": "obj/a" }
        \\  ],
        \\  "outputs": [
        \\    { "source": "kilnexus-out/app", "publish_as": "app", "mode": "0755" }
        \\  ]
        \\}
    ;

    try std.testing.expectError(error.LegacyBuildBlock, parseBuildSpec(allocator, json));
}

test "validateCanonicalJson prioritizes legacy build block over other schema errors" {
    const allocator = std.testing.allocator;
    const json =
        \\{
        \\  "version": 1,
        \\  "target": "x86_64-unknown-linux-musl",
        \\  "toolchain": {
        \\    "id": "zigcc-0.14.0",
        \\    "blob_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\    "tree_root": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        \\    "size": 1
        \\  },
        \\  "policy": {
        \\    "network": "off",
        \\    "clock": "fixed"
        \\  },
        \\  "env": {
        \\    "TZ": "UTC",
        \\    "LANG": "C",
        \\    "SOURCE_DATE_EPOCH": "1735689600"
        \\  },
        \\  "build": [
        \\    { "op": "knx.fs.copy", "from": "src/a", "to": "obj/a" }
        \\  ],
        \\  "outputs": [
        \\    { "path": "kilnexus-out/app", "mode": "0755" }
        \\  ]
        \\}
    ;

    try std.testing.expectError(error.LegacyBuildBlock, validateCanonicalJson(allocator, json));
}

test "validateCanonicalJson rejects missing operators block" {
    const allocator = std.testing.allocator;
    const json =
        \\{
        \\  "version": 1,
        \\  "target": "x86_64-unknown-linux-musl",
        \\  "toolchain": {
        \\    "id": "zigcc-0.14.0",
        \\    "blob_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\    "tree_root": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        \\    "size": 1
        \\  },
        \\  "policy": {
        \\    "network": "off",
        \\    "clock": "fixed"
        \\  },
        \\  "env": {
        \\    "TZ": "UTC",
        \\    "LANG": "C",
        \\    "SOURCE_DATE_EPOCH": "1735689600"
        \\  },
        \\  "outputs": [
        \\    { "source": "kilnexus-out/app", "publish_as": "app", "mode": "0755" }
        \\  ]
        \\}
    ;

    try std.testing.expectError(error.MissingRequiredField, validateCanonicalJson(allocator, json));
}
