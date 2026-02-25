const std = @import("std");
const parse_errors = @import("../../parser/parse_errors.zig");

const model = @import("model.zig");
const validate_canonical = @import("validate_canonical.zig");
const parse_toolchain = @import("parse_toolchain.zig");
const parse_workspace = @import("parse_workspace.zig");
const parse_output = @import("parse_output.zig");
const parse_build = @import("parse_build.zig");
const validate_isolation = @import("validate_isolation.zig");
const digest = @import("digest.zig");
const strict_wrap = @import("strict_wrap.zig");

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

test "parseBuildSpec parses operators object map style" {
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
        \\  "operators": {
        \\    "copy-final": {
        \\      "run": "knx.fs.copy",
        \\      "inputs": ["obj/main.o"],
        \\      "outputs": ["kilnexus-out/app"]
        \\    },
        \\    "copy-obj": {
        \\      "run": "knx.fs.copy",
        \\      "inputs": ["src/main.c"],
        \\      "outputs": ["obj/main.o"]
        \\    }
        \\  },
        \\  "outputs": [
        \\    { "source": "kilnexus-out/app", "publish_as": "app", "mode": "0755" }
        \\  ]
        \\}
    ;

    var spec = try parseBuildSpec(allocator, json);
    defer spec.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 2), spec.ops.len);
    switch (spec.ops[0]) {
        .fs_copy => |copy| {
            try std.testing.expectEqualStrings("src/main.c", copy.from_path);
            try std.testing.expectEqualStrings("obj/main.o", copy.to_path);
        },
        else => return error.TestUnexpectedResult,
    }
    switch (spec.ops[1]) {
        .fs_copy => |copy| {
            try std.testing.expectEqualStrings("obj/main.o", copy.from_path);
            try std.testing.expectEqualStrings("kilnexus-out/app", copy.to_path);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "parseBuildSpec rejects id field inside operators object map style" {
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
        \\  "operators": {
        \\    "copy-main": {
        \\      "id": "copy-main",
        \\      "run": "knx.fs.copy",
        \\      "inputs": ["src/main.c"],
        \\      "outputs": ["kilnexus-out/app"]
        \\    }
        \\  },
        \\  "outputs": [
        \\    { "source": "kilnexus-out/app", "publish_as": "app", "mode": "0755" }
        \\  ]
        \\}
    ;

    try std.testing.expectError(error.ValueInvalid, parseBuildSpec(allocator, json));
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

test "validateCanonicalJson accepts operators object map style" {
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
        \\  "operators": {
        \\    "copy-main": {
        \\      "run": "knx.fs.copy",
        \\      "inputs": ["src/main.c"],
        \\      "outputs": ["kilnexus-out/app"]
        \\    }
        \\  },
        \\  "outputs": [
        \\    { "source": "kilnexus-out/app", "publish_as": "app", "mode": "0755" }
        \\  ]
        \\}
    ;

    _ = try validateCanonicalJson(allocator, json);
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
