const std = @import("std");
const state_api = @import("state/api.zig");

pub const State = state_api.State;
pub const RunResult = state_api.RunResult;
pub const RunFailure = state_api.RunFailure;
pub const RunAttempt = state_api.RunAttempt;
pub const RunOptions = state_api.RunOptions;

pub const runFromPath = state_api.runFromPath;
pub const runFromPathWithOptions = state_api.runFromPathWithOptions;
pub const run = state_api.run;
pub const runWithOptions = state_api.runWithOptions;
pub const attemptRunFromPathWithOptions = state_api.attemptRunFromPathWithOptions;
pub const attemptRunWithOptions = state_api.attemptRunWithOptions;

comptime {
    _ = @import("state/tests_failures_a.zig");
    _ = @import("state/tests_failures_b.zig");
}

test "run completes bootstrap happy path" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("project/src");
    try tmp.dir.writeFile(.{
        .sub_path = "project/src/app",
        .data = "artifact\n",
    });

    const host_source = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/project/src/app", .{tmp.sub_path[0..]});
    defer allocator.free(host_source);
    const cache_root = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/cache", .{tmp.sub_path[0..]});
    defer allocator.free(cache_root);
    const output_root = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/final/kilnexus-out", .{tmp.sub_path[0..]});
    defer allocator.free(output_root);

    const source = try std.fmt.allocPrint(
        allocator,
        \\{{
        \\  "version": 1,
        \\  "target": "x86_64-unknown-linux-musl",
        \\  "toolchain": {{
        \\    "id": "zigcc-0.14.0",
        \\    "blob_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\    "tree_root": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        \\    "size": 1
        \\  }},
        \\  "policy": {{
        \\    "network": "off",
        \\    "clock": "fixed"
        \\  }},
        \\  "env": {{
        \\    "TZ": "UTC",
        \\    "LANG": "C",
        \\    "SOURCE_DATE_EPOCH": "1735689600"
        \\  }},
        \\  "inputs": [
        \\    {{ "path": "src/app", "source": "{s}" }}
        \\  ],
        \\  "operators": [
        \\    {{
        \\      "id": "copy-final",
        \\      "run": "knx.fs.copy",
        \\      "inputs": ["src/app"],
        \\      "outputs": ["kilnexus-out/app"]
        \\    }}
        \\  ],
        \\  "outputs": [
        \\    {{ "source": "kilnexus-out/app", "publish_as": "app", "mode": "0755" }}
        \\  ]
        \\}}
    ,
        .{host_source},
    );
    defer allocator.free(source);

    var result = try runWithOptions(allocator, source, .{
        .trust_metadata_dir = null,
        .trust_state_path = null,
        .cache_root = cache_root,
        .output_root = output_root,
    });
    defer result.deinit(allocator);

    try std.testing.expectEqual(State.done, result.final_state);
    try std.testing.expectEqual(@as(usize, 15), result.trace.items.len);
    try std.testing.expectEqual(State.parse_knxfile, result.trace.items[3]);
    try std.testing.expectEqual(State.done, result.trace.items[result.trace.items.len - 1]);
    try std.testing.expectEqual(@as(@TypeOf(result.verify_mode), .strict), result.verify_mode);
    try std.testing.expectEqual(@as(usize, 64), result.knx_digest_hex.len);
    try std.testing.expect(result.workspace_cwd.len > 0);

    const pointer_path = try std.fmt.allocPrint(allocator, "{s}.current", .{output_root});
    defer allocator.free(pointer_path);
    const pointer_raw = try std.fs.cwd().readFileAlloc(allocator, pointer_path, 2048);
    defer allocator.free(pointer_raw);
    const pointer_doc = try std.json.parseFromSlice(std.json.Value, allocator, pointer_raw, .{});
    defer pointer_doc.deinit();
    const pointer_obj = switch (pointer_doc.value) {
        .object => |obj| obj,
        else => return error.TestUnexpectedResult,
    };
    const pointer_knx = switch (pointer_obj.get("knx_digest") orelse return error.TestUnexpectedResult) {
        .string => |text| text,
        else => return error.TestUnexpectedResult,
    };
    const pointer_verify_mode = switch (pointer_obj.get("verify_mode") orelse return error.TestUnexpectedResult) {
        .string => |text| text,
        else => return error.TestUnexpectedResult,
    };
    const pointer_tree_root = switch (pointer_obj.get("toolchain_tree_root") orelse return error.TestUnexpectedResult) {
        .string => |text| text,
        else => return error.TestUnexpectedResult,
    };
    const pointer_release = switch (pointer_obj.get("release_rel") orelse return error.TestUnexpectedResult) {
        .string => |text| text,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expectEqualStrings(result.knx_digest_hex[0..], pointer_knx);
    try std.testing.expectEqualStrings("strict", pointer_verify_mode);
    try std.testing.expectEqualStrings("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", pointer_tree_root);

    const published = try std.fs.path.join(allocator, &.{ output_root, pointer_release, "app" });
    defer allocator.free(published);
    const bytes = try std.fs.cwd().readFileAlloc(allocator, published, 1024);
    defer allocator.free(bytes);
    try std.testing.expectEqualStrings("artifact\n", bytes);
}

test "run supports TOML operators DAG with local inputs and source/publish_as outputs" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("project/src");
    try tmp.dir.writeFile(.{
        .sub_path = "project/src/app.txt",
        .data = "toml-artifact\n",
    });
    try tmp.dir.writeFile(.{
        .sub_path = "project/src/skip.txt",
        .data = "skip\n",
    });

    const app_rel = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/project/src/app.txt", .{tmp.sub_path[0..]});
    defer allocator.free(app_rel);
    const include_pat = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/project/src/*.txt", .{tmp.sub_path[0..]});
    defer allocator.free(include_pat);
    const exclude_pat = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/project/src/skip*.txt", .{tmp.sub_path[0..]});
    defer allocator.free(exclude_pat);
    const cache_root = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/cache", .{tmp.sub_path[0..]});
    defer allocator.free(cache_root);
    const output_root = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/final/kilnexus-out", .{tmp.sub_path[0..]});
    defer allocator.free(output_root);

    const source = try std.fmt.allocPrint(
        allocator,
        \\#!knxfile
        \\
        \\version = 1
        \\target = "x86_64-unknown-linux-musl"
        \\
        \\[toolchain]
        \\id = "zigcc-0.14.0"
        \\blob_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        \\tree_root = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        \\size = 1
        \\
        \\[policy]
        \\network = "off"
        \\clock = "fixed"
        \\verify_mode = "strict"
        \\
        \\[env]
        \\TZ = "UTC"
        \\LANG = "C"
        \\SOURCE_DATE_EPOCH = "1735689600"
        \\
        \\[[inputs.local]]
        \\id = "local-src"
        \\include = ["{s}"]
        \\exclude = ["{s}"]
        \\
        \\[[workspace.mounts]]
        \\source = "local-src/{s}"
        \\target = "src/app.txt"
        \\mode = "0444"
        \\
        \\[[operators]]
        \\id = "copy-final"
        \\run = "knx.fs.copy"
        \\inputs = ["obj/app.txt"]
        \\outputs = ["kilnexus-out/app.txt"]
        \\
        \\[[operators]]
        \\id = "copy-obj"
        \\run = "knx.fs.copy"
        \\inputs = ["src/app.txt"]
        \\outputs = ["obj/app.txt"]
        \\
        \\[[outputs]]
        \\source = "kilnexus-out/app.txt"
        \\publish_as = "app.txt"
        \\mode = "0644"
    ,
        .{ include_pat, exclude_pat, app_rel },
    );
    defer allocator.free(source);

    var result = try runWithOptions(allocator, source, .{
        .trust_metadata_dir = null,
        .trust_state_path = null,
        .cache_root = cache_root,
        .output_root = output_root,
    });
    defer result.deinit(allocator);
    try std.testing.expectEqual(State.done, result.final_state);

    const pointer_path = try std.fmt.allocPrint(allocator, "{s}.current", .{output_root});
    defer allocator.free(pointer_path);
    const pointer_raw = try std.fs.cwd().readFileAlloc(allocator, pointer_path, 4096);
    defer allocator.free(pointer_raw);
    const pointer_doc = try std.json.parseFromSlice(std.json.Value, allocator, pointer_raw, .{});
    defer pointer_doc.deinit();
    const pointer_root = switch (pointer_doc.value) {
        .object => |obj| obj,
        else => return error.TestUnexpectedResult,
    };
    const build_id = switch (pointer_root.get("build_id") orelse return error.TestUnexpectedResult) {
        .string => |text| text,
        else => return error.TestUnexpectedResult,
    };
    const published = try std.fs.path.join(allocator, &.{ output_root, "releases", build_id, "app.txt" });
    defer allocator.free(published);
    const bytes = try std.fs.cwd().readFileAlloc(allocator, published, 1024);
    defer allocator.free(bytes);
    try std.testing.expectEqualStrings("toml-artifact\n", bytes);
}

test "run supports TOML operators object map style" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("project/src");
    try tmp.dir.writeFile(.{
        .sub_path = "project/src/app.txt",
        .data = "map-artifact\n",
    });

    const app_rel = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/project/src/app.txt", .{tmp.sub_path[0..]});
    defer allocator.free(app_rel);
    const include_pat = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/project/src/*.txt", .{tmp.sub_path[0..]});
    defer allocator.free(include_pat);
    const cache_root = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/cache", .{tmp.sub_path[0..]});
    defer allocator.free(cache_root);
    const output_root = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/final/kilnexus-out", .{tmp.sub_path[0..]});
    defer allocator.free(output_root);

    const source = try std.fmt.allocPrint(
        allocator,
        \\#!knxfile
        \\
        \\version = 1
        \\target = "x86_64-unknown-linux-musl"
        \\
        \\[toolchain]
        \\id = "zigcc-0.14.0"
        \\blob_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        \\tree_root = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        \\size = 1
        \\
        \\[policy]
        \\network = "off"
        \\clock = "fixed"
        \\verify_mode = "strict"
        \\
        \\[env]
        \\TZ = "UTC"
        \\LANG = "C"
        \\SOURCE_DATE_EPOCH = "1735689600"
        \\
        \\[[inputs.local]]
        \\id = "local-src"
        \\include = ["{s}"]
        \\
        \\[[workspace.mounts]]
        \\source = "local-src/{s}"
        \\target = "src/app.txt"
        \\mode = "0444"
        \\
        \\[operators.copy-final]
        \\run = "knx.fs.copy"
        \\inputs = ["obj/app.txt"]
        \\outputs = ["kilnexus-out/app.txt"]
        \\
        \\[operators.copy-obj]
        \\run = "knx.fs.copy"
        \\inputs = ["src/app.txt"]
        \\outputs = ["obj/app.txt"]
        \\
        \\[[outputs]]
        \\source = "kilnexus-out/app.txt"
        \\publish_as = "app.txt"
        \\mode = "0644"
    ,
        .{ include_pat, app_rel },
    );
    defer allocator.free(source);

    var result = try runWithOptions(allocator, source, .{
        .trust_metadata_dir = null,
        .trust_state_path = null,
        .cache_root = cache_root,
        .output_root = output_root,
    });
    defer result.deinit(allocator);
    try std.testing.expectEqual(State.done, result.final_state);

    const pointer_path = try std.fmt.allocPrint(allocator, "{s}.current", .{output_root});
    defer allocator.free(pointer_path);
    const pointer_raw = try std.fs.cwd().readFileAlloc(allocator, pointer_path, 4096);
    defer allocator.free(pointer_raw);
    const pointer_doc = try std.json.parseFromSlice(std.json.Value, allocator, pointer_raw, .{});
    defer pointer_doc.deinit();
    const pointer_root = switch (pointer_doc.value) {
        .object => |obj| obj,
        else => return error.TestUnexpectedResult,
    };
    const build_id = switch (pointer_root.get("build_id") orelse return error.TestUnexpectedResult) {
        .string => |text| text,
        else => return error.TestUnexpectedResult,
    };
    const published = try std.fs.path.join(allocator, &.{ output_root, "releases", build_id, "app.txt" });
    defer allocator.free(published);
    const bytes = try std.fs.cwd().readFileAlloc(allocator, published, 1024);
    defer allocator.free(bytes);
    try std.testing.expectEqualStrings("map-artifact\n", bytes);
}

test "run supports TOML remote input extraction and mount projection" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var tar_out: std.Io.Writer.Allocating = .init(allocator);
    defer tar_out.deinit();
    var tar_writer: std.tar.Writer = .{
        .underlying_writer = &tar_out.writer,
    };
    try tar_writer.writeFileBytes("pkg/remote.txt", "remote-run\n", .{});
    try tar_writer.finishPedantically();
    const tar_bytes = try tar_out.toOwnedSlice();
    defer allocator.free(tar_bytes);

    try tmp.dir.writeFile(.{
        .sub_path = "remote.tar",
        .data = tar_bytes,
    });

    const remote_rel = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/remote.tar", .{tmp.sub_path[0..]});
    defer allocator.free(remote_rel);
    const remote_url = try std.fmt.allocPrint(allocator, "file://{s}", .{remote_rel});
    defer allocator.free(remote_url);
    var remote_file = try std.fs.cwd().openFile(remote_rel, .{});
    defer remote_file.close();
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var buf: [4096]u8 = undefined;
    while (true) {
        const n = try remote_file.read(&buf);
        if (n == 0) break;
        hasher.update(buf[0..n]);
    }
    var remote_digest: [32]u8 = undefined;
    hasher.final(&remote_digest);
    const remote_hex = std.fmt.bytesToHex(remote_digest, .lower);
    try tmp.dir.makePath("expected/pkg");
    try tmp.dir.writeFile(.{
        .sub_path = "expected/pkg/remote.txt",
        .data = "remote-run\n",
    });
    const expected_tree_rel = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/expected", .{tmp.sub_path[0..]});
    defer allocator.free(expected_tree_rel);
    const remote_tree_hex = try @import("workspace_projector.zig").computeTreeRootHexForDir(allocator, expected_tree_rel);

    const cache_root = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/cache", .{tmp.sub_path[0..]});
    defer allocator.free(cache_root);
    const output_root = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/final/kilnexus-out", .{tmp.sub_path[0..]});
    defer allocator.free(output_root);

    const source = try std.fmt.allocPrint(
        allocator,
        \\#!knxfile
        \\
        \\version = 1
        \\target = "x86_64-unknown-linux-musl"
        \\
        \\[toolchain]
        \\id = "zigcc-0.14.0"
        \\blob_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        \\tree_root = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        \\size = 1
        \\
        \\[policy]
        \\network = "off"
        \\clock = "fixed"
        \\verify_mode = "strict"
        \\
        \\[env]
        \\TZ = "UTC"
        \\LANG = "C"
        \\SOURCE_DATE_EPOCH = "1735689600"
        \\
        \\[[inputs.remote]]
        \\id = "remote-src"
        \\url = "{s}"
        \\blob_sha256 = "{s}"
        \\tree_root = "{s}"
        \\extract = true
        \\
        \\[[workspace.mounts]]
        \\source = "remote-src/pkg/remote.txt"
        \\target = "src/remote.txt"
        \\mode = "0444"
        \\
        \\[[operators]]
        \\id = "copy-remote"
        \\run = "knx.fs.copy"
        \\inputs = ["src/remote.txt"]
        \\outputs = ["kilnexus-out/remote.txt"]
        \\
        \\[[outputs]]
        \\source = "kilnexus-out/remote.txt"
        \\publish_as = "remote.txt"
        \\mode = "0644"
    ,
        .{ remote_url, remote_hex[0..], remote_tree_hex[0..] },
    );
    defer allocator.free(source);

    var result = try runWithOptions(allocator, source, .{
        .trust_metadata_dir = null,
        .trust_state_path = null,
        .cache_root = cache_root,
        .output_root = output_root,
    });
    defer result.deinit(allocator);
    try std.testing.expectEqual(State.done, result.final_state);

    const pointer_path = try std.fmt.allocPrint(allocator, "{s}.current", .{output_root});
    defer allocator.free(pointer_path);
    const pointer_raw = try std.fs.cwd().readFileAlloc(allocator, pointer_path, 4096);
    defer allocator.free(pointer_raw);
    const pointer_doc = try std.json.parseFromSlice(std.json.Value, allocator, pointer_raw, .{});
    defer pointer_doc.deinit();
    const pointer_root = switch (pointer_doc.value) {
        .object => |obj| obj,
        else => return error.TestUnexpectedResult,
    };
    const build_id = switch (pointer_root.get("build_id") orelse return error.TestUnexpectedResult) {
        .string => |text| text,
        else => return error.TestUnexpectedResult,
    };
    const published = try std.fs.path.join(allocator, &.{ output_root, "releases", build_id, "remote.txt" });
    defer allocator.free(published);
    const bytes = try std.fs.cwd().readFileAlloc(allocator, published, 1024);
    defer allocator.free(bytes);
    try std.testing.expectEqualStrings("remote-run\n", bytes);
}

test "run publishes archive.pack output from workspace inputs" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("project/obj");
    try tmp.dir.writeFile(.{
        .sub_path = "project/obj/a.o",
        .data = "obj-a\n",
    });
    try tmp.dir.writeFile(.{
        .sub_path = "project/obj/b.o",
        .data = "obj-b\n",
    });

    const source_a = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/project/obj/a.o", .{tmp.sub_path[0..]});
    defer allocator.free(source_a);
    const source_b = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/project/obj/b.o", .{tmp.sub_path[0..]});
    defer allocator.free(source_b);
    const cache_root = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/cache", .{tmp.sub_path[0..]});
    defer allocator.free(cache_root);
    const output_root = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/final/kilnexus-out", .{tmp.sub_path[0..]});
    defer allocator.free(output_root);

    const source = try std.fmt.allocPrint(
        allocator,
        \\{{
        \\  "version": 1,
        \\  "target": "x86_64-unknown-linux-musl",
        \\  "toolchain": {{
        \\    "id": "zigcc-0.14.0",
        \\    "blob_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\    "tree_root": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        \\    "size": 1
        \\  }},
        \\  "policy": {{
        \\    "network": "off",
        \\    "clock": "fixed"
        \\  }},
        \\  "env": {{
        \\    "TZ": "UTC",
        \\    "LANG": "C",
        \\    "SOURCE_DATE_EPOCH": "1735689600"
        \\  }},
        \\  "inputs": [
        \\    {{ "path": "obj/a.o", "source": "{s}" }},
        \\    {{ "path": "obj/b.o", "source": "{s}" }}
        \\  ],
        \\  "operators": [
        \\    {{
        \\      "id": "pack-objects",
        \\      "run": "knx.archive.pack",
        \\      "inputs": ["obj/a.o", "obj/b.o"],
        \\      "outputs": ["kilnexus-out/objects.tar"]
        \\    }}
        \\  ],
        \\  "outputs": [
        \\    {{ "source": "kilnexus-out/objects.tar", "publish_as": "objects.tar", "mode": "0644" }}
        \\  ]
        \\}}
    ,
        .{ source_a, source_b },
    );
    defer allocator.free(source);

    var result = try runWithOptions(allocator, source, .{
        .trust_metadata_dir = null,
        .trust_state_path = null,
        .cache_root = cache_root,
        .output_root = output_root,
    });
    defer result.deinit(allocator);

    try std.testing.expectEqual(State.done, result.final_state);

    const pointer_path = try std.fmt.allocPrint(allocator, "{s}.current", .{output_root});
    defer allocator.free(pointer_path);
    const pointer_raw = try std.fs.cwd().readFileAlloc(allocator, pointer_path, 2048);
    defer allocator.free(pointer_raw);
    const pointer_doc = try std.json.parseFromSlice(std.json.Value, allocator, pointer_raw, .{});
    defer pointer_doc.deinit();
    const pointer_obj = switch (pointer_doc.value) {
        .object => |obj| obj,
        else => return error.TestUnexpectedResult,
    };
    const pointer_release = switch (pointer_obj.get("release_rel") orelse return error.TestUnexpectedResult) {
        .string => |text| text,
        else => return error.TestUnexpectedResult,
    };

    const archive_path = try std.fs.path.join(allocator, &.{ output_root, pointer_release, "objects.tar" });
    defer allocator.free(archive_path);
    var archive_file = try std.fs.cwd().openFile(archive_path, .{});
    defer archive_file.close();

    var read_buffer: [64 * 1024]u8 = undefined;
    var file_reader = archive_file.reader(&read_buffer);
    var file_name_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var link_name_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var it: std.tar.Iterator = .init(&file_reader.interface, .{
        .file_name_buffer = &file_name_buffer,
        .link_name_buffer = &link_name_buffer,
    });

    const entry1 = (try it.next()) orelse return error.TestUnexpectedResult;
    try std.testing.expect(entry1.kind == .file);
    try std.testing.expectEqualStrings("obj/a.o", entry1.name);
    const entry2 = (try it.next()) orelse return error.TestUnexpectedResult;
    try std.testing.expect(entry2.kind == .file);
    try std.testing.expectEqualStrings("obj/b.o", entry2.name);
}

test "run publishes archive.pack tar.gz output from workspace inputs" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("project/obj");
    try tmp.dir.writeFile(.{
        .sub_path = "project/obj/a.o",
        .data = "obj-a\n",
    });
    try tmp.dir.writeFile(.{
        .sub_path = "project/obj/b.o",
        .data = "obj-b\n",
    });

    const source_a = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/project/obj/a.o", .{tmp.sub_path[0..]});
    defer allocator.free(source_a);
    const source_b = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/project/obj/b.o", .{tmp.sub_path[0..]});
    defer allocator.free(source_b);
    const cache_root = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/cache", .{tmp.sub_path[0..]});
    defer allocator.free(cache_root);
    const output_root = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/final/kilnexus-out", .{tmp.sub_path[0..]});
    defer allocator.free(output_root);

    const source = try std.fmt.allocPrint(
        allocator,
        \\{{
        \\  "version": 1,
        \\  "target": "x86_64-unknown-linux-musl",
        \\  "toolchain": {{
        \\    "id": "zigcc-0.14.0",
        \\    "blob_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\    "tree_root": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        \\    "size": 1
        \\  }},
        \\  "policy": {{
        \\    "network": "off",
        \\    "clock": "fixed"
        \\  }},
        \\  "env": {{
        \\    "TZ": "UTC",
        \\    "LANG": "C",
        \\    "SOURCE_DATE_EPOCH": "1735689600"
        \\  }},
        \\  "inputs": [
        \\    {{ "path": "obj/a.o", "source": "{s}" }},
        \\    {{ "path": "obj/b.o", "source": "{s}" }}
        \\  ],
        \\  "operators": [
        \\    {{
        \\      "id": "pack-objects",
        \\      "run": "knx.archive.pack",
        \\      "inputs": ["obj/a.o", "obj/b.o"],
        \\      "outputs": ["kilnexus-out/objects.tar.gz"],
        \\      "format": "tar.gz"
        \\    }}
        \\  ],
        \\  "outputs": [
        \\    {{ "source": "kilnexus-out/objects.tar.gz", "publish_as": "objects.tar.gz", "mode": "0644" }}
        \\  ]
        \\}}
    ,
        .{ source_a, source_b },
    );
    defer allocator.free(source);

    var result = try runWithOptions(allocator, source, .{
        .trust_metadata_dir = null,
        .trust_state_path = null,
        .cache_root = cache_root,
        .output_root = output_root,
    });
    defer result.deinit(allocator);

    try std.testing.expectEqual(State.done, result.final_state);

    const pointer_path = try std.fmt.allocPrint(allocator, "{s}.current", .{output_root});
    defer allocator.free(pointer_path);
    const pointer_raw = try std.fs.cwd().readFileAlloc(allocator, pointer_path, 2048);
    defer allocator.free(pointer_raw);
    const pointer_doc = try std.json.parseFromSlice(std.json.Value, allocator, pointer_raw, .{});
    defer pointer_doc.deinit();
    const pointer_obj = switch (pointer_doc.value) {
        .object => |obj| obj,
        else => return error.TestUnexpectedResult,
    };
    const pointer_release = switch (pointer_obj.get("release_rel") orelse return error.TestUnexpectedResult) {
        .string => |text| text,
        else => return error.TestUnexpectedResult,
    };

    const archive_path = try std.fs.path.join(allocator, &.{ output_root, pointer_release, "objects.tar.gz" });
    defer allocator.free(archive_path);
    var archive_file = try std.fs.cwd().openFile(archive_path, .{});
    defer archive_file.close();

    var read_buffer: [64 * 1024]u8 = undefined;
    var file_reader = archive_file.reader(&read_buffer);
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var decompress = std.compress.flate.Decompress.init(&file_reader.interface, .gzip, &window);

    var file_name_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var link_name_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var it: std.tar.Iterator = .init(&decompress.reader, .{
        .file_name_buffer = &file_name_buffer,
        .link_name_buffer = &link_name_buffer,
    });

    const entry1 = (try it.next()) orelse return error.TestUnexpectedResult;
    try std.testing.expect(entry1.kind == .file);
    try std.testing.expectEqualStrings("obj/a.o", entry1.name);
    const entry2 = (try it.next()) orelse return error.TestUnexpectedResult;
    try std.testing.expect(entry2.kind == .file);
    try std.testing.expectEqualStrings("obj/b.o", entry2.name);
}
