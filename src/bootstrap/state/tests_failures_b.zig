const std = @import("std");
const kx_error = @import("../../errors/kx_error.zig");
const api = @import("api.zig");

const State = api.State;
const attemptRunWithOptions = api.attemptRunWithOptions;

test "attemptRunWithOptions fails at download when source file is missing" {
    const allocator = std.testing.allocator;
    const source =
        \\{
        \\  "version": 1,
        \\  "target": "x86_64-unknown-linux-musl",
        \\  "toolchain": {
        \\    "id": "zigcc-0.14.0",
        \\    "source": "file://__missing_blob__.bin",
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
        \\      "id": "copy-final",
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

    const attempt = attemptRunWithOptions(allocator, source, .{
        .trust_metadata_dir = null,
        .trust_state_path = null,
    });

    switch (attempt) {
        .success => |result| {
            var owned = result;
            defer owned.deinit(allocator);
            return error.ExpectedFailure;
        },
        .failure => |failure| {
            try std.testing.expectEqual(State.download_blob, failure.at);
            try std.testing.expectEqual(kx_error.Code.KX_IO_NOT_FOUND, failure.code);
            try std.testing.expect(failure.cause == .io);
            try std.testing.expectEqual(error.Unavailable, failure.cause.io);
        },
    }
}

test "attemptRunWithOptions fails in execute stage when declared source is missing" {
    const allocator = std.testing.allocator;
    const source =
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
        \\    { "path": "src/main.c", "source": "__missing_source__.c" }
        \\  ],
        \\  "operators": [
        \\    {
        \\      "id": "copy-final",
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

    const attempt = attemptRunWithOptions(allocator, source, .{
        .trust_metadata_dir = null,
        .trust_state_path = null,
    });

    switch (attempt) {
        .success => |result| {
            var owned = result;
            defer owned.deinit(allocator);
            return error.ExpectedFailure;
        },
        .failure => |failure| {
            try std.testing.expectEqual(State.execute_build_graph, failure.at);
            try std.testing.expectEqual(kx_error.Code.KX_IO_NOT_FOUND, failure.code);
            try std.testing.expect(failure.cause == .io);
            try std.testing.expectEqual(error.Unavailable, failure.cause.io);
        },
    }
}

test "attemptRunWithOptions maps missing toolchain for c.compile to build failure" {
    const allocator = std.testing.allocator;
    const source =
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
        \\      "outputs": ["obj/main.o"]
        \\    }
        \\  ],
        \\  "outputs": [
        \\    { "source": "kilnexus-out/app", "publish_as": "app", "mode": "0755" }
        \\  ]
        \\}
    ;

    const attempt = attemptRunWithOptions(allocator, source, .{
        .trust_metadata_dir = null,
        .trust_state_path = null,
    });

    switch (attempt) {
        .success => |result| {
            var owned = result;
            defer owned.deinit(allocator);
            return error.ExpectedFailure;
        },
        .failure => |failure| {
            try std.testing.expectEqual(State.execute_build_graph, failure.at);
            try std.testing.expectEqual(kx_error.Code.KX_BUILD_TOOLCHAIN_MISSING, failure.code);
            try std.testing.expect(failure.cause == .build);
            try std.testing.expectEqual(error.ToolchainMissing, failure.cause.build);
        },
    }
}

test "attemptRunWithOptions fails at verify_outputs on declared output sha mismatch" {
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
        \\    {{
        \\      "source": "kilnexus-out/app",
        \\      "publish_as": "app",
        \\      "mode": "0755",
        \\      "sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        \\    }}
        \\  ]
        \\}}
    ,
        .{host_source},
    );
    defer allocator.free(source);

    const attempt = attemptRunWithOptions(allocator, source, .{
        .trust_metadata_dir = null,
        .trust_state_path = null,
        .cache_root = cache_root,
        .output_root = output_root,
    });

    switch (attempt) {
        .success => |result| {
            var owned = result;
            defer owned.deinit(allocator);
            return error.ExpectedFailure;
        },
        .failure => |failure| {
            try std.testing.expectEqual(State.verify_outputs, failure.at);
            try std.testing.expectEqual(kx_error.Code.KX_PUBLISH_OUTPUT_HASH_MISMATCH, failure.code);
            try std.testing.expect(failure.cause == .publish);
            try std.testing.expectEqual(error.OutputHashMismatch, failure.cause.publish);
        },
    }
}
