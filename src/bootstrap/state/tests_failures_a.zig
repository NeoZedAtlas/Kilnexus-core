const std = @import("std");
const kx_error = @import("../../errors/kx_error.zig");
const api = @import("api.zig");

const State = api.State;
const run = api.run;
const attemptRunWithOptions = api.attemptRunWithOptions;
const attemptRunFromPathWithOptions = api.attemptRunFromPathWithOptions;

test "run fails on malformed lockfile" {
    const allocator = std.testing.allocator;
    const source = "#!knxfile\nversion=1";

    try std.testing.expectError(error.MissingField, run(allocator, source));
}

test "run fails on policy violation" {
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
        \\    "network": "on",
        \\    "clock": "fixed",
        \\    "verify_mode": "strict"
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
    try std.testing.expectError(error.ValueInvalid, run(allocator, source));
}

test "attemptRunWithOptions returns structured parse error" {
    const allocator = std.testing.allocator;
    const source = "#!knxfile\nversion=1";

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
            try std.testing.expectEqual(State.parse_knxfile, failure.at);
            try std.testing.expectEqual(kx_error.Code.KX_PARSE_MISSING_FIELD, failure.code);
            try std.testing.expectEqual(error.MissingField, failure.cause);
        },
    }
}

test "attemptRunWithOptions rejects build writes into mounted input path" {
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
        \\    { "path": "src/main.c", "source": "project/src/main.c" }
        \\  ],
        \\  "operators": [
        \\    {
        \\      "id": "copy-into-mount",
        \\      "run": "knx.fs.copy",
        \\      "inputs": ["src/main.c"],
        \\      "outputs": ["src/main.c"]
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
            try std.testing.expectEqual(State.parse_knxfile, failure.at);
            try std.testing.expectEqual(kx_error.Code.KX_PARSE_VALUE_INVALID, failure.code);
            try std.testing.expectEqual(error.ValueInvalid, failure.cause);
        },
    }
}

test "attemptRunFromPathWithOptions returns canonical io cause for missing input" {
    const allocator = std.testing.allocator;
    const attempt = attemptRunFromPathWithOptions(allocator, "__knx_missing_input__.knx", .{
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
            try std.testing.expectEqual(State.init, failure.at);
            try std.testing.expectEqual(kx_error.Code.KX_IO_NOT_FOUND, failure.code);
            try std.testing.expectEqual(error.IoNotFound, failure.cause);
        },
    }
}
