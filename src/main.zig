const app = @import("cli/app.zig");

pub fn main() !void {
    try app.runMain();
}

test {
    _ = @import("cli/app.zig");
}
