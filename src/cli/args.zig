const command_selection = @import("args/command_selection.zig");
const parse_bootstrap = @import("args/parse_bootstrap.zig");
const parse_parse_only = @import("args/parse_parse_only.zig");
const common = @import("args/common.zig");

pub const selectCommand = command_selection.selectCommand;
pub const parseBootstrapCliArgs = parse_bootstrap.parseBootstrapCliArgs;
pub const parseParseOnlyCliArgs = parse_parse_only.parseParseOnlyCliArgs;
pub const validateKnxfileCliPath = common.validateKnxfileCliPath;

test {
    _ = command_selection;
    _ = parse_bootstrap;
    _ = parse_parse_only;
    _ = common;
}
