const command_selection = @import("args/command_selection.zig");
const parse_bootstrap = @import("args/parse_bootstrap.zig");
const parse_parse_only = @import("args/parse_parse_only.zig");
const parse_json_only = @import("args/parse_json_only.zig");
const parse_cache = @import("args/parse_cache.zig");
const parse_toolchain = @import("args/parse_toolchain.zig");
const parse_doctor = @import("args/parse_doctor.zig");
const parse_clean = @import("args/parse_clean.zig");
const common = @import("args/common.zig");

pub const selectCommand = command_selection.selectCommand;
pub const parseBootstrapCliArgs = parse_bootstrap.parseBootstrapCliArgs;
pub const parseParseOnlyCliArgs = parse_parse_only.parseParseOnlyCliArgs;
pub const parseJsonOnlyCliArgs = parse_json_only.parseJsonOnlyCliArgs;
pub const parseCacheCliArgs = parse_cache.parseCacheCliArgs;
pub const parseToolchainCliArgs = parse_toolchain.parseToolchainCliArgs;
pub const parseDoctorCliArgs = parse_doctor.parseDoctorCliArgs;
pub const parseCleanCliArgs = parse_clean.parseCleanCliArgs;
pub const validateKnxfileCliPath = common.validateKnxfileCliPath;

test {
    _ = command_selection;
    _ = parse_bootstrap;
    _ = parse_parse_only;
    _ = parse_json_only;
    _ = parse_cache;
    _ = parse_toolchain;
    _ = parse_doctor;
    _ = parse_clean;
    _ = common;
}
