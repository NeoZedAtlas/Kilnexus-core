const common = @import("render/common.zig");
const validate_output = @import("render/validate_output.zig");
const plan_output = @import("render/plan_output.zig");
const build_output = @import("render/build_output.zig");
const current_pointer = @import("render/current_pointer.zig");

pub const printUsage = common.printUsage;
pub const printSimpleFailureHuman = common.printSimpleFailureHuman;
pub const printSimpleFailureJson = common.printSimpleFailureJson;

pub const printValidateHuman = validate_output.printValidateHuman;
pub const printValidateJson = validate_output.printValidateJson;

pub const printPlanHuman = plan_output.printPlanHuman;
pub const printPlanJson = plan_output.printPlanJson;

pub const printSuccessHuman = build_output.printSuccessHuman;
pub const printFailureHuman = build_output.printFailureHuman;
pub const printFailureJson = build_output.printFailureJson;
pub const buildFailureJsonLine = build_output.buildFailureJsonLine;
pub const printSuccessJson = build_output.printSuccessJson;

test {
    _ = common;
    _ = validate_output;
    _ = plan_output;
    _ = build_output;
    _ = current_pointer;
}
