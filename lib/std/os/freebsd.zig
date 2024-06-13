const std = @import("../std.zig");
const builtin = @import("builtin");

pub const c = @import("freebsd/c.zig");
pub const sys = @import("freebsd/sys.zig");

comptime {
    if (builtin.is_test) {
        _ = c;
        _ = sys;
    }
}
