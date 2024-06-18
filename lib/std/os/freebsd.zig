const std = @import("../std.zig");
const builtin = @import("builtin");

pub const c = @import("freebsd/c.zig");
pub const sys = @import("freebsd/sys.zig");

/// Check if a top-level decl exists in a namespace.
/// - absent decl returns false
/// - otherwise return decl != `missing_feature`
pub fn Feature(NS: type) type {
    return struct {
        /// Check if a top-level decl exists in a namespace.
        /// - absent decl returns false
        /// - decl != `missing_feature` returns true
        pub fn hasFeature(decl: @TypeOf(.EnumLiteral)) bool {
            comptime {
                const name = @tagName(decl);
                if (!@hasDecl(NS, name)) return false;
                const resolved = @field(NS, name);
                if (@TypeOf(resolved) != type) return true;
                return resolved != missing_feature;
            }
        }

        pub fn hasFeatures(decls: anytype) bool {
            comptime {
                for (decls) |d| if (!hasFeature(d)) return false;
                return true;
            }
        }

        /// Value which represents a missing feature and is relied
        /// upon by the `hasFeature*()` functions.
        pub const missing_feature = opaque {};
    };
}

comptime {
    if (builtin.is_test) {
        _ = sys;
        _ = if (builtin.link_libc) c;
        _ = @import("freebsd/test.zig");
    }
}
