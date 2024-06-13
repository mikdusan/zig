const std = @import("std.zig");

/// This models whether or not a feature is avaialble.
///
/// A feature can be any kind of decl and to qualify as available,
/// a decl must be defined, and must not be defined as `std.missing_feature`.
pub fn Feature(NS: type) type {
    return struct {
        /// Check if a top-level decl exists in a namespace.
        /// - absent decl returns false
        /// - decl != `std.missing_feature` returns true
        pub fn hasFeature(decl: @TypeOf(.EnumLiteral)) bool {
            comptime {
                const name = @tagName(decl);
                if (!@hasDecl(NS, name)) return false;
                const resolved = @field(NS, name);
                if (@TypeOf(resolved) != type) return true;
                return resolved != std.missing_feature;
            }
        }

        pub fn hasFeatures(decls: anytype) bool {
            comptime {
                for (decls) |d| if (!hasFeature(d)) return false;
                return true;
            }
        }
    };
}

/// Singleton value which represents a missing feature and is used by
/// implementations to mark missing features.
pub const missing_feature = opaque {};
