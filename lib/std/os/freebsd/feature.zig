/// Check if a top-level decl exists in sys.
/// - absent decl returns false
/// - decl != `missing_feature` returns true
pub fn hasFeature(decl: @TypeOf(.EnumLiteral)) bool {
    comptime {
        const name = @tagName(decl);
        if (!@hasDecl(sys, name)) return false;
        const resolved = @field(sys, name);
        if (@TypeOf(resolved) != type) return true;
        if (resolved == sys.missing_feature) return false;
        return true;
    }
}

pub fn hasFeatures(decls: anytype) bool {
    comptime {
        for (decls) |d| if (!sys.hasFeature(d)) return false;
        return true;
    }
}

/// Value which represents a missing feature and is relied
/// upon by the `hasFeature*()` functions.
pub const missing_feature = opaque {};
