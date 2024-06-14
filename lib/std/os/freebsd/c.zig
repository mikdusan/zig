//! This file provides the C interface to FreeBSD matching
//! those that are provided by system libc when libc is linked.
const std = @import("../../std.zig");
const builtin = @import("builtin");
const c = std.os.freebsd.c;
const sys = std.os.freebsd.sys;

pub fn errno() c.E { return __error().*; }
extern "c" fn __error() *c.E;

pub extern "c" fn close(fd: c.fd_t) c_int;

pub extern "c" fn getpid() c.pid_t;
pub extern "c" fn getppid() c.pid_t;

pub extern "c" fn getuid() c.uid_t;
pub extern "c" fn geteuid() c.uid_t;

pub extern "c" fn getgid() c.gid_t;
pub extern "c" fn getegid() c.gid_t;

pub extern "c" fn mkdir(path: [*:0]const u8, mode: c.mode_t) c_int;
pub extern "c" fn mkdirat(fd: c.fd_t, path: [*:0]const u8, mode: c.mode_t) c_int;

pub extern "c" fn open(path: [*:0]const u8, flags: c.O, c.mode_t) c.fd_t;
pub extern "c" fn openat(fd: c.fd_t, path: [*:0]const u8, flags: c.O, c.mode_t) c.fd_t;

pub extern "c" fn setuid(uid: c.uid_t) c_int;
pub extern "c" fn seteuid(euid: c.uid_t) c_int;

pub extern "c" fn setgid(gid: c.gid_t) c_int;
pub extern "c" fn setegid(egid: c.gid_t) c_int;

pub const AT = sys.AT;
pub const E = sys.E;
pub const O = sys.O;
pub const fd_t = sys.fd_t;
pub const gid_t = sys.gid_t;
pub const mode_t = sys.mode_t;
pub const pid_t = sys.pid_t;
pub const uid_t = sys.uid_t;

/// Check if a top-level decl exists in sys.
/// - absent decl returns false
/// - decl != `missing_feature` returns true
pub fn hasFeature(decl: @TypeOf(.EnumLiteral)) bool {
    comptime {
        const name = @tagName(decl);
        if (!@hasDecl(c, name)) return false;
        const resolved = @field(c, name);
        if (@TypeOf(resolved) != type) return true;
        if (resolved == c.missing_feature) return false;
        return true;
    }
}

pub fn hasFeatures(decls: anytype) bool {
    comptime {
        for (decls) |d| if (!c.hasFeature(d)) return false;
        return true;
    }
}

/// Value which represents a missing feature and is relied
/// upon by the `hasFeature*()` functions.
pub const missing_feature = opaque {};
