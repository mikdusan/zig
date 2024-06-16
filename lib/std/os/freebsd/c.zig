//! This file provides the C interface to FreeBSD, matching
//! those that are provided by system libc when libc is linked.
//!
//! The following abstractions are made:
//! * Match versioned symbols if they exist.
const std = @import("../../std.zig");
const builtin = @import("builtin");
const c = std.os.freebsd.c;
const sys = std.os.freebsd.sys;

pub extern "c" fn close(fd: c.fd_t) c_int;
pub extern "c" fn creat(path: [*:0]const u8, mode: c.mode_t) c.fd_t;

pub const getdents = if (sys.osintver < 12_000_000)
    struct {
        extern "c" fn @"getdents@FBSD_1.0"(fd: c.fd_t, buf: [*]u8, len: c_int) c_int;
    }.@"getdents@FBSD_1.0"
else
    struct {
        extern "c" fn getdents(fd: c.fd_t, buf: [*]u8, len: usize) isize;
    }.getdents;

pub extern "c" fn getegid() c.gid_t;
pub extern "c" fn geteuid() c.uid_t;
pub extern "c" fn getgid() c.gid_t;
pub extern "c" fn getpid() c.pid_t;
pub extern "c" fn getppid() c.pid_t;
pub extern "c" fn getuid() c.uid_t;
pub extern "c" fn mkdir(path: [*:0]const u8, mode: c.mode_t) c_int;
pub extern "c" fn mkdirat(fd: c.fd_t, path: [*:0]const u8, mode: c.mode_t) c_int;
pub extern "c" fn open(path: [*:0]const u8, flags: c.O, mode: c.mode_t) c.fd_t;
pub extern "c" fn openat(fd: c.fd_t, path: [*:0]const u8, flags: c.O, mode: c.mode_t) c.fd_t;
pub extern "c" fn read(fd: c.fd_t, buf: [*]u8, len: usize) isize;
pub extern "c" fn setegid(egid: c.gid_t) c_int;
pub extern "c" fn seteuid(euid: c.uid_t) c_int;
pub extern "c" fn setgid(gid: c.gid_t) c_int;
pub extern "c" fn setuid(uid: c.uid_t) c_int;
pub extern "c" fn write(fd: c.fd_t, buf: [*]const u8, len: usize) isize;

pub const errno = sys.errno;

pub const getdirentries = if (sys.osintver < 12_000_000)
    struct {
        extern "c" fn @"getdirentries@FBSD_1.0"(fd: c.fd_t, buf: [*]u8, len: usize, basep: ?*c.off_t) isize;
    }.@"getdirentries@FBSD_1.0"
else
    struct {
        extern "c" fn getdirentries(fd: sys.fd_t, buf: [*]u8, len: c_uint, basep: ?*c_long) c_int;
    }.getdirentries;

pub const AT = sys.AT;
pub const E = sys.E;
pub const O = sys.O;
pub const dirent_t = sys.dirent_t;
pub const fd_t = sys.fd_t;
pub const gid_t = sys.gid_t;
pub const ino_t = sys.ino_t;
pub const mode_t = sys.mode_t;
pub const off_t = sys.off_t;
pub const pid_t = sys.pid_t;
pub const uid_t = sys.uid_t;

const Feature = std.os.freebsd.Feature(@This());
pub const hasFeature = Feature.hasFeature;
pub const hasFeatures = Feature.hasFeatures;
pub const missing_feature = Feature.missing_feature;
