//! This file provides the C interface to FreeBSD, matching
//! those that are provided by system libc when libc is linked.
//!
//! The following abstractions are made:
//! * Match versioned symbols if they exist.
const std = @import("../../std.zig");
const builtin = @import("builtin");
const c = std.os.freebsd.c;
const sys = std.os.freebsd.sys;

pub extern "c" fn clock_getres(clock_id: c.clockid_t, tp: *c.timespec_t) c_int;
pub extern "c" fn clock_gettime(clock_id: c.clockid_t, tp: *c.timespec_t) c_int;
pub extern "c" fn clock_nanosleep(clock_id: c.clockid_t, mode: c.timer_t, rqtp: *const c.timespec_t, rmtp: ?*c.timespec_t) c_int;
pub extern "c" fn clock_settime(clock_id: c.clockid_t, tp: *const c.timespec_t) c_int;
pub extern "c" fn close(fd: c.fd_t) c_int;
pub extern "c" fn closedir(dirp: *c.DIR) c_int;
pub extern "c" fn creat(path: [*:0]const u8, mode: c.mode_t) c.fd_t;
pub extern "c" fn dirfd(dirp: *c.DIR) c.fd_t;
pub extern "c" fn fdclosedir(dirp: *c.DIR) c.fd_t;
pub extern "c" fn fdopendir(fd: c.fd_t) ?*c.DIR;
pub extern "c" fn getegid() c.gid_t;
pub extern "c" fn geteuid() c.uid_t;
pub extern "c" fn getgid() c.gid_t;
pub extern "c" fn getpid() c.pid_t;
pub extern "c" fn getppid() c.pid_t;
pub extern "c" fn getpriority(which: c.priority_t.which_t, who: c.id_t) c_int;
pub extern "c" fn getrlimit(resource: c.rlimit_t.resource_t, rlp: *c.rlimit_t) c_int;
pub extern "c" fn getrusage(who: c.rusage_t.who_t, usage: *c.rusage_t) c_int;
pub extern "c" fn getuid() c.uid_t;
pub extern "c" fn mkdir(path: [*:0]const u8, mode: c.mode_t) c_int;
pub extern "c" fn mkdirat(fd: c.fd_t, path: [*:0]const u8, mode: c.mode_t) c_int;
pub extern "c" fn mkfifo(path: [*:0]const u8, mode: c.mode_t) c_int;
pub extern "c" fn mkfifoat(fd: c.fd_t, path: [*:0]const u8, mode: c.mode_t) c_int;
pub extern "c" fn nanosleep(rqtp: *const timespec_t, rmtp: ?*c.timespec_t) c_int;
pub extern "c" fn open(path: [*:0]const u8, flags: c.O, mode: c.mode_t) c.fd_t;
pub extern "c" fn openat(fd: c.fd_t, path: [*:0]const u8, flags: c.O, mode: c.mode_t) c.fd_t;
pub extern "c" fn opendir(filename: [*:0]const u8) ?*c.DIR;
pub extern "c" fn read(fd: c.fd_t, buf: [*]u8, len: usize) isize;
pub extern "c" fn readdir(dirp: *c.DIR) ?*c.dirent_t;
pub extern "c" fn rewinddir(dirp: *c.DIR) void;
pub extern "c" fn seekdir(dirp: *c.DIR, loc: c_long) void;
pub extern "c" fn setegid(egid: c.gid_t) c_int;
pub extern "c" fn seteuid(euid: c.uid_t) c_int;
pub extern "c" fn setgid(gid: c.gid_t) c_int;
pub extern "c" fn setpriority(which: c.priority_t.which_t, who: c.id_t, prio: c_int) c_int;
pub extern "c" fn setrlimit(resource: c.rlimit_t.resource_t, rlp: *const c.rlimit_t) c_int;
pub extern "c" fn setuid(uid: c.uid_t) c_int;
pub extern "c" fn telldir(dirp: *c.DIR) c_long;
pub extern "c" fn write(fd: c.fd_t, buf: [*]const u8, len: usize) isize;

pub const AT = sys.AT;
pub const DIR = opaque {};
pub const E = sys.E;
pub const O = sys.O;
pub const __error = sys.__error;
pub const clockid_t = sys.clockid_t;
pub const dirent_t = sys.dirent_t;
pub const errno = sys.errno;
pub const fd_t = sys.fd_t;
pub const gid_t = sys.gid_t;
pub const id_t = sys.id_t;
pub const ino_t = sys.ino_t;
pub const mode_t = sys.mode_t;
pub const nanosleep_mode_t = sys.nanosleep_mode_t;
pub const off_t = sys.off_t;
pub const pid_t = sys.pid_t;
pub const priority_t = sys.priority_t;
pub const rlimit_t = sys.rlimit_t;
pub const timer_t = sys.timer_t;
pub const timespec_t = sys.timespec_t;
pub const timeval_t = sys.timeval_t;
pub const uid_t = sys.uid_t;
pub const rusage_t = sys.rusage_t;

pub const clock_getcpuclockid = if (sys.osintver < 10_000_000)
    struct {
        extern "c" fn clock_getcpuclockid(pid: c.pid_t, clockid: *c.clockid_t) c_int;
    }.clock_getcpuclockid
else
    struct {
        extern "c" fn @"clock_getcpuclockid@FBSD_1.3"(pid: c.pid_t, clockid: *c.clockid_t) c_int;
    }.@"clock_getcpuclockid@FBSD_1.3";

pub const getdents = if (sys.osintver < 12_000_000)
    struct {
        extern "c" fn @"getdents@FBSD_1.0"(fd: c.fd_t, buf: [*]u8, len: c_int) c_int;
    }.@"getdents@FBSD_1.0"
else
    struct {
        extern "c" fn getdents(fd: c.fd_t, buf: [*]u8, len: usize) isize;
    }.getdents;

pub const getdirentries = if (sys.osintver < 12_000_000)
    struct {
        extern "c" fn @"getdirentries@FBSD_1.0"(fd: c.fd_t, buf: [*]u8, len: usize, basep: ?*c.off_t) isize;
    }.@"getdirentries@FBSD_1.0"
else
    struct {
        extern "c" fn getdirentries(fd: sys.fd_t, buf: [*]u8, len: c_uint, basep: ?*c_long) c_int;
    }.getdirentries;

const Feature = std.os.freebsd.Feature(@This());
pub const hasFeature = Feature.hasFeature;
pub const hasFeatures = Feature.hasFeatures;
pub const missing_feature = Feature.missing_feature;
