//! This file provides the C interface to FreeBSD, matching
//! those that are provided by system libc when libc is linked.
//!
//! The following abstractions are made:
//! * Match versioned symbols if they exist.
const std = @import("../../std.zig");
const builtin = @import("builtin");
const c = std.os.freebsd.c;
const from_old_c = @import("../../c.zig");
const sys = std.os.freebsd.sys;

pub const versionCheck = from_old_c.versionCheck;

pub extern "c" fn abort() noreturn;
pub extern "c" fn clock_getres(clock_id: c.clockid_t, tp: *c.timespec_t) c_int;
pub extern "c" fn clock_gettime(clock_id: c.clockid_t, tp: *c.timespec_t) c_int;
pub extern "c" fn clock_nanosleep(clock_id: c.clockid_t, mode: c.timer_t, rqtp: *const c.timespec_t, rmtp: ?*c.timespec_t) c_int;
pub extern "c" fn clock_settime(clock_id: c.clockid_t, tp: *const c.timespec_t) c_int;
pub extern "c" fn close(fd: c.fd_t) c_int;
pub extern "c" fn closedir(dirp: *c.DIR) c_int;
pub extern "c" fn creat(path: [*:0]const u8, mode: c.mode_t) c.fd_t;
pub extern "c" fn dirfd(dirp: *c.DIR) c.fd_t;
pub extern "c" fn dl_iterate_phdr(callback: c.dl_iterate_phdr_callback, data: ?*anyopaque) c_int;
pub extern "c" fn exit(status: c_int) noreturn;
pub extern "c" fn fcntl(fd: c.fd_t, cmd: c_int, ...) c_int;
pub extern "c" fn fdclosedir(dirp: *c.DIR) c.fd_t;
pub extern "c" fn fdopendir(fd: c.fd_t) ?*c.DIR;
pub extern "c" fn fstat(fd: c.fd_t, info: *c.stat_t) c_int;
pub extern "c" fn fstatat(fd: c.fd_t, noalias path: [*:0]const u8, noalias info: *c.stat_t, flags: c.AT) c_int;
pub extern "c" fn futimens(fd: c.fd_t, times: *const [2]c.timespec_t) c_int;
pub extern "c" fn getcontext(ucp: *c.ucontext_t) c_int;
pub extern "c" fn getegid() c.gid_t;
pub extern "c" fn geteuid() c.uid_t;
pub extern "c" fn getgid() c.gid_t;
pub extern "c" fn getpid() c.pid_t;
pub extern "c" fn getppid() c.pid_t;
pub extern "c" fn getpriority(which: c.priority.which_t, who: c.id_t) c_int;
pub extern "c" fn getrandom(buf: [*]u8, len: usize, flags: c_int) isize;
pub extern "c" fn getrlimit(resource: c.rlimit_resource_t, rlp: *c.rlimit_t) c_int;
pub extern "c" fn getrusage(who: c.rusage_t.who_t, usage: *c.rusage_t) c_int;
pub extern "c" fn getuid() c.uid_t;
pub extern "c" fn kill(pid: c.pid_t, sig: c.SIG) c_int;
pub extern "c" fn killpg(pgrp: c.pid_t, sig: c.SIG) c_int;
pub extern "c" fn lstat(noalias path: [*:0]const u8, noalias info: *c.stat_t) c_int;
pub extern "c" fn mkdir(path: [*:0]const u8, mode: c.mode_t) c_int;
pub extern "c" fn mkdirat(fd: c.fd_t, path: [*:0]const u8, mode: c.mode_t) c_int;
pub extern "c" fn mkfifo(path: [*:0]const u8, mode: c.mode_t) c_int;
pub extern "c" fn mkfifoat(fd: c.fd_t, path: [*:0]const u8, mode: c.mode_t) c_int;
pub extern "c" fn mmap(addr: ?*align(c.PAGE_SIZE) anyopaque, len: usize, prot: c.PROT, flags: c.MAP, fd: c.fd_t, offset: c.off_t) *anyopaque;
pub extern "c" fn munmap(addr: ?*align(c.PAGE_SIZE) const anyopaque, len: usize) c_int;
pub extern "c" fn nanosleep(rqtp: *const timespec_t, rmtp: ?*c.timespec_t) c_int;
pub extern "c" fn open(path: [*:0]const u8, flags: c.O, mode: c.mode_t) c.fd_t;
pub extern "c" fn openat(fd: c.fd_t, path: [*:0]const u8, flags: c.O, mode: c.mode_t) c.fd_t;
pub extern "c" fn opendir(filename: [*:0]const u8) ?*c.DIR;
pub extern "c" fn raise(sig: c.SIG) c_int;
pub extern "c" fn read(fd: c.fd_t, buf: [*]u8, len: usize) isize;
pub extern "c" fn readdir(dirp: *c.DIR) ?*c.dirent_t;
pub extern "c" fn rewinddir(dirp: *c.DIR) void;
pub extern "c" fn sendfile(in: c.fd_t, out: c.fd_t, offset: c.off_t, nbytes: usize, hdtr: ?*c.sf_hdtr_t, sbytes: ?*c.off_t, flags: c_int) c_int;
pub extern "c" fn seekdir(dirp: *c.DIR, loc: c_long) void;
pub extern "c" fn setegid(egid: c.gid_t) c_int;
pub extern "c" fn seteuid(euid: c.uid_t) c_int;
pub extern "c" fn setgid(gid: c.gid_t) c_int;
pub extern "c" fn setpriority(which: c.priority.which_t, who: c.id_t, prio: c_int) c_int;
pub extern "c" fn setrlimit(resource: c.rlimit_resource_t, rlp: *const c.rlimit_t) c_int;
pub extern "c" fn setuid(uid: c.uid_t) c_int;
pub extern "c" fn sigaction(sig: c.SIG, noalias act: ?*const c.sigaction_t, noalias oact: ?*c.sigaction_t) c_int;
pub extern "c" fn stat(noalias path: [*:0]const u8, noalias info: *c.stat_t) c_int;
pub extern "c" fn symlink(target: [*:0]const u8, linkpath: [*:0]const u8) c_int;
pub extern "c" fn symlinkat(target: [*:0]const u8, fd: c.fd_t, linkpath: [*:0]const u8) c_int;
pub extern "c" fn telldir(dirp: *c.DIR) c_long;
pub extern "c" fn write(fd: c.fd_t, buf: [*]const u8, len: usize) isize;
pub extern "c" fn writev(fd: c.fd_t, iov: [*]const c.iovec_const_t, iovcnt: c_int) isize;

pub const AT = sys.AT;
pub const DIR = opaque {};
pub const E = sys.E;
pub const O = sys.O;
pub const MAP = sys.MAP;
pub const PAGE_SIZE = sys.PAGE_SIZE;
pub const PATH_MAX = sys.PATH_MAX;
pub const PROT = sys.PROT;
pub const SIG = sys.SIG;
pub const blkcnt_t = sys.blkcnt_t;
pub const blksize_t = sys.blksize_t;
pub const clockid_t = sys.clockid_t;
pub const default = sys.default;
pub const dev_t = sys.dev_t;
pub const dirent_t = sys.dirent_t;
pub const errno = sys.errno;
pub const errno_location = sys.errno_location;
pub const fd_t = sys.fd_t;
pub const fflags_t = sys.fflags_t;
pub const gid_t = sys.gid_t;
pub const id_t = sys.id_t;
pub const ino_t = sys.ino_t;
pub const mode_t = sys.mode_t;
pub const nanosleep_mode_t = sys.nanosleep_mode_t;
pub const nlink_t = sys.nlink_t;
pub const off_t = sys.off_t;
pub const pid_t = sys.pid_t;
pub const priority = sys.priority;
pub const pthread_t = sys.pthread_t;
pub const rlimit_resource_t = sys.rlimit_resource_t;
pub const rlimit_t = sys.rlimit_t;
pub const rusage_t = sys.rusage_t;
pub const sigaction_t = sys.sigaction_t;
pub const siginfo_t = sys.siginfo_t;
pub const sigset_t = sys.sigset_t;
pub const sigval_t = sys.sigval_t;
pub const stat_t = sys.stat_t;
pub const timer_t = sys.timer_t;
pub const timespec_t = sys.timespec_t;
pub const timeval_t = sys.timeval_t;
pub const uid_t = sys.uid_t;

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

const Feature = std.Feature(@This());
pub const hasFeature = Feature.hasFeature;
pub const hasFeatures = Feature.hasFeatures;

// TODO: mike: position

pub const dl_phdr_info_t = sys.dl_phdr_info_t;
pub const S = sys.S;
pub const STDIN_FILENO = sys.STDIN_FILENO;
pub const STDOUT_FILENO = sys.STDOUT_FILENO;
pub const STDERR_FILENO = sys.STDERR_FILENO;
pub const F = sys.F;
pub const ucontext_t = sys.ucontext_t;
pub const SA = sys.SA;
pub const dl_iterate_phdr_callback = *const fn(info: *c.dl_phdr_info_t, size: usize, data: ?*anyopaque) callconv(.C) c_int;
pub const sf_hdtr_t = sys.sf_hdtr_t;
pub const iovec_t = sys.iovec_t;
pub const iovec_const_t = sys.iovec_const_t;
pub const IOV_MAX = sys.IOV_MAX;
pub const CTL = sys.CTL;
pub const DT = sys.DT;
pub const T = sys.T;
pub const SEEK = sys.SEEK;

pub extern "c" fn ioctl(fd: c.fd_t, request: c_ulong, ...) c_int;
pub extern "c" fn rename(from: [*:0]const u8, to: [*:0]const u8) c_int;
pub extern "c" fn renameat(fromfd: c.fd_t, from: [*:0]const u8, tofd: c.fd_t, to: [*:0]const u8) c_int;
pub extern "c" fn lseek(fd: c.fd_t, offset: c.off_t, whence: c.SEEK) c.off_t;
pub extern "c" fn unlink(path: [*:0]const u8) c_int;
pub extern "c" fn unlinkat(dirfd: c.fd_t, path: [*:0]const u8, flags: c.AT) c_int;

pub extern "c" fn pread(fd: c.fd_t, buf: [*]u8, len: usize, offset: c.off_t) isize;
pub extern "c" fn preadv(fd: c.fd_t, iov: [*]const c.iovec_t, iovcnt: c_uint, offset: c.off_t) isize;
pub extern "c" fn pwrite(fd: c.fd_t, buf: [*]const u8, len: usize, offset: c.off_t) isize;
pub extern "c" fn pwritev(fd: c.fd_t, iov: [*]const c.iovec_const_t, iovcnt: c_int, offset: c.off_t) isize;

pub extern "c" fn sysctl(name: [*]const c_int, namelen: c_uint, oldp: ?*anyopaque, oldlenp: ?*usize, newp: ?*anyopaque, newlen: usize) c_int;
pub extern "c" fn sysctlbyname(name: [*:0]const u8, oldp: ?*anyopaque, oldlenp: ?*usize, newp: ?*anyopaque, newlen: usize) c_int;
pub extern "c" fn sysctlnametomib(name: [*:0]const u8, mibp: ?*c_int, sizep: ?*usize) c_int;

pub extern "c" fn pthread_attr_destroy(attr: *c.pthread_attr_t) c.E;
pub extern "c" fn pthread_attr_init(attr: *c.pthread_attr_t) c.E;
pub extern "c" fn pthread_attr_setguardsize(attr: *c.pthread_attr_t, guardsize: usize) c.E;
pub extern "c" fn pthread_attr_setstacksize(attr: *c.pthread_attr_t, stacksize: usize) c.E;
pub extern "c" fn pthread_get_name_np(thread: c.pthread_t, name: [*:0]u8, len: usize) void;
pub extern "c" fn pthread_getthreadid_np() c_int;
pub extern "c" fn pthread_join(thread: pthread_t, arg_return: ?*?*anyopaque) c.E;
pub extern "c" fn pthread_set_name_np(thread: c.pthread_t, name: [*:0]const u8) void;

pub extern "c" fn pthread_create(
    noalias thread: *c.pthread_t,
    noalias attr: ?*const c.pthread_attr_t,
    start_routine: *const fn (?*anyopaque) callconv(.C) ?*anyopaque,
    noalias arg: ?*anyopaque,
) c.E;

pub extern "c" fn pthread_atfork(
    prepare: ?*const fn () callconv(.C) void,
    parent: ?*const fn () callconv(.C) void,
    child: ?*const fn () callconv(.C) void,
) c_int;

pub const pthread_attr_t = extern struct {
    inner: ?*anyopaque = null,
};

pub const winsize = extern struct {
    row: u16 = 0,
    col: u16 = 0,
    xpixel: u16 = 0,
    ypixel: u16 = 0,
};

pub extern "c" var environ: [*:null]?[*:0]u8;

pub extern "c" fn realpath(noalias path: [*:0]const u8, noalias resolved_path: [*]u8) ?[*:0]u8;
pub extern "c" fn isatty(fd: c.fd_t) c_int;
pub extern "c" fn getenv(name: [*:0]const u8) ?[*:0]u8;

pub const _umtx_time = extern struct {
    _timeout: c.timespec_t,
    _flags: u32,
    _clockid: c.clockid_t,
};

pub extern "c" fn _umtx_op(obj: usize, op: c_int, val: c_ulong, uaddr: usize, uaddr2: usize) c_int;

pub const UMTX_OP = enum(c_int) {
    LOCK = 0,
    UNLOCK = 1,
    WAIT = 2,
    WAKE = 3,
    MUTEX_TRYLOCK = 4,
    MUTEX_LOCK = 5,
    MUTEX_UNLOCK = 6,
    SET_CEILING = 7,
    CV_WAIT = 8,
    CV_SIGNAL = 9,
    CV_BROADCAST = 10,
    WAIT_UINT = 11,
    RW_RDLOCK = 12,
    RW_WRLOCK = 13,
    RW_UNLOCK = 14,
    WAIT_UINT_PRIVATE = 15,
    WAKE_PRIVATE = 16,
    MUTEX_WAIT = 17,
    MUTEX_WAKE = 18, // deprecated
    SEM_WAIT = 19, // deprecated
    SEM_WAKE = 20, // deprecated
    NWAKE_PRIVATE = 31,
    MUTEX_WAKE2 = 22,
    SEM2_WAIT = 23,
    SEM2_WAKE = 24,
    SHM = 25,
    ROBUST_LISTS = 26,
};

pub extern "c" fn malloc(size: usize) ?*anyopaque;
pub extern "c" fn realloc(ptr: ?*anyopaque, size: usize) ?*anyopaque;
pub extern "c" fn free(ptr: ?*anyopaque) void;
