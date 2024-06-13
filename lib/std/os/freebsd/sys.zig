//! This file provides the system interface to FreeBSD, matching
//! those that are provided by system libc, whether or not libc
//! is linked.
//!
//! The following abstractions are made:
//! * Work around kernel bugs and limitations.
//! * Implement syscalls in the same way that libc functions;
//!   e.g. `open` uses the `openat` call when available.
//! * Do not support POSIX thread cancellation.
const std = @import("../../std.zig");
const builtin = @import("builtin");
const sys = std.os.freebsd.sys;
const syscall = @import("sys/syscall.zig");

pub const SYS = syscall.SYS;

pub const syscall0_errno = syscall.syscall0_errno;
pub const syscall1_errno = syscall.syscall1_errno;
pub const syscall1_noerrno = syscall.syscall1_noerrno;
pub const syscall1_noreturn = syscall.syscall1_noreturn;
pub const syscall2_errno = syscall.syscall2_errno;
pub const syscall2_noerrno = syscall.syscall2_noerrno;
pub const syscall3_errno = syscall.syscall3_errno;
pub const syscall3_noerrno = syscall.syscall3_noerrno;
pub const syscall4_errno = syscall.syscall4_errno;
pub const syscall4_noerrno = syscall.syscall4_noerrno;
pub const syscall5_errno = syscall.syscall5_errno;
pub const syscall6_errno = syscall.syscall6_errno;
pub const syscall7_errno = syscall.syscall7_errno;

pub const Result = syscall.Result;

// compute os integer version
// MAJOR * 1_000_000 + MINOR * 1_000 + POINT
pub const osintver = b: {
    const sv = builtin.os.version_range.semver.min;
    break :b sv.major * 1_000_000 + sv.minor * 1_000 + sv.patch;
};

pub const errno_location = if (builtin.link_libc)
    struct {
        extern "c" fn __error() *sys.E;
    }.__error
else
    struct {
        fn errno_location() *sys.E {
            return &__errno_value;
        }
    }.errno_location;

threadlocal var __errno_value: sys.E = .SUCCESS;

pub fn errno() sys.E {
    return sys.errno_location().*;
}

pub fn abort() noreturn {
    // POSIX requires stdio buffers to be flushed on abort.
    // Our libc sys layer does not implement streams.

    // Don't block SIGABRT to give any handler a chance; we ignore
    // any errors -- ISO C doesn't allow abort to return anyway.
    var set: sys.sigset_t = undefined;
    set.fill();
    set.del(.ABRT);
    _ = sys.sigprocmask(.SETMASK, &set, null);
    _ = sys.raise(.ABRT);

    // If SIGABRT was ignored, or caught and the handler returns, do
    // it again, only harder.
    var act: sys.sigaction_t = undefined;
    act.handler.handler = sys.SIG.DFL;
    act.flags = 0;
    act.mask.fill();
    _ = sigaction(.ABRT, &act, null);
    _ = sys.sigprocmask(.SETMASK, &set, null);
    _ = sys.raise(.ABRT);
    sys.exit(1);
}

pub const close = if (@hasField(sys.SYS, "close"))
    struct {
        fn close(fd: sys.fd_t) c_int {
            const rv = sys.syscall1_errno(
                .close,
                @as(u32, @bitCast(fd)),
            );
            return @bitCast(@as(u32, @truncate(rv)));
        }
    }.close
else
    std.missing_feature;

pub const creat = if (sys.hasFeature(.openat))
    struct {
        fn creat(path: [*:0]const u8, mode: sys.mode_t) sys.fd_t {
            return sys.openat(sys.AT.FDCWD, path, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, mode);
        }
    }.creat
else if (sys.hasFeature(.open))
    struct {
        fn creat(path: [*:0]const u8, mode: sys.mode_t) sys.fd_t {
            return sys.open(path, .{ .WRONLY = true, .CREAT = true, .TRUNC = true }, mode);
        }
    }.creat
else
    std.missing_feature;

pub const clock_getcpuclockid = if (@hasField(sys.SYS, "clock_getcpuclockid2"))
    struct {
        fn clock_getcpuclockid(pid: sys.pid_t, clockid: *sys.clockid_t) c_int {
            const rv = sys.syscall3_noerrno(
                .clock_getcpuclockid2,
                @as(u32, @bitCast(pid)),
                @as(u32, @bitCast(@intFromEnum(sys.cpuclock_which_t.PID))),
                @intFromPtr(clockid),
            );
            return @bitCast(@as(u32, @truncate(rv)));
        }
    }.clock_getcpuclockid
else
    std.missing_feature;

pub const clock_getres = if (@hasField(sys.SYS, "clock_getres"))
    struct {
        fn clock_getres(clock_id: sys.clockid_t, tp: *sys.timespec_t) c_int {
            const rv = sys.syscall2_errno(
                .clock_getres,
                @as(u32, @bitCast(@intFromEnum(clock_id))),
                @intFromPtr(tp),
            );
            return @bitCast(@as(u32, @truncate(rv)));
        }
    }.clock_getres
else
    std.missing_feature;

pub const clock_gettime = if (@hasField(sys.SYS, "clock_gettime"))
    struct {
        fn clock_gettime(clock_id: sys.clockid_t, tp: *sys.timespec_t) c_int {
            const rv = sys.syscall2_errno(
                .clock_gettime,
                @as(u32, @bitCast(@intFromEnum(clock_id))),
                @intFromPtr(tp),
            );
            return @bitCast(@as(u32, @truncate(rv)));
        }
    }.clock_gettime
else
    std.missing_feature;

pub const clock_nanosleep = if (@hasField(sys.SYS, "clock_nanosleep"))
    struct {
        fn clock_nanosleep(clock_id: sys.clockid_t, mode: sys.timer_t, rqtp: *const sys.timespec_t, rmtp: ?*sys.timespec_t) c_int {
            const rv = sys.syscall4_noerrno(
                .clock_nanosleep,
                @as(u32, @bitCast(@intFromEnum(clock_id))),
                @as(u32, @bitCast(@intFromEnum(mode))),
                @intFromPtr(rqtp),
                @intFromPtr(rmtp),
            );
            return @bitCast(@as(u32, @truncate(rv)));
        }
    }.clock_nanosleep
else
    std.missing_feature;

pub const clock_settime = if (@hasField(sys.SYS, "clock_settime"))
    struct {
        fn clock_settime(clock_id: sys.clockid_t, tp: *const sys.timespec_t) c_int {
            const rv = sys.syscall2_errno(
                .clock_settime,
                @as(u32, @bitCast(@intFromEnum(clock_id))),
                @intFromPtr(tp),
            );
            return @bitCast(@as(u32, @truncate(rv)));
        }
    }.clock_settime
else
    std.missing_feature;

pub const exit = if (@hasField(sys.SYS, "exit"))
    struct {
        fn exit(status: c_int) noreturn {
            sys.syscall1_noreturn(.exit, @as(u32, @bitCast(status)));
        }
    }.exit
else
    std.missing_feature;

pub const fcntl = if (@hasField(sys.SYS, "fcntl"))
    struct {
        fn fcntl(fd: sys.fd_t, cmd: c_int, arg: usize) c_int {
            const rv = sys.syscall3_errno(
                .@"fstat@12",
                @as(u32, @bitCast(fd)),
                @as(u32, @bitCast(cmd)),
                arg,
            );
            return @bitCast(@as(u32, @truncate(rv)));
        }
    }.fcntl
else
    std.missing_feature;

pub const fstat = if (@hasField(sys.SYS, "fstat@12"))
    struct {
        fn fstat(fd: sys.fd_t, info: *sys.stat_t) c_int {
            const rv = sys.syscall2_errno(
                .@"fstat@12",
                @as(u32, @bitCast(fd)),
                @intFromPtr(info),
            );
            return @bitCast(@as(u32, @truncate(rv)));
        }
    }.fstat
else
    std.missing_feature;

pub const fstatat = if (@hasField(sys.SYS, "fstatat@12"))
    struct {
        fn fstatat(fd: sys.fd_t, noalias path: [*:0]const u8, noalias info: *sys.stat_t, flags: sys.AT) c_int {
            const rv = sys.syscall4_errno(
                .@"fstatat@12",
                @as(u32, @bitCast(fd)),
                @intFromPtr(path),
                @intFromPtr(info),
                @as(u32, @bitCast(flags)),
            );
            return @bitCast(@as(u32, @truncate(rv)));
        }
    }.fstatat
else
    std.missing_feature;

pub const futimens = if (@hasField(sys.SYS, "futimens"))
    struct {
        fn futimens(fd: sys.fd_t, times: *const [2]sys.timespec_t) c_int {
            const rv = sys.syscall2_errno(
                .futimens,
                @as(u32, @bitCast(fd)),
                @intFromPtr(times),
            );
            return @bitCast(@as(u32, @truncate(rv)));
        }
    }.futimens
else
    std.missing_feature;

pub const getcontext = if (@hasField(sys.SYS, "getcontext"))
    struct {
        fn getcontext(ucp: *sys.ucontext_t) c_int {
            const rv = sys.syscall1_errno(
                .getcontext,
                @intFromPtr(ucp),
            );
            return @bitCast(@as(u32, @truncate(rv)));
        }
    }.getcontext
else
    std.missing_feature;

pub const getdents = if (@hasField(sys.SYS, "getdirentries@12"))
    struct {
        fn getdents(fd: sys.fd_t, buf: [*]u8, len: usize) isize {
            return getdirentries(fd, buf, len, null);
        }
    }.getdents
else if (@hasField(sys.SYS, "getdents"))
    struct {
        fn getdents(fd: sys.fd_t, buf: [*]u8, len: usize) isize {
            const rv = sys.syscall3_errno(
                .getdents,
                @as(u32, @bitCast(fd)),
                @intFromPtr(buf),
                len,
            );
            return @bitCast(rv);
        }
    }.getdents
else
    std.missing_feature;

pub const getdirentries = if (@hasField(sys.SYS, "getdirentries@12"))
    struct {
        fn getdirentries(fd: sys.fd_t, buf: [*]u8, len: usize, basep: ?*sys.off_t) isize {
            const rv = sys.syscall4_errno(
                .@"getdirentries@12",
                @as(u32, @bitCast(fd)),
                @intFromPtr(buf),
                len,
                @intFromPtr(basep),
            );
            return @bitCast(rv);
        }
    }.getdirentries
else if (@hasField(sys.SYS, "getdirentries@2"))
    struct {
        fn getdirentries(fd: sys.fd_t, buf: [*]u8, len: c_uint, basep: ?*c_long) c_int {
            const rv = sys.syscall4_errno(
                .@"getdirentries@2",
                @as(u32, @bitCast(fd)),
                @intFromPtr(buf),
                len,
                @intFromPtr(basep),
            );
            return @bitCast(@as(u32, @truncate(rv)));
        }
    }.getdirentries
else if (@hasField(sys.SYS, "getdirentries@1"))
    struct {
        fn getdirentries(fd: sys.fd_t, buf: [*]u8, len: c_uint, basep: ?*c_long) c_int {
            const rv = sys.syscall4_errno(
                .@"getdirentries@1",
                @as(u32, @bitCast(fd)),
                @intFromPtr(buf),
                len,
                @intFromPtr(basep),
            );
            return @bitCast(@as(u32, @truncate(rv)));
        }
    }.getdirentries
else
    std.missing_feature;

pub const getegid = if (@hasField(sys.SYS, "getegid"))
    struct {
        fn getegid() sys.gid_t {
            const rv = sys.syscall0_errno(.getegid);
            return @truncate(rv);
        }
    }.getegid
else
    std.missing_feature;

pub const geteuid = if (@hasField(sys.SYS, "geteuid"))
    struct {
        fn geteuid() sys.uid_t {
            const rv = sys.syscall0_errno(.geteuid);
            return @truncate(rv);
        }
    }.geteuid
else
    std.missing_feature;

pub const getgid = if (@hasField(sys.SYS, "getgid"))
    struct {
        fn getgid() sys.gid_t {
            const rv = sys.syscall0_errno(.getgid);
            return @truncate(rv);
        }
    }.getgid
else
    std.missing_feature;

pub const getpid = if (@hasField(sys.SYS, "getpid"))
    struct {
        fn getpid() sys.pid_t {
            const rv = sys.syscall0_errno(.getpid);
            return @bitCast(@as(u32, @truncate(rv)));
        }
    }.getpid
else
    std.missing_feature;

pub const getppid = if (@hasField(sys.SYS, "getppid"))
    struct {
        fn getppid() sys.pid_t {
            const rv = sys.syscall0_errno(.getppid);
            return @bitCast(@as(u32, @truncate(rv)));
        }
    }.getppid
else
    std.missing_feature;

pub const getpriority = if (@hasField(sys.SYS, "getpriority"))
    struct {
        fn getpriority(which: sys.priority.which_t, who: sys.id_t) c_int {
            const rv = sys.syscall2_errno(
                .getpriority,
                @as(u32, @bitCast(@intFromEnum(which))),
                @as(u32, @bitCast(who)),
            );
            return @bitCast(@as(u32, @truncate(rv)));
        }
    }.getpriority
else
    sys.missing_eeature;

pub const getrlimit = if (@hasField(sys.SYS, "getrlimit@2"))
    struct {
        fn getrlimit(resource: sys.rlimit_resource_t, rlp: *sys.rlimit_t) c_int {
            const rv = sys.syscall2_errno(
                .@"getrlimit@2",
                @as(u32, @bitCast(@intFromEnum(resource))),
                @intFromPtr(rlp),
            );
            return @bitCast(@as(u32, @truncate(rv)));
        }
    }.getrlimit
else
    std.missing_feature;

pub const getrusage = if (@hasField(sys.SYS, "getrusage"))
    struct {
        fn getrusage(who: sys.rusage_t.who_t, usage: *sys.rusage_t) c_int {
            const rv = sys.syscall2_errno(
                .getrusage,
                @as(u32, @bitCast(@intFromEnum(who))),
                @intFromPtr(usage),
            );
            return @bitCast(@as(u32, @truncate(rv)));
        }
    }.getrusage
else
    std.missing_feature;

pub const getuid = if (@hasField(sys.SYS, "getuid"))
    struct {
        fn getuid() sys.uid_t {
            const rv = sys.syscall0_errno(.getuid);
            return @truncate(rv);
        }
    }.getuid
else
    std.missing_feature;

// TODO: mike
pub fn isatty(fd: sys.fd_t) c_int {
    _ = fd;
    return -1;
}

pub const lseek = if (@hasField(sys.SYS, "lseek@7"))
    struct {
        fn lseek(fd: sys.fd_t, offset: sys.off_t, whence: sys.SEEK) sys.off_t {
            const rv = sys.syscall3_errno(
                .@"lseek@7",
                @as(u32, @bitCast(fd)),
                @bitCast(offset),
                @as(u32, @bitCast(@intFromEnum(whence))),
            );
            return @bitCast(rv);
        }
    }.lseek
else
    std.missing_feature;

pub const lstat = if (sys.hasFeature(.fstatat))
    struct {
        fn lstat(noalias path: [*:0]const u8, noalias info: *sys.stat_t) c_int {
            return sys.fstatat(sys.AT.FDCWD, path, info, .{ .SYMLINK_NOFOLLOW = true });
        }
    }.lstat
else
    std.missing_feature;

pub const mkdir = if (@hasField(sys.SYS, "mkdir"))
    struct {
        fn mkdir(path: [*:0]const u8, mode: sys.mode_t) c_int {
            const rv = sys.syscall2_errno(
                .mkdir,
                @intFromPtr(path),
                @as(u16, @bitCast(mode)),
            );
            return @bitCast(@as(u32, @truncate(rv)));
        }
    }.mkdir
else
    std.missing_feature;

pub const mkdirat = if (@hasField(sys.SYS, "mkdirat"))
    struct {
        fn mkdirat(fd: sys.fd_t, path: [*:0]const u8, mode: sys.mode_t) c_int {
            const rv = sys.syscall3_errno(
                .mkdirat,
                @as(u32, @bitCast(fd)),
                @intFromPtr(path),
                @as(u16, @bitCast(mode)),
            );
            return @bitCast(@as(u32, @truncate(rv)));
        }
    }.mkdirat
else
    std.missing_feature;

pub const mkfifo = if (@hasField(sys.SYS, "mkfifo"))
    struct {
        fn mkfifo(path: [*:0]const u8, mode: sys.mode_t) c_int {
            const rv = sys.syscall2_errno(
                .mkfifo,
                @intFromPtr(path),
                @as(u16, @bitCast(mode)),
            );
            return @bitCast(@as(u32, @truncate(rv)));
        }
    }.mkfifo
else
    std.missing_feature;

pub const mkfifoat = if (@hasField(sys.SYS, "mkfifoat"))
    struct {
        fn mkfifoat(fd: sys.fd_t, path: [*:0]const u8, mode: sys.mode_t) c_int {
            const rv = sys.syscall3_errno(
                .mkfifoat,
                @as(u32, @bitCast(fd)),
                @intFromPtr(path),
                @as(u16, @bitCast(mode)),
            );
            return @bitCast(@as(u32, @truncate(rv)));
        }
    }.mkfifoat
else
    std.missing_feature;

pub const mmap = if (@hasField(sys.SYS, "mmap@7"))
    struct {
        fn mmap(addr: ?*align(sys.PAGE_SIZE) anyopaque, len: usize, prot: sys.PROT, flags: sys.MAP, fd: sys.fd_t, offset: sys.off_t) *anyopaque {
            const rv = sys.syscall6_errno(
                .@"mmap@7",
                @intFromPtr(addr),
                len,
                @as(u32, @bitCast(prot)),
                @as(u32, @bitCast(flags)),
                @as(u32, @bitCast(fd)),
                @bitCast(offset),
            );
            return @ptrFromInt(rv);
        }
    }.mmap
else
    std.missing_feature;

pub const munmap = if (@hasField(sys.SYS, "munmap"))
    struct {
        fn munmap(addr: ?*align(sys.PAGE_SIZE) const anyopaque, len: usize) c_int {
            const rv = sys.syscall2_errno(
                .munmap,
                @intFromPtr(addr),
                len,
            );
            return @bitCast(@as(u32, @truncate(rv)));
        }
    }.munmap
else
    std.missing_feature;

pub const nanosleep = if (@hasField(sys.SYS, "clock_nanosleep"))
    struct {
        fn nanosleep(rqtp: *const timespec_t, rmtp: ?*sys.timespec_t) c_int {
            const rv = sys.syscall4_noerrno(
                .clock_nanosleep,
                @as(u32, @bitCast(@intFromEnum(sys.clockid_t.REALTIME))),
                @as(u32, @bitCast(@intFromEnum(sys.timer_t.RELTIME))),
                @intFromPtr(rqtp),
                @intFromPtr(rmtp),
            );
            if (rv != 0) sys.errno_location().* = @enumFromInt(rv);
            return @bitCast(@as(u32, @truncate(rv)));
        }
    }.nanosleep
else if (@hasField(sys.SYS, "nanosleep"))
    struct {
        fn nanosleep(rqtp: *const timespec_t, rmtp: ?*sys.timespec_t) c_int {
            const rv = sys.syscall2_errno(
                .nanosleep,
                @intFromPtr(rqtp),
                @intFromPtr(rmtp),
            );
            return @bitCast(@as(u32, @truncate(rv)));
        }
    }.nanosleep
else
    std.missing_feature;

pub const open = if (sys.hasFeature(.openat))
    struct {
        fn open(path: [*:0]const u8, flags: sys.O, mode: sys.mode_t) sys.fd_t {
            return sys.openat(sys.AT.FDCWD, path, flags, mode);
        }
    }.open
else if (@hasField(sys.SYS, "open"))
    struct {
        fn open(path: [*:0]const u8, flags: sys.O, mode: sys.mode_t) sys.fd_t {
            const rv = sys.syscall3_errno(
                .open,
                @intFromPtr(path),
                @as(u32, @bitCast(flags)),
                @as(u16, @bitCast(mode)),
            );
            return @bitCast(@as(u32, @truncate(rv)));
        }
    }.open
else
    std.missing_feature;

pub const openat = if (@hasField(sys.SYS, "openat"))
    struct {
        fn openat(fd: sys.fd_t, path: [*:0]const u8, flags: sys.O, mode: sys.mode_t) sys.fd_t {
            const rv = sys.syscall4_errno(
                .openat,
                @as(u32, @bitCast(fd)),
                @intFromPtr(path),
                @as(u32, @bitCast(flags)),
                @as(u16, @bitCast(mode)),
            );
            return @bitCast(@as(u32, @truncate(rv)));
        }
    }.openat
else
    std.missing_feature;

pub const pread = if (@hasField(sys.SYS, "pread@7"))
    struct {
        fn pread(fd: sys.fd_t, buf: [*]u8, len: usize, offset: sys.off_t) isize {
            const rv = sys.syscall4_errno(
                .@"pread@7",
                @as(u32, @bitCast(fd)),
                @intFromPtr(buf),
                len,
                @bitCast(offset),
            );
            return @bitCast(rv);
        }
    }.pread
else
    std.missing_feature;

pub const raise = if (sys.hasFeatures(.{ .thr_self, .thr_kill }))
    struct {
        fn raise(sig: sys.SIG) c_int {
            var id: c_long = undefined;
            if (sys.thr_self(&id) == -1) return -1;
            return sys.thr_kill(id, sig);
        }
    }.raise
else
    std.missing_feature;

pub const read = if (@hasField(sys.SYS, "read"))
    struct {
        fn read(fd: sys.fd_t, buf: [*]u8, len: usize) isize {
            const rv = sys.syscall3_errno(
                .read,
                @as(u32, @bitCast(fd)),
                @intFromPtr(buf),
                len,
            );
            return @bitCast(rv);
        }
    }.read
else
    std.missing_feature;

pub const renameat = if (@hasField(sys.SYS, "renameat"))
    struct {
        fn renameat(fromfd: sys.fd_t, from: [*:0]const u8, tofd: sys.fd_t, to: [*:0]const u8) c_int {
            const rv = sys.syscall4_errno(
                .unlinkat,
                @as(u32, @bitCast(fromfd)),
                @intFromPtr(from),
                @as(u32, @bitCast(tofd)),
                @intFromPtr(to),
            );
            return @bitCast(@as(u32, @truncate(rv)));
        }
    }.renameat
else
    std.missing_feature;

pub const rmdir = if (sys.hasFeature(.unlinkat))
    struct {
        fn rmdir(path: [*:0]const u8) c_int {
            return sys.unlinkat(sys.AT.FDCWD, path, .{ .REMOVEDIR = true }); 
        }
    }.rmdir
else
    std.missing_feature;

pub const sendfile = if (@hasField(sys.SYS, "sendfile@4"))
    struct {
        fn sendfile(in: sys.fd_t, out: sys.fd_t, offset: sys.off_t, nbytes: usize, hdtr: ?*sys.sf_hdtr_t, sbytes: ?*sys.off_t, flags: c_int) c_int {
            const rv = sys.syscall7_errno(
                .@"sendfile@4",
                @as(u32, @bitCast(in)),
                @as(u32, @bitCast(out)),
                @bitCast(offset),
                nbytes,
                @intFromPtr(hdtr),
                @intFromPtr(sbytes),
                @as(u32, @bitCast(flags)),
            );
            return @bitCast(@as(u32, @truncate(rv)));
        }
    }.sendfile
else
    std.missing_feature;

pub const setegid = if (@hasField(sys.SYS, "setegid"))
    struct {
        fn setegid(gid: sys.gid_t) c_int {
            const rv = sys.syscall1_errno(.setegid, gid);
            return @bitCast(@as(u32, @truncate(rv)));
        }
    }.setegid
else
    std.missing_feature;

pub const seteuid = if (@hasField(sys.SYS, "seteuid"))
    struct {
        fn seteuid(uid: sys.uid_t) c_int {
            const rv = sys.syscall1_errno(.seteuid, uid);
            return @bitCast(@as(u32, @truncate(rv)));
        }
    }.seteuid
else
    std.missing_feature;

pub const setgid = if (@hasField(sys.SYS, "setgid"))
    struct {
        fn setgid(gid: sys.gid_t) c_int {
            const rv = sys.syscall1_errno(.setgid, gid);
            return @bitCast(@as(u32, @truncate(rv)));
        }
    }.setgid
else
    std.missing_feature;

pub const setpriority = if (@hasField(sys.SYS, "setpriority"))
    struct {
        fn setpriority(which: sys.priority.which_t, who: sys.id_t, prio: c_int) c_int {
            const rv = sys.syscall3_errno(
                .setpriority,
                @as(u32, @bitCast(@intFromEnum(which))),
                @as(u32, @bitCast(who)),
                @as(u32, @bitCast(prio)),
            );
            return @bitCast(@as(u32, @truncate(rv)));
        }
    }.setpriority
else
    sys.missing_eeature;

pub const setrlimit = if (@hasField(sys.SYS, "setrlimit@2"))
    struct {
        fn setrlimit(resource: sys.rlimit_resource_t, rlp: *const sys.rlimit_t) c_int {
            const rv = sys.syscall2_errno(
                .@"setrlimit@2",
                @as(u32, @bitCast(@intFromEnum(resource))),
                @intFromPtr(rlp),
            );
            return @bitCast(@as(u32, @truncate(rv)));
        }
    }.setrlimit
else
    std.missing_feature;

pub const setuid = if (@hasField(sys.SYS, "setuid"))
    struct {
        fn setuid(uid: sys.uid_t) c_int {
            const rv = sys.syscall1_errno(.setuid, uid);
            return @bitCast(@as(u32, @truncate(rv)));
        }
    }.setuid
else
    std.missing_feature;

pub const sigaction = if (@hasField(sys.SYS, "sigaction@5"))
    struct {
        fn sigaction(sig: sys.SIG, noalias act: ?*const sys.sigaction_t, noalias oact: ?*sys.sigaction_t) c_int {
            const rv = sys.syscall3_errno(
                .@"sigaction@5",
                @as(u32, @bitCast(@intFromEnum(sig))),
                @intFromPtr(act),
                @intFromPtr(oact),
            );
            return @bitCast(@as(u32, @truncate(rv)));
        }
    }.sigaction
else
    std.missing_feature;

pub const sigprocmask = if (@hasField(sys.SYS, "sigprocmask@4"))
    struct {
        fn sigprocmask(how: sys.sigpm_how_t, noalias set: ?*const sys.sigset_t, noalias oset: ?*sys.sigset_t) c_int {
            const rv = sys.syscall3_errno(
                .@"sigprocmask@4",
                @as(u32, @bitCast(@intFromEnum(how))),
                @intFromPtr(set),
                @intFromPtr(oset),
            );
            return @bitCast(@as(u32, @truncate(rv)));
        }
    }.sigprocmask
else
    std.missing_feature;

pub const stat = if (sys.hasFeature(.fstatat))
    struct {
        fn stat(noalias path: [*:0]const u8, noalias info: *sys.stat_t) c_int {
            return sys.fstatat(sys.AT.FDCWD, path, info, .{});
        }
    }.stat
else
    std.missing_feature;

pub const symlink = if (@hasField(sys.SYS, "symlink"))
    struct {
        fn symlink(target: [*:0]const u8, linkpath: [*:0]const u8) c_int {
            const rv = sys.syscall2_errno(
                .symlink,
                @intFromPtr(target),
                @intFromPtr(linkpath),
            );
            return @bitCast(@as(u32, @truncate(rv)));
        }
    }.symlink
else
    std.missing_feature;

pub const symlinkat = if (@hasField(sys.SYS, "symlinkat"))
    struct {
        fn symlinkat(target: [*:0]const u8, fd: sys.fd_t, linkpath: [*:0]const u8) c_int {
            const rv = sys.syscall3_errno(
                .symlinkat,
                @intFromPtr(target),
                @as(u32, @bitCast(fd)),
                @intFromPtr(linkpath),
            );
            return @bitCast(@as(u32, @truncate(rv)));
        }
    }.symlinkat
else
    std.missing_feature;

pub const sysctl = if (@hasField(sys.SYS, "__sysctl"))
    struct {
        fn sysctl(name: [*]const c_int, namelen: c_uint, oldp: ?*anyopaque, oldlenp: ?*usize, newp: ?*anyopaque, newlen: usize) c_int {
            const rv = sys.syscall6_errno(
                .__sysctl,
                @intFromPtr(name),
                @as(u32, @bitCast(namelen)),
                @intFromPtr(oldp),
                @intFromPtr(oldlenp),
                @intFromPtr(newp),
                newlen,
            );
            return @bitCast(@as(u32, @truncate(rv)));
        }
    }.sysctl
else
    std.missing_feature;

pub const thr_kill = if (@hasField(sys.SYS, "thr_kill"))
    struct {
        fn thr_kill(id: c_long, sig: sys.SIG) c_int {
            const rv = sys.syscall2_errno(
                .thr_kill,
                @bitCast(id),
                @as(u32, @bitCast(@intFromEnum(sig))),
            );
            return @bitCast(@as(u32, @truncate(rv)));
        }
    }.thr_kill
else
    std.missing_feature;

pub const thr_self = if (@hasField(sys.SYS, "thr_self"))
    struct {
        fn thr_self(id: *c_long) c_int {
            const rv = sys.syscall1_errno(
                .thr_self,
                @intFromPtr(id),
            );
            return @bitCast(@as(u32, @truncate(rv)));
        }
    }.thr_self
else
    std.missing_feature;

pub const unlink = if (sys.hasFeature(.unlinkat))
    struct {
        fn unlink(path: [*:0]const u8) c_int {
            return sys.unlinkat(sys.AT.FDCWD, path, .{}); 
        }
    }.unlink
else
    std.missing_feature;

pub const unlinkat = if (@hasField(sys.SYS, "unlinkat"))
    struct {
        fn unlinkat(fd: sys.fd_t, path: [*:0]const u8, flags: sys.AT) c_int {
            const rv = sys.syscall3_errno(
                .unlinkat,
                @as(u32, @bitCast(fd)),
                @intFromPtr(path),
                @as(u32, @bitCast(flags)),
            );
            return @bitCast(@as(u32, @truncate(rv)));
        }
    }.unlinkat
else
    std.missing_feature;

pub const umtx_op = if (@hasField(sys.SYS, "_umtx_op"))
    struct {
        fn umtx_op(obj: usize, op: sys.umtx_op_t, val: usize, uaddr: usize, uaddr2: usize) c_int {
            const rv = sys.syscall5_errno(
                ._umtx_op,
                obj,
                @as(u32, @bitCast(@intFromEnum(op))),
                val,
                uaddr,
                uaddr2,
            );
            return @bitCast(@as(u32, @truncate(rv)));
        }
    }.umtx_op
else
    std.missing_feature;

pub const write = if (@hasField(sys.SYS, "write"))
    struct {
        fn write(fd: sys.fd_t, buf: [*]const u8, len: usize) isize {
            const rv = sys.syscall3_errno(
                .write,
                @as(u32, @bitCast(fd)),
                @intFromPtr(buf),
                len,
            );
            return @bitCast(rv);
        }
    }.write
else
    std.missing_feature;

pub const writev = if (@hasField(sys.SYS, "writev"))
    struct {
        fn writev(fd: sys.fd_t, iov: [*]const sys.iovec_const_t, iovcnt: c_int) isize {
            const rv = sys.syscall3_errno(
                .writev,
                @as(u32, @bitCast(fd)),
                @intFromPtr(iov),
                @as(u32, @bitCast(iovcnt)),
            );
            return @bitCast(rv);
        }
    }.writev
else
    std.missing_feature;

pub const IOV_MAX = 1024;

pub const HOST_NAME_MAX = 255;
pub const NAME_MAX = 255;
pub const PAGE_SIZE = 4096;
pub const PATH_MAX = 1024;

pub const STDIN_FILENO = 0;
pub const STDOUT_FILENO = 1;
pub const STDERR_FILENO = 2;

pub const blkcnt_t = i64;
pub const blksize_t = i32;
pub const clock_t = if (@sizeOf(usize) == 8) i32 else c_ulong;
pub const dev_t = u64;
pub const fd_t = c_int;
pub const fflags_t = u32;
pub const gid_t = u32;
pub const id_t = c_int;
pub const ino_t = u64;
pub const mode_t = u16;
pub const nlink_t = u64;
pub const off_t = i64;
pub const pthread_t = *opaque {};
pub const pid_t = i32;
pub const rlimit_value_t = i64;
pub const suseconds_t = c_long;
pub const time_t = if (@sizeOf(usize) == 8) i64 else i32;
pub const uid_t = u32;

pub const AT = packed struct(u32) {
    // zig fmt: off
    _1: u8 = 0,
    EACCESS:          bool = false,
    SYMLINK_NOFOLLOW: bool = false,
    SYMLINK_FOLLOW:   bool = false,
    REMOVEDIR:        bool = false,
    _13: u1 = 0,
    RESOLVE_BENEATH:  bool = false,
    EMPTY_PATH:       bool = false,
    _16: u17 = 0,
    // zig fmt: on

    pub const FDCWD: sys.fd_t = -100;
};

pub const E = enum(c_int) {
    // zig fmt: off
    SUCCESS        =  0,
    PERM           =  1, // Operation not permitted
    NOENT          =  2, // No such file or directory
    SRCH           =  3, // No such process
    INTR           =  4, // Interrupted system call
    IO             =  5, // Input/output error
    NXIO           =  6, // Device not configured
    @"2BIG"        =  7, // Argument list too long
    NOEXEC         =  8, // Exec format error
    BADF           =  9, // Bad file descriptor
    CHILD          = 10, // No child processes
    DEADLK         = 11, // Resource deadlock avoided
    NOMEM          = 12, // Cannot allocate memory
    ACCES          = 13, // Permission denied
    FAULT          = 14, // Bad address
    NOTBLK         = 15, // Block device required
    BUSY           = 16, // Device busy
    EXIST          = 17, // File exists
    XDEV           = 18, // Cross-device link
    NODEV          = 19, // Operation not supported by device
    NOTDIR         = 20, // Not a directory
    ISDIR          = 21, // Is a directory
    INVAL          = 22, // Invalid argument
    NFILE          = 23, // Too many open files in system
    MFILE          = 24, // Too many open files
    NOTTY          = 25, // Inappropriate ioctl for device
    TXTBSY         = 26, // Text file busy
    FBIG           = 27, // File too large
    NOSPC          = 28, // No space left on device
    SPIPE          = 29, // Illegal seek
    ROFS           = 30, // Read-only filesystem
    MLINK          = 31, // Too many links
    PIPE           = 32, // Broken pipe
    DOM            = 33, // Numerical argument out of domain
    RANGE          = 34, // Result too large
    AGAIN          = 35, // Resource temporarily unavailable
    INPROGRESS     = 36, // Operation now in progress
    ALREADY        = 37, // Operation already in progress
    NOTSOCK        = 38, // Socket operation on non-socket
    DESTADDRREQ    = 39, // Destination address required
    MSGSIZE        = 40, // Message too long
    PROTOTYPE      = 41, // Protocol wrong type for socket
    NOPROTOOPT     = 42, // Protocol not available
    PROTONOSUPPORT = 43, // Protocol not supported
    SOCKTNOSUPPORT = 44, // Socket type not supported
    OPNOTSUPP      = 45, // Operation not supported
    PFNOSUPPORT    = 46, // Protocol family not supported
    AFNOSUPPORT    = 47, // Address family not supported by protocol family
    ADDRINUSE      = 48, // Address already in use
    ADDRNOTAVAIL   = 49, // Can't assign requested address
    NETDOWN        = 50, // Network is down
    NETUNREACH     = 51, // Network is unreachable
    NETRESET       = 52, // Network dropped connection on reset
    CONNABORTED    = 53, // Software caused connection abort
    CONNRESET      = 54, // Connection reset by peer
    NOBUFS         = 55, // No buffer space available
    ISCONN         = 56, // Socket is already connected
    NOTCONN        = 57, // Socket is not connected
    SHUTDOWN       = 58, // Can't send after socket shutdown
    TOOMANYREFS    = 59, // Too many references: can't splice
    TIMEDOUT       = 60, // Operation timed out
    CONNREFUSED    = 61, // Connection refused
    LOOP           = 62, // Too many levels of symbolic links
    NAMETOOLONG    = 63, // File name too long
    HOSTDOWN       = 64, // Host is down
    HOSTUNREACH    = 65, // No route to host
    NOTEMPTY       = 66, // Directory not empty
    PROCLIM        = 67, // Too many processes
    USERS          = 68, // Too many users
    DQUOT          = 69, // Disc quota exceeded
    STALE          = 70, // Stale NFS file handle
    REMOTE         = 71, // Too many levels of remote in path
    BADRPC         = 72, // RPC struct is bad
    RPCMISMATCH    = 73, // RPC version wrong
    PROGUNAVAIL    = 74, // RPC prog. not avail
    PROGMISMATCH   = 75, // Program version wrong
    PROCUNAVAIL    = 76, // Bad procedure for program
    NOLCK          = 77, // No locks available
    NOSYS          = 78, // Function not implemented
    FTYPE          = 79, // Inappropriate file type or format
    AUTH           = 80, // Authentication error
    NEEDAUTH       = 81, // Need authenticator
    IDRM           = 82, // Identifier removed
    NOMSG          = 83, // No message of desired type
    OVERFLOW       = 84, // Value too large to be stored in data type
    CANCELED       = 85, // Operation canceled
    ILSEQ          = 86, // Illegal byte sequence
    NOATTR         = 87, // Attribute not found
    DOOFUS         = 88, // Programming error
    BADMSG         = 89, // Bad message
    MULTIHOP       = 90, // Multihop attempted
    NOLINK         = 91, // Link has been severed
    PROTO          = 92, // Protocol error
    NOTCAPABLE     = 93, // Capabilities insufficient
    CAPMODE        = 94, // Not permitted in capability mode
    NOTRECOVERABLE = 95, // State not recoverable
    OWNERDEAD      = 96, // Previous owner died
    INTEGRITY      = 97, // Integrity check failed
    _,
    // zig fmt: on

    pub const WOULDBLOCK = E.AGAIN;
    pub const ENOTSUP = E.OPNOTSUPP;
};

pub const F = struct {
    /// Duplicate file descriptor.
    pub const DUPFD = 0;
    /// Get file descriptor flags.
    pub const GETFD = 1;
    /// Set file descriptor flags.
    pub const SETFD = 2;
    /// Get file status flags.
    pub const GETFL = 3;
    /// Set file status flags.
    pub const SETFL = 4;

    /// Get SIGIO/SIGURG proc/pgrrp.
    pub const GETOWN = 5;
    /// Set SIGIO/SIGURG proc/pgrrp.
    pub const SETOWN = 6;

    /// Get record locking information.
    pub const GETLK = 11;
    /// Set record locking information.
    pub const SETLK = 12;
    /// Set record locking information and wait if blocked.
    pub const SETLKW = 13;

    /// Debugging support for remote locks.
    pub const SETLK_REMOTE = 14;
    /// Read ahead.
    pub const READAHEAD = 15;

    /// DUPFD with FD_CLOEXEC set.
    pub const DUPFD_CLOEXEC = 17;
    /// DUP2FD with FD_CLOEXEC set.
    pub const DUP2FD_CLOEXEC = 18;

    pub const ADD_SEALS = 19;
    pub const GET_SEALS = 20;
    /// Return `kinfo_file` for a file descriptor.
    pub const KINFO = 22;

    // Seals (ADD_SEALS, GET_SEALS)
    /// Prevent adding sealings.
    pub const SEAL_SEAL = 0x0001;
    /// May not shrink
    pub const SEAL_SHRINK = 0x0002;
    /// May not grow.
    pub const SEAL_GROW = 0x0004;
    /// May not write.
    pub const SEAL_WRITE = 0x0008;

    // Record locking flags (GETLK, SETLK, SETLKW).
    /// Shared or read lock.
    pub const RDLCK = 1;
    /// Unlock.
    pub const UNLCK = 2;
    /// Exclusive or write lock.
    pub const WRLCK = 3;
    /// Purge locks for a given system ID.
    pub const UNLCKSYS = 4;
    /// Cancel an async lock request.
    pub const CANCEL = 5;

    pub const SETOWN_EX = 15;
    pub const GETOWN_EX = 16;

    pub const GETOWNER_UIDS = 17;
};

pub const MAP = packed struct(u32) {
    // zig fmt: off
    TYPE: enum(u4) {
        UNSPECIFIED = 0,
        SHARED      = 1, // share changes
        PRIVATE     = 2, // changes are private
    } = .UNSPECIFIED,
    FIXED:          bool = false, // map addr must be exactly as requested
    _6: u4 = 0,
    HASSEMAPHORE:   bool = false, // region may contain semaphores
    STACK:          bool = false, // region grows down, like a stack
    NOSYNC:         bool = false, // page to but do not sync underlying file
    ANONYMOUS:      bool = false, // allocated from memory, swap space
    GUARD:          bool = false, // reserve but don't map address range
    EXCL:           bool = false, // for MAP_FIXED, fail if address is used
    _16: u2 = 0,
    NOCORE:         bool = false, // dont include these pages in a coredump
    PREFAULT_READ:  bool = false, // prefault mapping for reading
    @"32BIT":       bool = false, // map in the low 2GB of address space
    _21: u4 = 0,
    ALIGNED_SUPER:  bool = false, // align on a superpage
    _26: u7 = 0,
    // zig fmt: on

    pub const FAILED: *anyopaque = @ptrFromInt(@as(usize, @bitCast(@as(isize, -1))));
};

pub const O = packed struct(u32) {
    // zig fmt: off
    ACCMODE: accmode_t = .RDONLY,
    NONBLOCK:        bool = false, // no delay
    APPEND:          bool = false, // set append mode
    SHLOCK:          bool = false, // open with shared file lock
    EXLOCK:          bool = false, // open with exclusive file lock
    ASYNC:           bool = false, // signal pgrp when data ready
    SYNC:            bool = false, // synchronous writes
    NOFOLLOW:        bool = false, // don't follow symlinks
    CREAT:           bool = false, // create if nonexistent
    TRUNC:           bool = false, // truncate to zero length
    EXCL:            bool = false, // error if already exists
    _13: u3 = 0,
    NOCTTY:          bool = false, // don't assign controlling terminal
    DIRECT:          bool = false, // attempt to bypass buffer cache
    DIRECTORY:       bool = false, // fail if not directory
    EXEC:            bool = false, // open for execute only
    TTY_INIT:        bool = false, // restore default termios attributes
    CLOEXEC:         bool = false, // set FD_CLOEXEC upon open
    VERIFY:          bool = false, // open only after verification
    PATH:            bool = false, // record only the target path in the opened descriptor
    RESOLVE_BENEATH: bool = false, // do not allow name resolution to walk out of cwd
    DSYNC:           bool = false, // POSIX data sync
    EMPTY_PATH:      bool = false, // openat, open file referenced by fd if path is empty
    _27: u6 = 0,

    pub const accmode_t = enum(u2) {
        RDONLY = 0, // open for reading only
        WRONLY = 1, // open for writing only
        RDWR = 2,   // open for reading and writing
    };
    // zig fmt: on
};

pub const PROT = packed struct(u32) {
    // zig fmt: off
    READ:  bool = false, // pages can be read
    WRITE: bool = false, // pages can be written
    EXEC:  bool = false, // pages can be executed
    _4: u29 = 0,
    // zig fmt: on
};

pub const S = struct {
    pub const IFMT = 0o170000;

    pub const IFIFO = 0o010000;
    pub const IFCHR = 0o020000;
    pub const IFDIR = 0o040000;
    pub const IFBLK = 0o060000;
    pub const IFREG = 0o100000;
    pub const IFLNK = 0o120000;
    pub const IFSOCK = 0o140000;
    pub const IFWHT = 0o160000;

    pub const ISUID = 0o4000;
    pub const ISGID = 0o2000;
    pub const ISVTX = 0o1000;
    pub const IRWXU = 0o700;
    pub const IRUSR = 0o400;
    pub const IWUSR = 0o200;
    pub const IXUSR = 0o100;
    pub const IRWXG = 0o070;
    pub const IRGRP = 0o040;
    pub const IWGRP = 0o020;
    pub const IXGRP = 0o010;
    pub const IRWXO = 0o007;
    pub const IROTH = 0o004;
    pub const IWOTH = 0o002;
    pub const IXOTH = 0o001;

    pub fn ISFIFO(m: u32) bool {
        return m & IFMT == IFIFO;
    }

    pub fn ISCHR(m: u32) bool {
        return m & IFMT == IFCHR;
    }

    pub fn ISDIR(m: u32) bool {
        return m & IFMT == IFDIR;
    }

    pub fn ISBLK(m: u32) bool {
        return m & IFMT == IFBLK;
    }

    pub fn ISREG(m: u32) bool {
        return m & IFMT == IFREG;
    }

    pub fn ISLNK(m: u32) bool {
        return m & IFMT == IFLNK;
    }

    pub fn ISSOCK(m: u32) bool {
        return m & IFMT == IFSOCK;
    }

    pub fn IWHT(m: u32) bool {
        return m & IFMT == IFWHT;
    }
};

pub const SA = struct {
    // zig fmt: off
    pub const ONSTACK   = 0x0001; // take signal on signal stack
    pub const RESTART   = 0x0002; // restart system call on signal return
    pub const RESETHAND = 0x0004; // reset to SIG_DFL when taking signal
    pub const NOCLDSTOP = 0x0008; // do not generate SIGCHLD on child stop
    pub const NODEFER   = 0x0010; // don't mask the signal we're delivering
    pub const NOCLDWAIT = 0x0020; // don't keep zombies around
    pub const SIGINFO   = 0x0040; // signal handler with SA_SIGINFO args
    // zig fmt: on
};

pub const SIG = enum(c_int) {
    // zig fmt: off
    HUP    =  1, // hangup
    INT    =  2, // interrupt
    QUIT   =  3, // quit
    ILL    =  4, // illegal instr. (not reset when caught)
    TRAP   =  5, // trace trap (not reset when caught)
    ABRT   =  6, // abort()
    EMT    =  7, // EMT instruction
    FPE    =  8, // floating point exception
    KILL   =  9, // kill (cannot be caught or ignored)
    BUS    = 10, // bus error
    SEGV   = 11, // segmentation violation
    SYS    = 12, // non-existent system call invoked
    PIPE   = 13, // write on a pipe with no one to read it
    ALRM   = 14, // alarm clock
    TERM   = 15, // software termination signal from kill
    URG    = 16, // urgent condition on IO channel
    STOP   = 17, // sendable stop signal not from tty
    TSTP   = 18, // stop signal from tty
    CONT   = 19, // continue a stopped process
    CHLD   = 20, // to parent on child stop or exit
    TTIN   = 21, // to readers pgrp upon background tty read
    TTOU   = 22, // like TTIN if (tp->t_local&LTOSTOP)
    IO     = 23, // input/output possible signal
    XCPU   = 24, // exceeded CPU time limit
    XFSZ   = 25, // exceeded file size limit
    VTALRM = 26, // virtual time alarm
    PROF   = 27, // profiling time alarm
    WINCH  = 28, // window size changes
    INFO   = 29, // information request
    USR1   = 30, // user defined signal 1
    USR2   = 31, // user defined signal 2
    THR    = 32, // reserved by thread library.
    LIBRT  = 33, // reserved by real-time library.
    _,
    // zig fmt: on

    pub const IOT = SIG.ABRT; // compatibility
    pub const LWP = SIG.THR;

    pub const RTMIN = 65;
    pub const RTMAX = 126;

    pub const ERR = @as(?sys.sigaction_t.handler_fn, @ptrFromInt(-1));
    pub const DFL = @as(?sys.sigaction_t.handler_fn, @ptrFromInt(0));
    pub const IGN = @as(?sys.sigaction_t.handler_fn, @ptrFromInt(1));
    pub const CATCH = @as(?sys.sigaction_t.handler_fn, @ptrFromInt(2));
    pub const HOLD = @as(?sys.sigaction_t.handler_fn, @ptrFromInt(3));

    pub const EV_NONE = 0; // No async notification.
    pub const EV_SIGNAL = 1; // Generate a queued signal.
    pub const EV_THREAD = 2; // Call back from another pthread.
    pub const EV_KEVENT = 3; // Generate a kevent.
    pub const EV_THREAD_ID = 4; // Send signal to a kernel thread.

    pub const BLOCK = 1; // block specified signal set
    pub const UNBLOCK = 2; // unblock specified signal set
    pub const SETMASK = 3; // set specified signal set

    pub const MINSTKSZ = switch (builtin.target.cpu.arch) {
        .arm, .aarch64, .riscv64 => 1024 * 4,
        else => 512 * 4,
    };
    pub const STKSZ = (MINSTKSZ + 32768); // recommended stack size

    pub const WORDS = 4;
    pub const MAXSIG = 128;
};

pub const clockid_t = enum(i32) {
    // zig fmt: off
    REALTIME           =  0,
    VIRTUAL            =  1,
    PROF               =  2,
    MONOTONIC          =  4,
    UPTIME             =  5,
    UPTIME_PRECISE     =  7,
    UPTIME_FAST        =  8,
    REALTIME_PRECISE   =  9,
    REALTIME_FAST      = 10,
    MONOTONIC_PRECISE  = 11,
    MONOTONIC_FAST     = 12,
    SECOND             = 13,
    THREAD_CPUTIME_ID  = 14,
    PROCESS_CPUTIME_ID = 15,
    _,
    // zig fmt: on
};

pub const cpuclock_which_t = enum(c_int) {
    PID = 0,
    TID = 1,
    _,
};

pub const default = struct {
    pub const file_mode: sys.mode_t = 0o666;
    pub const dir_mode: sys.mode_t = 0o777;
};

pub const dl_phdr_info_t = extern struct {
    /// Module relocation base.
    dlpi_addr: if (builtin.target.ptrBitWidth() == 32) std.elf.Elf32_Addr else std.elf.Elf64_Addr,
    /// Module name.
    dlpi_name: ?[*:0]const u8,
    /// Pointer to module's phdr.
    dlpi_phdr: [*]std.elf.Phdr,
    /// Number of entries in phdr.
    dlpi_phnum: u16,
    /// Total number of loads.
    dlpi_adds: u64,
    /// Total number of unloads.
    dlpi_subs: u64,
    dlpi_tls_modid: usize,
    dlpi_tls_data: ?*anyopaque,
};

pub const dirent_t = if (@hasField(sys.SYS, "getdirentries@12"))
    extern struct {
        fileno: sys.ino_t,
        off: sys.off_t,
        reclen: u16,
        type: sys.DT,
        pad0: u8,
        namlen: u16,
        pad1: u16,
        name: [255 + 1]u8,

        comptime {
            const size = 280;
            if (@sizeOf(@This()) != size) {
                @compileError(std.fmt.comptimePrint("expected size {d} bytes, found {d}", .{ size, @sizeOf(@This()) }));
            }
        }
    }
else if (@hasField(sys.SYS, "getdirentries@2") or @hasField(sys.SYS, "getdirentries@1"))
    extern struct {
        fileno: u32,
        reclen: u16,
        type: sys.DT,
        namlen: u8,
        name: [255 + 1]u8,

        comptime {
            const size = 264;
            if (@sizeOf(@This()) != size) {
                @compileError(std.fmt.comptimePrint("expected size {d} bytes, found {d}", .{ size, @sizeOf(@This()) }));
            }
        }
    }
else
    std.missing_feature;

pub const iovec_t = extern struct {
    base: [*]u8,
    len: usize,

    comptime {
        const size = 16;
        if (@sizeOf(@This()) != size) {
            @compileError(std.fmt.comptimePrint("expected size {d} bytes, found {d}", .{ size, @sizeOf(@This()) }));
        }
    }
};

pub const iovec_const_t = extern struct {
    base: [*]const u8,
    len: usize,

    comptime {
        const size = 16;
        if (@sizeOf(@This()) != size) {
            @compileError(std.fmt.comptimePrint("expected size {d} bytes, found {d}", .{ size, @sizeOf(@This()) }));
        }
    }
};

pub const mcontext_t = extern struct {
    onstack: u64,
    rdi: u64,
    rsi: u64,
    rdx: u64,
    rcx: u64,
    r8: u64,
    r9: u64,
    rax: u64,
    rbx: u64,
    rbp: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    trapno: u32,
    fs: u16,
    gs: u16,
    addr: u64,
    flags: u32,
    es: u16,
    ds: u16,
    err: u64,
    rip: u64,
    cs: u64,
    rflags: u64,
    rsp: u64,
    ss: u64,
    len: u64,
    fpformat: u64,
    ownedfp: u64,
    fpstate: [64]u64 align(16),
    fsbase: u64,
    gsbase: u64,
    xfpustate: u64,
    xfpustate_len: u64,
    spare: [4]u64,

    comptime {
        const size = 800;
        if (@sizeOf(@This()) != size) {
            @compileError(std.fmt.comptimePrint("expected size {d} bytes, found {d}", .{ size, @sizeOf(@This()) }));
        }
    }
};

pub const priority = struct {
    pub const which_t = enum(c_int) {
        PROCESS = 0,
        PGRP = 1,
        USER = 2,
        _,
    };

    pub const MAX: c_int = 20;
    pub const MIN: c_int = -20;
};

pub const rlimit_t = extern struct {
    cur: sys.rlimit_value_t,
    max: sys.rlimit_value_t,

    pub const INFINITY: sys.rlimit_value_t = (@as(u64, 1) << 63) - 1;
    pub const SAVED_MAX = INFINITY;
    pub const SAVED_CUR = INFINITY;

    comptime {
        const size = 16;
        if (@sizeOf(@This()) != size) {
            @compileError(std.fmt.comptimePrint("expected size {d} bytes, found {d}", .{ size, @sizeOf(@This()) }));
        }
    }
};

pub const rlimit_resource_t = enum(c_int) {
    // zig fmt: off
    CPU     = 0,
    FSIZE   = 1,
    DATA    = 2,
    STACK   = 3,
    CORE    = 4,
    RSS     = 5,
    MEMLOCK = 6,
    NPROC   = 7,
    NOFILE  = 8,
    SBSIZE  = 9,
    VMEM    = 10,
    NPTS    = 11,
    SWAP    = 12,
    KQUEUES = 13,
    UMTXP   = 14,
    _,
    // zig fmt: on
};

pub const rusage_t = extern struct {
    utime: sys.timeval_t,
    stime: sys.timeval_t,
    maxrss: c_long,
    ixrss: c_long,
    idrss: c_long,
    isrss: c_long,
    minflt: c_long,
    majflt: c_long,
    nswap: c_long,
    inblock: c_long,
    oublock: c_long,
    msgsnd: c_long,
    msgrcv: c_long,
    nsignals: c_long,
    nvcsw: c_long,
    nivcsw: c_long,

    pub const who_t = enum(c_int) {
        SELF = 0,
        CHILDREN = -1,
        THREAD = 1,
        _,
    };

    comptime {
        const size = 144;
        if (@sizeOf(@This()) != size) {
            @compileError(std.fmt.comptimePrint("expected size {d} bytes, found {d}", .{ size, @sizeOf(@This()) }));
        }
    }
};

pub const sigaction_t = extern struct {
    pub const handler_fn = *align(1) const fn (sys.SIG) callconv(.C) void;
    pub const action_fn = *const fn (sys.SIG, *const sys.siginfo_t, ?*anyopaque) callconv(.C) void;

    handler: extern union {
        handler: ?handler_fn,
        action: ?action_fn,
    },
    flags: c_uint,
    mask: sys.sigset_t,

    comptime {
        const size = 32;
        if (@sizeOf(@This()) != size) {
            @compileError(std.fmt.comptimePrint("expected size {d} bytes, found {d}", .{ size, @sizeOf(@This()) }));
        }
    }
};

pub const siginfo_t = extern struct {
    signo: sys.SIG,
    errno: sys.E,
    code: c_int,
    pid: sys.pid_t,
    uid: sys.uid_t,
    status: c_int,
    addr: ?*anyopaque,
    value: sys.sigval_t,
    reason: extern union {
        fault: extern struct {
            trapno: c_int,
        },
        timer: extern struct {
            timerid: c_int,
            overrun: c_int,
        },
        mesgq: extern struct {
            mqd: c_int,
        },
        poll: extern struct {
            band: c_long,
        },
        _spare: extern struct {
            spare1: c_long,
            spare2: [7]c_int,
        },
    },

    comptime {
        const size = 80;
        if (@sizeOf(@This()) != size) {
            @compileError(std.fmt.comptimePrint("expected size {d} bytes, found {d}", .{ size, @sizeOf(@This()) }));
        }
    }
};

pub const sigset_t = extern struct {
    __bits: [sys.SIG.WORDS]u32 = [1]u32{0} ** sys.SIG.WORDS,

    pub fn add(self: *@This(), sig: sys.SIG) void {
        const signo = @intFromEnum(sig);
        std.debug.assert(signo > 0 and signo <= sys.SIG.MAXSIG);
        const idx = @as(u32, @bitCast(signo)) - 1;
        self.__bits[idx >> 5] |= @as(u32, 1) << @as(u5, @truncate(idx));
    }

    pub fn del(self: *@This(), sig: sys.SIG) void {
        const signo = @intFromEnum(sig);
        std.debug.assert(signo > 0 and signo <= sys.SIG.MAXSIG);
        const idx = @as(u32, @bitCast(signo)) - 1;
        self.__bits[idx >> 5] &= ~(@as(u32, 1) << @as(u5, @truncate(idx)));
    }

    pub fn assign_from(self: *@This(), other: sigset_t) void {
        @memcpy(&self.__bits, &other.__bits);
    }

    pub fn empty(self: *@This()) void {
        @memcpy(&self.__bits, &EMPTY.__bits);
    }

    pub fn fill(self: *@This()) void {
        @memcpy(&self.__bits, &FULL.__bits);
    }

    pub fn is_empty(self: @This()) bool {
        return std.mem.eql(u32, &self.__bits, &EMPTY.__bits);
    }

    pub fn is_full(self: @This()) bool {
        return std.mem.eql(u32, &self.__bits, &FULL.__bits);
    }

    pub fn is_member(self: @This(), sig: sys.SIG) bool {
        const signo = @intFromEnum(sig);
        std.debug.assert(signo > 0 and signo <= sys.SIG.MAXSIG);
        const idx = @as(u32, @bitCast(signo)) - 1;
        const word = self.__bits[idx >> 5];
        return if (word & (@as(u32, 1) << @as(u5, @truncate(idx))) != 0) true else false;
    }

    pub fn and_with(self: *@This(), other: sigset_t) void {
        for (&self.__bits, &other.__bits) |*lhs, rhs| lhs.* &= rhs;
    }

    pub fn or_with(self: *@This(), other: sigset_t) void {
        for (&self.__bits, &other.__bits) |*lhs, rhs| lhs.* |= rhs;
    }

    pub const EMPTY: @This() = .{ .__bits = [1]u32{0} ** sys.SIG.WORDS };
    pub const FULL: @This() = .{ .__bits = [1]u32{0xffff_ffff} ** sys.SIG.WORDS };

    comptime {
        const size = 16;
        if (@sizeOf(@This()) != size) {
            @compileError(std.fmt.comptimePrint("expected size {d} bytes, found {d}", .{ size, @sizeOf(@This()) }));
        }
    }

    comptime {
        const size = 16;
        if (@sizeOf(@This()) != size) {
            @compileError(std.fmt.comptimePrint("expected size {d} bytes, found {d}", .{ size, @sizeOf(@This()) }));
        }
    }
};

pub const sigval_t = extern union {
    int: c_int,
    ptr: ?*anyopaque,

    comptime {
        const size = 8;
        if (@sizeOf(@This()) != size) {
            @compileError(std.fmt.comptimePrint("expected size {d} bytes, found {d}", .{ size, @sizeOf(@This()) }));
        }
    }
};

pub const sigpm_how_t = enum(c_int) {
    // zig fmt: off
    BLOCK   = 1, // block specified signal set
    UNBLOCK = 2, // unblock specified signal set
    SETMASK = 3, // set specified signal set
    // zig fmt: on
};

pub const stat_t = extern struct {
    // zig fmt: off
    dev:      sys.dev_t,
    ino:      sys.ino_t,
    nlink:    sys.nlink_t,
    mode:     sys.mode_t,
    _pad0:    i16,
    uid:      sys.uid_t,
    gid:      sys.gid_t,
    _pad1:    i32,
    rdev:     sys.dev_t,
    atim:     sys.timespec_t,
    mtim:     sys.timespec_t,
    ctim:     sys.timespec_t,
    birthtim: sys.timespec_t,
    size:     sys.off_t,
    blocks:   sys.blkcnt_t,
    blksize:  sys.blksize_t,
    flags:    sys.fflags_t,
    gen:      u64,
    _spare:   [10]u64,
    // zig fmt: on

    comptime {
        const size = 224;
        if (@sizeOf(@This()) != size) {
            @compileError(std.fmt.comptimePrint("expected size {d} bytes, found {d}", .{ size, @sizeOf(@This()) }));
        }
    }
};

pub const timer_t = enum(c_int) {
    RELTIME = 0,
    ABSTIME = 1,
    _,
};

pub const timespec_t = extern struct {
    sec: sys.time_t,
    nsec: c_long,

    comptime {
        const size = 16;
        if (@sizeOf(@This()) != size) {
            @compileError(std.fmt.comptimePrint("expected size {d} bytes, found {d}", .{ size, @sizeOf(@This()) }));
        }
    }
};

pub const timeval_t = extern struct {
    sec: sys.time_t,
    usec: sys.suseconds_t,

    comptime {
        const size = 16;
        if (@sizeOf(@This()) != size) {
            @compileError(std.fmt.comptimePrint("expected size {d} bytes, found {d}", .{ size, @sizeOf(@This()) }));
        }
    }
};

pub const sf_hdtr_t = extern struct {
    headers: ?[*]const sys.iovec_const_t,
    hdr_cnt: c_int,
    trailers: ?[*]const sys.iovec_const_t,
    trl_cnt: c_int,

    comptime {
        const size = 32;
        if (@sizeOf(@This()) != size) {
            @compileError(std.fmt.comptimePrint("expected size {d} bytes, found {d}", .{ size, @sizeOf(@This()) }));
        }
    }
};

pub const stack_t = extern struct {
    /// Signal stack base.
    sp: *anyopaque,
    /// Signal stack length.
    size: usize,
    /// SS_DISABLE and/or SS_ONSTACK.
    flags: c_int,

    comptime {
        const size = 24;
        if (@sizeOf(@This()) != size) {
            @compileError(std.fmt.comptimePrint("expected size {d} bytes, found {d}", .{ size, @sizeOf(@This()) }));
        }
    }
};

pub const ucontext_t = extern struct {
    sigmask: sigset_t,
    mcontext: mcontext_t,
    link: ?*ucontext_t,
    stack: stack_t,
    flags: c_int,
    __spare__: [4]c_int,

    comptime {
        const size = 880;
        if (@sizeOf(@This()) != size) {
            @compileError(std.fmt.comptimePrint("expected size {d} bytes, found {d}", .{ size, @sizeOf(@This()) }));
        }
    }
};

const Feature = std.Feature(@This());
pub const hasFeature = Feature.hasFeature;
pub const hasFeatures = Feature.hasFeatures;

// TODO: mike: position

pub const DT = enum(u8) {
    // zig fmt: off
    UNKNOWN =  0,
    FIFO    =  1,
    CHR     =  2,
    DIR     =  4,
    BLK     =  6,
    REG     =  8,
    LNK     = 10,
    SOCK    = 12,
    WHT     = 14,
    _,
    // zig fmt: on
};

pub const SEEK = enum(c_int) {
    SET = 0,
    CUR = 1,
    END = 2,
    _,
};

pub const T = struct {
    pub const IOCEXCL = 0x2000740d;
    pub const IOCNXCL = 0x2000740e;
    pub const IOCSCTTY = 0x20007461;
    pub const IOCGPGRP = 0x40047477;
    pub const IOCSPGRP = 0x80047476;
    pub const IOCOUTQ = 0x40047473;
    pub const IOCSTI = 0x80017472;
    pub const IOCGWINSZ = 0x40087468;
    pub const IOCSWINSZ = 0x80087467;
    pub const IOCMGET = 0x4004746a;
    pub const IOCMBIS = 0x8004746c;
    pub const IOCMBIC = 0x8004746b;
    pub const IOCMSET = 0x8004746d;
    pub const FIONREAD = 0x4004667f;
    pub const IOCCONS = 0x80047462;
    pub const IOCPKT = 0x80047470;
    pub const FIONBIO = 0x8004667e;
    pub const IOCNOTTY = 0x20007471;
    pub const IOCSETD = 0x8004741b;
    pub const IOCGETD = 0x4004741a;
    pub const IOCSBRK = 0x2000747b;
    pub const IOCCBRK = 0x2000747a;
    pub const IOCGSID = 0x40047463;
    pub const IOCGPTN = 0x4004740f;
    pub const IOCSIG = 0x2004745f;
};

pub const CTL = enum(c_int) {
    // zig fmt: off
    sysctl   = 0, // "magic" numbers
    kern     = 1, // "high kernel": proc, limits
    vm       = 2, // virtual memory
    vfs      = 3, // filesystem, mount type is next
    net      = 4, // network, see socket.h
    debug    = 5, // debugging parameters
    hw       = 6, // generic cpu/io
    machdep  = 7, // machine dependent
    user     = 8, // user-level
    p1003_1b = 9, // POSIX 1003.1B
    _,

    pub const SYSCTL = enum(c_int) {
        debug           = 0, // printf all nodes
        name            = 1, // string name of OID
        next            = 2, // next OID, honoring CTLFLAG_SKIP
        name2oid        = 3, // int array of name
        oidfmt          = 4, // OID's kind and format
        oiddescr        = 5, // OID's description
        oidlabel        = 6, // aggregation label
        nextnoskip      = 7, // next OID, ignoring CTLFLAG_SKIP
        _,
    };

    pub const KERN = enum(c_int) {
        ostype          =  1, // string: system version
        osrelease       =  2, // string: system release
        osrev           =  3, // int: system revision
        version         =  4, // string: compile time info
        maxvnodes       =  5, // int: max vnodes
        maxproc         =  6, // int: max processes
        maxfiles        =  7, // int: max open files
        argmax          =  8, // int: max arguments to exec
        securelvl       =  9, // int: system security level
        hostname        = 10, // string: hostname
        hostid          = 11, // int: host identifier
        clockrate       = 12, // struct: struct clockrate
        _vnode          = 13, // disabled in 2003 and removed in 2023
        proc            = 14, // struct: process entries
        file            = 15, // struct: file entries
        prof            = 16, // node: kernel profiling info
        posix1          = 17, // int: POSIX.1 version
        ngroups         = 18, // int: # of supplemental group ids
        job_control     = 19, // int: is job control available
        saved_ids       = 20, // int: saved set-user/group-ID
        boottime        = 21, // struct: time kernel was booted
        nisdomainname   = 22, // string: YP domain name
        updateinterval  = 23, // int: update process sleep time
        osreldate       = 24, // int: kernel release date
        ntp_pll         = 25, // node: NTP PLL control
        bootfile        = 26, // string: name of booted kernel
        maxfilesperproc = 27, // int: max open files per proc
        maxprocperuid   = 28, // int: max processes per uid
        dumpdev         = 29, // struct cdev *: device to dump on
        ipc             = 30, // node: anything related to IPC
        _dummy          = 31, // unused
        ps_strings      = 32, // int: address of PS_STRINGS
        usrstack        = 33, // int: address of USRSTACK
        logsigexit      = 34, // int: do we log sigexit procs?
        iov_max         = 35, // int: value of UIO_MAXIOV
        hostuuid        = 36, // string: host UUID identifier
        arnd            = 37, // int: from arc4rand()
        maxphys         = 38, // int: MAXPHYS value
        lockf           = 39, // struct: lockf reports
        _,

        pub const PROC = enum(c_int) {
            all        =  0, // everything
            pid        =  1, // by process id
            pgrp       =  2, // by process group id
            session    =  3, // by session of pid
            tty        =  4, // by controlling tty
            uid        =  5, // by effective uid
            ruid       =  6, // by real uid
            args       =  7, // get/set arguments/proctitle
            proc       =  8, // only return procs
            sv_name    =  9, // get syscall vector name
            rgid       = 10, // by real group id
            gid        = 11, // by effective group id
            pathname   = 12, // path to executable
            ovmmap     = 13, // Old VM map entries for process
            ofiledesc  = 14, // Old file descriptors for process
            kstack     = 15, // Kernel stacks for process
            vmmap      = 32, // VM map entries for process
            filedesc   = 33, // File descriptors for process
            groups     = 34, // process groups
            env        = 35, // get environment
            auxv       = 36, // get ELF auxiliary vector
            rlimit     = 37, // process resource limits
            ps_strings = 38, // get ps_strings location
            umask      = 39, // process umask
            osrel      = 40, // osreldate for process binary
            sigtramp   = 41, // signal trampoline location
            cwd        = 42, // process current working directory
            nfds       = 43, // number of open file descriptors
            sigfastblk = 44, // address of fastsigblk magic word
            vm_layout  = 45, // virtual address space layout info
        };
    };

    pub const HW = enum(c_int) {
        machine         =  1, // string: machine class
        model           =  2, // string: specific machine model
        ncpu            =  3, // int: number of cpus
        byteorder       =  4, // int: machine byte order
        physmem         =  5, // int: total memory
        usermem         =  6, // int: non-kernel memory
        pagesize        =  7, // int: software page size
        disknames       =  8, // strings: disk drive names
        diskstats       =  9, // struct: diskstats[]
        floatingpt      = 10, // int: has HW floating point?
        machine_arch    = 11, // string: machine architecture
        realmem         = 12, // int: 'real' memory
    };
    // zig fmt: on
};

pub const in_port_t = u16;
pub const sa_family_t = u8;

pub const sockaddr = extern struct {
    /// total length
    len: u8,
    /// address family
    family: sa_family_t,
    /// actually longer; address value
    data: [14]u8,

    pub const SS_MAXSIZE = 128;
    pub const storage = extern struct {
        len: u8 align(8),
        family: sa_family_t,
        padding: [126]u8 = undefined,

        comptime {
            std.debug.assert(@sizeOf(storage) == SS_MAXSIZE);
            std.debug.assert(@alignOf(storage) == 8);
        }
    };

    pub const in = extern struct {
        len: u8 = @sizeOf(in),
        family: sa_family_t = AF.INET,
        port: in_port_t,
        addr: u32,
        zero: [8]u8 = [8]u8{ 0, 0, 0, 0, 0, 0, 0, 0 },
    };

    pub const in6 = extern struct {
        len: u8 = @sizeOf(in6),
        family: sa_family_t = AF.INET6,
        port: in_port_t,
        flowinfo: u32,
        addr: [16]u8,
        scope_id: u32,
    };

    pub const un = extern struct {
        len: u8 = @sizeOf(un),
        family: sa_family_t = AF.UNIX,
        path: [104]u8,
    };
};

pub const AF = struct {
    pub const UNSPEC = 0;
    pub const UNIX = 1;
    pub const LOCAL = UNIX;
    pub const FILE = LOCAL;
    pub const INET = 2;
    pub const IMPLINK = 3;
    pub const PUP = 4;
    pub const CHAOS = 5;
    pub const NETBIOS = 6;
    pub const ISO = 7;
    pub const OSI = ISO;
    pub const ECMA = 8;
    pub const DATAKIT = 9;
    pub const CCITT = 10;
    pub const SNA = 11;
    pub const DECnet = 12;
    pub const DLI = 13;
    pub const LAT = 14;
    pub const HYLINK = 15;
    pub const APPLETALK = 16;
    pub const ROUTE = 17;
    pub const LINK = 18;
    pub const pseudo_XTP = 19;
    pub const COIP = 20;
    pub const CNT = 21;
    pub const pseudo_RTIP = 22;
    pub const IPX = 23;
    pub const SIP = 24;
    pub const pseudo_PIP = 25;
    pub const ISDN = 26;
    pub const E164 = ISDN;
    pub const pseudo_KEY = 27;
    pub const INET6 = 28;
    pub const NATM = 29;
    pub const ATM = 30;
    pub const pseudo_HDRCMPLT = 31;
    pub const NETGRAPH = 32;
    pub const SLOW = 33;
    pub const SCLUSTER = 34;
    pub const ARP = 35;
    pub const BLUETOOTH = 36;
    pub const IEEE80211 = 37;
    pub const INET_SDP = 40;
    pub const INET6_SDP = 42;
    pub const MAX = 42;
};

pub const IFNAMESIZE = 16;

pub const SOCK = struct {
    pub const STREAM = 1;
    pub const DGRAM = 2;
    pub const RAW = 3;
    pub const RDM = 4;
    pub const SEQPACKET = 5;

    pub const CLOEXEC = 0x10000000;
    pub const NONBLOCK = 0x20000000;
};

pub const SO = struct {
    pub const DEBUG = 0x00000001;
    pub const ACCEPTCONN = 0x00000002;
    pub const REUSEADDR = 0x00000004;
    pub const KEEPALIVE = 0x00000008;
    pub const DONTROUTE = 0x00000010;
    pub const BROADCAST = 0x00000020;
    pub const USELOOPBACK = 0x00000040;
    pub const LINGER = 0x00000080;
    pub const OOBINLINE = 0x00000100;
    pub const REUSEPORT = 0x00000200;
    pub const TIMESTAMP = 0x00000400;
    pub const NOSIGPIPE = 0x00000800;
    pub const ACCEPTFILTER = 0x00001000;
    pub const BINTIME = 0x00002000;
    pub const NO_OFFLOAD = 0x00004000;
    pub const NO_DDP = 0x00008000;
    pub const REUSEPORT_LB = 0x00010000;

    pub const SNDBUF = 0x1001;
    pub const RCVBUF = 0x1002;
    pub const SNDLOWAT = 0x1003;
    pub const RCVLOWAT = 0x1004;
    pub const SNDTIMEO = 0x1005;
    pub const RCVTIMEO = 0x1006;
    pub const ERROR = 0x1007;
    pub const TYPE = 0x1008;
    pub const LABEL = 0x1009;
    pub const PEERLABEL = 0x1010;
    pub const LISTENQLIMIT = 0x1011;
    pub const LISTENQLEN = 0x1012;
    pub const LISTENINCQLEN = 0x1013;
    pub const SETFIB = 0x1014;
    pub const USER_COOKIE = 0x1015;
    pub const PROTOCOL = 0x1016;
    pub const PROTOTYPE = PROTOCOL;
    pub const TS_CLOCK = 0x1017;
    pub const MAX_PACING_RATE = 0x1018;
    pub const DOMAIN = 0x1019;
};

pub const AI = struct {
    /// get address to use bind()
    pub const PASSIVE = 0x00000001;
    /// fill ai_canonname
    pub const CANONNAME = 0x00000002;
    /// prevent host name resolution
    pub const NUMERICHOST = 0x00000004;
    /// prevent service name resolution
    pub const NUMERICSERV = 0x00000008;
    /// valid flags for addrinfo (not a standard def, apps should not use it)
    pub const MASK = (PASSIVE | CANONNAME | NUMERICHOST | NUMERICSERV | ADDRCONFIG | ALL | V4MAPPED);
    /// IPv6 and IPv4-mapped (with V4MAPPED)
    pub const ALL = 0x00000100;
    /// accept IPv4-mapped if kernel supports
    pub const V4MAPPED_CFG = 0x00000200;
    /// only if any address is assigned
    pub const ADDRCONFIG = 0x00000400;
    /// accept IPv4-mapped IPv6 address
    pub const V4MAPPED = 0x00000800;
    /// special recommended flags for getipnodebyname
    pub const DEFAULT = (V4MAPPED_CFG | ADDRCONFIG);
};

pub const FD_CLOEXEC = 1;

pub const access_mode_t = packed struct(u32) {
    // zig fmt: off
    EXECUTE: bool = false, // test for execute or search permission
    WRITE:   bool = false, // test for write permission
    READ:    bool = false, // test for read permission
    _4: u29 = 0,
    // zig fmt: on
};

pub const LOCK = struct {
    pub const SH = 1;
    pub const EX = 2;
    pub const UN = 8;
    pub const NB = 4;
};

pub const IPPROTO = struct {
    /// dummy for IP
    pub const IP = 0;
    /// control message protocol
    pub const ICMP = 1;
    /// tcp
    pub const TCP = 6;
    /// user datagram protocol
    pub const UDP = 17;
    /// IP6 header
    pub const IPV6 = 41;
    /// raw IP packet
    pub const RAW = 255;
    /// IP6 hop-by-hop options
    pub const HOPOPTS = 0;
    /// group mgmt protocol
    pub const IGMP = 2;
    /// gateway^2 (deprecated)
    pub const GGP = 3;
    /// IPv4 encapsulation
    pub const IPV4 = 4;
    /// for compatibility
    pub const IPIP = IPV4;
    /// Stream protocol II
    pub const ST = 7;
    /// exterior gateway protocol
    pub const EGP = 8;
    /// private interior gateway
    pub const PIGP = 9;
    /// BBN RCC Monitoring
    pub const RCCMON = 10;
    /// network voice protocol
    pub const NVPII = 11;
    /// pup
    pub const PUP = 12;
    /// Argus
    pub const ARGUS = 13;
    /// EMCON
    pub const EMCON = 14;
    /// Cross Net Debugger
    pub const XNET = 15;
    /// Chaos
    pub const CHAOS = 16;
    /// Multiplexing
    pub const MUX = 18;
    /// DCN Measurement Subsystems
    pub const MEAS = 19;
    /// Host Monitoring
    pub const HMP = 20;
    /// Packet Radio Measurement
    pub const PRM = 21;
    /// xns idp
    pub const IDP = 22;
    /// Trunk-1
    pub const TRUNK1 = 23;
    /// Trunk-2
    pub const TRUNK2 = 24;
    /// Leaf-1
    pub const LEAF1 = 25;
    /// Leaf-2
    pub const LEAF2 = 26;
    /// Reliable Data
    pub const RDP = 27;
    /// Reliable Transaction
    pub const IRTP = 28;
    /// tp-4 w/ class negotiation
    pub const TP = 29;
    /// Bulk Data Transfer
    pub const BLT = 30;
    /// Network Services
    pub const NSP = 31;
    /// Merit Internodal
    pub const INP = 32;
    /// Datagram Congestion Control Protocol
    pub const DCCP = 33;
    /// Third Party Connect
    pub const @"3PC" = 34;
    /// InterDomain Policy Routing
    pub const IDPR = 35;
    /// XTP
    pub const XTP = 36;
    /// Datagram Delivery
    pub const DDP = 37;
    /// Control Message Transport
    pub const CMTP = 38;
    /// TP++ Transport
    pub const TPXX = 39;
    /// IL transport protocol
    pub const IL = 40;
    /// Source Demand Routing
    pub const SDRP = 42;
    /// IP6 routing header
    pub const ROUTING = 43;
    /// IP6 fragmentation header
    pub const FRAGMENT = 44;
    /// InterDomain Routing
    pub const IDRP = 45;
    /// resource reservation
    pub const RSVP = 46;
    /// General Routing Encap.
    pub const GRE = 47;
    /// Mobile Host Routing
    pub const MHRP = 48;
    /// BHA
    pub const BHA = 49;
    /// IP6 Encap Sec. Payload
    pub const ESP = 50;
    /// IP6 Auth Header
    pub const AH = 51;
    /// Integ. Net Layer Security
    pub const INLSP = 52;
    /// IP with encryption
    pub const SWIPE = 53;
    /// Next Hop Resolution
    pub const NHRP = 54;
    /// IP Mobility
    pub const MOBILE = 55;
    /// Transport Layer Security
    pub const TLSP = 56;
    /// SKIP
    pub const SKIP = 57;
    /// ICMP6
    pub const ICMPV6 = 58;
    /// IP6 no next header
    pub const NONE = 59;
    /// IP6 destination option
    pub const DSTOPTS = 60;
    /// any host internal protocol
    pub const AHIP = 61;
    /// CFTP
    pub const CFTP = 62;
    /// "hello" routing protocol
    pub const HELLO = 63;
    /// SATNET/Backroom EXPAK
    pub const SATEXPAK = 64;
    /// Kryptolan
    pub const KRYPTOLAN = 65;
    /// Remote Virtual Disk
    pub const RVD = 66;
    /// Pluribus Packet Core
    pub const IPPC = 67;
    /// Any distributed FS
    pub const ADFS = 68;
    /// Satnet Monitoring
    pub const SATMON = 69;
    /// VISA Protocol
    pub const VISA = 70;
    /// Packet Core Utility
    pub const IPCV = 71;
    /// Comp. Prot. Net. Executive
    pub const CPNX = 72;
    /// Comp. Prot. HeartBeat
    pub const CPHB = 73;
    /// Wang Span Network
    pub const WSN = 74;
    /// Packet Video Protocol
    pub const PVP = 75;
    /// BackRoom SATNET Monitoring
    pub const BRSATMON = 76;
    /// Sun net disk proto (temp.)
    pub const ND = 77;
    /// WIDEBAND Monitoring
    pub const WBMON = 78;
    /// WIDEBAND EXPAK
    pub const WBEXPAK = 79;
    /// ISO cnlp
    pub const EON = 80;
    /// VMTP
    pub const VMTP = 81;
    /// Secure VMTP
    pub const SVMTP = 82;
    /// Banyon VINES
    pub const VINES = 83;
    /// TTP
    pub const TTP = 84;
    /// NSFNET-IGP
    pub const IGP = 85;
    /// dissimilar gateway prot.
    pub const DGP = 86;
    /// TCF
    pub const TCF = 87;
    /// Cisco/GXS IGRP
    pub const IGRP = 88;
    /// OSPFIGP
    pub const OSPFIGP = 89;
    /// Strite RPC protocol
    pub const SRPC = 90;
    /// Locus Address Resoloution
    pub const LARP = 91;
    /// Multicast Transport
    pub const MTP = 92;
    /// AX.25 Frames
    pub const AX25 = 93;
    /// IP encapsulated in IP
    pub const IPEIP = 94;
    /// Mobile Int.ing control
    pub const MICP = 95;
    /// Semaphore Comm. security
    pub const SCCSP = 96;
    /// Ethernet IP encapsulation
    pub const ETHERIP = 97;
    /// encapsulation header
    pub const ENCAP = 98;
    /// any private encr. scheme
    pub const APES = 99;
    /// GMTP
    pub const GMTP = 100;
    /// payload compression (IPComp)
    pub const IPCOMP = 108;
    /// SCTP
    pub const SCTP = 132;
    /// IPv6 Mobility Header
    pub const MH = 135;
    /// UDP-Lite
    pub const UDPLITE = 136;
    /// IP6 Host Identity Protocol
    pub const HIP = 139;
    /// IP6 Shim6 Protocol
    pub const SHIM6 = 140;
    /// Protocol Independent Mcast
    pub const PIM = 103;
    /// CARP
    pub const CARP = 112;
    /// PGM
    pub const PGM = 113;
    /// MPLS-in-IP
    pub const MPLS = 137;
    /// PFSYNC
    pub const PFSYNC = 240;
    /// Reserved
    pub const RESERVED_253 = 253;
    /// Reserved
    pub const RESERVED_254 = 254;
};

pub const SOL = struct {
    pub const SOCKET = 0xffff;
};

pub const socklen_t = u32;

pub const addrinfo = extern struct {
    flags: i32,
    family: i32,
    socktype: i32,
    protocol: i32,
    addrlen: socklen_t,
    canonname: ?[*:0]u8,
    addr: ?*sockaddr,
    next: ?*addrinfo,

    comptime {
        const size = 48;
        if (@sizeOf(@This()) != size) {
            @compileError(std.fmt.comptimePrint("expected size {d} bytes, found {d}", .{ size, @sizeOf(@This()) }));
        }
    }
};

pub const SHUT = enum(c_int) {
    // zig fmt: off
    RD   = 0, // shut down the reading side
    WR   = 1, // shut down the writing side
    RDWR = 2, // shut down both sides
    _,
    // zig fmt: on
};

pub const kinfo_file = extern struct {
    /// Size of this record.
    /// A zero value is for the sentinel record at the end of an array.
    structsize: c_int,
    /// Descriptor type.
    type: c_int,
    /// Array index.
    fd: fd_t,
    /// Reference count.
    ref_count: c_int,
    /// Flags.
    flags: c_int,
    // 64bit padding.
    _pad0: c_int,
    /// Seek location.
    offset: i64,
    un: extern union {
        socket: extern struct {
            /// Sendq size.
            sendq: u32,
            /// Socket domain.
            domain: c_int,
            /// Socket type.
            type: c_int,
            /// Socket protocol.
            protocol: c_int,
            /// Socket address.
            address: sockaddr.storage,
            /// Peer address.
            peer: sockaddr.storage,
            /// Address of so_pcb.
            pcb: u64,
            /// Address of inp_ppcb.
            inpcb: u64,
            /// Address of unp_conn.
            unpconn: u64,
            /// Send buffer state.
            snd_sb_state: u16,
            /// Receive buffer state.
            rcv_sb_state: u16,
            /// Recvq size.
            recvq: u32,
        },
        file: extern struct {
            /// Vnode type.
            type: i32,
            // Reserved for future use
            _spare1: [3]i32,
            _spare2: [30]u64,
            /// Vnode filesystem id.
            fsid: u64,
            /// File device.
            rdev: u64,
            /// Global file id.
            fileid: u64,
            /// File size.
            size: u64,
            /// fsid compat for FreeBSD 11.
            fsid_freebsd11: u32,
            /// rdev compat for FreeBSD 11.
            rdev_freebsd11: u32,
            /// File mode.
            mode: u16,
            // 64bit padding.
            _pad0: u16,
            _pad1: u32,
        },
        sem: extern struct {
            _spare0: [4]u32,
            _spare1: [32]u64,
            /// Semaphore value.
            value: u32,
            /// Semaphore mode.
            mode: u16,
        },
        pipe: extern struct {
            _spare1: [4]u32,
            _spare2: [32]u64,
            addr: u64,
            peer: u64,
            buffer_cnt: u32,
            // 64bit padding.
            kf_pipe_pad0: [3]u32,
        },
        proc: extern struct {
            _spare1: [4]u32,
            _spare2: [32]u64,
            pid: pid_t,
        },
        eventfd: extern struct {
            value: u64,
            flags: u32,
        },
    },
    /// Status flags.
    status: u16,
    // 32-bit alignment padding.
    _pad1: u16,
    // Reserved for future use.
    _spare: c_int,
    /// Capability rights.
    cap_rights: sys.cap_rights,
    /// Reserved for future cap_rights
    _cap_spare: u64,
    /// Path to file, if any.
    path: [PATH_MAX - 1:0]u8,

    comptime {
        const size = 1392;
        if (@sizeOf(@This()) != size) {
            @compileError(std.fmt.comptimePrint("expected size {d} bytes, found {d}", .{ size, @sizeOf(@This()) }));
        }

        const alignment = 8;
        if (@alignOf(@This()) != alignment) {
            @compileError(std.fmt.comptimePrint("expected alignment of {d} bytes, found {d}", .{ alignment, @alignOf(@This()) }));
        }
    }
};

pub const CAP_RIGHTS_VERSION = 0;

pub const cap_rights = extern struct {
    rights: [CAP_RIGHTS_VERSION + 2]u64,
};

pub const W = struct {
    pub const NOHANG = 1;
    pub const UNTRACED = 2;
    pub const STOPPED = UNTRACED;
    pub const CONTINUED = 4;
    pub const NOWAIT = 8;
    pub const EXITED = 16;
    pub const TRAPPED = 32;

    pub fn EXITSTATUS(s: u32) u8 {
        return @as(u8, @intCast((s & 0xff00) >> 8));
    }
    pub fn TERMSIG(s: u32) u32 {
        return s & 0x7f;
    }
    pub fn STOPSIG(s: u32) u32 {
        return EXITSTATUS(s);
    }
    pub fn IFEXITED(s: u32) bool {
        return TERMSIG(s) == 0;
    }
    pub fn IFSTOPPED(s: u32) bool {
        return @as(u16, @truncate((((s & 0xffff) *% 0x10001) >> 8))) > 0x7f00;
    }
    pub fn IFSIGNALED(s: u32) bool {
        return (s & 0xffff) -% 1 < 0xff;
    }
};

pub const pollfd = extern struct {
    fd: sys.fd_t,
    events: i16,
    revents: i16,
};

pub const POLL = struct {
    /// any readable data available.
    pub const IN = 0x0001;
    /// OOB/Urgent readable data.
    pub const PRI = 0x0002;
    /// file descriptor is writeable.
    pub const OUT = 0x0004;
    /// non-OOB/URG data available.
    pub const RDNORM = 0x0040;
    /// no write type differentiation.
    pub const WRNORM = OUT;
    /// OOB/Urgent readable data.
    pub const RDBAND = 0x0080;
    /// OOB/Urgent data can be written.
    pub const WRBAND = 0x0100;
    /// like IN, except ignore EOF.
    pub const INIGNEOF = 0x2000;
    /// some poll error occurred.
    pub const ERR = 0x0008;
    /// file descriptor was "hung up".
    pub const HUP = 0x0010;
    /// requested events "invalid".
    pub const NVAL = 0x0020;

    pub const STANDARD = IN | PRI | OUT | RDNORM | RDBAND | WRBAND | ERR | HUP | NVAL;
};

pub const nfds_t = u32;

pub const umtx_op_t = enum(c_int) {
    // zig fmt: off
    LOCK              =  0,
    UNLOCK            =  1,
    WAIT              =  2,
    WAKE              =  3,
    MUTEX_TRYLOCK     =  4,
    MUTEX_LOCK        =  5,
    MUTEX_UNLOCK      =  6,
    SET_CEILING       =  7,
    CV_WAIT           =  8,
    CV_SIGNAL         =  9,
    CV_BROADCAST      = 10,
    WAIT_UINT         = 11,
    RW_RDLOCK         = 12,
    RW_WRLOCK         = 13,
    RW_UNLOCK         = 14,
    WAIT_UINT_PRIVATE = 15,
    WAKE_PRIVATE      = 16,
    MUTEX_WAIT        = 17,
    MUTEX_WAKE        = 18, // deprecated
    SEM_WAIT          = 19, // deprecated
    SEM_WAKE          = 20, // deprecated
    NWAKE_PRIVATE     = 31,
    MUTEX_WAKE2       = 22,
    SEM2_WAIT         = 23,
    SEM2_WAKE         = 24,
    SHM               = 25,
    ROBUST_LISTS      = 26,
    // zig fmt: on
};

pub const umtx_time_t = extern struct {
    timeout: sys.timespec_t,
    flags: u32,
    clockid: sys.clockid_t,
};

pub var _elf_aux_vector: *const anyopaque = undefined;
pub var _progname: ?[*:0]u8 = undefined;
