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
pub const syscall2_errno = syscall.syscall2_errno;
pub const syscall2_noerrno = syscall.syscall2_noerrno;
pub const syscall3_errno = syscall.syscall3_errno;
pub const syscall3_noerrno = syscall.syscall3_noerrno;
pub const syscall4_errno = syscall.syscall4_errno;
pub const syscall4_noerrno = syscall.syscall4_noerrno;
pub const syscall5_errno = syscall.syscall5_errno;
pub const syscall6_errno = syscall.syscall6_errno;

pub const Result = syscall.Result;

// compute os integer version
// MAJOR * 1_000_000 + MINOR * 1_000 + POINT
pub const osintver = b: {
    const sv = builtin.os.version_range.semver.min;
    break :b sv.major * 1_000_000 + sv.minor * 1_000 + sv.patch;
};

pub const __error = if (builtin.link_libc)
    struct {
        extern "c" fn __error() *sys.E;
    }.__error
else
    struct {
        fn __error() *sys.E {
            return &__error_value;
        }
    }.__error;

threadlocal var __error_value: sys.E = 0;

pub fn errno() sys.E {
    return sys.__error().*;
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
    sys.missing_feature;

pub const creat = if (hasFeature(.openat))
    struct {
        fn creat(path: [*:0]const u8, mode: sys.mode_t) sys.fd_t {
            return openat(sys.AT.FDCWD, path, .{ .WRONLY = true, .CREAT = true, .TRUNC = true }, mode);
        }
    }.creat
else if (hasFeature(.open))
    struct {
        fn creat(path: [*:0]const u8, mode: sys.mode_t) sys.fd_t {
            return open(path, .{ .WRONLY = true, .CREAT = true, .TRUNC = true }, mode);
        }
    }.creat
else
    sys.missing_feature;

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
    sys.missing_feature;

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
    sys.missing_feature;

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
    sys.missing_feature;

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
    sys.missing_feature;

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
    sys.missing_feature;

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
    sys.missing_feature;

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
    sys.missing_feature;

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
    sys.missing_feature;

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
    sys.missing_feature;

pub const getegid = if (@hasField(sys.SYS, "getegid"))
    struct {
        fn getegid() sys.gid_t {
            const rv = sys.syscall0_errno(.getegid);
            return @truncate(rv);
        }
    }.getegid
else
    sys.missing_feature;

pub const geteuid = if (@hasField(sys.SYS, "geteuid"))
    struct {
        fn geteuid() sys.uid_t {
            const rv = sys.syscall0_errno(.geteuid);
            return @truncate(rv);
        }
    }.geteuid
else
    sys.missing_feature;

pub const getgid = if (@hasField(sys.SYS, "getgid"))
    struct {
        fn getgid() sys.gid_t {
            const rv = sys.syscall0_errno(.getgid);
            return @truncate(rv);
        }
    }.getgid
else
    sys.missing_feature;

pub const getpid = if (@hasField(sys.SYS, "getpid"))
    struct {
        fn getpid() sys.pid_t {
            const rv = sys.syscall0_errno(.getpid);
            return @bitCast(@as(u32, @truncate(rv)));
        }
    }.getpid
else
    sys.missing_feature;

pub const getppid = if (@hasField(sys.SYS, "getppid"))
    struct {
        fn getppid() sys.pid_t {
            const rv = sys.syscall0_errno(.getppid);
            return @bitCast(@as(u32, @truncate(rv)));
        }
    }.getppid
else
    sys.missing_feature;

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
        fn getrlimit(resource: sys.rlimit_t.resource_t, rlp: *sys.rlimit_t) c_int {
            const rv = sys.syscall2_errno(
                .@"getrlimit@2",
                @as(u32, @bitCast(@intFromEnum(resource))),
                @intFromPtr(rlp),
            );
            return @bitCast(@as(u32, @truncate(rv)));
        }
    }.getrlimit
else
    sys.missing_feature;

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
    sys.missing_feature;

pub const getuid = if (@hasField(sys.SYS, "getuid"))
    struct {
        fn getuid() sys.uid_t {
            const rv = sys.syscall0_errno(.getuid);
            return @truncate(rv);
        }
    }.getuid
else
    sys.missing_feature;

pub const lstat = if (hasFeature(.fstatat))
    struct {
        fn lstat(noalias path: [*:0]const u8, noalias info: *sys.stat_t) c_int {
            return fstatat(sys.AT.FDCWD, path, info, .{ .SYMLINK_NOFOLLOW = true });
        }
    }.lstat
else
    sys.missing_feature;

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
    sys.missing_feature;

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
    sys.missing_feature;

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
    sys.missing_feature;

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
    sys.missing_feature;

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
            if (rv != 0) sys.__error().* = @enumFromInt(rv);
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
    sys.missing_feature;

pub const open = if (hasFeature(.openat))
    struct {
        fn open(path: [*:0]const u8, flags: sys.O, mode: sys.mode_t) sys.fd_t {
            return openat(sys.AT.FDCWD, path, flags, mode);
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
    sys.missing_feature;

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
    sys.missing_feature;

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
    sys.missing_feature;

pub const setegid = if (@hasField(sys.SYS, "setegid"))
    struct {
        fn setegid(gid: sys.gid_t) c_int {
            const rv = sys.syscall1_errno(.setegid, gid);
            return @bitCast(@as(u32, @truncate(rv)));
        }
    }.setegid
else
    sys.missing_feature;

pub const seteuid = if (@hasField(sys.SYS, "seteuid"))
    struct {
        fn seteuid(uid: sys.uid_t) c_int {
            const rv = sys.syscall1_errno(.seteuid, uid);
            return @bitCast(@as(u32, @truncate(rv)));
        }
    }.seteuid
else
    sys.missing_feature;

pub const setgid = if (@hasField(sys.SYS, "setgid"))
    struct {
        fn setgid(gid: sys.gid_t) c_int {
            const rv = sys.syscall1_errno(.setgid, gid);
            return @bitCast(@as(u32, @truncate(rv)));
        }
    }.setgid
else
    sys.missing_feature;

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
        fn setrlimit(resource: sys.rlimit_t.resource_t, rlp: *const sys.rlimit_t) c_int {
            const rv = sys.syscall2_errno(
                .@"setrlimit@2",
                @as(u32, @bitCast(@intFromEnum(resource))),
                @intFromPtr(rlp),
            );
            return @bitCast(@as(u32, @truncate(rv)));
        }
    }.setrlimit
else
    sys.missing_feature;

pub const setuid = if (@hasField(sys.SYS, "setuid"))
    struct {
        fn setuid(uid: sys.uid_t) c_int {
            const rv = sys.syscall1_errno(.setuid, uid);
            return @bitCast(@as(u32, @truncate(rv)));
        }
    }.setuid
else
    sys.missing_feature;

pub const stat = if (hasFeature(.fstatat))
    struct {
        fn stat(noalias path: [*:0]const u8, noalias info: *sys.stat_t) c_int {
            return fstatat(sys.AT.FDCWD, path, info, .{});
        }
    }.stat
else
    sys.missing_feature;

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
    sys.missing_feature;

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
    sys.missing_feature;

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
    sys.missing_feature;

pub const PATH_MAX = 1024;
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
pub const pid_t = i32;
pub const rlim_t = i64;
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

pub const O = packed struct(u32) {
    // zig fmt: off
    WRONLY:          bool = false, // open for writing only
    RDWR:            bool = false, // open for reading and writing
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

    _12: u3 = 0,

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

    _: u6 = 0,
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

    pub const ERR = @as(sys.sigaction_t.handler_fn, @ptrFromInt(-1));
    pub const DFL = @as(sys.sigaction_t.handler_fn, @ptrFromInt(0));
    pub const IGN = @as(sys.sigaction_t.handler_fn, @ptrFromInt(1));
    pub const CATCH = @as(sys.sigaction_t.handler_fn, @ptrFromInt(2));
    pub const HOLD = @as(sys.sigaction_t.handler_fn, @ptrFromInt(3));

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

pub const dirent_t = if (@hasField(sys.SYS, "getdirentries@12"))
    extern struct {
        fileno: sys.ino_t,
        off: sys.off_t,
        reclen: u16,
        type: u8,
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
        type: u8,
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
    sys.missing_feature;

pub const timer_t = enum(c_int) {
    RELTIME = 0,
    ABSTIME = 1,
    _,
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
    cur: sys.rlim_t,
    max: sys.rlim_t,

    pub const resource_t = enum(c_int) {
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

        pub const INFINITY: sys.rlim_t = (@as(u64, 1) << 63) - 1;
        pub const SAVED_MAX = INFINITY;
        pub const SAVED_CUR = INFINITY;
    };

    comptime {
        const size = 16;
        if (@sizeOf(@This()) != size) {
            @compileError(std.fmt.comptimePrint("expected size {d} bytes, found {d}", .{ size, @sizeOf(@This()) }));
        }
    }
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
    pub const action_fn = *const fn (sys.SIG, *const sys.siginfo_t, ?*const anyopaque) callconv(.C) void;

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
};

pub const sigset_t = extern struct {
    __bits: [sys.SIG.WORDS]u32 = EMPTY,

    pub fn clear(self: *sigset_t, sig: sys.SIG) void {
        const signo = @intFromEnum(sig);
        std.debug.assert(signo > 0 and signo <= sys.SIG.MAXSIG);
        const idx = @as(u32, @bitCast(signo)) - 1;
        self.__bits[idx >> 5] &= ~(@as(u32, 1) << @as(u5, @truncate(idx)));
    }

    pub fn set(self: *sigset_t, sig: sys.SIG) void {
        const signo = @intFromEnum(sig);
        std.debug.assert(signo > 0 and signo <= sys.SIG.MAXSIG);
        const idx = @as(u32, @bitCast(signo)) - 1;
        self.__bits[idx >> 5] |= @as(u32, 1) << @as(u5, @truncate(idx));
    }

    pub fn assign(self: *sigset_t, other: sigset_t) void {
        @memcpy(&self.__bits, &other.__bits);
    }

    pub fn empty(self: *sigset_t) void {
        self.__bits = EMPTY;
    }

    pub fn fill(self: *sigset_t) void {
        self.__bits = FULL;
    }

    pub fn is_empty(self: sigset_t) bool {
        return std.mem.eql(u32, &self.__bits, &EMPTY);
    }

    pub fn is_full(self: sigset_t) bool {
        return std.mem.eql(u32, &self.__bits, &FULL);
    }

    pub fn is_set(self: sigset_t, sig: sys.SIG) bool {
        const signo = @intFromEnum(sig);
        std.debug.assert(signo > 0 and signo <= sys.SIG.MAXSIG);
        const idx = @as(u32, @bitCast(signo)) - 1;
        const word = self.__bits[idx >> 5];
        return if (word & (@as(u32, 1) << @as(u5, @truncate(idx))) != 0) true else false;
    }

    pub fn and_with(self: *sigset_t, other: sigset_t) void {
        for (&self.__bits, &other.__bits) |*lhs, rhs| lhs.* &= rhs;
    }

    pub fn or_with(self: *sigset_t, other: sigset_t) void {
        for (&self.__bits, &other.__bits) |*lhs, rhs| lhs.* |= rhs;
    }

    const EMPTY = [1]u32{ 0 } ** sys.SIG.WORDS;
    const FULL = [1]u32{ 0xffff_ffff } ** sys.SIG.WORDS;

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

const Feature = std.os.freebsd.Feature(@This());
pub const hasFeature = Feature.hasFeature;
pub const hasFeatures = Feature.hasFeatures;
pub const missing_feature = std.os.freebsd.missing_feature;
