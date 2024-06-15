//! This file provides the system interface to FreeBSD, matching
//! those that are provided by system libc, whether or not libc
//! is linked. The following abstractions are made:
//!
//! * Work around kernel bugs and limitations.
//! * Implement syscalls in the same way that libc functions;
//!   e.g. `open` uses the `openat` call when available.
//! * Do not support POSIX thread cancellation.
const std = @import("../../std.zig");
const builtin = @import("builtin");
const sys = std.os.freebsd.sys;
const syscall = @import("sys/syscall.zig");

pub const SYS = syscall.SYS;

pub const syscall0 = syscall.syscall0;
pub const syscall1 = syscall.syscall1;
pub const syscall2 = syscall.syscall2;
pub const syscall3 = syscall.syscall3;
pub const syscall4 = syscall.syscall4;
pub const syscall5 = syscall.syscall5;
pub const syscall6 = syscall.syscall6;

pub const Result = syscall.Result;

// compute os integer version
// MAJOR * 1_000_000 + MINOR * 1_000 + POINT
pub const osintver = b: {
    const sv = builtin.os.version_range.semver.min;
    break :b sv.major * 1_000_000 + sv.minor * 1_000 + sv.patch;
};

pub const close = if (@hasField(sys.SYS, "close"))
    struct {
        fn close(fd: sys.fd_t) sys.Result(sys.fd_t) {
            return @bitCast(sys.syscall1(.close, @as(u32, @bitCast(fd))));
        }
    }.close
else
    sys.missing_feature;

pub const creat = if (hasFeature(.openat))
    struct {
        fn creat(path: [*:0]const u8, mode: sys.mode_t) sys.Result(sys.fd_t) {
            return openat(sys.AT.FDCWD, path, .{ .WRONLY = true, .CREAT = true, .TRUNC = true }, mode);
        }
    }.creat
else if (hasFeature(.open))
    struct {
        fn creat(path: [*:0]const u8, mode: sys.mode_t) sys.Result(sys.fd_t) {
            return open(path, .{ .WRONLY = true, .CREAT = true, .TRUNC = true }, mode);
        }
    }.creat
else
    sys.missing_feature;

pub const getdents = if (hasFeature(.getdirentries))
    struct {
        const len_t = @typeInfo(@TypeOf(getdirentries)).Fn.params[2].type.?;

        fn getdents(fd: sys.fd_t, buf: [*]u8, len: len_t) sys.Result(isize) {
            return getdirentries(fd, buf, len, null);
        }
    }.getdents
else
    sys.missing_feature;

pub const getdirentries = if (@hasField(sys.SYS, "getdirentries_k12"))
    struct {
        fn getdirentries(fd: sys.fd_t, buf: [*]u8, len: usize, basep: ?*sys.off_t) sys.Result(isize) {
            return @bitCast(sys.syscall4(.getdirentries_k12, @as(u32, @bitCast(fd)), @intFromPtr(buf), len, @intFromPtr(basep)));
        }
    }.getdirentries
else if (@hasField(sys.SYS, "getdirentries_k3"))
    struct {
        fn getdirentries(fd: sys.fd_t, buf: [*]u8, len: c_uint, basep: ?*c_long) sys.Result(c_int) {
            return @bitCast(sys.syscall4(.getdirentries_k3, @as(u32, @bitCast(fd)), @intFromPtr(buf), len, @intFromPtr(basep)));
        }
    }.getdirentries
else if (@hasField(sys.SYS, "getdirentries"))
    struct {
        fn getdirentries(fd: sys.fd_t, buf: [*]u8, len: c_uint, basep: ?*c_long) sys.Result(c_int) {
            return @bitCast(sys.syscall4(.getdirentries, @as(u32, @bitCast(fd)), @intFromPtr(buf), len, @intFromPtr(basep)));
        }
    }.getdirentries
else
    sys.missing_feature;

pub const getpid = if (@hasField(sys.SYS, "getpid"))
    struct {
        fn getpid() sys.Result(sys.pid_t) {
            return @bitCast(sys.syscall0(.getpid));
        }
    }.getpid
else
    sys.missing_feature;

pub const getppid = if (@hasField(sys.SYS, "getppid"))
    struct {
        fn getppid() sys.Result(sys.pid_t) {
            return @bitCast(sys.syscall0(.getppid));
        }
    }.getppid
else
    sys.missing_feature;

pub const getuid = if (@hasField(sys.SYS, "getuid"))
    struct {
        fn getuid() sys.Result(sys.uid_t) {
            return @bitCast(sys.syscall0(.getuid));
        }
    }.getuid
else
    sys.missing_feature;

pub const geteuid = if (@hasField(sys.SYS, "geteuid"))
    struct {
        fn geteuid() sys.Result(sys.uid_t) {
            return @bitCast(sys.syscall0(.geteuid));
        }
    }.geteuid
else
    sys.missing_feature;

pub const getgid = if (@hasField(sys.SYS, "getgid"))
    struct {
        fn getgid() sys.Result(sys.gid_t) {
            return @bitCast(sys.syscall0(.getgid));
        }
    }.getgid
else
    sys.missing_feature;

pub const getegid = if (@hasField(sys.SYS, "getegid"))
    struct {
        fn getegid() sys.Result(sys.gid_t) {
            return @bitCast(sys.syscall0(.getegid));
        }
    }.getegid
else
    sys.missing_feature;

pub const mkdir = if (@hasField(sys.SYS, "mkdir"))
    struct {
        fn mkdir(path: [*:0]const u8, mode: sys.mode_t) sys.Result(void) {
            return @bitCast(sys.syscall2(.mkdir, @intFromPtr(path), @as(u16, @bitCast(mode))));
        }
    }.mkdir
else
    sys.missing_feature;

pub const mkdirat = if (@hasField(sys.SYS, "mkdirat"))
    struct {
        fn mkdirat(fd: sys.fd_t, path: [*:0]const u8, mode: sys.mode_t) sys.Result(void) {
            return @bitCast(sys.syscall3(.mkdirat, @as(u32, @bitCast(fd)), @intFromPtr(path), @as(u16, @bitCast(mode))));
        }
    }.mkdirat
else
    sys.missing_feature;

pub const open = if (hasFeature(.openat))
    struct {
        fn open(path: [*:0]const u8, flags: sys.O, mode: sys.mode_t) sys.Result(sys.fd_t) {
            return openat(sys.AT.FDCWD, path, flags, mode);
        }
    }.open
else if (@hasField(sys.SYS, "open"))
    struct {
        fn open(path: [*:0]const u8, flags: sys.O, mode: sys.mode_t) sys.Result(sys.fd_t) {
            return @bitCast(sys.syscall3(.open, @intFromPtr(path), @as(u32, @bitCast(flags)), @as(u16, @bitCast(mode))));
        }
    }.open
else
    sys.missing_feature;

pub const openat = if (@hasField(sys.SYS, "openat"))
    struct {
        fn openat(fd: sys.fd_t, path: [*:0]const u8, flags: sys.O, mode: sys.mode_t) sys.Result(sys.fd_t) {
            return @bitCast(sys.syscall4(.openat, @as(u32, @bitCast(fd)), @intFromPtr(path), @as(u32, @bitCast(flags)), @as(u16, @bitCast(mode))));
        }
    }.openat
else
    sys.missing_feature;

pub const read = if (@hasField(sys.SYS, "read"))
    struct {
        fn read(fd: sys.fd_t, buf: [*]u8, len: usize) sys.Result(isize) {
            return @bitCast(sys.syscall3(.read, @as(u32, @bitCast(fd)), @intFromPtr(buf), len));
        }
    }.read
else
    sys.missing_feature;

pub const setuid = if (@hasField(sys.SYS, "setuid"))
    struct {
        fn setuid(uid: sys.uid_t) sys.Result(void) {
            return @bitCast(sys.syscall1(.setuid, uid));
        }
    }.setuid
else
    sys.missing_feature;

pub const seteuid = if (@hasField(sys.SYS, "seteuid"))
    struct {
        fn seteuid(uid: sys.uid_t) sys.Result(void) {
            return @bitCast(sys.syscall1(.seteuid, uid));
        }
    }.seteuid
else
    sys.missing_feature;

pub const setgid = if (@hasField(sys.SYS, "setgid"))
    struct {
        fn setgid(gid: sys.gid_t) sys.Result(void) {
            return @bitCast(sys.syscall1(.setgid, gid));
        }
    }.setgid
else
    sys.missing_feature;

pub const setegid = if (@hasField(sys.SYS, "setegid"))
    struct {
        fn setegid(gid: sys.gid_t) sys.Result(void) {
            return @bitCast(sys.syscall1(.setegid, gid));
        }
    }.setegid
else
    sys.missing_feature;

pub const write = if (@hasField(sys.SYS, "write"))
    struct {
        fn write(fd: sys.fd_t, buf: [*]const u8, len: usize) sys.Result(isize) {
            return @bitCast(sys.syscall3(.write, @as(u32, @bitCast(fd)), @intFromPtr(buf), len));
        }
    }.write
else
    sys.missing_feature;

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

pub const fd_t = c_int;
pub const gid_t = u32;
pub const ino_t = usize;
pub const off_t = isize;
pub const pid_t = i32;
pub const uid_t = u32;

pub const AT = packed struct(u32) {
    // zig fmt: off
    _1: u6 = 0,
    EACCESS:          bool = false,
    SYMLINK_NOFOLLOW: bool = false,
    SYMLINK_FOLLOW:   bool = false,
    REMOVEDIR:        bool = false,
    _11: u1 = 0,
    RESOLVE_BENEATH:  bool = false,
    EMPTY_PATH:       bool = false,
    // zig fmt: on

    pub const FDCWD: sys.fd_t = -100;
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

pub const dirent_t = extern struct {
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
};

pub const mode_t = packed struct(u16) {
    // zig fmt: off
    XOTH: bool = false, // X for other
    WOTH: bool = false, // W for other
    ROTH: bool = false, // R for other

    XGRP: bool = false, // X for group
    WGRP: bool = false, // W for group
    RGRP: bool = false, // R for group

    XUSR: bool = false, // X for owner
    WUSR: bool = false, // W for owner
    RUSR: bool = false, // R for owner

    SVTX: bool = false, // sticky bit
    SGID: bool = false, // set group id on execution
    SUID: bool = false, // set user id on execution

    _: u4 = 0,
    // zig fmt: on

    pub const default_file: mode_t = .{
        .RUSR = true,
        .WUSR = true,
        .RGRP = true,
        .WGRP = true,
        .ROTH = true,
        .WOTH = true,
    };

    pub const default_dir: mode_t = .{
        .RUSR = true,
        .WUSR = true,
        .XUSR = true,
        .RGRP = true,
        .WGRP = true,
        .XGRP = true,
        .ROTH = true,
        .WOTH = true,
        .XOTH = true,
    };
};

const Feature = std.os.freebsd.Feature(@This());
pub const hasFeature = Feature.hasFeature;
pub const hasFeatures = Feature.hasFeatures;
pub const missing_feature = Feature.missing_feature;
