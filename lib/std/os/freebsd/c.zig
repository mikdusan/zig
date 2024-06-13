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
pub extern "c" fn dup(fd: c.fd_t) c_int;
pub extern "c" fn dup2(old: c.fd_t, new: c.fd_t) c_int;
pub extern "c" fn exit(status: c_int) noreturn;
pub extern "c" fn _exit(status: c_int) noreturn;
pub extern "c" fn fcntl(fd: c.fd_t, cmd: c_int, ...) c_int;
pub extern "c" fn fdclosedir(dirp: *c.DIR) c.fd_t;
pub extern "c" fn fdopendir(fd: c.fd_t) ?*c.DIR;
pub extern "c" fn fork() c_int;
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
pub extern "c" fn pipe(fds: *[2]c.fd_t) c_int;
pub extern "c" fn pipe2(fds: *[2]c.fd_t, flags: c.O) c_int;
pub extern "c" fn raise(sig: c.SIG) c_int;
pub extern "c" fn read(fd: c.fd_t, buf: [*]u8, len: usize) isize;
pub extern "c" fn readv(fd: c.fd_t, iov: [*]const c.iovec_t, iovcnt: c_int) isize;
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
pub extern "c" fn sched_yield() c_int;
pub extern "c" fn rmdir(path: [*:0]const u8) c_int;

pub extern "c" fn getresgid(rgid: c.gid_t, egid: c.gid_t) c_int;
pub extern "c" fn getresuid(ruid: c.uid_t, euid: c.uid_t) c_int;

pub extern "c" fn setreuid(ruid: c.uid_t, euid: c.uid_t) c_int;
pub extern "c" fn setregid(rgid: c.gid_t, egid: c.gid_t) c_int;
pub extern "c" fn setresuid(ruid: c.uid_t, euid: c.uid_t, suid: c.uid_t) c_int;
pub extern "c" fn setresgid(rgid: c.gid_t, egid: c.gid_t, sgid: c.gid_t) c_int;

pub extern "c" fn sigprocmask(how: c.sigpm_how_t, noalias set: ?*const c.sigset_t, noalias oset: ?*c.sigset_t) c_int;

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
pub const rlimit_value_t = sys.rlimit_value_t;
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
pub const sigpm_how_t = sys.sigpm_how_t;

//pub extern "c" fn clock_getcpuclockid(pid: c.pid_t, clockid: *c.clockid_t) c_int;
pub const clock_getcpuclockid = if (sys.osintver < 10_000_000)
    struct {
        extern "c" fn clock_getcpuclockid(pid: c.pid_t, clockid: *c.clockid_t) c_int;
    }.clock_getcpuclockid
else
    struct {
        extern "c" fn @"clock_getcpuclockid@@FBSD_1.3"(pid: c.pid_t, clockid: *c.clockid_t) c_int;
    }.@"clock_getcpuclockid@@FBSD_1.3";

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
pub const dl_iterate_phdr_callback = *const fn (info: *c.dl_phdr_info_t, size: usize, data: ?*anyopaque) callconv(.C) c_int;
pub const sf_hdtr_t = sys.sf_hdtr_t;
pub const iovec_t = sys.iovec_t;
pub const iovec_const_t = sys.iovec_const_t;
pub const IOV_MAX = sys.IOV_MAX;
pub const CTL = sys.CTL;
pub const DT = sys.DT;
pub const T = sys.T;
pub const SEEK = sys.SEEK;
pub const NAME_MAX = sys.NAME_MAX;
pub const HOST_NAME_MAX = sys.HOST_NAME_MAX;
pub const stack_t = sys.stack_t;
pub const sockaddr = sys.sockaddr;
pub const in_port_t = sys.in_port_t;
pub const sa_family_t = sys.sa_family_t;
pub const AF = sys.AF;
pub const AI = sys.AI;
pub const IFNAMESIZE = sys.IFNAMESIZE;
pub const FD_CLOEXEC = sys.FD_CLOEXEC;
pub const SO = sys.SO;
pub const SOCK = sys.SOCK;
pub const access_mode_t = sys.access_mode_t;
pub const LOCK = sys.LOCK;
pub const IPPROTO = sys.IPPROTO;
pub const SOL = sys.SOL;
pub const socklen_t = sys.socklen_t;
pub const addrinfo = sys.addrinfo;
pub const SHUT = sys.SHUT;
pub const kinfo_file = sys.kinfo_file;
pub const cap_rights = sys.cap_rights;
pub const W = sys.W;
pub const pollfd = sys.pollfd;
pub const POLL = sys.POLL;
pub const nfds_t = sys.nfds_t;
pub const umtx_op_t = sys.umtx_op_t;
pub const umtx_time_t = sys.umtx_time_t;

pub extern "c" fn sigaltstack(ss: ?*c.stack_t, oss: ?*c.stack_t) c_int;

pub extern "c" fn chdir(path: [*:0]const u8) c_int;
pub extern "c" fn fchdir(fd: c.fd_t) c_int;
pub extern "c" fn execve(path: [*:0]const u8, argv: [*:null]const ?[*:0]const u8, envp: [*:null]const ?[*:0]const u8) c_int;

pub extern "c" fn memfd_create(name: [*:0]const u8, flags: c.O) c_int;
pub extern "c" fn copy_file_range(in: c.fd_t, inoffp: ?*c.off_t, out: fd_t, outoffp: ?*c.off_t, len: usize, flags: u32) usize;

pub extern "c" fn access(path: [*:0]const u8, mode: c.access_mode_t) c_int;
pub extern "c" fn faccessat(fd: c.fd_t, path: [*:0]const u8, mode: access_mode_t, flag: c.AT) c_int;
pub extern "c" fn getcwd(buf: [*]u8, size: usize) ?[*]u8;

pub extern "c" fn flock(fd: c.fd_t, operation: c_int) c_int;
pub extern "c" fn ftruncate(fd: c.fd_t, length: c.off_t) c_int;
pub extern "c" fn ioctl(fd: c.fd_t, request: c_ulong, ...) c_int;
pub extern "c" fn rename(from: [*:0]const u8, to: [*:0]const u8) c_int;
pub extern "c" fn renameat(fromfd: c.fd_t, from: [*:0]const u8, tofd: c.fd_t, to: [*:0]const u8) c_int;
pub extern "c" fn lseek(fd: c.fd_t, offset: c.off_t, whence: c.SEEK) c.off_t;
pub extern "c" fn truncate(path: [*:0]const u8, length: c.off_t) c_int;
pub extern "c" fn unlink(path: [*:0]const u8) c_int;
pub extern "c" fn unlinkat(fd: c.fd_t, path: [*:0]const u8, flags: c.AT) c_int;

pub extern "c" fn readlink(noalias path: [*:0]const u8, noalias buf: [*]u8, len: usize) isize;
pub extern "c" fn readlinkat(fd: c.fd_t, noalias path: [*:0]const u8, noalias buf: [*]u8, len: usize) isize;

pub extern "c" fn chmod(path: [*:0]const u8, mode: c.mode_t) c_int;
pub extern "c" fn fchmod(fd: c.fd_t, mode: c.mode_t) c_int;
pub extern "c" fn fchmodat(fd: c.fd_t, path: [*:0]const u8, mode: c.mode_t, flags: c.AT) c_int;

pub extern "c" fn chown(path: [*:0]const u8, owner: c.uid_t, group: c.gid_t) c_int;
pub extern "c" fn fchown(fd: c.fd_t, owner: c.uid_t, group: c.gid_t) c_int;
pub extern "c" fn fchownat(fd: c.fd_t, path: [*:0]const u8, owner: c.uid_t, group: c.gid_t, flags: c.AT) c_int;

pub extern "c" fn umask(mode: c.mode_t) c.mode_t;

pub const FILE = opaque {};

pub extern "c" fn fclose(stream: *FILE) c_int;
pub extern "c" fn fdclose(stream: *FILE, fdp: *c.fd_t) c_int;
pub extern "c" fn fopen(noalias path: [*:0]const u8, noalias mode: [*:0]const u8) ?*FILE;
pub extern "c" fn fread(noalias ptr: [*]u8, size: usize, nmemb: usize, noalias stream: *FILE) usize;
pub extern "c" fn fwrite(noalias ptr: [*]const u8, size: usize, nmemb: usize, noalias stream: *FILE) usize;

pub extern "c" fn pread(fd: c.fd_t, buf: [*]u8, len: usize, offset: c.off_t) isize;
pub extern "c" fn preadv(fd: c.fd_t, iov: [*]const c.iovec_t, iovcnt: c_uint, offset: c.off_t) isize;
pub extern "c" fn pwrite(fd: c.fd_t, buf: [*]const u8, len: usize, offset: c.off_t) isize;
pub extern "c" fn pwritev(fd: c.fd_t, iov: [*]const c.iovec_const_t, iovcnt: c_int, offset: c.off_t) isize;

pub extern "c" fn sysctl(name: [*]const c_int, namelen: c_uint, oldp: ?*anyopaque, oldlenp: ?*usize, newp: ?*anyopaque, newlen: usize) c_int;
pub extern "c" fn sysctlbyname(name: [*:0]const u8, oldp: ?*anyopaque, oldlenp: ?*usize, newp: ?*anyopaque, newlen: usize) c_int;
pub extern "c" fn sysctlnametomib(name: [*:0]const u8, mibp: ?*c_int, sizep: ?*usize) c_int;

pub const pthread_key_t = c_int;

pub extern "c" fn pthread_attr_destroy(attr: *c.pthread_attr_t) c.E;
pub extern "c" fn pthread_attr_init(attr: *c.pthread_attr_t) c.E;
pub extern "c" fn pthread_attr_setguardsize(attr: *c.pthread_attr_t, guardsize: usize) c.E;
pub extern "c" fn pthread_attr_setstack(attr: *c.pthread_attr_t, stackaddr: *anyopaque, stacksize: usize) c.E;
pub extern "c" fn pthread_attr_setstacksize(attr: *c.pthread_attr_t, stacksize: usize) c.E;
pub extern "c" fn pthread_detach(thread: c.pthread_t) c.E;
pub extern "c" fn pthread_get_name_np(thread: c.pthread_t, name: [*:0]u8, len: usize) void;
pub extern "c" fn pthread_getspecific(key: c.pthread_key_t) ?*anyopaque;
pub extern "c" fn pthread_getthreadid_np() c_int;
pub extern "c" fn pthread_join(thread: c.pthread_t, retval: ?*?*anyopaque) c.E;
pub extern "c" fn pthread_key_create(key: *c.pthread_key_t, destructor: ?*const fn (value: *anyopaque) callconv(.C) void) c.E;
pub extern "c" fn pthread_self() c.pthread_t;
pub extern "c" fn pthread_set_name_np(thread: c.pthread_t, name: [*:0]const u8) void;
pub extern "c" fn pthread_setspecific(key: c.pthread_key_t, value: ?*const anyopaque) c_int;
pub extern "c" fn pthread_sigmask(how: c_int, noalias set: *const c.sigset_t, noalias oset: *c.sigset_t) c_int;

pub extern "c" fn pthread_atfork(
    prepare: ?*const fn () callconv(.C) void,
    parent: ?*const fn () callconv(.C) void,
    child: ?*const fn () callconv(.C) void,
) c_int;

pub extern "c" fn pthread_create(
    noalias thread: *c.pthread_t,
    noalias attr: ?*const c.pthread_attr_t,
    start_routine: *const fn (?*anyopaque) callconv(.C) ?*anyopaque,
    noalias arg: ?*anyopaque,
) c.E;

pub const pthread_attr_t = extern struct {
    inner: ?*anyopaque = null,
};

pub const pthread_cond_t = extern struct {
    inner: ?*anyopaque = null,
};

pub const pthread_mutex_t = extern struct {
    inner: ?*anyopaque = null,
};

pub const pthread_rwlock_t = extern struct {
    ptr: ?*anyopaque = null,
};

pub const PTHREAD_MUTEX_INITIALIZER = pthread_mutex_t{};
pub extern "c" fn pthread_mutex_destroy(mutex: *pthread_mutex_t) c.E;
pub extern "c" fn pthread_mutex_lock(mutex: *pthread_mutex_t) c.E;
pub extern "c" fn pthread_mutex_trylock(mutex: *pthread_mutex_t) c.E;
pub extern "c" fn pthread_mutex_unlock(mutex: *pthread_mutex_t) c.E;

pub const PTHREAD_COND_INITIALIZER = pthread_cond_t{};
pub extern "c" fn pthread_cond_broadcast(cond: *pthread_cond_t) c.E;
pub extern "c" fn pthread_cond_destroy(cond: *pthread_cond_t) c.E;
pub extern "c" fn pthread_cond_signal(cond: *pthread_cond_t) c.E;
pub extern "c" fn pthread_cond_timedwait(noalias cond: *pthread_cond_t, noalias mutex: *pthread_mutex_t, noalias abstime: *const c.timespec) c.E;
pub extern "c" fn pthread_cond_wait(noalias cond: *pthread_cond_t, noalias mutex: *pthread_mutex_t) c.E;

pub extern "c" fn pthread_rwlock_destroy(rwl: *c.pthread_rwlock_t) c.E;
pub extern "c" fn pthread_rwlock_rdlock(rwl: *c.pthread_rwlock_t) c.E;
pub extern "c" fn pthread_rwlock_tryrdlock(rwl: *c.pthread_rwlock_t) c.E;
pub extern "c" fn pthread_rwlock_trywrlock(rwl: *c.pthread_rwlock_t) c.E;
pub extern "c" fn pthread_rwlock_unlock(rwl: *c.pthread_rwlock_t) c.E;
pub extern "c" fn pthread_rwlock_wrlock(rwl: *c.pthread_rwlock_t) c.E;

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

pub const umtx_op = struct {
    extern "c" fn _umtx_op(obj: usize, op: c.umtx_op_t, val: usize, uaddr: usize, uaddr2: usize) c_int;
}._umtx_op;

pub extern "c" fn malloc(size: usize) ?*anyopaque;
pub extern "c" fn realloc(ptr: ?*anyopaque, size: usize) ?*anyopaque;
pub extern "c" fn free(ptr: ?*anyopaque) void;

pub const max_align_t = extern struct {
    a: c_longlong,
    b: c_longdouble,
};

pub extern "c" fn getaddrinfo(
    noalias host: [*:0]const u8,
    noalias service: [*:0]const u8,
    noalias hints: ?*const c.addrinfo,
    noalias res: *?*c.addrinfo,
) c.EAI;

pub extern "c" fn freeaddrinfo(ai: *c.addrinfo) void;

pub const EAI = enum(c_int) {
    /// address family for hostname not supported
    ADDRFAMILY = 1,

    /// name could not be resolved at this time
    AGAIN = 2,

    /// flags parameter had an invalid value
    BADFLAGS = 3,

    /// non-recoverable failure in name resolution
    FAIL = 4,

    /// address family not recognized
    FAMILY = 5,

    /// memory allocation failure
    MEMORY = 6,

    /// no address associated with hostname
    NODATA = 7,

    /// name does not resolve
    NONAME = 8,

    /// service not recognized for socket type
    SERVICE = 9,

    /// intended socket type was not recognized
    SOCKTYPE = 10,

    /// system error returned in errno
    SYSTEM = 11,

    /// invalid value for hints
    BADHINTS = 12,

    /// resolved protocol is unknown
    PROTOCOL = 13,

    /// argument buffer overflow
    OVERFLOW = 14,

    _,
};

pub extern "c" fn accept(sockfd: c.fd_t, noalias addr: ?*c.sockaddr, noalias addrlen: ?*c.socklen_t) c_int;
pub extern "c" fn accept4(sockfd: c.fd_t, noalias addr: ?*c.sockaddr, noalias addrlen: ?*c.socklen_t, flags: c_uint) c_int;
pub extern "c" fn bind(socket: c.fd_t, address: ?*const c.sockaddr, address_len: c.socklen_t) c_int;
pub extern "c" fn connect(sockfd: c.fd_t, sock_addr: *const c.sockaddr, addrlen: c.socklen_t) c_int;
pub extern "c" fn gethostname(name: [*]u8, len: usize) c_int;
pub extern "c" fn getpeername(sockfd: c.fd_t, noalias addr: *c.sockaddr, noalias addrlen: *c.socklen_t) c_int;
pub extern "c" fn getsockname(sockfd: c.fd_t, noalias addr: *c.sockaddr, noalias addrlen: *c.socklen_t) c_int;
pub extern "c" fn getsockopt(sockfd: c.fd_t, level: i32, optname: u32, noalias optval: ?*anyopaque, noalias optlen: *c.socklen_t) c_int;
pub extern "c" fn listen(sockfd: c.fd_t, backlog: c_uint) c_int;
pub extern "c" fn recv(sockfd: c.fd_t, arg1: ?*anyopaque, arg2: usize, arg3: c_int) isize;
pub extern "c" fn recvmsg(sockfd: c.fd_t, msg: *c.msghdr, flags: c_int) isize;
pub extern "c" fn recvmmsg(sockfd: c.fd_t, noalias msgvec: [*]const c.msghdr, vlen: usize, flags: c_int, noalias timeout: ?*const c.timespec_t) isize;
pub extern "c" fn send(sockfd: c.fd_t, buf: *const anyopaque, len: usize, flags: u32) isize;
pub extern "c" fn sendmsg(sockfd: c.fd_t, msg: *const c.msghdr_const, flags: u32) isize;
pub extern "c" fn sendmmsg(sockfd: c.fd_t, noalias msgvec: [*]const c.msghdr_const, vlen: usize, flags: c_int) isize;
pub extern "c" fn sethostname(name: [*]const u8, len: usize) c_int;
pub extern "c" fn setsockopt(sockfd: c.fd_t, level: i32, optname: u32, optval: ?*const anyopaque, optlen: c.socklen_t) c_int;
pub extern "c" fn shutdown(sockfd: c.fd_t, how: c.SHUT) c_int;
pub extern "c" fn socket(domain: c_uint, sock_type: c_uint, protocol: c_uint) c_int;
pub extern "c" fn socketpair(domain: c_uint, sock_type: c_uint, protocol: c_uint, sv: *[2]c.fd_t) c_int;

pub extern "c" fn recvfrom(
    sockfd: c.fd_t,
    noalias buf: *anyopaque,
    len: usize,
    flags: u32,
    noalias src_addr: ?*c.sockaddr,
    noalias addrlen: ?*c.socklen_t,
) isize;

pub extern "c" fn sendto(
    sockfd: c.fd_t,
    buf: *const anyopaque,
    len: usize,
    flags: u32,
    dest_addr: ?*const c.sockaddr,
    addrlen: c.socklen_t,
) isize;

pub extern "c" fn dlopen(path: [*:0]const u8, mode: c_int) ?*anyopaque;
pub extern "c" fn dlclose(handle: *anyopaque) c_int;
pub extern "c" fn dlsym(noalias handle: ?*anyopaque, noalias symbol: [*:0]const u8) ?*anyopaque;
pub extern "c" fn dlerror() ?[*:0]u8;

pub const RTLD = struct {
    /// Bind function calls lazily.
    pub const LAZY = 1;
    /// Bind function calls immediately.
    pub const NOW = 2;
    pub const MODEMASK = 0x3;
    /// Make symbols globally available.
    pub const GLOBAL = 0x100;
    /// Opposite of GLOBAL, and the default.
    pub const LOCAL = 0;
    /// Trace loaded objects and exit.
    pub const TRACE = 0x200;
    /// Do not remove members.
    pub const NODELETE = 0x01000;
    /// Do not load if not already loaded.
    pub const NOLOAD = 0x02000;
};

pub extern "c" fn sync() void;
pub extern "c" fn fsync(fd: c.fd_t) c_int;
pub extern "c" fn fdatasync(fd: c.fd_t) c_int;

pub extern "c" fn waitpid(pid: c.pid_t, status: ?*c_int, options: c_int) c.pid_t;
pub extern "c" fn wait4(pid: c.pid_t, status: ?*c_int, options: c_int, rusage: ?*c.rusage_t) c.pid_t;

pub extern "c" fn poll(fds: [*]c.pollfd, nfds: c.nfds_t, timeout: c_int) c_int;
pub extern "c" fn ppoll(fds: [*]c.pollfd, nfds: c.nfds_t, noalias timeout: ?*const c.timespec_v, noalias sigmask: ?*const c.sigset_t) c_int;


pub extern "c" fn thr_kill(id: c_long, sig: c.SIG) c_int;
pub extern "c" fn thr_self(id: *c_long) c_int;

