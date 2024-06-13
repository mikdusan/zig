const std = @import("../../../std.zig");
const builtin = @import("builtin");
const sys = std.os.freebsd.sys;

pub const osintver = sys.osintver;

// generated syscall enum
// - see sys_tab for names
// - names/syscalls for os version greater than target are absent
pub const SYS = SYS: {
    // collect syscalls up to and including osintver
    var list: [sys_tab_num_max]std.builtin.Type.EnumField = undefined;
    var slot = 0;
    for (sys_tab) |row| {
        if (row[2] > osintver) continue;
        list[slot] = .{ .name = @tagName(row[1]), .value = row[0] };
        slot += 1;
    }

    break :SYS @Type(.{
        .Enum = .{
            .tag_type = usize,
            .fields = list[0..slot],
            .decls = &.{},
            .is_exhaustive = true,
        },
    });
};

// FreeBSD has a stable syscall ABI but the naming in syscall.h
// is not stable and periodically renames calls. Our policy is
// to suffix conflicting names with "@MAJOR" where MAJOR is the
// major freebsd version for which the call became available.
//
// e.g. "swapoff@5" and "swapoff@13"
//
// Such conflicts are rare and since 1.0 it is sufficient to
// use only the major version for naming conflicts.
//
// Note we do not follow the syscall.h naming nodel which
// deprecated the older name by renaming it. This is risky
// because it defers incompatibility issues to runtime.
//
// Derived from sys/sys/syscall.h from 1.0 → 14.1.0 .
const sys_tab = .{
    // fields:
    //   0: syscall num
    //   1: name
    //   2: osintver

    // zig fmt: off
    .{   0, .syscall,                   2_000_000 },
    .{   1, .exit,                      1_000_000 },
    .{   2, .fork,                      1_000_000 },
    .{   3, .read,                      1_000_000 },
    .{   4, .write,                     1_000_000 },
    .{   5, .open,                      1_000_000 },
    .{   6, .close,                     1_000_000 },
    .{   7, .wait4,                     1_000_000 },
    .{   9, .link,                      1_000_000 },
    .{  10, .unlink,                    1_000_000 },
    .{  12, .chdir,                     1_000_000 },
    .{  13, .fchdir,                    1_000_000 },
    .{  14, .mknod,                     1_000_000 },
    .{  15, .chmod,                     1_000_000 },
    .{  16, .chown,                     1_000_000 },
    .{  17, .@"break",                  1_000_000 },
    .{  18, .@"getfsstat@1",            1_000_000 },
    .{  19, .@"lseek@1",                1_000_000 },
    .{  20, .getpid,                    1_000_000 },
    .{  21, .mount,                     1_000_000 },
    .{  22, .unmount,                   1_000_000 },
    .{  23, .setuid,                    1_000_000 },
    .{  24, .getuid,                    1_000_000 },
    .{  25, .geteuid,                   1_000_000 },
    .{  26, .ptrace,                    1_000_000 },
    .{  27, .recvmsg,                   1_000_000 },
    .{  28, .sendmsg,                   1_000_000 },
    .{  29, .recvfrom,                  1_000_000 },
    .{  30, .accept,                    1_000_000 },
    .{  31, .getpeername,               1_000_000 },
    .{  32, .getsockname,               1_000_000 },
    .{  33, .access,                    1_000_000 },
    .{  34, .chflags,                   1_000_000 },
    .{  35, .fchflags,                  1_000_000 },
    .{  36, .sync,                      1_000_000 },
    .{  37, .kill,                      1_000_000 },
    .{  38, .@"stat@1",                 1_000_000 },
    .{  39, .getppid,                   1_000_000 },
    .{  40, .@"lstat@1",                1_000_000 },
    .{  41, .dup,                       1_000_000 },
    .{  42, .pipe,                      1_000_000 },
    .{  43, .getegid,                   1_000_000 },
    .{  44, .profil,                    1_000_000 },
    .{  45, .ktrace,                    1_000_000 },
    .{  46, .@"sigaction@1",            1_000_000 },
    .{  47, .getgid,                    1_000_000 },
    .{  48, .@"sigprocmask@1",          1_000_000 },
    .{  49, .getlogin,                  1_000_000 },
    .{  50, .setlogin,                  1_000_000 },
    .{  51, .acct,                      1_000_000 },
    .{  52, .@"sigpending@1",           1_000_000 },
    .{  53, .sigaltstack,               1_000_000 },
    .{  54, .ioctl,                     1_000_000 },
    .{  55, .reboot,                    1_000_000 },
    .{  56, .revoke,                    1_000_000 },
    .{  57, .symlink,                   1_000_000 },
    .{  58, .readlink,                  1_000_000 },
    .{  59, .execve,                    1_000_000 },
    .{  60, .umask,                     1_000_000 },
    .{  61, .chroot,                    1_000_000 },
    .{  62, .@"fstat@1",                1_000_000 },
    .{  63, .getkerninfo,               1_000_000 },
    .{  64, .getpagesize,               1_000_000 },
    .{  65, .msync,                     1_000_000 },
    .{  66, .vfork,                     1_000_000 },
    .{  69, .sbrk,                      1_000_000 },
    .{  70, .sstk,                      1_000_000 },
    .{  71, .@"mmap@1",                 1_000_000 },
    .{  72, .vadvise,                   1_000_000 },
    .{  73, .munmap,                    1_000_000 },
    .{  74, .mprotect,                  1_000_000 },
    .{  75, .madvise,                   1_000_000 },
    .{  78, .mincore,                   1_000_000 },
    .{  79, .getgroups,                 1_000_000 },
    .{  80, .setgroups,                 1_000_000 },
    .{  81, .getpgrp,                   1_000_000 },
    .{  82, .setpgid,                   1_000_000 },
    .{  83, .setitimer,                 1_000_000 },
    .{  85, .swapon,                    1_000_000 },
    .{  86, .getitimer,                 1_000_000 },
    .{  87, .gethostname,               1_000_000 },
    .{  88, .sethostname,               1_000_000 },
    .{  89, .getdtablesize,             1_000_000 },
    .{  90, .dup2,                      1_000_000 },
    .{  92, .fcntl,                     1_000_000 },
    .{  93, .select,                    1_000_000 },
    .{  95, .fsync,                     1_000_000 },
    .{  96, .setpriority,               1_000_000 },
    .{  97, .socket,                    1_000_000 },
    .{  98, .connect,                   1_000_000 },
    .{ 100, .getpriority,               1_000_000 },
    .{ 103, .@"sigreturn@1",            1_000_000 },
    .{ 104, .bind,                      1_000_000 },
    .{ 105, .setsockopt,                1_000_000 },
    .{ 106, .listen,                    1_000_000 },
    .{ 111, .@"sigsuspend@1",           1_000_000 },
    .{ 112, .sigstack,                  1_000_000 },
    .{ 115, .vtrace,                    1_000_000 },
    .{ 116, .gettimeofday,              1_000_000 },
    .{ 117, .getrusage,                 1_000_000 },
    .{ 118, .getsockopt,                1_000_000 },
    .{ 119, .resuba,                    1_000_000 },
    .{ 120, .readv,                     1_000_000 },
    .{ 121, .writev,                    1_000_000 },
    .{ 122, .settimeofday,              1_000_000 },
    .{ 123, .fchown,                    1_000_000 },
    .{ 124, .fchmod,                    1_000_000 },
    .{ 126, .setreuid,                  1_000_000 },
    .{ 127, .setregid,                  1_000_000 },
    .{ 128, .rename,                    1_000_000 },
    .{ 129, .@"truncate@1",             1_000_000 },
    .{ 130, .@"ftruncate@1",            1_000_000 },
    .{ 131, .flock,                     1_000_000 },
    .{ 132, .mkfifo,                    1_000_000 },
    .{ 133, .sendto,                    1_000_000 },
    .{ 134, .shutdown,                  1_000_000 },
    .{ 135, .socketpair,                1_000_000 },
    .{ 136, .mkdir,                     1_000_000 },
    .{ 137, .rmdir,                     1_000_000 },
    .{ 138, .utimes,                    1_000_000 },
    .{ 140, .adjtime,                   1_000_000 },
    .{ 142, .gethostid,                 1_000_000 },
    .{ 143, .sethostid,                 1_000_000 },
    .{ 144, .@"getrlimit@1",            1_000_000 },
    .{ 145, .@"setrlimit@1",            1_000_000 },
    .{ 147, .setsid,                    1_000_000 },
    .{ 148, .quotactl,                  1_000_000 },
    .{ 154, .nlm_syscall,               6_004_000 },
    .{ 155, .nfssvc,                    1_000_000 },
    .{ 156, .@"getdirentries@1",        1_000_000 },
    .{ 157, .@"statfs@1",               1_000_000 },
    .{ 158, .@"fstatfs@1",              1_000_000 },
    .{ 160, .async_daemon,              1_000_000 },
    .{ 161, .getfh,                     1_000_000 },
    .{ 162, .getdomainname,             1_000_000 },
    .{ 163, .setdomainname,             1_000_000 },
    .{ 164, .uname,                     1_000_000 },
    .{ 165, .sysarch,                   1_001_000 },
    .{ 166, .rtprio,                    2_000_000 },
    .{ 169, .semsys,                    1_001_000 },
    .{ 170, .msgsys,                    1_001_000 },
    .{ 171, .shmsys,                    1_000_000 },
    .{ 173, .@"pread@3",                3_002_000 },
    .{ 174, .@"pwrite@3",               3_002_000 },
    .{ 175, .@"ntp_gettime@1",          1_001_005 },
    .{ 176, .ntp_adjtime,               1_001_005 },
    .{ 177, .vm_allocate,               1_001_000 },
    .{ 178, .vm_deallocate,             1_001_000 },
    .{ 179, .vm_inherit,                1_001_000 },
    .{ 180, .vm_protect,                1_001_000 },
    .{ 181, .setgid,                    1_000_000 },
    .{ 182, .setegid,                   1_000_000 },
    .{ 183, .seteuid,                   1_000_000 },
    .{ 184, .lfs_bmapv,                 2_000_000 },
    .{ 185, .lfs_markv,                 2_000_000 },
    .{ 186, .lfs_segclean,              2_000_000 },
    .{ 187, .lfs_segwait,               2_000_000 },
    .{ 188, .@"stat@2",                 2_000_000 },
    .{ 189, .@"fstat@2",                2_000_000 },
    .{ 190, .@"lstat@2",                2_000_000 },
    .{ 191, .pathconf,                  2_000_000 },
    .{ 192, .fpathconf,                 2_000_000 },
    .{ 194, .@"getrlimit@2",            2_000_000 },
    .{ 195, .@"setrlimit@2",            2_000_000 },
    .{ 196, .@"getdirentries@2",        2_000_000 },
    .{ 197, .@"mmap@2",                 2_000_000 },
    .{ 198, .__syscall,                 2_000_000 },
    .{ 199, .@"lseek@2",                2_000_000 },
    .{ 200, .@"truncate@2",             2_000_000 },
    .{ 201, .@"ftruncate@2",            2_000_000 },
    .{ 202, .__sysctl,                  2_000_000 },
    .{ 203, .mlock,                     2_000_000 },
    .{ 204, .munlock,                   2_000_000 },
    .{ 205, .@"utrace@2",               2_002_000 },
    .{ 206, .futimes,                   3_000_000 },
    .{ 207, .getpgid,                   3_000_000 },
    .{ 209, .poll,                      3_000_000 },
    .{ 220, .@"__semctl@2",             2_002_000 },
    .{ 221, .semget,                    2_002_000 },
    .{ 222, .semop,                     2_002_000 },
    .{ 223, .semconfig,                 2_002_000 },
    .{ 224, .@"msgctl@2",               2_002_000 },
    .{ 225, .msgget,                    2_002_000 },
    .{ 226, .msgsnd,                    2_002_000 },
    .{ 227, .msgrcv,                    2_002_000 },
    .{ 228, .shmat,                     2_002_000 },
    .{ 229, .@"shmctl@2",               2_002_000 },
    .{ 230, .shmdt,                     2_002_000 },
    .{ 231, .shmget,                    2_002_000 },
    .{ 232, .clock_gettime,             3_000_000 },
    .{ 233, .clock_settime,             3_000_000 },
    .{ 234, .clock_getres,              3_000_000 },
    .{ 235, .ktimer_create,             7_000_000 },
    .{ 236, .ktimer_delete,             7_000_000 },
    .{ 237, .ktimer_settime,            7_000_000 },
    .{ 238, .ktimer_gettime,            7_000_000 },
    .{ 239, .ktimer_getoverrun,         7_000_000 },
    .{ 240, .nanosleep,                 3_000_000 },
    .{ 241, .ffclock_getcounter,       10_000_000 },
    .{ 242, .ffclock_setestimate,      10_000_000 },
    .{ 243, .ffclock_getestimate,      10_000_000 },
    .{ 244, .clock_nanosleep,          11_001_000 },
    .{ 247, .clock_getcpuclockid2,      9_003_000 },
    .{ 248, .@"ntp_gettime@6",          6_000_000 },
    .{ 250, .minherit,                  2_002_000 },
    .{ 251, .rfork,                     2_002_000 },
    .{ 252, .openbsd_poll,              3_000_000 },
    .{ 253, .issetugid,                 2_002_005 },
    .{ 254, .lchown,                    2_002_002 },
    .{ 255, .@"aio_read@7",             7_000_000 },
    .{ 256, .@"aio_write@7",            7_000_000 },
    .{ 257, .@"lio_listio@7",           7_000_000 },
    .{ 272, .getdents,                  3_000_000 },
    .{ 274, .lchmod,                    3_000_000 },
    .{ 275, .netbsd_lchown,             3_000_000 },
    .{ 276, .lutimes,                   3_000_000 },
    .{ 277, .netbsd_msync,              3_000_000 },
    .{ 278, .nstat,                     3_000_000 },
    .{ 279, .nfstat,                    3_000_000 },
    .{ 280, .nlstat,                    3_000_000 },
    .{ 289, .preadv,                    5_005_000 },
    .{ 290, .pwritev,                   5_005_000 },
    .{ 297, .@"fhstatfs@4",             4_000_000 },
    .{ 298, .fhopen,                    4_000_000 },
    .{ 299, .@"fhstat@4",               4_000_000 },
    .{ 300, .modnext,                   3_000_000 },
    .{ 301, .modstat,                   3_000_000 },
    .{ 302, .modfnext,                  3_000_000 },
    .{ 303, .modfind,                   3_000_000 },
    .{ 304, .kldload,                   3_000_000 },
    .{ 305, .kldunload,                 3_000_000 },
    .{ 306, .kldfind,                   3_000_000 },
    .{ 307, .kldnext,                   3_000_000 },
    .{ 308, .kldstat,                   3_000_000 },
    .{ 309, .kldfirstmod,               3_000_000 },
    .{ 310, .getsid,                    3_000_000 },
    .{ 311, .setresuid,                 4_000_000 },
    .{ 312, .setresgid,                 4_000_000 },
    .{ 314, .aio_return,                3_000_000 },
    .{ 315, .aio_suspend,               3_000_000 },
    .{ 316, .aio_cancel,                3_000_000 },
    .{ 317, .aio_error,                 3_000_000 },
    .{ 318, .@"aio_read@3",             3_000_000 },
    .{ 319, .@"aio_write@3",            3_000_000 },
    .{ 320, .@"lio_listio@3",           3_000_000 },
    .{ 321, .yield,                     3_000_000 },
    .{ 322, .thr_sleep,                 3_000_000 },
    .{ 323, .thr_wakeup,                3_000_000 },
    .{ 324, .mlockall,                  3_000_000 },
    .{ 325, .munlockall,                3_000_000 },
    .{ 326, .__getcwd,                  3_000_000 },
    .{ 327, .sched_setparam,            3_000_000 },
    .{ 328, .sched_getparam,            3_000_000 },
    .{ 329, .sched_setscheduler,        3_000_000 },
    .{ 330, .sched_getscheduler,        3_000_000 },
    .{ 331, .sched_yield,               3_000_000 },
    .{ 332, .sched_get_priority_max,    3_000_000 },
    .{ 333, .sched_get_priority_min,    3_000_000 },
    .{ 334, .sched_rr_get_interval,     3_000_000 },
    .{ 335, .@"utrace@3",               3_000_000 },
    .{ 336, .@"sendfile@3",             3_001_000 },
    .{ 337, .kldsym,                    3_001_000 },
    .{ 338, .jail,                      4_000_000 },
    .{ 339, .nnpfs_syscall,             8_002_000 },
    .{ 340, .@"sigprocmask@4",          4_000_000 },
    .{ 341, .@"sigsuspend@4",           4_000_000 },
    .{ 342, .@"sigaction@4",            4_000_000 },
    .{ 343, .@"sigpending@4",           4_000_000 },
    .{ 344, .@"sigreturn@4",            4_000_000 },
    .{ 345, .sigtimedwait,              5_001_000 },
    .{ 346, .sigwaitinfo,               5_001_000 },
    .{ 347, .__acl_get_file,            4_000_000 },
    .{ 348, .__acl_set_file,            4_000_000 },
    .{ 349, .__acl_get_fd,              4_000_000 },
    .{ 350, .__acl_set_fd,              4_000_000 },
    .{ 351, .__acl_delete_file,         4_000_000 },
    .{ 352, .__acl_delete_fd,           4_000_000 },
    .{ 353, .__acl_aclcheck_file,       4_000_000 },
    .{ 354, .__acl_aclcheck_fd,         4_000_000 },
    .{ 355, .extattrctl,                4_000_000 },
    .{ 356, .extattr_set_file,          4_000_000 },
    .{ 357, .extattr_get_file,          4_000_000 },
    .{ 358, .extattr_delete_file,       4_000_000 },
    .{ 359, .aio_waitcomplete,          4_000_000 },
    .{ 360, .getresuid,                 4_000_000 },
    .{ 361, .getresgid,                 4_000_000 },
    .{ 362, .kqueue,                    4_001_000 },
    .{ 363, .@"kevent@4",               4_001_000 },
    .{ 371, .extattr_set_fd,            5_000_000 },
    .{ 372, .extattr_get_fd,            5_000_000 },
    .{ 373, .extattr_delete_fd,         5_000_000 },
    .{ 374, .__setugid,                 5_000_000 },
    .{ 375, .nfsclnt,                   5_000_000 },
    .{ 376, .eaccess,                   5_000_000 },
    .{ 377, .afs3_syscall,              8_002_000 },
    .{ 378, .nmount,                    5_000_000 },
    .{ 379, .kse_exit,                  5_000_000 },
    .{ 380, .kse_wakeup,                5_000_000 },
    .{ 381, .kse_create,                5_000_000 },
    .{ 382, .kse_thr_interrupt,         5_000_000 },
    .{ 383, .kse_release,               5_000_000 },
    .{ 384, .__mac_get_proc,            5_000_000 },
    .{ 385, .__mac_set_proc,            5_000_000 },
    .{ 386, .__mac_get_fd,              5_000_000 },
    .{ 387, .__mac_get_file,            5_000_000 },
    .{ 388, .__mac_set_fd,              5_000_000 },
    .{ 389, .__mac_set_file,            5_000_000 },
    .{ 390, .kenv,                      5_000_000 },
    .{ 391, .lchflags,                  5_000_000 },
    .{ 392, .uuidgen,                   5_000_000 },
    .{ 393, .@"sendfile@4",             4_007_000 },
    .{ 394, .mac_syscall,               5_000_000 },
    .{ 395, .@"getfsstat@5",            5_002_000 },
    .{ 396, .@"statfs@5",               5_002_000 },
    .{ 397, .@"fstatfs@5",              5_002_000 },
    .{ 398, .@"fhstatfs@5",             5_002_000 },
    .{ 400, .ksem_close,                5_000_000 },
    .{ 401, .ksem_post,                 5_000_000 },
    .{ 402, .ksem_wait,                 5_000_000 },
    .{ 403, .ksem_trywait,              5_000_000 },
    .{ 404, .ksem_init,                 5_000_000 },
    .{ 405, .ksem_open,                 5_000_000 },
    .{ 406, .ksem_unlink,               5_000_000 },
    .{ 407, .ksem_getvalue,             5_000_000 },
    .{ 408, .ksem_destroy,              5_000_000 },
    .{ 409, .__mac_get_pid,             5_000_000 },
    .{ 410, .__mac_get_link,            5_000_000 },
    .{ 411, .__mac_set_link,            5_000_000 },
    .{ 412, .extattr_set_link,          5_000_000 },
    .{ 413, .extattr_get_link,          5_000_000 },
    .{ 414, .extattr_delete_link,       5_000_000 },
    .{ 415, .__mac_execve,              5_000_000 },
    .{ 416, .@"sigaction@5",            5_000_000 },
    .{ 417, .@"sigreturn@5",            5_000_000 },
    .{ 421, .getcontext,                5_000_000 },
    .{ 422, .setcontext,                5_000_000 },
    .{ 423, .swapcontext,               5_000_000 },
    .{ 424, .@"swapoff@5",              5_001_000 },
    .{ 425, .__acl_get_link,            5_001_000 },
    .{ 426, .__acl_set_link,            5_001_000 },
    .{ 427, .__acl_delete_link,         5_001_000 },
    .{ 428, .__acl_aclcheck_link,       5_001_000 },
    .{ 429, .sigwait,                   5_001_000 },
    .{ 430, .thr_create,                5_001_000 },
    .{ 431, .thr_exit,                  5_001_000 },
    .{ 432, .thr_self,                  5_001_000 },
    .{ 433, .thr_kill,                  5_001_000 },
    .{ 434, ._umtx_lock,                5_001_000 },
    .{ 435, ._umtx_unlock,              5_001_000 },
    .{ 436, .jail_attach,               5_001_000 },
    .{ 437, .extattr_list_fd,           5_002_000 },
    .{ 438, .extattr_list_file,         5_002_000 },
    .{ 439, .extattr_list_link,         5_002_000 },
    .{ 440, .kse_switchin,              5_003_000 },
    .{ 441, .ksem_timedwait,            5_003_000 },
    .{ 442, .thr_suspend,               5_003_000 },
    .{ 443, .thr_wake,                  5_003_000 },
    .{ 444, .kldunloadf,                5_003_000 },
    .{ 445, .audit,                     6_000_000 },
    .{ 446, .auditon,                   6_000_000 },
    .{ 447, .getauid,                   6_000_000 },
    .{ 448, .setauid,                   6_000_000 },
    .{ 449, .getaudit,                  6_000_000 },
    .{ 450, .setaudit,                  6_000_000 },
    .{ 451, .getaudit_addr,             6_000_000 },
    .{ 452, .setaudit_addr,             6_000_000 },
    .{ 453, .auditctl,                  6_000_000 },
    .{ 454, ._umtx_op,                  6_000_000 },
    .{ 455, .thr_new,                   6_000_000 },
    .{ 456, .sigqueue,                  7_000_000 },
    .{ 457, .kmq_open,                  7_000_000 },
    .{ 458, .kmq_setattr,               7_000_000 },
    .{ 459, .kmq_timedreceive,          7_000_000 },
    .{ 460, .kmq_timedsend,             7_000_000 },
    .{ 461, .kmq_notify,                7_000_000 },
    .{ 462, .kmq_unlink,                7_000_000 },
    .{ 463, .abort2,                    7_000_000 },
    .{ 464, .thr_set_name,              7_000_000 },
    .{ 465, .aio_fsync,                 7_000_000 },
    .{ 466, .rtprio_thread,             7_000_000 },
    .{ 471, .sctp_peeloff,              7_000_000 },
    .{ 472, .sctp_generic_sendmsg,      7_000_000 },
    .{ 473, .sctp_generic_sendmsg_iov,  7_000_000 },
    .{ 474, .sctp_generic_recvmsg,      7_000_000 },
    .{ 475, .@"pread@7",                7_000_000 },
    .{ 476, .@"pwrite@7",               7_000_000 },
    .{ 477, .@"mmap@7",                 7_000_000 },
    .{ 478, .@"lseek@7",                7_000_000 },
    .{ 479, .@"truncate@7",             7_000_000 },
    .{ 480, .@"ftruncate@7",            7_000_000 },
    .{ 481, .thr_kill2,                 7_000_000 },
    .{ 482, .shm_open,                  8_000_000 },
    .{ 483, .shm_unlink,                8_000_000 },
    .{ 484, .cpuset,                    7_001_000 },
    .{ 485, .cpuset_setid,              7_001_000 },
    .{ 486, .cpuset_getid,              7_001_000 },
    .{ 487, .cpuset_getaffinity,        7_001_000 },
    .{ 488, .cpuset_setaffinity,        7_001_000 },
    .{ 489, .faccessat,                 8_000_000 },
    .{ 490, .fchmodat,                  8_000_000 },
    .{ 491, .fchownat,                  8_000_000 },
    .{ 492, .fexecve,                   8_000_000 },
    .{ 493, .@"fstatat@8",              8_000_000 },
    .{ 494, .futimesat,                 8_000_000 },
    .{ 495, .linkat,                    8_000_000 },
    .{ 496, .mkdirat,                   8_000_000 },
    .{ 497, .mkfifoat,                  8_000_000 },
    .{ 498, .@"mknodat@8",              8_000_000 },
    .{ 499, .openat,                    8_000_000 },
    .{ 500, .readlinkat,                8_000_000 },
    .{ 501, .renameat,                  8_000_000 },
    .{ 502, .symlinkat,                 8_000_000 },
    .{ 503, .unlinkat,                  8_000_000 },
    .{ 504, .posix_openpt,              8_000_000 },
    .{ 505, .gssd_syscall,              8_000_000 },
    .{ 506, .jail_get,                  8_000_000 },
    .{ 507, .jail_set,                  8_000_000 },
    .{ 508, .jail_remove,               8_000_000 },
    .{ 509, .closefrom,                 7_003_000 },
    .{ 510, .@"__semctl@7",             7_003_000 },
    .{ 511, .@"msgctl@7",               7_003_000 },
    .{ 512, .@"shmctl@7",               7_003_000 },
    .{ 513, .lpathconf,                 8_000_000 },
    .{ 514, .cap_new,                   9_000_000 },
    .{ 515, .cap_getrights,             9_000_000 },
    .{ 516, .cap_enter,                 9_000_000 },
    .{ 517, .cap_getmode,               9_000_000 },
    .{ 518, .pdfork,                    9_000_000 },
    .{ 519, .pdkill,                    9_000_000 },
    .{ 520, .pdgetpid,                  9_000_000 },
    .{ 522, .pselect,                   8_001_000 },
    .{ 523, .getloginclass,             9_000_000 },
    .{ 524, .setloginclass,             9_000_000 },
    .{ 525, .rctl_get_racct,            9_000_000 },
    .{ 526, .rctl_get_rules,            9_000_000 },
    .{ 527, .rctl_get_limits,           9_000_000 },
    .{ 528, .rctl_add_rule,             9_000_000 },
    .{ 529, .rctl_remove_rule,          9_000_000 },
    .{ 530, .posix_fallocate,           8_003_000 },
    .{ 531, .posix_fadvise,             8_003_000 },
    .{ 532, .wait6,                     9_002_000 },
    .{ 533, .cap_rights_limit,         10_000_000 },
    .{ 534, .cap_ioctls_limit,         10_000_000 },
    .{ 535, .cap_ioctls_get,           10_000_000 },
    .{ 536, .cap_fcntls_limit,         10_000_000 },
    .{ 537, .cap_fcntls_get,           10_000_000 },
    .{ 538, .bindat,                   10_000_000 },
    .{ 539, .connectat,                10_000_000 },
    .{ 540, .chflagsat,                10_000_000 },
    .{ 541, .accept4,                  10_000_000 },
    .{ 542, .pipe2,                    10_000_000 },
    .{ 543, .aio_mlock,                10_000_000 },
    .{ 544, .procctl,                   9_003_000 },
    .{ 545, .ppoll,                    10_002_000 },
    .{ 546, .futimens,                 10_003_000 },
    .{ 547, .utimensat,                10_003_000 },
    .{ 548, .numa_getaffinity,         11_000_000 },
    .{ 549, .numa_setaffinity,         11_000_000 },
    .{ 550, .fdatasync,                11_001_000 },
    .{ 551, .@"fstat@12",              12_000_000 },
    .{ 552, .@"fstatat@12",            12_000_000 },
    .{ 553, .@"fhstat@12",             12_000_000 },
    .{ 554, .@"getdirentries@12",      12_000_000 },
    .{ 555, .@"statfs@12",             12_000_000 },
    .{ 556, .@"fstatfs@12",            12_000_000 },
    .{ 557, .@"getfsstat@12",          12_000_000 },
    .{ 558, .@"fhstatfs@12",           12_000_000 },
    .{ 559, .@"mknodat@12",            12_000_000 },
    .{ 560, .@"kevent@12",             12_000_000 },
    .{ 561, .cpuset_getdomain,         12_000_000 },
    .{ 562, .cpuset_setdomain,         12_000_000 },
    .{ 563, .getrandom,                12_000_000 },
    .{ 564, .getfhat,                  12_001_000 },
    .{ 565, .fhlink,                   12_001_000 },
    .{ 566, .fhlinkat,                 12_001_000 },
    .{ 567, .fhreadlink,               12_001_000 },
    .{ 568, .funlinkat,                13_000_000 },
    .{ 569, .copy_file_range,          13_000_000 },
    .{ 570, .__sysctlbyname,           12_002_000 },
    .{ 571, .shm_open2,                13_000_000 },
    .{ 572, .shm_rename,               13_000_000 },
    .{ 573, .sigfastblock,             13_000_000 },
    .{ 574, .__realpathat,             13_000_000 },
    .{ 575, .close_range,              12_002_000 },
    .{ 576, .rpctls_syscall,           13_000_000 },
    .{ 577, .__specialfd,              13_000_000 },
    .{ 578, .aio_writev,               13_000_000 },
    .{ 579, .aio_readv,                13_000_000 },
    .{ 580, .fspacectl,                14_000_000 },
    .{ 581, .sched_getcpu,             13_001_000 },
    .{ 582, .@"swapoff@13",            13_001_000 },
    .{ 583, .kqueuex,                  13_003_000 },
    .{ 584, .membarrier,               13_003_000 },
    .{ 585, .timerfd_create,           14_000_000 },
    .{ 586, .timerfd_gettime,          14_000_000 },
    .{ 587, .timerfd_settime,          14_000_000 },
    .{ 588, .kcmp,                     14_001_000 },

    // zig fmt: on
};

const sys_tab_num_max = b: {
    var max = 0;
    for (sys_tab) |row| {
        if (row[0] > max) max = row[0];
    }
    break :b max;
};

pub fn syscall0_errno(number: SYS) usize {
    const result = asm volatile (
        \\ movq %%rcx, %%r10
        \\ syscall
        : [ret] "={rax}" (-> usize),
        : [number] "{rax}" (@intFromEnum(number)),
        : "rdi", "rsi", "rdx", "rcx", "r8", "r9", "r10", "r11", "cc", "memory"
    );
    if (asm volatile (
        \\ jc 0f
        \\ movq $0, %%rax
        \\ jmp 1f
        \\ 0:
        \\ movq $1, %%rax
        \\ 1:
        : [ret] "={rax}" (-> usize),
    ) == 1) {
        sys.errno_location().* = @enumFromInt(result);
        return @bitCast(@as(isize, -1));
    }
    return result;
}

pub fn syscall1_errno(number: SYS, arg1: usize) usize {
    const result = asm volatile (
        \\ movq %%rcx, %%r10
        \\ syscall
        : [ret] "={rax}" (-> usize),
        : [number] "{rax}" (@intFromEnum(number)),
          [arg1] "{rdi}" (arg1),
        : "rsi", "rdx", "rcx", "r8", "r9", "r10", "r11", "cc", "memory"
    );
    if (asm volatile (
        \\ jc 0f
        \\ movq $0, %%rax
        \\ jmp 1f
        \\ 0:
        \\ movq $1, %%rax
        \\ 1:
        : [ret] "={rax}" (-> usize),
    ) == 1) {
        sys.errno_location().* = @enumFromInt(result);
        return @bitCast(@as(isize, -1));
    }
    return result;
}

pub fn syscall1_noerrno(number: SYS, arg1: usize) usize {
    return asm volatile (
        \\ movq %%rcx, %%r10
        \\ syscall
        : [ret] "={rax}" (-> usize),
        : [number] "{rax}" (@intFromEnum(number)),
          [arg1] "{rdi}" (arg1),
        : "rsi", "rdx", "rcx", "r8", "r9", "r10", "r11", "cc", "memory"
    );
}

pub fn syscall1_noreturn(number: SYS, arg1: usize) noreturn {
    _ = asm volatile (
        \\ movq %%rcx, %%r10
        \\ syscall
        : [ret] "={rax}" (-> usize),
        : [number] "{rax}" (@intFromEnum(number)),
          [arg1] "{rdi}" (arg1),
        : "rsi", "rdx", "rcx", "r8", "r9", "r10", "r11", "cc", "memory"
    );
    unreachable;
}

pub fn syscall2_errno(number: SYS, arg1: usize, arg2: usize) usize {
    const result = asm volatile (
        \\ movq %%rcx, %%r10
        \\ syscall
        : [ret] "={rax}" (-> usize),
        : [number] "{rax}" (@intFromEnum(number)),
          [arg1] "{rdi}" (arg1),
          [arg2] "{rsi}" (arg2),
        : "rdx", "rcx", "r8", "r9", "r10", "r11", "cc", "memory"
    );
    if (asm volatile (
        \\ jc 0f
        \\ movq $0, %%rax
        \\ jmp 1f
        \\ 0:
        \\ movq $1, %%rax
        \\ 1:
        : [ret] "={rax}" (-> usize),
    ) == 1) {
        sys.errno_location().* = @enumFromInt(result);
        return @bitCast(@as(isize, -1));
    }
    return result;
}

pub fn syscall2_noerrno(number: SYS, arg1: usize, arg2: usize) usize {
    return asm volatile (
        \\ movq %%rcx, %%r10
        \\ syscall
        : [ret] "={rax}" (-> usize),
        : [number] "{rax}" (@intFromEnum(number)),
          [arg1] "{rdi}" (arg1),
          [arg2] "{rsi}" (arg2),
        : "rdx", "rcx", "r8", "r9", "r10", "r11", "cc", "memory"
    );
}

pub fn syscall3_errno(number: SYS, arg1: usize, arg2: usize, arg3: usize) usize {
    const result = asm volatile (
        \\ movq %%rcx, %%r10
        \\ syscall
        : [ret] "={rax}" (-> usize),
        : [number] "{rax}" (@intFromEnum(number)),
          [arg1] "{rdi}" (arg1),
          [arg2] "{rsi}" (arg2),
          [arg3] "{rdx}" (arg3),
        : "rcx", "r8", "r9", "r10", "r11", "cc", "memory"
    );
    if (asm volatile (
        \\ jc 0f
        \\ movq $0, %%rax
        \\ jmp 1f
        \\ 0:
        \\ movq $1, %%rax
        \\ 1:
        : [ret] "={rax}" (-> usize),
    ) == 1) {
        sys.errno_location().* = @enumFromInt(result);
        return @bitCast(@as(isize, -1));
    }
    return result;
}

pub fn syscall3_noerrno(number: SYS, arg1: usize, arg2: usize, arg3: usize) usize {
    return asm volatile (
        \\ movq %%rcx, %%r10
        \\ syscall
        : [ret] "={rax}" (-> usize),
        : [number] "{rax}" (@intFromEnum(number)),
          [arg1] "{rdi}" (arg1),
          [arg2] "{rsi}" (arg2),
          [arg3] "{rdx}" (arg3),
        : "rcx", "r8", "r9", "r10", "r11", "cc", "memory"
    );
}

pub fn syscall4_errno(number: SYS, arg1: usize, arg2: usize, arg3: usize, arg4: usize) usize {
    const result = asm volatile (
        \\ movq %%rcx, %%r10
        \\ syscall
        : [ret] "={rax}" (-> usize),
        : [number] "{rax}" (@intFromEnum(number)),
          [arg1] "{rdi}" (arg1),
          [arg2] "{rsi}" (arg2),
          [arg3] "{rdx}" (arg3),
          [arg4] "{rcx}" (arg4),
        : "r8", "r9", "r10", "r11", "cc", "memory"
    );
    if (asm volatile (
        \\ jc 0f
        \\ movq $0, %%rax
        \\ jmp 1f
        \\ 0:
        \\ movq $1, %%rax
        \\ 1:
        : [ret] "={rax}" (-> usize),
    ) == 1) {
        sys.errno_location().* = @enumFromInt(result);
        return @bitCast(@as(isize, -1));
    }
    return result;
}

pub fn syscall4_noerrno(number: SYS, arg1: usize, arg2: usize, arg3: usize, arg4: usize) usize {
    return asm volatile (
        \\ movq %%rcx, %%r10
        \\ syscall
        : [ret] "={rax}" (-> usize),
        : [number] "{rax}" (@intFromEnum(number)),
          [arg1] "{rdi}" (arg1),
          [arg2] "{rsi}" (arg2),
          [arg3] "{rdx}" (arg3),
          [arg4] "{rcx}" (arg4),
        : "r8", "r9", "r10", "r11", "cc", "memory"
    );
}

pub fn syscall5_errno(number: SYS, arg1: usize, arg2: usize, arg3: usize, arg4: usize, arg5: usize) usize {
    const result = asm volatile (
        \\ movq %%rcx, %%r10
        \\ syscall
        : [ret] "={rax}" (-> usize),
        : [number] "{rax}" (@intFromEnum(number)),
          [arg1] "{rdi}" (arg1),
          [arg2] "{rsi}" (arg2),
          [arg3] "{rdx}" (arg3),
          [arg4] "{rcx}" (arg4),
          [arg5] "{r8}" (arg5),
        : "r9", "r10", "r11", "cc", "memory"
    );
    if (asm volatile (
        \\ jc 0f
        \\ movq $0, %%rax
        \\ jmp 1f
        \\ 0:
        \\ movq $1, %%rax
        \\ 1:
        : [ret] "={rax}" (-> usize),
    ) == 1) {
        sys.errno_location().* = @enumFromInt(result);
        return @bitCast(@as(isize, -1));
    }
    return result;
}

pub fn syscall6_errno(number: SYS, arg1: usize, arg2: usize, arg3: usize, arg4: usize, arg5: usize, arg6: usize) usize {
    const result = asm volatile (
        \\ movq %%rcx, %%r10
        \\ syscall
        : [ret] "={rax}" (-> usize),
        : [number] "{rax}" (@intFromEnum(number)),
          [arg1] "{rdi}" (arg1),
          [arg2] "{rsi}" (arg2),
          [arg3] "{rdx}" (arg3),
          [arg4] "{rcx}" (arg4),
          [arg5] "{r8}" (arg5),
          [arg6] "{r9}" (arg6),
        : "r10", "r11", "cc", "memory"
    );
    if (asm volatile (
        \\ jc 0f
        \\ movq $0, %%rax
        \\ jmp 1f
        \\ 0:
        \\ movq $1, %%rax
        \\ 1:
        : [ret] "={rax}" (-> usize),
    ) == 1) {
        sys.errno_location().* = @enumFromInt(result);
        return @bitCast(@as(isize, -1));
    }
    return result;
}

pub fn syscall7_errno(number: SYS, arg1: usize, arg2: usize, arg3: usize, arg4: usize, arg5: usize, arg6: usize, arg7: usize) usize {
    const result = asm volatile (
        \\ movq %%rcx, %%r10
        \\ syscall
        : [ret] "={rax}" (-> usize),
        : [number] "{rax}" (@intFromEnum(number)),
          [arg1] "{rdi}" (arg1),
          [arg2] "{rsi}" (arg2),
          [arg3] "{rdx}" (arg3),
          [arg4] "{rcx}" (arg4),
          [arg5] "{r8}" (arg5),
          [arg6] "{r9}" (arg6),
          [arg7] "{r11}" (arg7),
        : "r10", "cc", "memory"
    );
    if (asm volatile (
        \\ jc 0f
        \\ movq $0, %%rax
        \\ jmp 1f
        \\ 0:
        \\ movq $1, %%rax
        \\ 1:
        : [ret] "={rax}" (-> usize),
    ) == 1) {
        sys.errno_location().* = @enumFromInt(result);
        return @bitCast(@as(isize, -1));
    }
    return result;
}

pub fn Result(T: type) type {
    return packed union {
        value: T,
        eflag: packed struct(usize) {
            _: u63 = 0,
            present: bool = true,
        },
        ecode: sys.E,

        pub const Type = T;

        comptime {
            if (@sizeOf(@This()) != @sizeOf(usize)) {
                @compileError(std.fmt.comptimePrint("expecting size {d} bytes, found {d}", .{ @sizeOf(@This()), @sizeOf(usize) }));
            }
        }
    };
}
