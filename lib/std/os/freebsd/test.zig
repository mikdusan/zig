//! This file tests both { c, sys } calls.
const std = @import("../../std.zig");
const builtin = @import("builtin");
const testing = std.testing;

fn Test(NS: type) type {
    return struct {
        const expect = std.os.freebsd.Expect(NS);

        const invalid_clockid: NS.clockid_t = @enumFromInt(std.math.maxInt(@typeInfo(NS.clockid_t).Enum.tag_type));
        const invalid_priority: c_int = std.math.maxInt(c_int);

        test "clock_getcpuclockid" {
            if (!comptime NS.hasFeature(.clock_getcpuclockid)) return error.SkipZigTest;

            var id: NS.clockid_t = undefined;
            _ = try expect.directNoError(NS.clock_getcpuclockid(0, &id));
            _ = try expect.directError(.SRCH, NS.clock_getcpuclockid(-1, &id));
        }

        test "clock_getres" {
            if (!comptime NS.hasFeature(.clock_getres)) return error.SkipZigTest;

            var tp: NS.timespec_t = undefined;
            _ = try expect.sentinelNoError(-1, NS.clock_getres(.MONOTONIC, &tp));
            try testing.expect(tp.sec > 0 or tp.nsec > 0);

            _ = try expect.sentinelError(-1, .INVAL, NS.clock_getres(invalid_clockid, &tp));
        }

        test "clock_gettime" {
            if (!comptime NS.hasFeature(.clock_gettime)) return error.SkipZigTest;

            var tp: NS.timespec_t = undefined;
            _ = try expect.sentinelNoError(-1, NS.clock_gettime(.MONOTONIC, &tp));
            try testing.expect(tp.sec > 0 or tp.nsec > 0);

            _ = try expect.sentinelError(-1, .INVAL, NS.clock_gettime(invalid_clockid, &tp));
        }

        test "clock_nanosleep" {
            if (!comptime NS.hasFeature(.clock_nanosleep)) return error.SkipZigTest;

            const rqtp: NS.timespec_t = .{ .sec = 0, .nsec = 1000 };
            _ = try expect.directNoError(NS.clock_nanosleep(.MONOTONIC, .RELTIME, &rqtp, null));
            _ = try expect.directError(.INVAL, NS.clock_nanosleep(invalid_clockid, .RELTIME, &rqtp, null));
        }

        test "clock_settime" {
            if (!comptime NS.hasFeature(.clock_settime)) return error.SkipZigTest;
            // do not run this test as root
            if (NS.geteuid() == 0) return error.SkipZigTest;

            _ = try expect.sentinelError(-1, .PERM, NS.clock_settime(.MONOTONIC, &.{ .sec = 0, .nsec = 1000 }));
        }

        test "close" {
            if (!comptime NS.hasFeature(.close)) return error.SkipZigTest;

            var arena_s = std.heap.ArenaAllocator.init(testing.allocator);
            defer arena_s.deinit();
            const arena = arena_s.allocator();
            var tmp = try TmpDir.init(arena, .{});
            defer tmp.cleanup();

            const file_path = try std.fs.path.joinZ(arena, &.{ tmp.path, "close_me.txt" });
            const fd = try expect.sentinelNoError(-1, NS.open(file_path, .{ .CREAT = true }, NS.default.file_mode));
            _ = try expect.sentinelNoError(-1, NS.close(fd));
            try expect.sentinelError(-1, .BADF, NS.close(fd));
        }

        test "creat" {
            if (!comptime NS.hasFeature(.creat)) return error.SkipZigTest;

            var arena_s = std.heap.ArenaAllocator.init(testing.allocator);
            defer arena_s.deinit();
            const arena = arena_s.allocator();
            var tmp = try TmpDir.init(arena, .{});
            defer tmp.cleanup();

            const file_path = try std.fs.path.joinZ(arena, &.{ tmp.path, "create_me.txt" });
            const fd = try expect.sentinelNoError(-1, NS.creat(file_path, NS.default.file_mode));
            _ = try expect.sentinelNoError(-1, NS.close(fd));

            const bogus_path = try std.fs.path.joinZ(arena, &.{ tmp.path, "bogus", "create_me.txt" });
            try expect.sentinelError(-1, .NOENT, NS.creat(bogus_path, NS.default.file_mode));
        }

        test "exit" {
            if (!comptime NS.hasFeature(.exit)) return error.SkipZigTest;
            _ = &NS.exit;
        }

        test "fstat" {
            if (!comptime NS.hasFeature(.fstat)) return error.SkipZigTest;

            var arena_s = std.heap.ArenaAllocator.init(testing.allocator);
            defer arena_s.deinit();
            const arena = arena_s.allocator();
            var tmp = try TmpDir.init(arena, .{});
            defer tmp.cleanup();

            const basename = "tiny.txt";
            const file = try tmp.dir.createFile(basename, .{});
            defer file.close();
            try file.writeAll("12345");

            var info: NS.stat_t = undefined;
            _ = try expect.sentinelNoError(-1, NS.fstat(file.handle, &info));
            try testing.expectEqual(5, info.size);
        }

        test "fstatat" {
            if (!comptime NS.hasFeature(.fstatat)) return error.SkipZigTest;

            var arena_s = std.heap.ArenaAllocator.init(testing.allocator);
            defer arena_s.deinit();
            const arena = arena_s.allocator();
            var tmp = try TmpDir.init(arena, .{});
            defer tmp.cleanup();

            const basename = "tiny.txt";
            const file = try tmp.dir.createFile(basename, .{});
            defer file.close();
            try file.writeAll("12345");

            var info: NS.stat_t = undefined;
            _ = try expect.sentinelNoError(-1, NS.fstatat(tmp.dir.fd, basename, &info, .{}));
            try testing.expectEqual(5, info.size);
        }

        test "futimens" {
            if (!comptime NS.hasFeature(.futimens)) return error.SkipZigTest;

            var arena_s = std.heap.ArenaAllocator.init(testing.allocator);
            defer arena_s.deinit();
            const arena = arena_s.allocator();
            var tmp = try TmpDir.init(arena, .{});
            defer tmp.cleanup();

            const basename = "tiny.txt";
            const file = try tmp.dir.createFile(basename, .{});
            defer file.close();
            try file.writeAll("12345");

            var info: NS.stat_t = undefined;
            _ = try expect.sentinelNoError(-1, NS.fstat(file.handle, &info));
            try testing.expectEqual(5, info.size);

            // bump by 1 year and set
            var times = [_]NS.timespec_t{
                info.atim,
                info.mtim,
            };
            times[0].sec += 3600 * 24 * 365;
            times[1].sec += 3600 * 24 * 365;
            _ = try expect.sentinelNoError(-1, NS.futimens(file.handle, &times));

            // stat again and check times (only .sec to avoid filesystem capability differences)
            _ = try expect.sentinelNoError(-1, NS.fstat(file.handle, &info));
            try testing.expectEqual(times[0].sec, info.atim.sec);
            try testing.expectEqual(times[1].sec, info.mtim.sec);
        }

        test "getdents" {
            if (!comptime NS.hasFeature(.getdents)) return error.SkipZigTest;

            var arena_s = std.heap.ArenaAllocator.init(testing.allocator);
            defer arena_s.deinit();
            const arena = arena_s.allocator();
            var tmp = try TmpDir.init(arena, .{ .iterate = true });
            defer tmp.cleanup();

            const file = try tmp.dir.createFile("empty.txt", .{});
            defer file.close();

            var buf: [8192]u8 align(@alignOf(NS.dirent_t)) = undefined;
            const len = try expect.sentinelNoError(-1, NS.getdents(tmp.dir.fd, &buf, buf.len));

            var entries: [3]*const NS.dirent_t = undefined;
            var i: usize = 0;
            var entry_index: usize = 0;
            while (i < len and entry_index < 3) {
                const entry: *NS.dirent_t = @alignCast(@ptrCast(&buf[i]));
                entries[entry_index] = entry;
                i += entry.reclen;
                entry_index += 1;
            }
            try testing.expectEqual(len, @as(@TypeOf(len), @intCast(i)));
            try testing.expectEqual(3, entry_index);

            for (entries) |p| {
                switch (p.namlen) {
                    1 => try testing.expectEqualStrings(".", p.name[0..p.namlen]),
                    2 => try testing.expectEqualStrings("..", p.name[0..p.namlen]),
                    9 => try testing.expectEqualStrings("empty.txt", p.name[0..p.namlen]),
                    else => {},
                }
            }

            try expect.sentinelError(-1, .BADF, NS.getdents(file.handle, &buf, buf.len));
        }

        test "getdirentries" {
            if (!comptime NS.hasFeature(.getdirentries)) return error.SkipZigTest;

            var arena_s = std.heap.ArenaAllocator.init(testing.allocator);
            defer arena_s.deinit();
            const arena = arena_s.allocator();
            var tmp = try TmpDir.init(arena, .{ .iterate = true });
            defer tmp.cleanup();

            const file = try tmp.dir.createFile("empty.txt", .{});
            defer file.close();

            var buf: [1024]u8 = undefined;
            const len = try expect.sentinelNoError(-1, NS.getdirentries(tmp.dir.fd, &buf, buf.len * @sizeOf(NS.dirent_t), null));

            var entries: [3]*const NS.dirent_t = undefined;
            var i: usize = 0;
            var entry_index: usize = 0;
            while (i < len and entry_index < 3) {
                const entry: *NS.dirent_t = @alignCast(@ptrCast(&buf[i]));
                entries[entry_index] = entry;
                i += entry.reclen;
                entry_index += 1;
            }
            try testing.expectEqual(len, @as(@TypeOf(len), @intCast(i)));
            try testing.expectEqual(3, entry_index);

            for (entries) |p| {
                switch (p.namlen) {
                    1 => try testing.expectEqualStrings(".", p.name[0..p.namlen]),
                    2 => try testing.expectEqualStrings("..", p.name[0..p.namlen]),
                    9 => try testing.expectEqualStrings("empty.txt", p.name[0..p.namlen]),
                    else => {},
                }
            }

            try expect.sentinelError(-1, .BADF, NS.getdirentries(file.handle, &buf, buf.len * @sizeOf(NS.dirent_t), null));
        }

        test "getpid" {
            if (!comptime NS.hasFeature(.getpid)) return error.SkipZigTest;
            // always successful
            _ = NS.getpid();
        }

        test "getppid" {
            if (!comptime NS.hasFeature(.getppid)) return error.SkipZigTest;
            // always successful
            _ = NS.getppid();
        }

        test "getpriority" {
            if (!comptime NS.hasFeature(.getpriority)) return error.SkipZigTest;

            {
                NS.errno_location().* = .SUCCESS;
                const pr = NS.getpriority(.PROCESS, 0);
                try expect.errno(.SUCCESS);
                try testing.expect(pr >= NS.priority.MIN);
                try testing.expect(pr <= NS.priority.MAX);
            }
            {
                NS.errno_location().* = .SUCCESS;
                _ = NS.getpriority(.PROCESS, invalid_priority);
                try expect.errno(.SRCH);
            }
        }

        test "getrlimit" {
            if (!comptime NS.hasFeature(.getrlimit)) return error.SkipZigTest;

            var limit: NS.rlimit_t = undefined;
            _ = try expect.sentinelNoError(-1, NS.getrlimit(.NPROC, &limit));
        }

        test "getrusage" {
            if (!comptime NS.hasFeature(.getrusage)) return error.SkipZigTest;

            var usage: NS.rusage_t = undefined;
            _ = try expect.sentinelNoError(-1, NS.getrusage(.SELF, &usage));
        }

        test "getuid" {
            if (!comptime NS.hasFeature(.getuid)) return error.SkipZigTest;
            // always successful
            _ = NS.getuid();
        }

        test "geteuid" {
            if (!comptime NS.hasFeature(.geteuid)) return error.SkipZigTest;
            // always successful
            _ = NS.geteuid();
        }

        test "getgid" {
            if (!comptime NS.hasFeature(.getgid)) return error.SkipZigTest;
            // always successful
            _ = NS.getgid();
        }

        test "getegid" {
            if (!comptime NS.hasFeature(.getegid)) return error.SkipZigTest;
            // always successful
            _ = NS.getegid();
        }

        test "kill" {
            if (!comptime NS.hasFeature(.kill)) return error.SkipZigTest;
            _ = &NS.kill;
        }

        test "killpg" {
            if (!comptime NS.hasFeature(.killpg)) return error.SkipZigTest;
            _ = &NS.killpg;
        }

        test "lstat" {
            if (!comptime NS.hasFeature(.lstat)) return error.SkipZigTest;

            var arena_s = std.heap.ArenaAllocator.init(testing.allocator);
            defer arena_s.deinit();
            const arena = arena_s.allocator();
            var tmp = try TmpDir.init(arena, .{});
            defer tmp.cleanup();

            const realname = "1234567890.txt";
            const linkname = "link.txt";
            const file = try tmp.dir.createFile(realname, .{});
            defer file.close();
            try tmp.dir.symLink(realname, linkname, .{});

            const file_path = try std.fs.path.joinZ(arena, &.{ tmp.path, linkname });
            var info: NS.stat_t = undefined;
            _ = try expect.sentinelNoError(-1, NS.lstat(file_path, &info));
            try testing.expectEqual(realname.len, @as(usize, @bitCast(info.size)));
        }

        test "mkdir" {
            if (!comptime NS.hasFeature(.mkdir)) return error.SkipZigTest;

            var arena_s = std.heap.ArenaAllocator.init(testing.allocator);
            defer arena_s.deinit();
            const arena = arena_s.allocator();
            var tmp = try TmpDir.init(arena, .{});
            defer tmp.cleanup();

            const dir_path = try std.fs.path.joinZ(arena, &.{ tmp.path, "create_me" });
            _ = try expect.sentinelNoError(-1, NS.mkdir(dir_path, NS.default.dir_mode));

            const bogus_path = try std.fs.path.joinZ(arena, &.{ tmp.path, "bogus", "create_me" });
            try expect.sentinelError(-1, .NOENT, NS.mkdir(bogus_path, NS.default.dir_mode));
        }

        test "mkdirat" {
            if (!comptime NS.hasFeature(.mkdirat)) return error.SkipZigTest;

            var arena_s = std.heap.ArenaAllocator.init(testing.allocator);
            defer arena_s.deinit();
            const arena = arena_s.allocator();
            var tmp = try TmpDir.init(arena, .{});
            defer tmp.cleanup();

            const dir_path = try std.fs.path.joinZ(arena, &.{ tmp.path, "create_me" });
            _ = try expect.sentinelNoError(-1, NS.mkdirat(NS.AT.FDCWD, dir_path, NS.default.dir_mode));

            const bogus_path = try std.fs.path.joinZ(arena, &.{ tmp.path, "bogus", "create_me" });
            try expect.sentinelError(-1, .NOENT, NS.mkdirat(NS.AT.FDCWD, bogus_path, NS.default.dir_mode));
        }

        test "mkfifo" {
            if (!comptime NS.hasFeature(.mkfifo)) return error.SkipZigTest;

            var arena_s = std.heap.ArenaAllocator.init(testing.allocator);
            defer arena_s.deinit();
            const arena = arena_s.allocator();
            var tmp = try TmpDir.init(arena, .{});
            defer tmp.cleanup();

            const dir_path = try std.fs.path.joinZ(arena, &.{ tmp.path, "create_me" });
            _ = try expect.sentinelNoError(-1, NS.mkfifo(dir_path, NS.default.file_mode));

            const bogus_path = try std.fs.path.joinZ(arena, &.{ tmp.path, "bogus", "create_me" });
            try expect.sentinelError(-1, .NOENT, NS.mkfifo(bogus_path, NS.default.file_mode));
        }

        test "mkfifoat" {
            if (!comptime NS.hasFeature(.mkfifoat)) return error.SkipZigTest;

            var arena_s = std.heap.ArenaAllocator.init(testing.allocator);
            defer arena_s.deinit();
            const arena = arena_s.allocator();
            var tmp = try TmpDir.init(arena, .{});
            defer tmp.cleanup();

            const dir_path = try std.fs.path.joinZ(arena, &.{ tmp.path, "create_me" });
            _ = try expect.sentinelNoError(-1, NS.mkfifoat(NS.AT.FDCWD, dir_path, NS.default.file_mode));

            const bogus_path = try std.fs.path.joinZ(arena, &.{ tmp.path, "bogus", "create_me" });
            try expect.sentinelError(-1, .NOENT, NS.mkfifoat(NS.AT.FDCWD, bogus_path, NS.default.file_mode));
        }

        test "nanosleep" {
            if (!comptime NS.hasFeature(.nanosleep)) return error.SkipZigTest;

            const rqtp: NS.timespec_t = .{ .sec = 0, .nsec = 1000 };
            _ = try expect.directNoError(NS.nanosleep(&rqtp, null));
        }

        test "open" {
            if (!comptime NS.hasFeature(.open)) return error.SkipZigTest;

            var arena_s = std.heap.ArenaAllocator.init(testing.allocator);
            defer arena_s.deinit();
            const arena = arena_s.allocator();

            var tmp = try TmpDir.init(arena, .{});
            defer tmp.cleanup();
            const file_path = try std.fs.path.joinZ(arena, &.{ tmp.path, "create_me.txt" });

            const fd = try expect.sentinelNoError(-1, NS.open(file_path, .{ .CREAT = true }, NS.default.file_mode));
            _ = try expect.sentinelNoError(-1, NS.close(fd));
        }

        test "openat" {
            if (!comptime NS.hasFeature(.openat)) return error.SkipZigTest;

            var arena_s = std.heap.ArenaAllocator.init(testing.allocator);
            defer arena_s.deinit();
            const arena = arena_s.allocator();

            var tmp = try TmpDir.init(arena, .{});
            defer tmp.cleanup();
            const file_path = try std.fs.path.joinZ(arena, &.{ tmp.path, "create_me.txt" });

            const fd = try expect.sentinelNoError(-1, NS.openat(NS.AT.FDCWD, file_path, .{ .CREAT = true }, NS.default.file_mode));
            _ = try expect.sentinelNoError(-1, NS.close(fd));
        }

        test "raise" {
            if (!comptime NS.hasFeature(.raise)) return error.SkipZigTest;
            _ = &NS.raise;
        }

        test "read" {
            if (!comptime NS.hasFeature(.read)) return error.SkipZigTest;

            const fd = try expect.sentinelNoError(-1, NS.open("/dev/zero", .{}, 0));
            var buf: [4]u8 = undefined;
            _ = try expect.sentinelNoError(-1, NS.read(fd, &buf, buf.len));
            _ = try expect.sentinelNoError(-1, NS.close(fd));
        }

        test "seteuid" {
            if (!comptime NS.hasFeature(.seteuid)) return error.SkipZigTest;
            const euid = try expect.sentinelNoError(-1, NS.geteuid());
            _ = try expect.sentinelNoError(-1, NS.seteuid(euid));
            if (euid != 0) try expect.sentinelError(-1, .PERM, NS.seteuid(0));
        }

        test "setgid" {
            if (!comptime NS.hasFeature(.setgid)) return error.SkipZigTest;
            const egid = try expect.sentinelNoError(-1, NS.getegid());
            _ = try expect.sentinelNoError(-1, NS.setgid(egid));
            if (egid != 0) try expect.sentinelError(-1, .PERM, NS.setgid(0));
        }

        test "setegid" {
            if (!comptime NS.hasFeature(.setegid)) return error.SkipZigTest;
            const egid = try expect.sentinelNoError(-1, NS.getegid());
            _ = try expect.sentinelNoError(-1, NS.setegid(egid));
            if (egid != 0) try expect.sentinelError(-1, .PERM, NS.setegid(0));
        }

        test "setpriority" {
            if (!comptime NS.hasFeature(.setpriority)) return error.SkipZigTest;

            NS.errno_location().* = .SUCCESS;
            const pr0 = NS.getpriority(.PROCESS, 0);
            try expect.errno(.SUCCESS);

            const pr1: @TypeOf(pr0) = @min(pr0 + 1, NS.priority.MAX);
            _ = try expect.sentinelNoError(-1, NS.setpriority(.PROCESS, 0, pr1));

            NS.errno_location().* = .SUCCESS;
            const pr2 = NS.getpriority(.PROCESS, 0);
            try expect.errno(.SUCCESS);
            try testing.expectEqual(pr1, pr2);

            // lowering priority fails if not super-user
            if (NS.geteuid() != 0) _ = try expect.sentinelError(-1, .ACCES, NS.setpriority(.PROCESS, 0, pr0));
        }

        test "setrlimit" {
            if (!comptime NS.hasFeature(.setrlimit)) return error.SkipZigTest;

            var saved: NS.rlimit_t = undefined;
            _ = try expect.sentinelNoError(-1, NS.getrlimit(.NPROC, &saved));

            const changed: NS.rlimit_t = .{
                .cur = saved.cur - 1,
                .max = saved.max,
            };
            _ = try expect.sentinelNoError(-1, NS.setrlimit(.NPROC, &changed));

            var tmp: NS.rlimit_t = undefined;
            _ = try expect.sentinelNoError(-1, NS.getrlimit(.NPROC, &tmp));
            try testing.expectEqual(tmp.cur, changed.cur);

            _ = try expect.sentinelNoError(-1, NS.setrlimit(.NPROC, &saved));
        }

        test "setuid" {
            if (!comptime NS.hasFeature(.setuid)) return error.SkipZigTest;
            const euid = try expect.sentinelNoError(-1, NS.geteuid());
            _ = try expect.sentinelNoError(-1, NS.setuid(euid));
            if (euid != 0) try expect.sentinelError(-1, .PERM, NS.setuid(0));
        }

        test "stat" {
            if (!comptime NS.hasFeature(.stat)) return error.SkipZigTest;

            var arena_s = std.heap.ArenaAllocator.init(testing.allocator);
            defer arena_s.deinit();
            const arena = arena_s.allocator();
            var tmp = try TmpDir.init(arena, .{});
            defer tmp.cleanup();

            const basename = "tiny.txt";
            const file = try tmp.dir.createFile(basename, .{});
            defer file.close();
            try file.writeAll("12345");

            const file_path = try std.fs.path.joinZ(arena, &.{ tmp.path, basename });
            var info: NS.stat_t = undefined;
            _ = try expect.sentinelNoError(-1, NS.stat(file_path, &info));
            try testing.expectEqual(5, info.size);
        }

        test "sigaction" {
            if (!comptime NS.hasFeature(.sigaction)) return error.SkipZigTest;

            var oact: NS.sigaction_t = undefined;
            _ = try expect.sentinelNoError(-1, NS.sigaction(.USR1, null, &oact));
        }

        test "sigset_t" {
            if (!comptime NS.hasFeature(.sigset_t)) return error.SkipZigTest;

            var ss0: NS.sigset_t = .{};
            try testing.expectEqual(true, ss0.is_empty());
            try testing.expectEqual(false, ss0.is_member(.HUP));

            ss0.empty();
            try testing.expectEqual(true, ss0.is_empty());

            ss0.fill();
            try testing.expectEqual(true, ss0.is_full());
            try testing.expectEqual(true, ss0.is_member(.HUP));

            var ss1: NS.sigset_t = .{};
            ss0.empty();
            ss1.empty();
            ss0.and_with(ss1);
            try testing.expectEqual(true, ss0.is_empty());

            ss0.empty();
            ss1.fill();
            ss0.and_with(ss1);
            try testing.expectEqual(true, ss0.is_empty());
            ss0.or_with(ss1);
            try testing.expectEqual(true, ss0.is_full());

            ss0.empty();
            ss0.add(.HUP);
            ss0.add(.QUIT);
            try testing.expectEqual(true, ss0.is_member(.HUP));
            try testing.expectEqual(false, ss0.is_member(.INT));
            try testing.expectEqual(true, ss0.is_member(.QUIT));
            ss1.empty();
            ss1.add(.INT);
            ss1.add(.QUIT);
            ss1.and_with(ss0);
            try testing.expectEqual(false, ss1.is_member(.HUP));
            try testing.expectEqual(false, ss1.is_member(.INT));
            try testing.expectEqual(true, ss1.is_member(.QUIT));

            ss0.empty();
            ss0.add(.HUP);
            ss1.empty();
            ss1.add(.INT);
            ss0.assign_from(ss1);
            try testing.expectEqual(false, ss0.is_member(.HUP));
            try testing.expectEqual(true, ss0.is_member(.INT));
            try testing.expectEqual(false, ss0.is_member(.QUIT));
        }

        test "symlink" {
            if (!comptime NS.hasFeature(.symlink)) return error.SkipZigTest;

            var arena_s = std.heap.ArenaAllocator.init(testing.allocator);
            defer arena_s.deinit();
            const arena = arena_s.allocator();
            var tmp = try TmpDir.init(arena, .{});
            defer tmp.cleanup();

            const realname = "real.txt";
            const linkname = "link.txt";
            const file = try tmp.dir.createFile(realname, .{});
            defer file.close();

            const path_real = try std.fs.path.joinZ(arena, &.{ tmp.path, realname });
            const path_link = try std.fs.path.joinZ(arena, &.{ tmp.path, linkname });
            _ = try expect.sentinelNoError(-1, NS.symlink(path_real, path_link));
            _ = try expect.sentinelError(-1, .EXIST, NS.symlink(path_real, path_link));
        }

        test "symlinkat" {
            if (!comptime NS.hasFeature(.symlinkat)) return error.SkipZigTest;

            var arena_s = std.heap.ArenaAllocator.init(testing.allocator);
            defer arena_s.deinit();
            const arena = arena_s.allocator();
            var tmp = try TmpDir.init(arena, .{});
            defer tmp.cleanup();

            const realname = "real.txt";
            const linkname = "link.txt";
            const file = try tmp.dir.createFile(realname, .{});
            defer file.close();

            const path_real = try std.fs.path.joinZ(arena, &.{ tmp.path, realname });
            _ = try expect.sentinelNoError(-1, NS.symlinkat(path_real, tmp.dir.fd, linkname));
            _ = try expect.sentinelError(-1, .EXIST, NS.symlinkat(path_real, tmp.dir.fd, linkname));
        }

        test "write" {
            if (!comptime NS.hasFeature(.write)) return error.SkipZigTest;

            const fd = try expect.sentinelNoError(-1, NS.open("/dev/null", .{ .ACCMODE = .WRONLY }, 0));
            var buf: [4]u8 = .{ 0x0, 0x1, 0x2, 0x3 };
            _ = try expect.sentinelNoError(-1, NS.write(fd, &buf, buf.len));
            _ = try expect.sentinelNoError(-1, NS.close(fd));
            try expect.sentinelError(-1, .BADF, NS.write(-42, &buf, buf.len));
        }
    };
}

const TmpDir = struct {
    dir: std.fs.Dir,
    parent_dir: std.fs.Dir,
    basename: [TmpDir.basename_len]u8,
    path: []const u8,

    const random_bytes_count = 12;
    const basename_len = std.fs.base64_encoder.calcSize(random_bytes_count);

    pub fn init(arena: std.mem.Allocator, opts: std.fs.Dir.OpenDirOptions) !TmpDir {
        var self: TmpDir = undefined;

        var random_bytes: [TmpDir.random_bytes_count]u8 = undefined;
        std.crypto.random.bytes(&random_bytes);

        _ = std.fs.base64_encoder.encode(&self.basename, &random_bytes);

        const cwd = std.fs.cwd();
        const parent_path = try std.fs.path.join(arena, &.{ ".zig-cache", "tmp" });
        self.parent_dir = try cwd.makeOpenPath(parent_path, .{});
        errdefer self.parent_dir.close();

        self.dir = try self.parent_dir.makeOpenPath(&self.basename, opts);
        errdefer self.dir.close();

        self.path = try std.fs.path.join(arena, &.{ ".zig-cache", "tmp", &self.basename });

        return self;
    }

    pub fn cleanup(self: *TmpDir) void {
        self.dir.close();
        self.parent_dir.deleteTree(&self.basename) catch {};
        self.parent_dir.close();
    }
};

comptime {
    _ = Test(std.os.freebsd.sys);
    _ = if (builtin.link_libc) Test(std.os.freebsd.c);
}
