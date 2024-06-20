//! This file tests both { c, sys } calls.
const std = @import("../../std.zig");
const builtin = @import("builtin");
const c = std.os.freebsd.c;
const expect = std.os.freebsd.Expect(c);
const sys = std.os.freebsd.sys;
const testing = std.testing;

fn Test(NS: type) type {
    return struct {
        const invalid_clockid: NS.clockid_t = @enumFromInt(std.math.maxInt(@typeInfo(NS.clockid_t).Enum.tag_type));

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
            var tmp = try TmpDir.init(arena);
            defer tmp.cleanup();

            const file_path = try std.fs.path.joinZ(arena, &.{ tmp.path, "close_me.txt" });
            const fd = try expect.sentinelNoError(-1, NS.open(file_path, .{ .CREAT = true }, NS.mode_t.default_file));
            _ = try expect.sentinelNoError(-1, NS.close(fd));
            try expect.sentinelError(-1, .BADF, NS.close(fd));
        }

        test "creat" {
            if (!comptime NS.hasFeature(.creat)) return error.SkipZigTest;

            var arena_s = std.heap.ArenaAllocator.init(testing.allocator);
            defer arena_s.deinit();
            const arena = arena_s.allocator();
            var tmp = try TmpDir.init(arena);
            defer tmp.cleanup();

            const file_path = try std.fs.path.joinZ(arena, &.{ tmp.path, "create_me.txt" });
            const fd = try expect.sentinelNoError(-1, NS.creat(file_path, NS.mode_t.default_file));
            _ = try expect.sentinelNoError(-1, NS.close(fd));

            const bogus_path = try std.fs.path.joinZ(arena, &.{ tmp.path, "bogus", "create_me.txt" });
            try expect.sentinelError(-1, .NOENT, NS.creat(bogus_path, NS.mode_t.default_file));
        }

        test "getdents" {
            if (!comptime NS.hasFeature(.getdents)) return error.SkipZigTest;

            var arena_s = std.heap.ArenaAllocator.init(testing.allocator);
            defer arena_s.deinit();
            const arena = arena_s.allocator();
            var tmp = try TmpDir.init(arena);
            defer tmp.cleanup();

            const file = try tmp.dir.createFile("empty.txt", .{});
            defer file.close();

            var buf: [8192]u8 align(@alignOf(NS.dirent_t)) = undefined;
            const len = try expect.sentinelNoError(-1, NS.getdents(tmp.dir.fd, &buf, buf.len));

            var entries: [3]*const sys.dirent_t = undefined;
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
            var tmp = try TmpDir.init(arena);
            defer tmp.cleanup();

            const file = try tmp.dir.createFile("empty.txt", .{});
            defer file.close();

            var buf: [1024]u8 = undefined;
            const len = try expect.sentinelNoError(-1, NS.getdirentries(tmp.dir.fd, &buf, buf.len * @sizeOf(sys.dirent_t), null));

            var entries: [3]*const sys.dirent_t = undefined;
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

            try expect.sentinelError(-1, .BADF, NS.getdirentries(file.handle, &buf, buf.len * @sizeOf(sys.dirent_t), null));
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

            NS.__error().* = .SUCCESS;
            const pr = NS.getpriority(.PROCESS, 0);
            try expect.errno(.SUCCESS);
            try testing.expect(pr >= NS.priority.MIN);
            try testing.expect(pr <= NS.priority.MAX);
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

        test "mkdir" {
            if (!comptime NS.hasFeature(.mkdir)) return error.SkipZigTest;

            var arena_s = std.heap.ArenaAllocator.init(testing.allocator);
            defer arena_s.deinit();
            const arena = arena_s.allocator();
            var tmp = try TmpDir.init(arena);
            defer tmp.cleanup();

            const dir_path = try std.fs.path.joinZ(arena, &.{ tmp.path, "create_me" });
            _ = try expect.sentinelNoError(-1, NS.mkdir(dir_path, NS.mode_t.default_dir));

            const bogus_path = try std.fs.path.joinZ(arena, &.{ tmp.path, "bogus", "create_me" });
            try expect.sentinelError(-1, .NOENT, NS.mkdir(bogus_path, NS.mode_t.default_dir));
        }

        test "mkdirat" {
            if (!comptime NS.hasFeature(.mkdirat)) return error.SkipZigTest;

            var arena_s = std.heap.ArenaAllocator.init(testing.allocator);
            defer arena_s.deinit();
            const arena = arena_s.allocator();
            var tmp = try TmpDir.init(arena);
            defer tmp.cleanup();

            const dir_path = try std.fs.path.joinZ(arena, &.{ tmp.path, "create_me" });
            _ = try expect.sentinelNoError(-1, NS.mkdirat(NS.AT.FDCWD, dir_path, NS.mode_t.default_dir));

            const bogus_path = try std.fs.path.joinZ(arena, &.{ tmp.path, "bogus", "create_me" });
            try expect.sentinelError(-1, .NOENT, NS.mkdirat(NS.AT.FDCWD, bogus_path, NS.mode_t.default_dir));
        }

        test "mkfifo" {
            if (!comptime NS.hasFeature(.mkfifo)) return error.SkipZigTest;

            var arena_s = std.heap.ArenaAllocator.init(testing.allocator);
            defer arena_s.deinit();
            const arena = arena_s.allocator();
            var tmp = try TmpDir.init(arena);
            defer tmp.cleanup();

            const dir_path = try std.fs.path.joinZ(arena, &.{ tmp.path, "create_me" });
            _ = try expect.sentinelNoError(-1, NS.mkfifo(dir_path, NS.mode_t.default_file));

            const bogus_path = try std.fs.path.joinZ(arena, &.{ tmp.path, "bogus", "create_me" });
            try expect.sentinelError(-1, .NOENT, NS.mkfifo(bogus_path, NS.mode_t.default_file));
        }

        test "mkfifoat" {
            if (!comptime NS.hasFeature(.mkfifoat)) return error.SkipZigTest;

            var arena_s = std.heap.ArenaAllocator.init(testing.allocator);
            defer arena_s.deinit();
            const arena = arena_s.allocator();
            var tmp = try TmpDir.init(arena);
            defer tmp.cleanup();

            const dir_path = try std.fs.path.joinZ(arena, &.{ tmp.path, "create_me" });
            _ = try expect.sentinelNoError(-1, NS.mkfifoat(NS.AT.FDCWD, dir_path, NS.mode_t.default_file));

            const bogus_path = try std.fs.path.joinZ(arena, &.{ tmp.path, "bogus", "create_me" });
            try expect.sentinelError(-1, .NOENT, NS.mkfifoat(NS.AT.FDCWD, bogus_path, NS.mode_t.default_file));
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

            var tmp = try TmpDir.init(arena);
            defer tmp.cleanup();
            const file_path = try std.fs.path.joinZ(arena, &.{ tmp.path, "create_me.txt" });

            const fd = try expect.sentinelNoError(-1, NS.open(file_path, .{ .CREAT = true }, NS.mode_t.default_file));
            _ = try expect.sentinelNoError(-1, NS.close(fd));
        }

        test "openat" {
            if (!comptime NS.hasFeature(.openat)) return error.SkipZigTest;

            var arena_s = std.heap.ArenaAllocator.init(testing.allocator);
            defer arena_s.deinit();
            const arena = arena_s.allocator();

            var tmp = try TmpDir.init(arena);
            defer tmp.cleanup();
            const file_path = try std.fs.path.joinZ(arena, &.{ tmp.path, "create_me.txt" });

            const fd = try expect.sentinelNoError(-1, NS.openat(NS.AT.FDCWD, file_path, .{ .CREAT = true }, NS.mode_t.default_file));
            _ = try expect.sentinelNoError(-1, NS.close(fd));
        }

        test "read" {
            if (!comptime NS.hasFeature(.read)) return error.SkipZigTest;

            const fd = try expect.sentinelNoError(-1, NS.open("/dev/zero", .{}, .{}));
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

            NS.__error().* = .SUCCESS;
            const pr0 = NS.getpriority(.PROCESS, 0);
            try expect.errno(.SUCCESS);

            const pr1: @TypeOf(pr0) = @min(pr0 + 1, NS.priority.MAX);
            _ = try expect.sentinelNoError(-1, NS.setpriority(.PROCESS, 0, pr1));

            NS.__error().* = .SUCCESS;
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

        test "write" {
            if (!comptime NS.hasFeature(.write)) return error.SkipZigTest;

            const fd = try expect.sentinelNoError(-1, NS.open("/dev/null", .{ .WRONLY = true }, .{}));
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

    pub fn init(arena: std.mem.Allocator) !TmpDir {
        var self: TmpDir = undefined;

        var random_bytes: [TmpDir.random_bytes_count]u8 = undefined;
        std.crypto.random.bytes(&random_bytes);

        _ = std.fs.base64_encoder.encode(&self.basename, &random_bytes);

        const cwd = std.fs.cwd();
        const parent_path = try std.fs.path.join(arena, &.{ ".zig-cache", "tmp" });
        self.parent_dir = try cwd.makeOpenPath(parent_path, .{});
        errdefer self.parent_dir.close();

        self.dir = try self.parent_dir.makeOpenPath(&self.basename, .{});
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
    _ = Test(sys);
    _ = if (builtin.link_libc) Test(c);
}
