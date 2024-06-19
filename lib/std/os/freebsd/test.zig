//! This file tests both { c, sys } calls.
const std = @import("../../std.zig");
const builtin = @import("builtin");
const c = std.os.freebsd.c;
const sys = std.os.freebsd.sys;
const testing = std.testing;

comptime {
    _ = Test(sys);
    _ = if (builtin.link_libc) Test(c);
}

fn Test(NS: type) type {
    return struct {
        test "clock_getcpuclockid" {
            if (!comptime NS.hasFeature(.clock_getcpuclockid)) return error.SkipZigTest;

            var id: NS.clockid_t = undefined;
            _ = try invExpectNoError(NS.clock_getcpuclockid(0, &id));
        }

        test "clock_getres" {
            if (!comptime NS.hasFeature(.clock_getres)) return error.SkipZigTest;

            var tp: NS.timespec_t = undefined;
            _ = try invExpectNoError(NS.clock_getres(.MONOTONIC, &tp));
            try testing.expect(tp.sec > 0 or tp.nsec > 0);
        }

        test "clock_gettime" {
            if (!comptime NS.hasFeature(.clock_gettime)) return error.SkipZigTest;

            var tp: NS.timespec_t = undefined;
            _ = try invExpectNoError(NS.clock_gettime(.MONOTONIC, &tp));
            try testing.expect(tp.sec > 0 or tp.nsec > 0);
        }

        test "clock_nanosleep" {
            if (!comptime NS.hasFeature(.clock_nanosleep)) return error.SkipZigTest;

            const rqtp: NS.timespec_t = .{ .sec = 0, .nsec = 1000 };
            _ = try directExpectNoError(NS.clock_nanosleep(.MONOTONIC, .RELTIME, &rqtp, null));
        }

        test "clock_settime" {
            if (!comptime NS.hasFeature(.clock_settime)) return error.SkipZigTest;
            // do not run this test as root
            if (NS.geteuid() == 0) return error.SkipZigTest;

            _ = try invExpectError(.PERM, NS.clock_settime(.MONOTONIC, &.{ .sec = 0, .nsec = 1000 }));
        }

        test "close" {
            if (!comptime NS.hasFeature(.close)) return error.SkipZigTest;

            var arena_s = std.heap.ArenaAllocator.init(testing.allocator);
            defer arena_s.deinit();
            const arena = arena_s.allocator();
            var tmp = try TmpDir.init(arena);
            defer tmp.cleanup();

            const file_path = try std.fs.path.joinZ(arena, &.{ tmp.path, "close_me.txt" });
            const fd = try expectNoError(-1, NS.open(file_path, .{ .CREAT = true }, NS.mode_t.default_file));
            _ = try expectNoError(-1, NS.close(fd));
            try expectError(-1, .BADF, NS.close(fd));
        }

        test "closedir" {
            if (!comptime NS.hasFeature(.closedir)) return error.SkipZigTest;

            const dir = NS.opendir(".") orelse return error.TestExpectedNoError;
            _ = try expectNoError(-1, NS.closedir(dir));
        }

        test "creat" {
            if (!comptime NS.hasFeature(.creat)) return error.SkipZigTest;

            var arena_s = std.heap.ArenaAllocator.init(testing.allocator);
            defer arena_s.deinit();
            const arena = arena_s.allocator();
            var tmp = try TmpDir.init(arena);
            defer tmp.cleanup();

            const file_path = try std.fs.path.joinZ(arena, &.{ tmp.path, "create_me.txt" });
            const fd = try expectNoError(-1, NS.creat(file_path, NS.mode_t.default_file));
            _ = try expectNoError(-1, NS.close(fd));

            const bogus_path = try std.fs.path.joinZ(arena, &.{ tmp.path, "bogus", "create_me.txt" });
            try expectError(-1, .NOENT, NS.creat(bogus_path, NS.mode_t.default_file));
        }

        test "dirfd" {
            if (!comptime NS.hasFeature(.dirfd)) return error.SkipZigTest;

            const dir = NS.opendir(".") orelse return error.TestExpectedNoError;
            defer _ = NS.closedir(dir);
            _ = try expectNoError(-1, NS.dirfd(dir));
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
            const len = try expectNoError(-1, NS.getdents(tmp.dir.fd, &buf, buf.len));

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

            try expectError(-1, .BADF, NS.getdents(file.handle, &buf, buf.len));
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
            const len = try expectNoError(-1, NS.getdirentries(tmp.dir.fd, &buf, buf.len * @sizeOf(sys.dirent_t), null));

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

            try expectError(-1, .BADF, NS.getdirentries(file.handle, &buf, buf.len * @sizeOf(sys.dirent_t), null));
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
            _ = try expectNoError(-1, NS.mkdir(dir_path, NS.mode_t.default_dir));

            const bogus_path = try std.fs.path.joinZ(arena, &.{ tmp.path, "bogus", "create_me" });
            try expectError(-1, .NOENT, NS.mkdir(bogus_path, NS.mode_t.default_dir));
        }

        test "mkdirat" {
            if (!comptime NS.hasFeature(.mkdirat)) return error.SkipZigTest;

            var arena_s = std.heap.ArenaAllocator.init(testing.allocator);
            defer arena_s.deinit();
            const arena = arena_s.allocator();
            var tmp = try TmpDir.init(arena);
            defer tmp.cleanup();

            const dir_path = try std.fs.path.joinZ(arena, &.{ tmp.path, "create_me" });
            _ = try expectNoError(-1, NS.mkdirat(NS.AT.FDCWD, dir_path, NS.mode_t.default_dir));

            const bogus_path = try std.fs.path.joinZ(arena, &.{ tmp.path, "bogus", "create_me" });
            try expectError(-1, .NOENT, NS.mkdirat(NS.AT.FDCWD, bogus_path, NS.mode_t.default_dir));
        }

        test "nanosleep" {
            if (!comptime NS.hasFeature(.nanosleep)) return error.SkipZigTest;

            const rqtp: NS.timespec_t = .{ .sec = 0, .nsec = 1000 };
            _ = try directExpectNoError(NS.nanosleep(&rqtp, null));
        }

        test "open" {
            if (!comptime NS.hasFeature(.open)) return error.SkipZigTest;

            var arena_s = std.heap.ArenaAllocator.init(testing.allocator);
            defer arena_s.deinit();
            const arena = arena_s.allocator();

            var tmp = try TmpDir.init(arena);
            defer tmp.cleanup();
            const file_path = try std.fs.path.joinZ(arena, &.{ tmp.path, "create_me.txt" });

            const fd = try expectNoError(-1, NS.open(file_path, .{ .CREAT = true }, NS.mode_t.default_file));
            _ = try expectNoError(-1, NS.close(fd));
        }

        test "openat" {
            if (!comptime NS.hasFeature(.openat)) return error.SkipZigTest;

            var arena_s = std.heap.ArenaAllocator.init(testing.allocator);
            defer arena_s.deinit();
            const arena = arena_s.allocator();

            var tmp = try TmpDir.init(arena);
            defer tmp.cleanup();
            const file_path = try std.fs.path.joinZ(arena, &.{ tmp.path, "create_me.txt" });

            const fd = try expectNoError(-1, NS.openat(NS.AT.FDCWD, file_path, .{ .CREAT = true }, NS.mode_t.default_file));
            _ = try expectNoError(-1, NS.close(fd));
        }

        test "opendir" {
            if (!comptime NS.hasFeature(.opendir)) return error.SkipZigTest;

            const dir = NS.opendir(".") orelse return error.TestExpectedNoError;
            _ = NS.closedir(dir);
        }

        test "read" {
            if (!comptime NS.hasFeature(.read)) return error.SkipZigTest;

            const fd = try expectNoError(-1, NS.open("/dev/zero", .{}, .{}));
            var buf: [4]u8 = undefined;
            _ = try expectNoError(-1, NS.read(fd, &buf, buf.len));
            _ = try expectNoError(-1, NS.close(fd));
        }

        test "readdir" {
            if (!comptime NS.hasFeature(.readdir)) return error.SkipZigTest;

            const dir = NS.opendir(".") orelse return error.TestExpectedNoError;
            defer _ = NS.closedir(dir);
            const entry = NS.readdir(dir) orelse return error.TestExpectedNoError;
            try testing.expect(entry.namlen > 0);
        }

        test "rewinddir" {
            if (!comptime NS.hasFeature(.rewinddir)) return error.SkipZigTest;

            const dir = NS.opendir(".") orelse return error.TestExpectedNoError;
            defer _ = NS.closedir(dir);
            const pos0 = try expectNoError(-1, NS.telldir(dir));
            _ = NS.readdir(dir) orelse return error.TestExpectedNoError;
            NS.rewinddir(dir);
            const pos1 = try expectNoError(-1, NS.telldir(dir));
            try testing.expectEqual(pos0, pos1);
        }

        test "seekdir" {
            if (!comptime NS.hasFeature(.seekdir)) return error.SkipZigTest;

            const dir = NS.opendir(".") orelse return error.TestExpectedNoError;
            defer _ = NS.closedir(dir);
            const pos0 = try expectNoError(-1, NS.telldir(dir));
            _ = NS.readdir(dir) orelse return error.TestExpectedNoError;
            NS.seekdir(dir, pos0);
            const pos1 = try expectNoError(-1, NS.telldir(dir));
            try testing.expectEqual(pos0, pos1);
        }

        test "setuid" {
            if (!comptime NS.hasFeature(.setuid)) return error.SkipZigTest;
            const euid = try expectNoError(-1, NS.geteuid());
            _ = try expectNoError(-1, NS.setuid(euid));
            if (euid != 0) try expectError(-1, .PERM, NS.setuid(0));
        }

        test "seteuid" {
            if (!comptime NS.hasFeature(.seteuid)) return error.SkipZigTest;
            const euid = try expectNoError(-1, NS.geteuid());
            _ = try expectNoError(-1, NS.seteuid(euid));
            if (euid != 0) try expectError(-1, .PERM, NS.seteuid(0));
        }

        test "setgid" {
            if (!comptime NS.hasFeature(.setgid)) return error.SkipZigTest;
            const egid = try expectNoError(-1, NS.getegid());
            _ = try expectNoError(-1, NS.setgid(egid));
            if (egid != 0) try expectError(-1, .PERM, NS.setgid(0));
        }

        test "setegid" {
            if (!comptime NS.hasFeature(.setegid)) return error.SkipZigTest;
            const egid = try expectNoError(-1, NS.getegid());
            _ = try expectNoError(-1, NS.setegid(egid));
            if (egid != 0) try expectError(-1, .PERM, NS.setegid(0));
        }

        test "telldir" {
            if (!comptime NS.hasFeature(.telldir)) return error.SkipZigTest;

            const dir = NS.opendir(".") orelse return error.TestExpectedNoError;
            defer _ = NS.closedir(dir);
            const pos0 = try expectNoError(-1, NS.telldir(dir));
            _ = NS.readdir(dir) orelse return error.TestExpectedNoError;
            const pos1 = try expectNoError(-1, NS.telldir(dir));
            try testing.expect(pos1 > pos0);
        }

        test "write" {
            if (!comptime NS.hasFeature(.write)) return error.SkipZigTest;

            const fd = try expectNoError(-1, NS.open("/dev/null", .{ .WRONLY = true }, .{}));
            var buf: [4]u8 = .{ 0x0, 0x1, 0x2, 0x3 };
            _ = try expectNoError(-1, NS.write(fd, &buf, buf.len));
            _ = try expectNoError(-1, NS.close(fd));
            try expectError(-1, .BADF, NS.write(-42, &buf, buf.len));
        }

        // use with return convention where:
        //   - error rv == -1 and errno
        fn expectError(expected_error_sentinel: anytype, expected_ecode: NS.E, rv: anytype) !void {
            if (rv != expected_error_sentinel) {
                print("expected error sentinel {}, found {}\n", .{ expected_error_sentinel, rv });
                return error.TestExpectedError;
            }
            const ec = NS.errno();
            if (ec != expected_ecode) {
                print("expected error {}, found {}\n", .{ expected_ecode, ec });
                return error.TestExpectedError;
            }
        }

        // use with return convention where:
        //   - error rv == -1 and errno
        fn expectNoError(unexpected_error_sentinel: anytype, rv: anytype) !@TypeOf(rv) {
            if (rv == unexpected_error_sentinel) {
                print("expected no error sentinel {}, found {} and errno={s}\n", .{ unexpected_error_sentinel, rv, @tagName(NS.errno()) });
                return error.TestExpectedNoError;
            }
            return rv;
        }

        // use with return convention where:
        //   - success rv == 0
        //   - otherwise errno
        fn invExpectError(expected_ecode: NS.E, rv: anytype) !void {
            if (rv == 0) {
                print("expected sentinel != 0, found {} and errno={s}\n", .{ rv, @tagName(NS.errno()) });
                return error.TestExpectedNoError;
            }
            const ec = NS.errno();
            if (ec != expected_ecode) {
                print("expected errno {}, found {}\n", .{ expected_ecode, ec });
                return error.TestExpectedError;
            }
        }

        // use with return convention where:
        //   - success rv == 0
        //   - otherwise errno
        fn invExpectNoError(rv: anytype) !@TypeOf(rv) {
            if (rv != 0) {
                print("expected sentinel == 0, found {} and errno={s}\n", .{ rv, @tagName(NS.errno()) });
                return error.TestExpectedNoError;
            }
            return rv;
        }

        // use with return convention where:
        //   - success rv == 0
        //   - otherwise rv is the error code
        fn directExpectError(expected_ecode: NS.E, rv: anytype) !void {
            if (@typeInfo(@TypeOf(rv)) == .Pointer) {
                if (rv == null) {
                    print("expected sentinel != null, found {}\n", .{rv});
                    return error.TestExpectedError;
                }
            } else {
                if (rv == 0) {
                    print("expected sentinel != 0, found {}\n", .{rv});
                    return error.TestExpectedError;
                }
            }
            if (rv != expected_ecode) {
                print("expected error {}, found {}\n", .{ expected_ecode, rv });
                return error.TestExpectedError;
            }
        }

        // use with return convention where:
        //   - success rv == 0
        //   - otherwise rv is the error code
        fn directExpectNoError(rv: anytype) !@TypeOf(rv) {
//@compileLog(@TypeOf(rv));
            const info = @typeInfo(@TypeOf(rv));
            if (info == .Optional and @typeInfo(info.Optional.child) == .Pointer) {
                if (rv != null) {
                    print("expected sentinel == null, found {}\n", .{ rv });
                    return error.TestExpectedNoError;
                }
            } else {
                if (rv != 0) {
                    const ec: NS.E = @enumFromInt(rv);
                    print("expected sentinel == 0, found {} and direct errno={s}\n", .{ rv, @tagName(ec) });
                    return error.TestExpectedNoError;
                }
            }
            return rv;
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

fn print(comptime fmt: []const u8, args: anytype) void {
    if (@inComptime()) {
        @compileError(std.fmt.comptimePrint(fmt, args));
    } else if (testing.backend_can_print) {
        std.debug.print(fmt, args);
    }
}
