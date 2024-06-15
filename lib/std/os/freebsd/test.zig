//! This file tests both { c, sys } calls.
const std = @import("../../std.zig");
const builtin = @import("builtin");
const c = std.os.freebsd.c;
const sys = std.os.freebsd.sys;
const testing = std.testing;

comptime {
    _ = Test(c);
    _ = Test(sys);
}

fn Test(NS: type) type {
    return struct {
        test "close" {
            if (!comptime NS.hasFeatures(.{ .open, .close })) return error.SkipZigTest;

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

        test "creat" {
            if (!comptime NS.hasFeatures(.{ .creat, .close })) return error.SkipZigTest;

            var arena_s = std.heap.ArenaAllocator.init(testing.allocator);
            defer arena_s.deinit();
            const arena = arena_s.allocator();

            var tmp = try TmpDir.init(arena);
            defer tmp.cleanup();
            const file_path = try std.fs.path.joinZ(arena, &.{ tmp.path, "create_me.txt" });

            const fd = try expectNoError(-1, NS.creat(file_path, NS.mode_t.default_file));
            _ = try expectNoError(-1, NS.close(fd));
        }

        test "getdents" {
            if (!comptime NS.hasFeatures(.{ .getdents })) return error.SkipZigTest;

            var arena_s = std.heap.ArenaAllocator.init(testing.allocator);
            defer arena_s.deinit();
            const arena = arena_s.allocator();

            var tmp = try TmpDir.init(arena);
            defer tmp.cleanup();

            const file = try tmp.dir.createFile("small.txt", .{});
            defer file.close();
            try testing.expectEqual(4, try file.write("1234"));

            var buf: [1024]u8 = undefined;
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
                    9 => try testing.expectEqualStrings("small.txt", p.name[0..p.namlen]),
                    else => {},
                }
            }
        }

        test "getdirentries" {
            if (!comptime NS.hasFeatures(.{ .getdirentries })) return error.SkipZigTest;

            var arena_s = std.heap.ArenaAllocator.init(testing.allocator);
            defer arena_s.deinit();
            const arena = arena_s.allocator();

            var tmp = try TmpDir.init(arena);
            defer tmp.cleanup();

            const file = try tmp.dir.createFile("small.txt", .{});
            defer file.close();
            try testing.expectEqual(4, try file.write("1234"));

            var buf: [1024]u8 = undefined;
            const len = try expectNoError(-1, NS.getdirentries(tmp.dir.fd, @ptrCast(&buf), buf.len * @sizeOf(sys.dirent_t), null));

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
                    9 => try testing.expectEqualStrings("small.txt", p.name[0..p.namlen]),
                    else => {},
                }
            }
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
        }

        test "open" {
            if (!comptime NS.hasFeatures(.{ .open, .close })) return error.SkipZigTest;

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
            if (!comptime NS.hasFeatures(.{ .openat, .close })) return error.SkipZigTest;

            var arena_s = std.heap.ArenaAllocator.init(testing.allocator);
            defer arena_s.deinit();
            const arena = arena_s.allocator();

            var tmp = try TmpDir.init(arena);
            defer tmp.cleanup();
            const file_path = try std.fs.path.joinZ(arena, &.{ tmp.path, "create_me.txt" });

            const fd = try expectNoError(-1, NS.openat(NS.AT.FDCWD, file_path, .{ .CREAT = true }, NS.mode_t.default_file));
            _ = try expectNoError(-1, NS.close(fd));
        }

        test "read" {
            if (!comptime NS.hasFeatures(.{ .open, .read, .close })) return error.SkipZigTest;

            const fd = try expectNoError(-1, NS.open("/dev/zero", .{}, .{}));
            var buf: [4]u8 = undefined;
            _ = try expectNoError(-1, NS.read(fd, &buf, buf.len));
            _ = try expectNoError(-1, NS.close(fd));
        }

        test "setuid" {
            if (!comptime NS.hasFeatures(.{ .geteuid, .setuid })) return error.SkipZigTest;
            const euid = try expectNoError(-1, NS.geteuid());
            _ = try expectNoError(-1, NS.setuid(euid));
            if (euid != 0) try expectError(-1, .PERM, NS.setuid(0));
        }

        test "seteuid" {
            if (!comptime NS.hasFeatures(.{ .geteuid, .seteuid })) return error.SkipZigTest;
            const euid = try expectNoError(-1, NS.geteuid());
            _ = try expectNoError(-1, NS.seteuid(euid));
            if (euid != 0) try expectError(-1, .PERM, NS.seteuid(0));
        }

        test "setgid" {
            if (!comptime NS.hasFeatures(.{ .getegid, .setgid })) return error.SkipZigTest;
            const egid = try expectNoError(-1, NS.getegid());
            _ = try expectNoError(-1, NS.setgid(egid));
            if (egid != 0) try expectError(-1, .PERM, NS.setgid(0));
        }

        test "setegid" {
            if (!comptime NS.hasFeatures(.{ .getegid, .setegid })) return error.SkipZigTest;
            const egid = try expectNoError(-1, NS.getegid());
            _ = try expectNoError(-1, NS.setegid(egid));
            if (egid != 0) try expectError(-1, .PERM, NS.setegid(0));
        }

        test "write" {
            if (!comptime NS.hasFeatures(.{ .open, .write, .close })) return error.SkipZigTest;

            const fd = try expectNoError(-1, NS.open("/dev/null", .{ .WRONLY = true }, .{}));
            var buf: [4]u8 = .{ 0x0, 0x1, 0x2, 0x3 };
            _ = try expectNoError(-1, NS.write(fd, &buf, buf.len));
            _ = try expectNoError(-1, NS.close(fd));
        }

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

        fn expectNoError(unexpected_error_sentinel: anytype, rv: anytype) !@TypeOf(rv) {
            if (rv == unexpected_error_sentinel) {
                print("expected no error sentinel, found {} and errno={s}\n", .{ unexpected_error_sentinel, @tagName(NS.errno()) });
                return error.TestExpectedNoError;
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
