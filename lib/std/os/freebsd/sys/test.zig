const std = @import("../../../std.zig");
const builtin = @import("builtin");
const sys = std.os.freebsd.sys;
const testing = std.testing;

test "close" {
    if (!comptime sys.hasFeatures(.{ .open, .close })) return error.SkipZigTest;

    var arena_s = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_s.deinit();
    const arena = arena_s.allocator();

    var tmp = try TmpDir.init(arena);
    defer tmp.cleanup();
    const file_path = try std.fs.path.joinZ(arena, &.{ tmp.path, "close_me.txt" });

    const fd = try expectSrNoError(sys.open(file_path, .{ .CREAT = true }, sys.mode_t.default_file));
    _ = try expectSrNoError(sys.close(fd));
    try expectSrError(.BADF, sys.close(fd));
}

test "getpid" {
    if (!comptime sys.hasFeature(.getpid)) return error.SkipZigTest;
    _ = try expectSrNoError(sys.getpid());
}

test "getppid" {
    if (!comptime sys.hasFeature(.getppid)) return error.SkipZigTest;
    _ = try expectSrNoError(sys.getppid());
}

test "getuid" {
    if (!comptime sys.hasFeature(.getuid)) return error.SkipZigTest;
    _ = try expectSrNoError(sys.getuid());
}

test "geteuid" {
    if (!comptime sys.hasFeature(.geteuid)) return error.SkipZigTest;
    _ = try expectSrNoError(sys.geteuid());
}

test "getgid" {
    if (!comptime sys.hasFeature(.getgid)) return error.SkipZigTest;
    _ = try expectSrNoError(sys.getgid());
}

test "getegid" {
    if (!comptime sys.hasFeature(.getegid)) return error.SkipZigTest;
    _ = try expectSrNoError(sys.getegid());
}

test "mkdir" {
    if (!comptime sys.hasFeature(.mkdir)) return error.SkipZigTest;

    var arena_s = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_s.deinit();
    const arena = arena_s.allocator();

    var tmp = try TmpDir.init(arena);
    defer tmp.cleanup();
    const dir_path = try std.fs.path.joinZ(arena, &.{ tmp.path, "create_me" });

    _ = try expectSrNoError(sys.mkdir(dir_path, sys.mode_t.default_dir));
}

test "mkdirat" {
    if (!comptime sys.hasFeature(.mkdirat)) return error.SkipZigTest;

    var arena_s = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_s.deinit();
    const arena = arena_s.allocator();

    var tmp = try TmpDir.init(arena);
    defer tmp.cleanup();
    const dir_path = try std.fs.path.joinZ(arena, &.{ tmp.path, "create_me" });

    _ = try expectSrNoError(sys.mkdirat(sys.AT.FDCWD, dir_path, sys.mode_t.default_dir));
}

test "open" {
    if (!comptime sys.hasFeatures(.{ .open, .close })) return error.SkipZigTest;

    var arena_s = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_s.deinit();
    const arena = arena_s.allocator();

    var tmp = try TmpDir.init(arena);
    defer tmp.cleanup();
    const file_path = try std.fs.path.joinZ(arena, &.{ tmp.path, "create_me.txt" });

    const fd = try expectSrNoError(sys.open(file_path, .{ .CREAT = true }, sys.mode_t.default_file));
    _ = try expectSrNoError(sys.close(fd));
}

test "openat" {
    if (!comptime sys.hasFeatures(.{ .openat, .close })) return error.SkipZigTest;

    var arena_s = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_s.deinit();
    const arena = arena_s.allocator();

    var tmp = try TmpDir.init(arena);
    defer tmp.cleanup();
    const file_path = try std.fs.path.joinZ(arena, &.{ tmp.path, "create_me.txt" });

    const fd = try expectSrNoError(sys.openat(sys.AT.FDCWD, file_path, .{ .CREAT = true }, sys.mode_t.default_file));
    _ = try expectSrNoError(sys.close(fd));
}

test "setuid" {
    if (!comptime sys.hasFeatures(.{ .geteuid, .setuid })) return error.SkipZigTest;
    const euid = try expectSrNoError(sys.geteuid());
    _ = try expectSrNoError(sys.setuid(euid));
    if (euid != 0) try expectSrError(.PERM, sys.setuid(0));
}

test "seteuid" {
    if (!comptime sys.hasFeatures(.{ .geteuid, .seteuid })) return error.SkipZigTest;
    const euid = try expectSrNoError(sys.geteuid());
    _ = try expectSrNoError(sys.seteuid(euid));
    if (euid != 0) try expectSrError(.PERM, sys.seteuid(0));
}

test "setgid" {
    if (!comptime sys.hasFeatures(.{ .getegid, .setgid })) return error.SkipZigTest;
    const egid = try expectSrNoError(sys.getegid());
    _ = try expectSrNoError(sys.setgid(egid));
    if (egid != 0) try expectSrError(.PERM, sys.setgid(0));
}

test "setegid" {
    if (!comptime sys.hasFeatures(.{ .getegid, .setegid })) return error.SkipZigTest;
    const egid = try expectSrNoError(sys.getegid());
    _ = try expectSrNoError(sys.setegid(egid));
    if (egid != 0) try expectSrError(.PERM, sys.setegid(0));
}

pub const TmpDir = struct {
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

fn expectSrError(expected_ecode: sys.E, sr: anytype) !void {
    if (!sr.eflag.present) {
        print("expected {s}, found no error\n", .{ @tagName(expected_ecode) });
        return error.TestExpectedSrNoError;
    }
    if (sr.ecode != expected_ecode) {
        print("expected {s}, found {s}\n", .{ @tagName(expected_ecode), @tagName(sr.ecode) });
        return error.TestExpectedSrNoError;
    }
}

fn expectSrNoError(sr: anytype) !@TypeOf(sr).Type {
    if (sr.eflag.present) {
        print("expected no error, found {s}\n", .{ @tagName(sr.ecode) });
        return error.TestExpectedSrNoError;
    }
    return sr.value;
}

fn print(comptime fmt: []const u8, args: anytype) void {
    if (@inComptime()) {
        @compileError(std.fmt.comptimePrint(fmt, args));
    } else if (testing.backend_can_print) {
        std.debug.print(fmt, args);
    }
}
