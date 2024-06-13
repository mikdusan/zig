const std = @import("../../../std.zig");
const builtin = @import("builtin");
const testing = std.testing;
const sys = std.os.freebsd.sys;

test "close" {
    if (!comptime sys.hasFeatures(.{ .open, .close })) return error.SkipZigTest;
    const sr = sys.open("mike.txt", .{ .CREAT = true }, sys.mode_t.default_file);
    const fd: sys.fd_t = @intCast(try expectSrNoError(sr));
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
    const sr = sys.mkdir("mike.dir", sys.mode_t.default_dir);
    _ = try expectSrNoError(sr);
}

test "mkdirat" {
    if (!comptime sys.hasFeature(.mkdirat)) return error.SkipZigTest;
    const sr = sys.mkdirat(sys.AT.FDCWD, "mike.dir2", sys.mode_t.default_dir);
    _ = try expectSrNoError(sr);
}

test "open" {
    if (!comptime sys.hasFeatures(.{ .open, .close })) return error.SkipZigTest;
    const sr = sys.open("mike.txt", .{ .CREAT = true }, sys.mode_t.default_file);
    const fd: sys.fd_t = @intCast(try expectSrNoError(sr));
    _ = try expectSrNoError(sys.close(fd));
}

test "openat" {
    if (!comptime sys.hasFeatures(.{ .openat, .close })) return error.SkipZigTest;
    const sr = sys.openat(sys.AT.FDCWD, "mike.txt", .{ .CREAT = true }, sys.mode_t.default_file);
    const fd: sys.fd_t = @intCast(try expectSrNoError(sr));
    _ = try expectSrNoError(sys.close(fd));
}

test "setuid" {
    if (!comptime sys.hasFeatures(.{ .geteuid, .setuid })) return error.SkipZigTest;
    const euid: sys.uid_t = @intCast(try expectSrNoError(sys.geteuid()));
    _ = try expectSrNoError(sys.setuid(euid));
    if (euid != 0) try expectSrError(.PERM, sys.setuid(0));
}

test "seteuid" {
    if (!comptime sys.hasFeatures(.{ .geteuid, .seteuid })) return error.SkipZigTest;
    const euid: sys.uid_t = @intCast(try expectSrNoError(sys.geteuid()));
    _ = try expectSrNoError(sys.seteuid(euid));
    if (euid != 0) try expectSrError(.PERM, sys.seteuid(0));
}

test "setgid" {
    if (!comptime sys.hasFeatures(.{ .getegid, .setgid })) return error.SkipZigTest;
    const egid: sys.gid_t = @intCast(try expectSrNoError(sys.getegid()));
    _ = try expectSrNoError(sys.setgid(egid));
    if (egid != 0) try expectSrError(.PERM, sys.setgid(0));
}

test "setegid" {
    if (!comptime sys.hasFeatures(.{ .getegid, .setegid })) return error.SkipZigTest;
    const egid: sys.gid_t = @intCast(try expectSrNoError(sys.getegid()));
    _ = try expectSrNoError(sys.setegid(egid));
    if (egid != 0) try expectSrError(.PERM, sys.setegid(0));
}

fn expectSrError(expected_ecode: sys.E, sr: sys.SyscallResult) !void {
    if (!sr.eflag.present) return error.TestExpectedSrNoError;
    if (sr.ecode != expected_ecode) {
        print("expected {s}, found {s}\n", .{ @tagName(expected_ecode), @tagName(sr.ecode) });
        return error.TestExpectedSrNoError;
    }
}

fn expectSrNoError(sr: sys.SyscallResult) !usize {
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
