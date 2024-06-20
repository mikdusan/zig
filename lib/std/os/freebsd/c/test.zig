//! This file tests both { c, sys } calls.
const std = @import("../../../std.zig");
const builtin = @import("builtin");
const c = std.os.freebsd.c;
const expect = std.os.freebsd.Expect(c);
const testing = std.testing;

test "closedir" {
    if (!comptime c.hasFeature(.closedir)) return error.SkipZigTest;

    const dir = c.opendir(".") orelse return error.TestExpectedNoError;
    _ = try expect.sentinelNoError(-1, c.closedir(dir));
}

test "dirfd" {
    if (!comptime c.hasFeature(.dirfd)) return error.SkipZigTest;

    const dir = c.opendir(".") orelse return error.TestExpectedNoError;
    defer _ = c.closedir(dir);
    _ = try expect.sentinelNoError(-1, c.dirfd(dir));
}

test "fdclosedir" {
    if (!comptime c.hasFeature(.fdclosedir)) return error.SkipZigTest;

    const dir = c.opendir(".") orelse return error.TestExpectedNoError;
    const fd = try expect.sentinelNoError(-1, c.fdclosedir(dir));
    _ = try expect.sentinelNoError(-1, c.close(fd));
}

test "fdopendir" {
    if (!comptime c.hasFeature(.fdopendir)) return error.SkipZigTest;

    const fd = try expect.sentinelNoError(-1, c.open(".", .{}, c.default.dir_mode));
    defer _ = c.close(fd);
    _ = try expect.sentinelNoError(null, c.fdopendir(fd));
}

test "opendir" {
    if (!comptime c.hasFeature(.opendir)) return error.SkipZigTest;

    const dir = c.opendir(".") orelse return error.TestExpectedNoError;
    _ = c.closedir(dir);
}

test "readdir" {
    if (!comptime c.hasFeature(.readdir)) return error.SkipZigTest;

    const dir = c.opendir(".") orelse return error.TestExpectedNoError;
    defer _ = c.closedir(dir);
    const entry = c.readdir(dir) orelse return error.TestExpectedNoError;
    try testing.expect(entry.namlen > 0);
}

test "rewinddir" {
    if (!comptime c.hasFeature(.rewinddir)) return error.SkipZigTest;

    const dir = c.opendir(".") orelse return error.TestExpectedNoError;
    defer _ = c.closedir(dir);
    const pos0 = try expect.sentinelNoError(-1, c.telldir(dir));
    _ = c.readdir(dir) orelse return error.TestExpectedNoError;
    c.rewinddir(dir);
    const pos1 = try expect.sentinelNoError(-1, c.telldir(dir));
    try testing.expectEqual(pos0, pos1);
}

test "seekdir" {
    if (!comptime c.hasFeature(.seekdir)) return error.SkipZigTest;

    const dir = c.opendir(".") orelse return error.TestExpectedNoError;
    defer _ = c.closedir(dir);
    const pos0 = try expect.sentinelNoError(-1, c.telldir(dir));
    _ = c.readdir(dir) orelse return error.TestExpectedNoError;
    c.seekdir(dir, pos0);
    const pos1 = try expect.sentinelNoError(-1, c.telldir(dir));
    try testing.expectEqual(pos0, pos1);
}

test "telldir" {
    if (!comptime c.hasFeature(.telldir)) return error.SkipZigTest;

    const dir = c.opendir(".") orelse return error.TestExpectedNoError;
    defer _ = c.closedir(dir);
    const pos0 = try expect.sentinelNoError(-1, c.telldir(dir));
    _ = c.readdir(dir) orelse return error.TestExpectedNoError;
    const pos1 = try expect.sentinelNoError(-1, c.telldir(dir));
    try testing.expect(pos1 > pos0);
}
