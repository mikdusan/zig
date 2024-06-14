const std = @import("../../../std.zig");
const builtin = @import("builtin");
const c = std.os.freebsd.c;
const testing = std.testing;

test "open" {
    if (!comptime c.hasFeatures(.{ .open, .close })) return error.SkipZigTest;

    var arena_s = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_s.deinit();
    const arena = arena_s.allocator();

    var tmp = try TmpDir.init(arena);
    defer tmp.cleanup();
    const file_path = try std.fs.path.joinZ(arena, &.{ tmp.path, "close_me.txt" });

    const fd = c.open(file_path, .{ .CREAT = true }, c.mode_t.default_file);
    try testing.expect(fd != -1);
    try testing.expectEqual(0, c.close(fd));
}

//test "openat" {
//    if (!comptime c.hasFeatures(.{ .openat, .close })) return error.SkipZigTest;
//    const fd = c.openat(c.AT.FDCWD, "mike.txt", .{ .CREAT = true }, c.mode_t.default_file);
//    try testing.expect(fd != -1);
//    try testing.expectEqual(0, c.close(fd));
//}
//
//test "mkdir" {
//    if (!comptime c.hasFeature(.mkdir)) return error.SkipZigTest;
//    try testing.expectEqual(0, c.mkdir("mike.dir3", c.mode_t.default_dir));
//}
//
//test "mkdirat" {
//    if (!comptime c.hasFeature(.mkdirat)) return error.SkipZigTest;
//    try testing.expectEqual(0, c.mkdirat(c.AT.FDCWD, "mike.dir4", c.mode_t.default_dir));
//}
//
