const std = @import("../std.zig");
const builtin = @import("builtin");
const testing = std.testing;

pub const c = if (builtin.link_libc) @import("freebsd/c.zig") else std.missing_feature;
pub const sys = @import("freebsd/sys.zig");

pub fn Expect(NS: type) type {
    return struct {
        /// Test return has sentinel value which indicates error,
        /// and that errno() is set to the expected value.
        pub fn sentinelError(expected_error_sentinel: anytype, expected_ecode: NS.E, rv: anytype) !void {
            if (rv != expected_error_sentinel) {
                print("expected sentinel error {}, but found {any}\n", .{ expected_error_sentinel, rv });
                return error.TestExpectedError;
            }
            const ec = NS.errno();
            if (ec != expected_ecode) {
                print("expected errno {s}, but found {s}\n", .{ @tagName(expected_ecode), @tagName(ec) });
                return error.TestExpectedError;
            }
        }

        /// Test return does not have sentinel value which indicates error.
        pub fn sentinelNoError(unexpected_error_sentinel: anytype, rv: anytype) !@TypeOf(rv) {
            if (rv == unexpected_error_sentinel) {
                print("expected no sentinel error, but found {any} with errno {s}\n", .{ rv, @tagName(NS.errno()) });
                return error.TestExpectedNoError;
            }
            return rv;
        }

        /// Test return does not have sentinel value which indicates no-error,
        /// and that errno() is set to the expected value.
        pub fn directError(expected_ecode: NS.E, rv: anytype) !void {
            const info = @typeInfo(@TypeOf(rv));
            if (info == .Optional and @typeInfo(info.Optional.child) == .Pointer) {
                if (rv == null) {
                    print("expected sentinel != null, but found {any}", .{rv});
                    return error.TestExpectedError;
                }
            } else {
                if (rv == 0) {
                    print("expected sentinel != 0, but found {}\n", .{rv});
                    return error.TestExpectedError;
                }
            }
            if (rv != @intFromEnum(expected_ecode)) {
                const ec: NS.E = @enumFromInt(rv);
                print("expected errno {s}, but found {s}\n", .{ @tagName(expected_ecode), @tagName(ec) });
                return error.TestExpectedError;
            }
        }

        /// Test return does not have sentinel value which indicates no-error.
        pub fn directNoError(rv: anytype) !@TypeOf(rv) {
            const info = @typeInfo(@TypeOf(rv));
            if (info == .Optional and @typeInfo(info.Optional.child) == .Pointer) {
                if (rv != null) {
                    print("expected sentinel == null, but found {any}\n", .{rv});
                    return error.TestExpectedNoError;
                }
            } else {
                if (rv != 0) {
                    const ec: NS.E = @enumFromInt(rv);
                    print("expected sentinel == 0, but found {s}\n", .{@tagName(ec)});
                    return error.TestExpectedNoError;
                }
            }
            return rv;
        }

        /// Test errno() has the expected value.
        pub fn errno(expected_ecode: NS.E) !void {
            const ec = NS.errno();
            if (ec != expected_ecode) {
                print("expected errno {s}, found {s}\n", .{ @tagName(expected_ecode), @tagName(ec) });
                return error.TestExpectedErrno;
            }
        }

        pub fn print(comptime fmt: []const u8, args: anytype) void {
            if (@inComptime()) {
                @compileError(std.fmt.comptimePrint(fmt, args));
            } else if (testing.backend_can_print) {
                std.debug.print(fmt, args);
            }
        }
    };
}

comptime {
    if (builtin.is_test) {
        _ = if (builtin.link_libc) @import("freebsd/c/test.zig");
        _ = sys;
        _ = @import("freebsd/test.zig");
    }
}
