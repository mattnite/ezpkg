const std = @import("std");
const fs = std.fs;

const State = @import("State.zig");
const PackageId = State.PackageId;
const os = std.os;

// const C = @cImport(@cInclude("linux_impl.h"));
const clear_cb_t = ?*const fn () callconv(.C) void;
const handle_cb_t = ?*const fn () callconv(.C) void;
const add_cb_t = ?*const fn ([*c]u8) callconv(.C) void;

pub extern fn LI_init(clear_cb_t, add_cb_t, handle_cb_t) void;
pub extern fn LI_loop(c_int, paths: [*c][*c]u8) c_int;
pub extern fn LI_errdefer_handler() void;

//
// CALLBACKS from C
//
var package_set: std.AutoArrayHashMap(PackageId, void) = undefined;

// careful: path passed in below is temporary and will be reused
pub fn add_path(path: [*c]u8) callconv(.C) void {
    // brute force search through redirects should be fine
    const input_path = std.mem.span(path);
    for (_state.redirects.keys(), _state.redirects.values()) |package_id, package_path| {
        // check if paths are semantically the same, there could be trailing /'s
        var lhs_it = try fs.path.componentIterator(input_path);
        var rhs_it = try fs.path.componentIterator(package_path);

        var lhs = lhs_it.next();
        var rhs = rhs_it.next();
        const match = while (lhs != null and rhs != null) : ({
            lhs = lhs_it.next();
            rhs = rhs_it.next();
        }) {
            if (!std.mem.eql(u8, lhs.?.name, rhs.?.name))
                break false;
        } else if (lhs == null and rhs == null) true else false;

        std.debug.print("   trying {s} <--> {s}\n", .{ input_path, package_path });
        if (match) {
            package_set.put(package_id, {}) catch |err| {
                std.log.err("failed the package callback function: {}", .{err});
            };
            std.debug.print("    -> {}:{s}\n", .{ package_id, package_path });
            break;
        }
    } else {
        std.debug.print("    -> NO MATCH for {s}\n", .{input_path});
    }
}

pub fn clear_paths() callconv(.C) void {
    package_set.clearRetainingCapacity();
}

pub fn handle_paths() callconv(.C) void {
    @import("root").handle_package_change(_state, package_set.keys()) catch |err| {
        std.log.err("failed the package callback function: {}", .{err});
    };
}

// man, what a hack :-)
var _state: *State = undefined;
var cleanup_paths: std.ArrayList([:0]u8) = undefined;

pub fn update_packages_on_change(
    state: *State,
) !void {
    _state = state;
    LI_init(clear_paths, add_path, handle_paths);
    package_set = std.AutoArrayHashMap(PackageId, void).init(state.gpa);
    defer package_set.deinit();
    cleanup_paths = std.ArrayList([:0]u8).init(state.gpa);
    defer cleanup_paths.deinit();

    // super hacky no-alloc C-interop
    var all_paths_buf: [128][*c]const u8 = undefined;
    std.log.info("paths to watch:", .{});
    for (0.., state.redirects.values()) |index, path| {
        const c_str_path = try state.gpa.dupeZ(u8, path);
        try cleanup_paths.append(c_str_path);

        all_paths_buf[index] = c_str_path;
        std.log.info(" - {s}\n", .{path});
    }
    const num_paths: c_int = @intCast(state.redirects.values().len);
    const ptr: [*c][*c]u8 = @ptrCast(&all_paths_buf);
    _ = LI_loop(num_paths, ptr);
}

pub fn deinit() void {
    std.debug.print("\nLinux cleaning up\n", .{});
    for (cleanup_paths.items) |p| {
        // _ = p;
        _state.gpa.free(p);
    }
    cleanup_paths.deinit();
    LI_errdefer_handler();
}
