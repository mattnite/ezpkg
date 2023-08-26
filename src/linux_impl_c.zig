const C = @cImport({
    @cInclude("errno.h");
    @cInclude("poll.h");
    @cInclude("stdio.h");
    @cInclude("stdlib.h");
    @cInclude("sys/inotify.h");
    @cInclude("unistd.h");
    @cInclude("string.h");
});

pub const clear_cb_t = ?*const fn () void;
pub const handle_cb_t = ?*const fn () void;
pub const add_cb_t = ?*const fn ([*c]u8) void;

var zig_add_path: add_cb_t = null;
var zig_clear_paths: clear_cb_t = null;
var zig_handle_paths: handle_cb_t = null;

pub fn LI_init(clear_paths_cb: clear_cb_t, add_path_cb: add_cb_t, handle_paths_cb: handle_cb_t) void {
    zig_handle_paths = handle_paths_cb;
    zig_add_path = add_path_cb;
    zig_clear_paths = clear_paths_cb;
}

const HandleEventError = error{
    Read,
};

fn handle_events(fd_arg: c_int, wd_arg: [*c]c_int, num_paths: c_int, paths: [*c][*:0]u8) !void {
    const bufsize = 4096;
    var buf: [bufsize]u8 align(@alignOf(C.inotify_event)) = undefined;
    var event: [*c]const C.inotify_event = undefined;
    var len: isize = undefined;

    var have_new_stuff: bool = false;

    var ptr: [*c]u8 = @as([*c]u8, @ptrCast(@alignCast(&buf)));

    while (true) {
        len = C.read(fd_arg, &buf, @intCast(bufsize));
        if (len == -1 and C.__errno_location().* != C.EAGAIN) {
            return HandleEventError.Read;
        }

        if (len <= 0)
            break;

        // for (char *ptr = buf; ptr < buf + len; ptr += sizeof(struct inotify_event) + event->len) {
        while (ptr < (@as([*c]u8, @ptrCast(@alignCast(&buf))) + @as(usize, @bitCast(@as(isize, @intCast(len)))))) : (ptr += @sizeOf(C.inotify_event) +% @as(c_ulong, @bitCast(@as(c_ulong, event.*.len)))) {
            event = @as([*c]const C.inotify_event, @ptrCast(@alignCast(ptr)));
            const is_close_write = event.*.mask & @as(u32, @bitCast(@as(c_int, C.IN_CLOSE_WRITE))) != 0;
            const is_delete = event.*.mask & @as(u32, @bitCast(@as(c_int, C.IN_DELETE))) != 0;
            if (is_close_write or is_delete) {
                var i: usize = 0;
                while (i < @as(usize, @bitCast(@as(c_long, num_paths)))) : (i +%= 1) {
                    if (wd_arg[i] == event.*.wd) {
                        if (zig_add_path != null) {
                            zig_add_path.?(@as([*c]u8, @ptrCast(@alignCast(paths[i]))));
                            have_new_stuff = true;
                        }
                        break;
                    }
                }
            }
        }
    }
    if (have_new_stuff) {
        zig_handle_paths.?();
        zig_clear_paths.?();
    }
}

// global so we can errdefer
var fd: c_int = -1; // inotify file descriptor
var wd: [*c]c_int = undefined; // inotify watch file descriptor array

pub const nfds_t = c_ulong;
const LoopError = error{
    E_CALLBACKS,
    E_INOTIFY_INIT,
    E_CALLOC,
    E_INOTIFY_WATCH,
    E_POLL,
};
pub fn LI_loop(arg_num_paths: c_int, arg_paths: [*c][*c]u8) !void {
    var num_paths = arg_num_paths;
    var paths = arg_paths;
    var i: c_int = undefined;
    var poll_num: c_int = undefined;
    var nfds: nfds_t = undefined;
    var poll_fd: C.struct_pollfd = undefined;
    if (((zig_add_path == null) or (zig_clear_paths == null)) or (zig_handle_paths == null)) {
        return LoopError.E_CALLBACKS;
    }
    fd = C.inotify_init1(C.IN_NONBLOCK);
    if (fd == -@as(c_int, 1)) {
        return LoopError.E_INOTIFY_INIT;
    }
    // TODO: no calloc
    // wd = calloc(...)
    wd = @as([*c]c_int, @ptrCast(@alignCast(C.calloc(@as(c_ulong, @bitCast(@as(c_long, num_paths))), @sizeOf(c_int)))));

    // if (wd == NULL)
    if (wd == @as([*c]c_int, @ptrCast(@alignCast(@as(?*anyopaque, @ptrFromInt(@as(c_int, 0))))))) {
        return LoopError.E_CALLOC;
    }

    // /* Mark directories for events
    //        - file was closed after writing
    //        - file was deleted */
    //     for (i = 0; i < num_paths; i++) {
    //         wd[i] = inotify_add_watch(fd, paths[i], IN_CLOSE_WRITE | IN_DELETE);
    //         if (wd[i] == -1) {
    //             fprintf(stderr, "Cannot watch '%s': %s\n", paths[i], strerror(errno));
    //             return E_INOTIFY_WATCH;
    //         }
    //     }
    {
        i = 0;
        while (i < num_paths) : (i += 1) {
            (blk: {
                const tmp = i;
                if (tmp >= 0) break :blk wd + @as(usize, @intCast(tmp)) else break :blk wd - ~@as(usize, @bitCast(@as(isize, @intCast(tmp)) +% -1));
            }).* = C.inotify_add_watch(fd, @as([*c]const u8, @ptrCast(@alignCast((blk: {
                const tmp = i;
                if (tmp >= 0) break :blk paths + @as(usize, @intCast(tmp)) else break :blk paths - ~@as(usize, @bitCast(@as(isize, @intCast(tmp)) +% -1));
            }).*))), @as(u32, @bitCast(@as(c_int, C.IN_CLOSE_WRITE) | @as(c_int, C.IN_DELETE))));
            if ((blk: {
                const tmp = i;
                if (tmp >= 0) break :blk wd + @as(usize, @intCast(tmp)) else break :blk wd - ~@as(usize, @bitCast(@as(isize, @intCast(tmp)) +% -1));
            }).* == -@as(c_int, 1)) {
                // cannot watch {s} : {s}
                return LoopError.E_INOTIFY_WATCH;
            }
        }
    }

    nfds = 1;
    poll_fd.fd = fd;
    poll_fd.events = 1;
    while (true) {
        zig_clear_paths.?();
        poll_num = C.poll(&poll_fd, nfds, -@as(c_int, 1));
        if (poll_num == -@as(c_int, 1)) {
            if (C.__errno_location().* == @as(c_int, 4)) continue;
            _ = C.close(fd);
            C.free(@as(?*anyopaque, @ptrCast(wd)));
            return LoopError.E_POLL;
        }
        if (poll_num > @as(c_int, 0)) {
            if ((@as(c_int, @bitCast(@as(c_int, poll_fd.revents))) & @as(c_int, 1)) != 0) {
                if (handle_events(fd, wd, num_paths, @as([*c][*:0]u8, @ptrCast(@alignCast(paths))))) {
                    // pass
                } else |err| {
                    return err;
                }
            }
        }
    }
    _ = C.close(fd);
    C.free(@as(?*anyopaque, @ptrCast(wd)));
    return 0;
}

pub fn LI_errdefer_handler() void {
    if (fd > @as(c_int, 0)) {
        _ = C.close(fd);
    }
    if (wd != null) {
        C.free(@as(?*anyopaque, @ptrCast(wd)));
    }
}
