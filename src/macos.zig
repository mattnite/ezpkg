const std = @import("std");
const fs = std.fs;

const State = @import("State.zig");
const PackageId = State.PackageId;

const c = @cImport({
    @cInclude("CoreServices/CoreServices.h");
});

pub fn update_packages_on_change(
    state: *State,
) !void {
    var paths_to_watch = c.CFArrayCreateMutable(null, 0, null);
    for (state.redirects.keys(), state.redirects.values()) |package_id, path| {
        const cf_string = c.CFStringCreateWithBytesNoCopy(
            null,
            path.ptr,
            @intCast(path.len),
            c.kCFStringEncodingUTF8,
            @intFromBool(false),
            null,
        );
        c.CFArrayAppendValue(paths_to_watch, cf_string);
        _ = package_id;
    }

    var context = c.FSEventStreamContext{
        .info = @ptrCast(state),
        .retain = null,
        .release = null,
        .copyDescription = null,
        .version = 0,
    };

    std.log.info("paths to watch: {}", .{c.CFArrayGetCount(paths_to_watch)});
    const latency: c.CFAbsoluteTime = 0.0;
    var stream = c.FSEventStreamCreate(
        null,
        event_stream_cb,
        &context,
        paths_to_watch,
        c.kFSEventStreamEventIdSinceNow,
        latency,
        c.kFSEventStreamCreateFlagNone,
    );
    c.FSEventStreamScheduleWithRunLoop(stream, c.CFRunLoopGetCurrent(), c.kCFRunLoopDefaultMode);
    _ = c.FSEventStreamStart(stream);
    c.CFRunLoopRun();
}

fn event_stream_cb(
    stream: c.ConstFSEventStreamRef,
    client_callback_info: ?*anyopaque,
    num_events: usize,
    event_paths: ?*anyopaque,
    event_flags: ?[*]const c.FSEventStreamEventFlags,
    event_ids: ?[*]const c.FSEventStreamEventId,
) callconv(.C) void {
    event_stream_cb_impl(stream, client_callback_info, num_events, event_paths, event_flags, event_ids) catch |err| {
        std.log.err("failed the package callback function: {}", .{err});
    };
}

fn event_stream_cb_impl(
    stream: c.ConstFSEventStreamRef,
    client_callback_info: ?*anyopaque,
    num_events: usize,
    event_paths: ?*anyopaque,
    event_flags: ?[*]const c.FSEventStreamEventFlags,
    event_ids: ?[*]const c.FSEventStreamEventId,
) !void {
    _ = stream;
    _ = event_flags;
    _ = event_ids;
    const state: *State = @ptrCast(@alignCast(client_callback_info orelse unreachable));
    if (num_events == 0)
        return;

    // this set will deduplicate paths
    var package_set = std.AutoArrayHashMap(PackageId, void).init(state.allocator);
    defer package_set.deinit();

    const paths: [*]const [*:0]const u8 = @ptrCast(@alignCast(event_paths.?));
    for (0..num_events) |i| {
        // TODO: check flags arg

        // brute force search through redirects should be fine
        for (state.redirects.keys(), state.redirects.values()) |package_id, package_path| {
            // check if paths are semantically the same, there could be trailing /'s
            var lhs_it = try fs.path.componentIterator(std.mem.span(paths[i]));
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

            if (match) {
                try package_set.put(package_id, {});
                break;
            }
        }
    }

    try @import("root").handle_package_change(state, package_set.keys());
}
