const std = @import("std");
const fs = std.fs;
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const WaitGroup = std.Thread.WaitGroup;

const Archive = @import("Archive.zig");
const State = @import("State.zig");
const RedirectCommand = State.RedirectCommand;
const PackageId = State.PackageId;

const builtin = @import("builtin");
const known_folders = @import("known-folders");
const compiler = @import("compiler.zig");
const tar = @import("tar.zig");
const zlib = @import("zlib.zig");

pub fn panic(msg: []const u8, trace: ?*std.builtin.StackTrace, first_trace_addr: ?usize) noreturn {
    cleanup_state(0);
    std.debug.panicImpl(trace, first_trace_addr, msg);
}

fn fetch_dependencies_and_apply_redirects(allocator: Allocator, commands: []const RedirectCommand) !void {
    global_state = try State.init(allocator);
    errdefer global_state.deinit();

    try global_state.read_in_dependencies_from_project(.root, fs.cwd());
    if (global_state.packages.count() == 0)
        return;

    var redirects = std.ArrayList(RedirectCommand).init(allocator);
    defer redirects.deinit();

    try redirects.appendSlice(commands);

    var packages = std.ArrayList(PackageId).init(allocator);
    defer packages.deinit();

    // fetch dependencies, and apply redirects until everything has been fetched
    while (0 < try global_state.fetch_dependencies()) {
        var try_again = std.ArrayList(RedirectCommand).init(allocator);
        defer try_again.deinit();

        for (redirects.items) |redirect| {
            if (try global_state.apply_redirect(redirect)) |package_id| {
                try packages.append(package_id);
            } else {
                try try_again.append(redirect);
            }
        }

        redirects.clearRetainingCapacity();
        try redirects.appendSlice(try_again.items);
        std.log.info("retrying {} redirects", .{try_again.items.len});
    }

    if (redirects.items.len != 0) {
        std.log.err("failed to fulfill all redirect commands", .{});
        return error.FailedRedirects;
    }

    // TODO: print list of deduplications that are not redireted

    // TODO: determine why the zig compiler fails to connect when this is
    // uncommented. For now users need to make one edit in a redirected package
    // for the redirections to take place
    //try handle_package_change(&global_state, packages.items);
}

const RankStep = struct {
    parent: PackageId,
    count: u8,
};

const DependencyPathEntry = struct {
    path: []const u8,
    parent: PackageId,
};

fn parents_are_all_root(entries: anytype) bool {
    return for (entries) |entry| {
        if (entry.parent != .root)
            break false;
    } else true;
}

fn iterate_dep_paths(
    allocator: Allocator,
    graph: State.FlattenedDependencyGraph,
    dep_paths: *std.ArrayList(DependencyPathEntry),
) !void {
    var new_dep_paths = std.ArrayList(DependencyPathEntry).init(allocator);
    defer new_dep_paths.deinit();

    for (dep_paths.items) |dep_path| {
        defer allocator.free(dep_path.path);
        if (dep_path.parent == .root) {
            try new_dep_paths.append(.{
                .path = try allocator.dupe(u8, dep_path.path),
                .parent = .root,
            });
            continue;
        }

        for (graph.entries.items) |dependency| {
            if (dependency.to != dep_path.parent)
                continue;

            const path = if (dependency.from == .root)
                try std.fmt.allocPrint(allocator, "{s}{s}", .{ dependency.name, dep_path.path })
            else
                try std.fmt.allocPrint(allocator, ".{s}{s}", .{ dependency.name, dep_path.path });

            try new_dep_paths.append(.{
                .path = path,
                .parent = dependency.from,
            });
        }
    }

    dep_paths.clearRetainingCapacity();
    try dep_paths.appendSlice(new_dep_paths.items);
}

var gpa = std.heap.GeneralPurposeAllocator(.{
    .stack_trace_frames = 10,
}){};
var global_state: State = undefined;

pub fn main() !void {
    defer _ = gpa.deinit();

    {
        var args = try std.process.argsAlloc(gpa.allocator());
        defer std.process.argsFree(gpa.allocator(), args);

        var commands = std.ArrayList(RedirectCommand).init(gpa.allocator());
        defer {
            for (commands.items) |command| {
                command.dependency.deinit();
                gpa.allocator().free(command.path);
            }
            commands.deinit();
        }

        if (args.len > 1) {
            for (args[1..]) |command_str| {
                const equals_pos = std.mem.indexOfScalar(u8, command_str, '=') orelse return error.NoEquals;
                var dependency = std.ArrayList([]const u8).init(gpa.allocator());
                errdefer dependency.deinit();

                var it = std.mem.splitScalar(u8, command_str[0..equals_pos], '.');
                while (it.next()) |component| {
                    if (component.len == 0)
                        return error.ComponentEmpty;

                    try dependency.append(component);
                }

                const path = command_str[equals_pos + 1 ..];
                const real_path = fs.cwd().realpathAlloc(gpa.allocator(), path) catch |err| {
                    if (err == error.FileNotFound) {
                        std.log.err("path doesn't exist: {s}", .{path});
                    }

                    return err;
                };
                errdefer gpa.allocator().free(real_path);

                const stat = try fs.cwd().statFile(real_path);
                if (stat.kind != .directory) {
                    std.log.err("{s} is not a directory", .{path});
                    return error.NotADiretory;
                }

                try commands.append(.{
                    .dependency = dependency,
                    .path = real_path,
                });
            }
        }

        try fetch_dependencies_and_apply_redirects(gpa.allocator(), commands.items);
    }
    defer global_state.deinit();

    if (global_state.packages.count() == 0) {
        std.log.err("no packages found!", .{});
        std.process.exit(1);
    }

    {
        var graph = try global_state.create_flattenend_dependency_graph(gpa.allocator());
        defer graph.deinit();

        std.log.info("redirects:", .{});
        for (global_state.redirects.keys(), global_state.redirects.values()) |package_id, path| {
            var dep_paths = std.ArrayList(DependencyPathEntry).init(gpa.allocator());
            defer {
                for (dep_paths.items) |dep_path|
                    gpa.allocator().free(dep_path.path);

                dep_paths.deinit();
            }

            try dep_paths.append(.{
                .path = try gpa.allocator().dupe(u8, ""),
                .parent = package_id,
            });

            while (!parents_are_all_root(dep_paths.items))
                try iterate_dep_paths(gpa.allocator(), graph, &dep_paths);

            for (dep_paths.items) |entry|
                std.log.info("  {s}", .{entry.path});

            std.log.info("    => {s}", .{path});
        }
    }

    if (global_state.redirects.count() == 0) {
        std.log.err("no packages to redirect!", .{});
        std.process.exit(1);
    }

    const cleanup_action = std.os.Sigaction{
        .handler = .{
            .handler = cleanup_state,
        },
        .mask = std.os.empty_sigset,
        .flags = 0,
    };

    try std.os.sigaction(std.os.SIG.INT, &cleanup_action, null);

    {
        const zon_file = try std.fs.cwd().createFile("build.zig.zon", .{});
        defer zon_file.close();
        try global_state.write_zon(.root, zon_file.writer(), .{});
    }

    var server = std.http.Server.init(gpa.allocator(), .{});
    defer server.deinit();

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    try server.listen(address);
    global_state.port = server.socket.listen_address.in.getPort();
    std.log.info("serving on localhost:{}", .{global_state.port});

    const server_thread = try std.Thread.spawn(.{}, serve_packages, .{ &server, &global_state });
    defer server_thread.join();

    try update_packages_on_change(&global_state);
}

fn cleanup_state(_: c_int) callconv(.C) void {
    global_state.dump();
    global_state.deinit();
    _ = gpa.deinit();
    std.process.exit(1);
}

fn serve_packages(server: *std.http.Server, state: *State) !void {
    const max_header_size = 8096;
    const allocator = state.gpa;
    std.log.info("accepting connections", .{});
    while (true) {
        const res = try allocator.create(std.http.Server.Response);
        res.* = try server.accept(.{
            .allocator = allocator,
            .header_strategy = .{ .dynamic = max_header_size },
        });

        try state.thread_pool.spawn(handle_request, .{ res, state });
    }
}

fn handle_request(res: *std.http.Server.Response, state: *State) void {
    defer {
        _ = res.reset();
        res.deinit();
        state.gpa.destroy(res);
    }
    handle_request_impl(res, state) catch |err| blk: {
        std.log.err("failed to handle request: {}", .{err});
        // TODO: proper error handling
        res.status = .internal_server_error;
        res.do() catch break :blk;
        res.finish() catch {};
    };
}

fn handle_request_impl(res: *std.http.Server.Response, state: *State) !void {
    try res.wait();

    if (!state.mtx.tryLockShared()) {
        res.status = .not_found;
        const message = "ezpkg is busy updating packages right now, try again when it's done!\n";
        res.transfer_encoding = .{ .content_length = message.len };
        try res.headers.append("content-type", "text/plain");
        try res.headers.append("connection", "close");
        try res.do();
        _ = try res.writer().writeAll(message);
        try res.finish();
        return;
    }
    defer state.mtx.unlockShared();

    std.log.info("request target: {s}", .{res.request.target});

    // get or create tarball
    assert(res.request.method == .GET);
    const package_id: PackageId = @enumFromInt(try std.fmt.parseInt(u8, res.request.target[1..], 10));
    std.log.info("looking for package_id: {}", .{package_id});

    const tarball = state.tarballs.get(package_id).?;

    res.transfer_encoding = .{ .content_length = tarball.len };
    try res.headers.append("content-type", "application/gzip");
    try res.headers.append("connection", "close");
    try res.do();

    _ = try res.writer().writeAll(tarball);
    try res.finish();
}

pub fn handle_package_change(state: *State, package_ids: []const PackageId) !void {
    state.mtx.lock();
    defer state.mtx.unlock();

    // TODO: can be parallelized
    for (package_ids) |package_id|
        try state.update_archive(package_id);

    var update_plan = try create_update_plan(state.*, package_ids);
    defer update_plan.deinit();

    std.log.info("update plan: {} entries", .{update_plan.items.len});
    for (update_plan.items) |package_id| {
        const path = try state.get_path(state.gpa, package_id);
        defer state.gpa.free(path);

        std.log.info("  {}: name: {?s}, {s}", .{ package_id, state.get_name(package_id), path });

        if (state.archives.get(package_id).?.files.contains("build.zig.zon")) {
            try state.update_zon(package_id);
        }

        try state.update_hash(package_id);
    }

    // TODO: can be parallelized
    for (update_plan.items) |package_id|
        try state.update_tarball(package_id);

    // The root package is the only one that's on the filesystem and doesn't need to hash
    const zon_file = try std.fs.cwd().createFile("build.zig.zon", .{});
    defer zon_file.close();

    try state.write_zon(.root, zon_file.writer(), .{});
    std.log.info("DONE UPDATE", .{});
}

fn package_id_rank_less_than(state: State, lhs: PackageId, rhs: PackageId) bool {
    // greater than because we want opposite of rank order
    return state.ranks.get(lhs).? > state.ranks.get(rhs).?;
}

fn create_update_plan(state: State, package_ids: []const PackageId) !std.ArrayList(PackageId) {
    var package_set = std.AutoArrayHashMap(PackageId, void).init(state.gpa);
    defer package_set.deinit();

    var to_visit = std.ArrayList(PackageId).init(state.gpa);
    defer to_visit.deinit();

    var graph = try state.create_flattenend_dependency_graph(state.gpa);
    defer graph.deinit();

    std.log.info("dependency graph len: {}", .{graph.entries.items.len});

    try to_visit.appendSlice(package_ids);
    while (to_visit.popOrNull()) |package_id| {
        if (package_set.contains(package_id) or package_id == .root)
            continue;

        try package_set.put(package_id, {});
        for (graph.entries.items) |dependency| {
            if (dependency.to != package_id)
                continue;

            try to_visit.append(dependency.from);
        }
    }

    var update_plan = std.ArrayList(PackageId).init(state.gpa);
    errdefer update_plan.deinit();

    try update_plan.appendSlice(package_set.keys());
    std.mem.sortUnstable(PackageId, update_plan.items, state, package_id_rank_less_than);
    return update_plan;
}

/// Creates OS specific mechination to detect filesystem changes of a
/// redirected repo. Takes a callback and blocks until the application exits
fn update_packages_on_change(state: *State) !void {
    switch (builtin.os.tag) {
        .macos => try @import("macos.zig").update_packages_on_change(state),
        else => @compileError("unsupported OS"),
    }
}
