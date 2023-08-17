const std = @import("std");
const fs = std.fs;
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const WaitGroup = std.Thread.WaitGroup;

const State = @import("State.zig");
const RedirectCommand = State.RedirectCommand;
const PackageId = State.PackageId;

const builtin = @import("builtin");
const known_folders = @import("known-folders");
const zon = @import("eggzon.zig");
const compiler = @import("compiler.zig");

pub fn panic(msg: []const u8, trace: ?*std.builtin.StackTrace, first_trace_addr: ?usize) noreturn {
    std.debug.panicImpl(trace, first_trace_addr, msg);
    cleanup_state(0);
}

fn fetch_dependencies(allocator: Allocator, commands: []const RedirectCommand) !State {
    var client = std.http.Client{
        .allocator = allocator,
    };
    defer client.deinit();

    var state = try State.init(allocator);
    errdefer state.deinit();

    try read_in_dependencies(&state, .root, fs.cwd());
    if (state.packages.count() == 0)
        return state;

    const project_name = state.names.get(.root).?;

    var global_cache = (try known_folders.open(allocator, .cache, .{})) orelse return error.NoCache;
    defer global_cache.close();

    var ezpkg_cache = try global_cache.makeOpenPath("ezpkg", .{});
    defer ezpkg_cache.close();

    var project_dir = try ezpkg_cache.makeOpenPath(project_name, .{});

    var deps_dir = try project_dir.makeOpenPath("dependencies", .{});
    defer deps_dir.close();

    var fetched = std.AutoArrayHashMap(PackageId, void).init(allocator);
    defer fetched.deinit();

    while (fetched.count() < state.packages.count()) {
        var fetch_list = std.ArrayList(PackageId).init(allocator);
        defer fetch_list.deinit();

        for (state.packages.keys()) |package_id|
            if (!fetched.contains(package_id))
                try fetch_list.append(package_id);

        for (fetch_list.items) |package_id| {
            var dep_dir = try fetch_dependency(&state, package_id, deps_dir, &client);
            defer dep_dir.close();

            try fetched.put(package_id, {});
            try read_in_dependencies(&state, package_id, dep_dir.dir);
        }
    }

    // this has its own separate step because it doesn't quite fit when we're
    // scanning redirects
    try state.ranks.put(state.allocator, .root, 0);
    for (state.packages.keys()) |package_id| {
        var steps = std.ArrayList(RankStep).init(state.allocator);
        defer steps.deinit();

        try steps.append(.{
            .parent = package_id,
            .count = 0,
        });

        while (!parents_are_all_root(steps.items)) {
            var new_steps = std.ArrayList(RankStep).init(allocator);
            defer new_steps.deinit();

            for (steps.items) |step| {
                if (step.parent == .root) {
                    try new_steps.append(step);
                    continue;
                }

                for (state.dependencies.items) |dependency| {
                    if (dependency.to != step.parent)
                        continue;

                    try new_steps.append(.{
                        .parent = dependency.from,
                        .count = step.count + 1,
                    });
                }
            }

            steps.clearRetainingCapacity();
            try steps.appendSlice(new_steps.items);
        }

        var max_count: u8 = 0;
        for (steps.items) |step|
            max_count = @max(max_count, step.count);

        try state.ranks.put(state.allocator, package_id, max_count);
    }

    for (commands) |command|
        try state.apply_redirect(command);

    return state;
}

const RankStep = struct {
    parent: PackageId,
    count: u8,
};

fn read_in_dependencies(state: *State, id: PackageId, dep_dir: fs.Dir) !void {
    const text = dep_dir.readFileAlloc(state.allocator, "build.zig.zon", 0x4000) catch |err| {
        if (err == error.FileNotFound)
            return
        else
            return err;
    };
    defer state.allocator.free(text);

    var result = zon.parseString(state.allocator, text) catch |err| {
        var buf: [4096]u8 = undefined;
        const real_path = try dep_dir.realpath("build.zig.zon", &buf);
        std.log.err("failed to parse: {s}", .{real_path});
        return err;
    };
    defer result.deinit();

    if (result.root != .object)
        return error.RootIsNotObject;

    const root = result.root.object;
    const name = root.get("name") orelse return error.ProjectMissingName;
    if (name != .string)
        return error.ProjectNameNotString;

    const version = root.get("version") orelse return error.ProjectMissingVersion;
    if (version != .string)
        return error.VersionIsNotString;

    const name_copy = try state.allocator.dupe(u8, name.string);
    try state.names.put(state.allocator, id, name_copy);

    const semver = try std.SemanticVersion.parse(version.string);
    try state.versions.put(state.allocator, id, semver);

    if (root.get("dependencies")) |dependencies_node| {
        if (dependencies_node != .object)
            return error.DependenciesIsNotObject;

        for (dependencies_node.object.keys(), dependencies_node.object.values()) |dep_key, dep_value| {
            if (dep_value != .object)
                return error.DependencyIsNotObject;

            const dep = dep_value.object;
            const url = dep.get("url") orelse return error.DependencyMissingUrl;
            const hash = dep.get("hash") orelse return error.DependencyMissingHash;

            if (url != .string)
                return error.UrlIsNotString;

            if (hash != .string)
                return error.HashIsNotString;

            try state.add_package(id, dep_key, .{
                .url = url.string,
                .hash = hash.string,
            });
        }
    }
}

fn fetch_dependency(
    state: *State,
    id: PackageId,
    deps_dir: fs.Dir,
    client: *std.http.Client,
) !fs.IterableDir {
    const info = state.packages.get(id) orelse unreachable;

    // assume that if the directory exists then it previously successfully
    // downloaded
    if (deps_dir.access(info.hash, .{}))
        return try deps_dir.openIterableDir(info.hash, .{})
    else |_| {}

    var dep_dir = try deps_dir.makeOpenPathIterable(info.hash, .{});
    errdefer dep_dir.close();

    const uri = try std.Uri.parse(info.url);
    var headers = std.http.Headers.init(state.allocator);
    defer headers.deinit();

    std.log.info("downloading: {s}", .{info.url});
    var req = try client.request(.GET, uri, headers, .{});
    defer req.deinit();

    try req.start();
    try req.wait();

    if (req.response.status != .ok)
        return error.NotOk;

    const content_type = req.response.headers.getFirstValue("Content-Type") orelse return error.NoContentType;
    if (std.ascii.eqlIgnoreCase(content_type, "application/gzip") or
        std.ascii.eqlIgnoreCase(content_type, "application/x-gzip") or
        std.ascii.eqlIgnoreCase(content_type, "application/tar+gzip"))
    {
        var buffered = std.io.bufferedReaderSize(std.crypto.tls.max_ciphertext_record_len, req.reader());
        var decompress = try std.compress.gzip.decompress(state.allocator, buffered.reader());
        defer decompress.deinit();

        try std.tar.pipeToFileSystem(dep_dir.dir, decompress.reader(), .{
            .strip_components = 1,
            .mode_mode = .ignore,
        });
    } else {
        std.log.err("unsupported content type: {s}", .{content_type});
        return error.UnsupportedContentType;
    }

    const hash = try compiler.compute_package_hash(state.thread_pool, dep_dir);
    const hash_str = try std.fmt.allocPrint(state.allocator, "1220{}", .{std.fmt.fmtSliceHexLower(&hash)});
    defer state.allocator.free(hash_str);

    if (!std.mem.eql(u8, hash_str, state.packages.get(id).?.hash)) {
        std.log.err("package {} failed hash check", .{id});
        return error.HashDoesntMatch;
    }

    return dep_dir;
}

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
    state: State,
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

        for (state.dependencies.items) |dependency| {
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

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
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

        global_state = try fetch_dependencies(gpa.allocator(), commands.items);
    }
    defer global_state.deinit();

    if (global_state.packages.count() == 0) {
        std.log.err("no packages found!", .{});
        std.process.exit(1);
    }

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
            try iterate_dep_paths(gpa.allocator(), global_state, &dep_paths);

        for (dep_paths.items) |entry|
            std.log.info("  {s}", .{entry.path});

        std.log.info("    => {s}", .{path});
    }

    if (global_state.redirects.count() == 0) {
        std.log.err("no packages to redirect!", .{});
        std.process.exit(1);
    }

    var server = std.http.Server.init(gpa.allocator(), .{});
    defer server.deinit();

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    try server.listen(address);
    global_state.port = server.socket.listen_address.in.getPort();
    std.log.info("serving on localhost:{}", .{global_state.port});

    const cleanup_action = std.os.Sigaction{
        .handler = .{
            .handler = cleanup_state,
        },
        .mask = std.os.empty_sigset,
        .flags = 0,
    };

    try std.os.sigaction(std.os.SIG.INT, &cleanup_action, null);

    const server_thread = try std.Thread.spawn(.{}, serve_packages, .{ &server, &global_state });
    defer server_thread.join();

    try update_packages_on_change(&global_state);
}

fn cleanup_state(_: c_int) callconv(.C) void {
    global_state.deinit();
    _ = gpa.deinit();
    std.process.exit(1);
}

fn serve_packages(server: *std.http.Server, state: *State) !void {
    const max_header_size = 8096;
    const allocator = state.allocator;
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
    handle_request_impl(res, state) catch |err| {
        std.log.err("failed to handle request: {}", .{err});
    };
}

fn handle_request_impl(res: *std.http.Server.Response, state: *State) !void {
    defer state.allocator.destroy(res);
    defer res.deinit();
    defer _ = res.reset();
    try res.wait();

    if (!state.mtx.tryLockShared()) {
        res.status = .not_found;
        return;
    }
    defer state.mtx.unlockShared();

    // get or create tarball
    assert(res.request.method == .GET);
    const package_id: PackageId = @enumFromInt(try std.fmt.parseInt(u8, res.request.target, 10));
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

    std.log.info("packages changed:", .{});
    for (package_ids) |package_id|
        std.log.info(" {}", .{package_id});

    // it's important to handle situations where multiple packages have been
    // updated in a single event.
    //
    // What we do here is create an update plan that only loads a tarball of a
    // package that's changed. The total set is of those who are updated, and
    // any packages upstream from them. We need to make sure that we tarball
    // and hash bottom up as the hash of dependencies is part of a package.

    var update_plan = try create_update_plan(state.*, package_ids);
    defer update_plan.deinit();

    std.log.info("update plan:", .{});
    for (update_plan.items) |package_id| {
        const path = try state.get_path(state.allocator, package_id);
        defer state.allocator.free(path);

        std.log.info("  {}: name: {?s}, {s}", .{ package_id, state.names.get(package_id), path });
        try state.write_zon(package_id, .{});

        var package_dir = try state.get_iterable_dir(package_id);
        defer package_dir.close();

        const hash = try compiler.compute_package_hash(state.thread_pool, package_dir);
        try state.updated_hashes.put(state.allocator, package_id, hash);
        std.log.info("package hash: {}", .{std.fmt.fmtSliceHexLower(&hash)});
    }

    var wait_group = std.Thread.WaitGroup{};
    defer {
        state.thread_pool.waitAndWork(&wait_group);
        std.log.info("DONE", .{});
    }

    var map_mtx = std.Thread.Mutex{};
    for (update_plan.items) |package_id| {
        if (package_id == .root)
            continue;

        wait_group.start();
        try state.thread_pool.spawn(swap_out_tarball, .{ &wait_group, &map_mtx, state, package_id });
    }
}

fn swap_out_tarball(wait_group: *WaitGroup, map_mtx: *std.Thread.Mutex, state: *State, package_id: PackageId) void {
    defer wait_group.finish();

    const max_tries = 100;
    var tries: u8 = 0;
    while (tries < max_tries) : (tries += 1) {
        if (swap_out_tarball_impl(state, package_id, map_mtx)) {
            break;
        } else |err| {
            const wait_for = @max(tries, 5);
            std.log.info("failed to create tarball for {}: {}, retrying in {} seconds", .{ package_id, err, wait_for });
            std.os.nanosleep(wait_for, 0);
        }
    }
}

fn swap_out_tarball_impl(state: *State, package_id: PackageId, map_mtx: *std.Thread.Mutex) !void {
    std.log.info("swapping out tarball for {}", .{package_id});
    const path = try state.get_path(state.allocator, package_id);
    defer state.allocator.free(path);

    var dir = try fs.openIterableDirAbsolute(path, .{});
    defer dir.close();

    var tar_gz = std.ArrayList(u8).init(state.allocator);
    defer tar_gz.deinit();

    var gzip = try std.compress.deflate.compressor(state.allocator, tar_gz.writer(), .{});
    defer gzip.deinit();

    var gzip_mutex = std.Thread.Mutex{};
    var tarball_wait_group = WaitGroup{};
    defer state.thread_pool.waitAndWork(&tarball_wait_group);

    var walker = try dir.walk(state.allocator);
    while (try walker.next()) |entry| {
        switch (entry.kind) {
            .file => {
                const file_path = try state.allocator.dupe(u8, entry.path);
                tarball_wait_group.start();
                try state.thread_pool.spawn(write_tarball_file, .{ &gzip, &gzip_mutex, &tarball_wait_group, state, package_id, file_path });
            },
            .directory => {
                const dir_path = try state.allocator.dupe(u8, entry.path);
                tarball_wait_group.start();
                try state.thread_pool.spawn(write_tarball_dir, .{ &gzip, &gzip_mutex, &tarball_wait_group, state, package_id, dir_path });
            },
            else => {
                std.log.err("unhandled: {}", .{entry.kind});
                @panic("unhandled");
            },
        }
    }

    map_mtx.lock();
    defer map_mtx.unlock();

    if (try state.tarballs.fetchPut(state.allocator, package_id, try tar_gz.toOwnedSlice())) |old|
        state.allocator.free(old.value);
}

const Compressor = std.compress.deflate.Compressor(std.ArrayList(u8).Writer);

fn write_tarball_file(
    gzip: *Compressor,
    mutex: *std.Thread.Mutex,
    wait_group: *WaitGroup,
    state: *State,
    package_id: PackageId,
    path: []const u8,
) void {
    write_tarball_file_impl(gzip, mutex, wait_group, state, package_id, path) catch |err| {
        std.log.fatal("failed to collect file for tarball in package {}: {s}, reason: {}", .{ package_id, path, err });
    };
}

fn write_tarball_file_impl(
    gzip: *Compressor,
    mutex: *std.Thread.Mutex,
    wait_group: *WaitGroup,
    state: *State,
    package_id: PackageId,
    path: []const u8,
) !void {
    defer state.allocator.free(path);

    defer wait_group.finish();

    std.log.info("creating file header: {s}", .{path});
    _ = gzip;
    _ = mutex;
    _ = package_id;
}

fn write_tarball_dir(
    gzip: *Compressor,
    mutex: *std.Thread.Mutex,
    wait_group: *WaitGroup,
    state: *State,
    package_id: PackageId,
    path: []const u8,
) void {
    write_tarball_dir_impl(gzip, mutex, wait_group, state, package_id, path) catch |err| {
        std.log.fatal("failed to write dir for tarball in package {}: {s}, reason: {}", .{ package_id, path, err });
    };
}

fn write_tarball_dir_impl(
    gzip: *Compressor,
    mutex: *std.Thread.Mutex,
    wait_group: *WaitGroup,
    state: *State,
    package_id: PackageId,
    path: []const u8,
) !void {
    defer state.allocator.free(path);

    defer wait_group.finish();

    std.log.info("creating dir header: {s}", .{path});
    var bytes = std.mem.zeroes([512]u8);
    var header: std.tar.Header = .{
        .bytes = &bytes,
    };
    _ = header;

    // TODO: copy path into header
    _ = gzip;
    _ = mutex;
    _ = package_id;
}

fn package_id_rank_less_than(state: State, lhs: PackageId, rhs: PackageId) bool {
    // greater than because we want opposite of rank order
    return state.ranks.get(lhs).? > state.ranks.get(rhs).?;
}

fn create_update_plan(state: State, package_ids: []const PackageId) !std.ArrayList(PackageId) {
    var package_set = std.AutoArrayHashMap(PackageId, void).init(state.allocator);
    defer package_set.deinit();

    var to_visit = std.ArrayList(PackageId).init(state.allocator);
    defer to_visit.deinit();

    try to_visit.appendSlice(package_ids);
    while (to_visit.popOrNull()) |package_id| {
        if (package_set.contains(package_id))
            continue;

        try package_set.put(package_id, {});
        for (state.dependencies.items) |dependency| {
            if (dependency.to != package_id)
                continue;

            try to_visit.append(dependency.from);
        }
    }

    var update_plan = std.ArrayList(PackageId).init(state.allocator);
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

test "all" {
    _ = @import("eggzon.zig");
}
