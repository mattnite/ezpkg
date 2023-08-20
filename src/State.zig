gpa: std.mem.Allocator,
package_count: u8 = 0,
mtx: std.Thread.RwLock = .{},
thread_pool: *std.Thread.Pool,
port: u16 = 0,

packages: Map(PackageId, PackageInfo) = .{},
names: Map(PackageId, []const u8) = .{},
versions: Map(PackageId, std.SemanticVersion) = .{},
dependencies: Map(PackageId, Dependencies) = .{},
redirects: Map(PackageId, []const u8) = .{},
fetched: Map(PackageId, void) = .{},
/// the longest number of jumps to root
ranks: Map(PackageId, u8) = .{},
/// changes to the build.zig.zon
updated: struct {
    hashes: Map(PackageId, [compiler.package_hash_len]u8) = .{},
    names: Map(PackageId, []const u8) = .{},
    versions: Map(PackageId, std.SemanticVersion) = .{},
    dependencies: Map(PackageId, Dependencies) = .{},
} = .{},
archives: Map(PackageId, Archive) = .{},
tarballs: Map(PackageId, []const u8) = .{},

const State = @This();
const std = @import("std");
const fs = std.fs;
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const Map = std.AutoArrayHashMapUnmanaged;

const Archive = @import("Archive.zig");
/// files copied from compiler
const compiler = @import("compiler.zig");
const known_folders = @import("known-folders");
const Manifest = @import("Manifest.zig");

const log = std.log.scoped(.state);

// If you have more than 255 packages in your dependency tree you need more
// help than what this tool can provide.
pub const PackageId = enum(u8) {
    root,
    _,
};

pub const PackageInfo = struct {
    url: []const u8,
    hash: []const u8,
};

pub const Dependency = struct {
    from: PackageId,
    to: PackageId,
    name: []const u8,
};

pub const Dependencies = struct {
    entries: std.StringArrayHashMapUnmanaged(PackageId) = .{},

    pub fn deinit(deps: *Dependencies, allocator: Allocator) void {
        for (deps.entries.keys()) |name|
            allocator.free(name);

        deps.entries.deinit(allocator);
    }
};

pub const RedirectCommand = struct {
    dependency: std.ArrayList([]const u8),
    path: []const u8,
};

pub fn init(allocator: Allocator) !State {
    const thread_pool = try allocator.create(std.Thread.Pool);
    errdefer allocator.destroy(thread_pool);

    try thread_pool.init(.{
        .allocator = allocator,
    });

    return State{
        .gpa = allocator,
        .thread_pool = thread_pool,
    };
}

pub fn deinit(state: *State) void {
    restore: {
        const file = std.fs.cwd().createFile("build.zig.zon", .{}) catch break :restore;
        defer file.close();

        state.write_zon(.root, file.writer(), .{ .restore = true }) catch |err| {
            log.warn("Failed to restore build.zig.zon of root: {}", .{err});
        };
    }

    state.thread_pool.deinit();
    for (state.packages.values()) |info| {
        state.gpa.free(info.url);
        state.gpa.free(info.hash);
    }
    state.packages.deinit(state.gpa);

    for (state.archives.values()) |*archive| archive.deinit(state.gpa);
    state.archives.deinit(state.gpa);

    for (state.dependencies.values()) |*deps| deps.deinit(state.gpa);
    state.dependencies.deinit(state.gpa);

    for (state.updated.dependencies.values()) |*deps| deps.deinit(state.gpa);
    state.updated.dependencies.deinit(state.gpa);

    for (state.names.values()) |name| state.gpa.free(name);
    state.names.deinit(state.gpa);

    for (state.updated.names.values()) |name| state.gpa.free(name);
    state.updated.names.deinit(state.gpa);

    for (state.redirects.values()) |path| state.gpa.free(path);
    state.redirects.deinit(state.gpa);

    for (state.tarballs.values()) |tarball| state.gpa.free(tarball);
    state.tarballs.deinit(state.gpa);

    state.updated.hashes.deinit(state.gpa);
    state.versions.deinit(state.gpa);
    state.updated.versions.deinit(state.gpa);
    state.ranks.deinit(state.gpa);
    state.fetched.deinit(state.gpa);
    state.gpa.destroy(state.thread_pool);
}

fn create_package_id(state: *State) !PackageId {
    if (state.package_count == std.math.maxInt(@typeInfo(PackageId).Enum.tag_type))
        return error.TooManyPackages;

    state.package_count += 1;
    return @enumFromInt(state.package_count);
}

fn get_or_create_package(state: *State, url: []const u8, hash: []const u8) !PackageId {
    // deduplicate exact hash matches
    for (state.packages.keys(), state.packages.values()) |other_id, other_info|
        if (std.mem.eql(u8, hash, other_info.hash))
            return other_id;

    const package_id = try state.create_package_id();

    const url_copy = try state.gpa.dupe(u8, url);
    errdefer state.gpa.free(url_copy);

    const hash_copy = try state.gpa.dupe(u8, hash);
    errdefer state.gpa.free(hash_copy);

    try state.packages.put(state.gpa, package_id, .{
        .url = url_copy,
        .hash = hash_copy,
    });

    return package_id;
}

pub fn read_in_dependencies_from_project(
    state: *State,
    package_id: PackageId,
    dir: std.fs.Dir,
) !void {
    const text = dir.readFileAlloc(state.gpa, "build.zig.zon", 0x4000) catch |err| {
        if (err == error.FileNotFound)
            return
        else
            return err;
    };
    defer state.gpa.free(text);

    return state.read_in_dependencies(package_id, text);
}

fn read_in_dependencies(
    state: *State,
    package_id: PackageId,
    text: []const u8,
) !void {
    var manifest = try Manifest.from_text(state.gpa, text);
    defer manifest.deinit();

    try state.incorporate_manifest(package_id, manifest, .original);
}

const Delta = enum {
    original,
    updated,
};

fn find_updated_dependency_index(state: State, package_id: PackageId) ?usize {
    return for (state.updated.dependencies.items, 0..) |dep, i| {
        if (dep.from == package_id)
            break i;
    } else null;
}

fn incorporate_manifest(state: *State, package_id: PackageId, manifest: Manifest, delta: Delta) !void {
    {
        const name_copy = try state.gpa.dupe(u8, manifest.name);
        errdefer state.gpa.free(name_copy);

        switch (delta) {
            .original => try state.names.putNoClobber(state.gpa, package_id, name_copy),
            .updated => {
                if (try state.updated.names.fetchPut(state.gpa, package_id, name_copy)) |old_name| {
                    state.gpa.free(old_name.value);
                }
            },
        }
    }

    try state.versions.put(state.gpa, package_id, manifest.version);

    var deps = Dependencies{};
    errdefer deps.deinit(state.gpa);

    for (manifest.dependencies.keys(), manifest.dependencies.values()) |dep_key, info| {
        const dep_key_copy = try state.gpa.dupe(u8, dep_key);
        errdefer state.gpa.free(dep_key_copy);

        const dep_id = try state.get_or_create_package(info.url, info.hash);
        try deps.entries.put(state.gpa, dep_key_copy, dep_id);
    }

    switch (delta) {
        .original => try state.dependencies.putNoClobber(state.gpa, package_id, deps),
        .updated => {
            var old_deps = try state.updated.dependencies.fetchPut(state.gpa, package_id, deps);
            if (old_deps != null)
                old_deps.?.value.deinit(state.gpa);
        },
    }
}

/// Add archive from filesystem, this means double checking the hash, and
/// saving the file in memory
pub fn add_archive(
    state: *State,
    package_id: PackageId,
    cache_dir: std.fs.Dir,
    hash: []const u8,
) !void {
    const file = try cache_dir.openFile(hash, .{});
    defer file.close();

    var buffered = std.io.bufferedReaderSize(4096, file.reader());
    var decompress = try std.compress.gzip.decompress(state.gpa, buffered.reader());
    defer decompress.deinit();

    var archive = try Archive.read_from_tar(state.gpa, decompress.reader(), .{
        .strip_components = 1,
    });
    errdefer archive.deinit(state.gpa);

    const calculated_hash = try archive.hash(state.gpa, .ignore_executable_bit);
    var hash_buf: [4 + (2 * std.crypto.hash.sha2.Sha256.digest_length)]u8 = undefined;
    const hash_str = try std.fmt.bufPrint(&hash_buf, "1220{}", .{std.fmt.fmtSliceHexLower(&calculated_hash)});
    if (!std.mem.eql(u8, hash, hash_str)) {
        log.err("{}: expected hash of {s}, but got {s}", .{
            package_id,
            hash,
            hash_str,
        });
        return error.HashDoesntMatch;
    }

    try state.archives.putNoClobber(state.gpa, package_id, archive);
    if (archive.files.get("build.zig.zon")) |entry| {
        try state.read_in_dependencies(package_id, entry.text);
    }
}

pub fn apply_redirect(state: *State, redirect: RedirectCommand) !PackageId {
    var current_package: PackageId = .root;
    for (redirect.dependency.items) |name| {
        current_package = if (state.dependencies.get(current_package)) |deps|
            if (deps.entries.get(name)) |next_package|
                next_package
            else {
                // TODO: detailed error message
                log.err("dependency not found: {s}", .{name});
                return error.DependencyNotFound;
            }
        else {
            log.err("dependencies not found for {}", .{current_package});
            return error.DependencyNotFound;
        };
    }

    if (state.redirects.contains(current_package)) {
        log.err("package is already being redirected: {}", .{current_package});
        return error.AlreadyRedirected;
    }

    const path_copy = try state.gpa.dupe(u8, redirect.path);
    errdefer state.gpa.free(path_copy);

    try state.redirects.put(state.gpa, current_package, path_copy);
    return current_package;
}

pub fn get_path(state: State, allocator: Allocator, package_id: PackageId) ![]const u8 {
    return if (state.redirects.get(package_id)) |path|
        try allocator.dupe(u8, path)
    else if (package_id == .root)
        try fs.cwd().realpathAlloc(allocator, ".")
    else blk: {
        const global_cache_path = (try known_folders.getPath(allocator, .cache)) orelse return error.NoCache;
        defer allocator.free(global_cache_path);

        const project_name = state.names.get(.root).?;
        break :blk fs.path.join(allocator, &.{
            global_cache_path,
            "ezpkg",
            project_name,
            "dependencies",
            state.packages.get(package_id).?.hash,
        });
    };
}

pub fn get_iterable_dir(state: State, package_id: PackageId) !fs.IterableDir {
    const package_path = try state.get_path(state.gpa, package_id);
    defer state.gpa.free(package_path);

    return try fs.openIterableDirAbsolute(package_path, .{});
}

pub fn get_name(state: State, package_id: PackageId) ?[]const u8 {
    return if (state.updated.names.get(package_id)) |name|
        name
    else if (state.names.get(package_id)) |name|
        name
    else
        null;
}

pub fn get_version(state: State, package_id: PackageId) ?std.SemanticVersion {
    return if (state.updated.versions.get(package_id)) |name|
        name
    else if (state.versions.get(package_id)) |name|
        name
    else
        null;
}

// string memory is not owned
pub fn get_dependencies(state: State, package_id: PackageId) ?Dependencies {
    return if (state.updated.dependencies.get(package_id)) |deps|
        deps
    else if (state.dependencies.get(package_id)) |deps|
        deps
    else
        null;
}

const WriteZonOptions = struct {
    restore: bool = false,
};

pub fn write_zon(state: State, package_id: PackageId, writer: anytype, opts: WriteZonOptions) !void {
    try writer.print(
        \\.{{
        \\    .name = "{s}",
        \\
    , .{
        state.get_name(package_id).?,
    });

    if (state.get_version(package_id)) |version|
        try writer.print(
            \\    .version = "{}",
            \\
        , .{version});

    if (state.get_dependencies(package_id)) |deps| {
        try writer.writeAll(
            \\    .dependencies = .{
            \\
        );

        for (deps.entries.keys(), deps.entries.values()) |dep_name, dep_id| {
            try writer.print(
                \\        .{} = .{{
                \\
            , .{std.zig.fmtId(dep_name)});

            const maybe_hash = state.updated.hashes.get(dep_id);
            if (!opts.restore and maybe_hash != null)
                try writer.print(
                    \\            .url = "http://localhost:{}/{}",
                    \\            .hash = "1220{}",
                    \\
                , .{ state.port, @as(u8, @intFromEnum(dep_id)), std.fmt.fmtSliceHexLower(&maybe_hash.?) })
            else {
                // This package needs no updates, or we're restoring
                const info = state.packages.get(dep_id).?;
                try writer.print(
                    \\            .url = "{s}",
                    \\            .hash = "{s}",
                    \\
                , .{
                    info.url,
                    info.hash,
                });
            }

            try writer.writeAll(
                \\        },
                \\
            );
        }

        try writer.writeAll(
            \\    },
            \\
        );
    }
    try writer.writeAll(
        \\}
        \\
    );
}

pub fn update_archive(state: *State, package_id: PackageId) !void {
    log.info("updating {}", .{package_id});
    var package_dir = try state.get_iterable_dir(package_id);
    defer package_dir.close();

    var new_archive = try Archive.read_from_fs(state.gpa, package_dir);
    errdefer new_archive.deinit(state.gpa);

    var old_archive_entry = (try state.archives.fetchPut(state.gpa, package_id, new_archive)) orelse return;
    var old_archive = old_archive_entry.value;
    defer old_archive.deinit(state.gpa);

    const new_manifest_text = (new_archive.files.get("build.zig.zon") orelse return).text;
    var new_manifest = Manifest.from_text(state.gpa, new_manifest_text) catch |err| {
        log.warn("{}: failed to parse updated manifest: {}, ignoring for now", .{
            package_id,
            err,
        });
        return;
    };
    defer new_manifest.deinit();

    try state.incorporate_manifest(package_id, new_manifest, .updated);
    try state.fetch_dependencies();

    // TODO: scenario where manifest is deleted
}

pub fn fetch_dependencies(state: *State) !void {
    if (state.fetched.count() == state.packages.count())
        return;

    var global_cache = (try known_folders.open(state.gpa, .cache, .{})) orelse return error.NoCache;
    defer global_cache.close();

    var ezpkg_cache = try global_cache.makeOpenPath("ezpkg", .{});
    defer ezpkg_cache.close();

    var client = std.http.Client{
        .allocator = state.gpa,
    };
    defer client.deinit();

    while (state.fetched.count() < state.packages.count()) {
        var fetch_list = std.ArrayList(PackageId).init(state.gpa);
        defer fetch_list.deinit();

        for (state.packages.keys()) |package_id|
            if (!state.fetched.contains(package_id))
                try fetch_list.append(package_id);

        for (fetch_list.items) |package_id| {
            try state.fetch_dependency(package_id, ezpkg_cache, &client);
            try state.fetched.put(state.gpa, package_id, {});
        }
    }

    try state.calculate_ranks();
}

fn fetch_dependency(
    state: *State,
    id: PackageId,
    ezpkg_cache: fs.Dir,
    client: *std.http.Client,
) !void {
    const info = state.packages.get(id) orelse unreachable;

    // assume that if the directory exists then it previously successfully
    // downloaded
    if (ezpkg_cache.access(info.hash, .{})) {
        return try state.add_archive(id, ezpkg_cache, info.hash);
    } else |_| {}

    const uri = try std.Uri.parse(info.url);
    var headers = std.http.Headers.init(state.gpa);
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
        const file = try ezpkg_cache.createFile(info.hash, .{});
        defer file.close();

        var fifo = std.fifo.LinearFifo(u8, .{ .Static = std.crypto.tls.max_ciphertext_record_len }).init();
        try fifo.pump(req.reader(), file.writer());
    } else {
        std.log.err("unsupported content type: {s}", .{content_type});
        return error.UnsupportedContentType;
    }

    try state.add_archive(id, ezpkg_cache, info.hash);
}

const RankStep = struct {
    parent: PackageId,
    count: u8,
};

fn parents_are_all_root(entries: anytype) bool {
    return for (entries) |entry| {
        if (entry.parent != .root)
            break false;
    } else true;
}

fn calculate_ranks(state: *State) !void {
    if (!state.ranks.contains(.root))
        try state.ranks.put(state.gpa, .root, 0);

    var graph = try state.create_flattenend_dependency_graph(state.gpa);
    defer graph.deinit();

    for (state.packages.keys()) |package_id| {
        if (state.ranks.contains(package_id))
            continue;

        var steps = std.ArrayList(RankStep).init(state.gpa);
        defer steps.deinit();

        try steps.append(.{
            .parent = package_id,
            .count = 0,
        });

        while (!parents_are_all_root(steps.items)) {
            var new_steps = std.ArrayList(RankStep).init(state.gpa);
            defer new_steps.deinit();

            for (steps.items) |step| {
                if (step.parent == .root) {
                    try new_steps.append(step);
                    continue;
                }

                for (graph.entries.items) |dependency| {
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

        try state.ranks.put(state.gpa, package_id, max_count);
    }
}

pub fn update_zon(state: *State, package_id: PackageId) !void {
    var archive = state.archives.getPtr(package_id).?;
    if (!archive.files.contains("build.zig.zon"))
        return;

    var text = std.ArrayList(u8).init(state.gpa);
    defer text.deinit();

    try state.write_zon(package_id, text.writer(), .{});
    var old = (try archive.files.fetchPut(state.gpa, "build.zig.zon", .{
        .text = try text.toOwnedSlice(),
        .mode = 0o644,
    })).?;
    state.gpa.free(old.value.text);
}

pub fn update_hash(state: *State, package_id: PackageId) !void {
    std.log.info("updating hash: {}", .{package_id});
    const archive = state.archives.get(package_id).?;
    const hash = try archive.hash(state.gpa, .ignore_executable_bit);
    try state.updated.hashes.put(state.gpa, package_id, hash);
}

pub fn update_tarball(state: *State, package_id: PackageId) !void {
    std.log.info("updating tarball for {}", .{package_id});
    const tar_gz = try state.archives.get(package_id).?.to_tar_gz(state.gpa);
    std.log.info("  tarball is {} bytes", .{tar_gz.len});
    const old = (try state.tarballs.fetchPut(state.gpa, package_id, tar_gz)) orelse return;
    state.gpa.free(old.value);
}

pub const FlattenedDependency = struct {
    name: []const u8,
    from: PackageId,
    to: PackageId,
};

pub const FlattenedDependencyGraph = struct {
    allocator: Allocator,
    entries: std.ArrayListUnmanaged(FlattenedDependency) = .{},

    pub fn deinit(graph: *FlattenedDependencyGraph) void {
        for (graph.entries.items) |entry|
            graph.allocator.free(entry.name);

        graph.entries.deinit(graph.allocator);
    }
};

pub fn create_flattenend_dependency_graph(
    state: State,
    allocator: Allocator,
) !FlattenedDependencyGraph {
    var graph = FlattenedDependencyGraph{
        .allocator = allocator,
    };
    errdefer graph.deinit();

    if (state.get_dependencies(.root)) |deps| {
        for (deps.entries.keys(), deps.entries.values()) |dep_name, dep_id| {
            const name_copy = try allocator.dupe(u8, dep_name);
            errdefer allocator.free(name_copy);

            try graph.entries.append(allocator, .{
                .name = name_copy,
                .from = .root,
                .to = dep_id,
            });
        }
    }

    for (state.packages.keys()) |package_id| {
        if (state.get_dependencies(package_id)) |deps| {
            for (deps.entries.keys(), deps.entries.values()) |dep_name, dep_id| {
                const name_copy = try allocator.dupe(u8, dep_name);
                errdefer allocator.free(name_copy);

                try graph.entries.append(allocator, .{
                    .name = name_copy,
                    .from = package_id,
                    .to = dep_id,
                });
            }
        }
    }

    return graph;
}

pub fn dump(state: *State) void {
    std.log.info("packages:", .{});
    for (state.packages.keys(), state.packages.values()) |id, info| {
        std.log.info("  {}:", .{id});
        std.log.info("    url: {s}", .{info.url});
        std.log.info("    hash: {s}", .{info.hash});
    }

    std.log.info("ranks:", .{});
    for (state.ranks.keys(), state.ranks.values()) |id, rank|
        std.log.info("  {}: {}", .{ id, rank });

    std.log.info("archives:", .{});
    for (state.archives.keys(), state.archives.values()) |id, archive| {
        std.log.info("  {}: {} files", .{ id, archive.files.count() });
    }
}
