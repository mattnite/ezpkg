allocator: std.mem.Allocator,
package_count: u8 = 0,
mtx: std.Thread.RwLock = .{},
thread_pool: *std.Thread.Pool,
port: u16 = 0,

// tables
packages: std.AutoArrayHashMapUnmanaged(PackageId, PackageInfo) = .{},
names: std.AutoArrayHashMapUnmanaged(PackageId, []const u8) = .{},
versions: std.AutoArrayHashMapUnmanaged(PackageId, std.SemanticVersion) = .{},
zons: std.AutoArrayHashMapUnmanaged(PackageId, []const u8) = .{},
dependencies: std.ArrayListUnmanaged(Dependency) = .{},
redirects: std.AutoArrayHashMapUnmanaged(PackageId, []const u8) = .{},
/// the longest number of jumps to root
ranks: std.AutoArrayHashMapUnmanaged(PackageId, u8) = .{},
updated_hashes: std.AutoArrayHashMapUnmanaged(PackageId, [compiler.package_hash_len]u8) = .{},
tarballs: std.AutoArrayHashMapUnmanaged(PackageId, []const u8) = .{},

const State = @This();
const std = @import("std");
const fs = std.fs;
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;

/// files copied from compiler
const compiler = @import("compiler.zig");
const known_folders = @import("known-folders");

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
        .allocator = allocator,
        .thread_pool = thread_pool,
    };
}

pub fn deinit(state: *State) void {
    state.restore_zon_files();
    for (state.packages.values()) |info| {
        state.allocator.free(info.url);
        state.allocator.free(info.hash);
    }
    state.packages.deinit(state.allocator);

    for (state.dependencies.items) |dependency| state.allocator.free(dependency.name);
    state.dependencies.deinit(state.allocator);

    for (state.names.values()) |name| state.allocator.free(name);
    state.names.deinit(state.allocator);

    for (state.zons.values()) |zon_path| state.allocator.free(zon_path);
    state.zons.deinit(state.allocator);

    for (state.redirects.values()) |path| state.allocator.free(path);
    state.redirects.deinit(state.allocator);

    state.versions.deinit(state.allocator);
    state.ranks.deinit(state.allocator);
    state.thread_pool.deinit();
    state.allocator.destroy(state.thread_pool);
}

pub fn add_package(state: *State, parent: PackageId, dependency_name: []const u8, info: PackageInfo) !void {
    if (state.package_count == std.math.maxInt(@typeInfo(PackageId).Enum.tag_type))
        return error.TooManyPackages;

    const name_copy = try state.allocator.dupe(u8, dependency_name);
    errdefer state.allocator.free(name_copy);

    // deduplicate exact hash matches
    for (state.packages.keys(), state.packages.values()) |other_id, other_info| {
        if (std.mem.eql(u8, info.hash, other_info.hash)) {
            try state.dependencies.append(state.allocator, .{
                .from = parent,
                .to = other_id,
                .name = name_copy,
            });

            // there won't be another match
            return;
        }
    }

    state.package_count += 1;
    const id: PackageId = @enumFromInt(state.package_count);
    errdefer state.package_count -= 1;

    const url_copy = try state.allocator.dupe(u8, info.url);
    errdefer state.allocator.free(url_copy);

    const hash_copy = try state.allocator.dupe(u8, info.hash);
    errdefer state.allocator.free(hash_copy);

    try state.packages.put(state.allocator, id, .{
        .url = url_copy,
        .hash = hash_copy,
    });

    try state.dependencies.append(state.allocator, .{
        .from = parent,
        .to = id,
        .name = name_copy,
    });
}

pub fn apply_redirect(state: *State, redirect: RedirectCommand) !void {
    var current_package: PackageId = .root;
    for (redirect.dependency.items) |name| {
        current_package = for (state.dependencies.items) |dependency| {
            if (dependency.from != current_package)
                continue;

            if (std.mem.eql(u8, dependency.name, name))
                break dependency.to;
        } else {
            // TODO: detailed error message
            std.log.err("dependency not found: {s}", .{name});
            return error.DependencyNotFound;
        };
    }

    if (state.redirects.contains(current_package)) {
        std.log.err("package is already being redirected: {}", .{current_package});
        return error.AlreadyRedirected;
    }

    const path_copy = try state.allocator.dupe(u8, redirect.path);
    errdefer state.allocator.free(path_copy);

    try state.redirects.put(state.allocator, current_package, path_copy);
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
    const package_path = try state.get_path(state.allocator, package_id);
    defer state.allocator.free(package_path);

    return try fs.openIterableDirAbsolute(package_path, .{});
}

// best effort
fn restore_zon_files(state: State) void {
    for (state.packages.keys()) |package_id|
        state.write_zon(package_id, .{ .restore = true }) catch |err| {
            std.log.warn("Failed to restore build.zig.zon of {}: {}", .{ package_id, err });
        };

    state.write_zon(.root, .{ .restore = true }) catch |err| {
        std.log.warn("Failed to restore build.zig.zon of root: {}", .{err});
    };
}

const WriteZonOptions = struct {
    restore: bool = false,
};

pub fn write_zon(state: State, package_id: PackageId, opts: WriteZonOptions) !void {
    var dependencies = std.ArrayList(Dependency).init(state.allocator);
    defer dependencies.deinit();

    for (state.dependencies.items) |dependency| {
        if (dependency.from != package_id)
            continue;

        try dependencies.append(dependency);
    }

    // don't need to update the zon file if it doesn't have dependencies
    if (dependencies.items.len == 0)
        return;

    const path = try state.get_path(state.allocator, package_id);
    defer state.allocator.free(path);

    const zon_path = try fs.path.join(state.allocator, &.{
        path,
        "build.zig.zon",
    });
    defer state.allocator.free(zon_path);

    const file = try fs.createFileAbsolute(zon_path, .{});
    defer file.close();

    const writer = file.writer();
    try writer.print(
        \\.{{
        \\    .name = "{s}",
        \\
    , .{
        state.names.get(package_id).?,
    });

    if (state.versions.get(package_id)) |version|
        try writer.print(
            \\    .version = "{}",
            \\
        , .{version});

    try writer.writeAll(
        \\    .dependencies = .{
        \\
    );

    for (dependencies.items) |dependency| {
        try writer.print(
            \\        .{} = .{{
            \\
        , .{std.zig.fmtId(dependency.name)});

        const maybe_hash = state.updated_hashes.get(dependency.to);
        if (!opts.restore and maybe_hash != null)
            try writer.print(
                \\            .url = "http://localhost:{}/{}",
                \\            .hash = "1220{}",
                \\
            , .{ state.port, @as(u8, @intFromEnum(dependency.to)), std.fmt.fmtSliceHexLower(&maybe_hash.?) })
        else {
            // This package needs no updates, or we're restoring
            const info = state.packages.get(dependency.to).?;
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
        \\}
        \\
    );
}
