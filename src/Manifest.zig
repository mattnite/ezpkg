allocator: Allocator,
name: []const u8,
version: std.SemanticVersion,
dependencies: std.StringArrayHashMap(State.PackageInfo),

const Manifest = @This();
const std = @import("std");
const Allocator = std.mem.Allocator;
const State = @import("State.zig");
const zon = @import("eggzon");

const log = std.log.scoped(.manifest);

pub fn from_text(allocator: Allocator, text: []const u8) !Manifest {
    var result = try zon.parseString(allocator, text);
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

    const name_copy = try allocator.dupe(u8, name.string);
    const semver = try std.SemanticVersion.parse(version.string);
    var dependencies = std.StringArrayHashMap(State.PackageInfo).init(allocator);
    errdefer {
        for (dependencies.keys(), dependencies.values()) |dep_key, info| {
            allocator.free(dep_key);
            allocator.free(info.url);
            allocator.free(info.hash);
        }
        dependencies.deinit();
    }

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

            const dep_key_copy = try allocator.dupe(u8, dep_key);
            errdefer allocator.free(dep_key_copy);

            const url_copy = try allocator.dupe(u8, url.string);
            errdefer allocator.free(url_copy);

            const hash_copy = try allocator.dupe(u8, hash.string);
            errdefer allocator.free(url_copy);

            try dependencies.put(dep_key_copy, .{
                .url = url_copy,
                .hash = hash_copy,
            });
        }
    }

    return Manifest{
        .allocator = allocator,
        .name = name_copy,
        .version = semver,
        .dependencies = dependencies,
    };
}

pub fn deinit(manifest: *Manifest) void {
    manifest.allocator.free(manifest.name);

    for (manifest.dependencies.keys(), manifest.dependencies.values()) |name, info| {
        manifest.allocator.free(name);
        manifest.allocator.free(info.url);
        manifest.allocator.free(info.hash);
    }

    manifest.dependencies.deinit();
}
