const builtin = @import("builtin");
const std = @import("std");
const fs = std.fs;
const mem = std.mem;
const Allocator = mem.Allocator;
const ThreadPool = std.Thread.Pool;
const WaitGroup = std.Thread.WaitGroup;

pub const Hash = std.crypto.hash.sha2.Sha256;

const HashedFile = struct {
    fs_path: []const u8,
    normalized_path: []const u8,
    hash: [Hash.digest_length]u8,
    failure: Error!void,

    const Error = fs.File.OpenError || fs.File.ReadError || fs.File.StatError;

    fn lessThan(context: void, lhs: *const HashedFile, rhs: *const HashedFile) bool {
        _ = context;
        return mem.lessThan(u8, lhs.normalized_path, rhs.normalized_path);
    }
};

pub const WhatToDoWithExecutableBit = enum {
    ignore_executable_bit,
    include_executable_bit,
};

pub fn computePackageHash(
    thread_pool: *ThreadPool,
    pkg_dir: fs.IterableDir,
    executable_bit: WhatToDoWithExecutableBit,
) ![Hash.digest_length]u8 {
    const gpa = thread_pool.allocator;

    // We'll use an arena allocator for the path name strings since they all
    // need to be in memory for sorting.
    var arena_instance = std.heap.ArenaAllocator.init(gpa);
    defer arena_instance.deinit();
    const arena = arena_instance.allocator();

    // Collect all files, recursively, then sort.
    var all_files = std.ArrayList(*HashedFile).init(gpa);
    defer all_files.deinit();

    var walker = try pkg_dir.walk(gpa);
    defer walker.deinit();

    {
        // The final hash will be a hash of each file hashed independently. This
        // allows hashing in parallel.
        var wait_group: WaitGroup = .{};
        defer wait_group.wait();

        while (try walker.next()) |entry| {
            //if (try @import("root").entry_should_be_skipped(entry)) {
            //    if (entry.kind != .directory and entry.kind != .file) {
            //        std.log.warn("skipping {}: {s}", .{ entry.kind, entry.path });
            //    }

            //    continue;
            //}

            const hashed_file = try arena.create(HashedFile);
            const fs_path = try arena.dupe(u8, entry.path);
            hashed_file.* = .{
                .fs_path = fs_path,
                .normalized_path = try normalizePath(arena, fs_path),
                .hash = undefined, // to be populated by the worker
                .failure = undefined, // to be populated by the worker
            };
            wait_group.start();
            try thread_pool.spawn(workerHashFile, .{ pkg_dir.dir, hashed_file, &wait_group, executable_bit });

            try all_files.append(hashed_file);
        }
    }

    mem.sort(*HashedFile, all_files.items, {}, HashedFile.lessThan);

    var hasher = Hash.init(.{});
    var any_failures = false;
    for (all_files.items) |hashed_file| {
        hashed_file.failure catch |err| {
            any_failures = true;
            std.log.err("unable to hash '{s}': {s}", .{ hashed_file.fs_path, @errorName(err) });
        };
        hasher.update(&hashed_file.hash);
    }
    if (any_failures) return error.PackageHashUnavailable;
    const final = hasher.finalResult();
    return final;
}

/// Make a file system path identical independently of operating system path inconsistencies.
/// This converts backslashes into forward slashes.
fn normalizePath(arena: Allocator, fs_path: []const u8) ![]const u8 {
    const canonical_sep = '/';

    const normalized = try arena.dupe(u8, fs_path);
    for (normalized) |*byte| {
        switch (byte.*) {
            fs.path.sep => byte.* = canonical_sep,
            else => continue,
        }
    }
    return normalized;
}

fn workerHashFile(dir: fs.Dir, hashed_file: *HashedFile, wg: *WaitGroup, executable_bit: WhatToDoWithExecutableBit) void {
    defer wg.finish();
    hashed_file.failure = hashFileFallible(dir, hashed_file, executable_bit);
}

fn hashFileFallible(dir: fs.Dir, hashed_file: *HashedFile, executable_bit: WhatToDoWithExecutableBit) HashedFile.Error!void {
    var buf: [8000]u8 = undefined;
    var file = try dir.openFile(hashed_file.fs_path, .{});
    defer file.close();
    var hasher = Hash.init(.{});
    hasher.update(hashed_file.normalized_path);
    hasher.update(&.{ 0, @intFromBool(try isExecutable(file, executable_bit)) });
    while (true) {
        const bytes_read = try file.read(&buf);
        if (bytes_read == 0) break;
        hasher.update(buf[0..bytes_read]);
    }
    hasher.final(&hashed_file.hash);
}

pub fn isExecutable(file: fs.File, executable_bit: WhatToDoWithExecutableBit) !bool {
    switch (executable_bit) {
        .ignore_executable_bit => return false,
        .include_executable_bit => {},
    }

    if (builtin.os.tag == .windows) {
        // TODO check the ACL on Windows.
        // Until this is implemented, this could be a false negative on
        // Windows, which is why we do not yet set executable_bit_only above
        // when unpacking the tarball.
        return false;
    } else {
        const stat = try file.stat();
        return (stat.mode & std.os.S.IXUSR) != 0;
    }
}
