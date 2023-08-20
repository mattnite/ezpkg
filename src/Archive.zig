files: std.StringArrayHashMapUnmanaged(File) = .{},

const Archive = @This();
const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const Hash = std.crypto.hash.sha2.Sha256;

const builtin = @import("builtin");
const tar = @import("tar.zig");
const zlib = @import("zlib.zig");

const log = std.log.scoped(.archive);

pub const File = struct {
    mode: std.fs.File.Mode,
    text: []const u8,
};

pub fn deinit(archive: *Archive, allocator: Allocator) void {
    for (archive.files.keys(), archive.files.values()) |path, file| {
        allocator.free(path);
        allocator.free(file.text);
    }

    archive.files.deinit(allocator);
}

fn padding_from_size(size: usize) usize {
    const mod = (512 + size) % 512;
    return if (mod > 0) 512 - mod else 0;
}

pub fn entry_should_be_skipped(path: []const u8) !bool {
    var it = try std.fs.path.componentIterator(path);
    const first = it.next().?;
    return std.mem.eql(u8, first.name, ".git") or
        std.mem.eql(u8, first.name, "zig-out") or
        std.mem.eql(u8, first.name, "zig-cache");
}

fn stripComponents(path: []const u8, count: u32) ![]const u8 {
    var i: usize = 0;
    var c = count;
    while (c > 0) : (c -= 1) {
        if (std.mem.indexOfScalarPos(u8, path, i, '/')) |pos| {
            i = pos + 1;
        } else {
            return error.TarComponentsOutsideStrippedPrefix;
        }
    }
    return path[i..];
}

const ReadFromTarOptions = struct {
    strip_components: u32,
};

pub fn read_from_tar(
    allocator: Allocator,
    reader: anytype,
    options: ReadFromTarOptions,
) !Archive {
    var timer = try std.time.Timer.start();
    defer {
        const result = timer.read();
        log.info("read_from_tar took {} nanoseconds", .{result});
    }

    var archive = Archive{};
    errdefer archive.deinit(allocator);

    var file_name_buffer: [255]u8 = undefined;
    var buffer: [512 * 8]u8 = undefined;
    var start: usize = 0;
    var end: usize = 0;
    header: while (true) {
        if (buffer.len - start < 1024) {
            const dest_end = end - start;
            @memcpy(buffer[0..dest_end], buffer[start..end]);
            end = dest_end;
            start = 0;
        }
        const ask_header = @min(buffer.len - end, 1024 -| (end - start));
        end += try reader.readAtLeast(buffer[end..], ask_header);
        switch (end - start) {
            0 => return archive,
            1...511 => return error.UnexpectedEndOfStream,
            else => {},
        }
        const header: std.tar.Header = .{ .bytes = buffer[start..][0..512] };
        start += 512;
        const file_size = try header.fileSize();
        const rounded_file_size = std.mem.alignForward(u64, file_size, 512);
        const pad_len = @as(usize, @intCast(rounded_file_size - file_size));
        const unstripped_file_name = try header.fullFileName(&file_name_buffer);
        switch (header.fileType()) {
            .directory => {},
            .normal => {
                if (file_size == 0 and unstripped_file_name.len == 0) return archive;
                const file_name = try stripComponents(unstripped_file_name, options.strip_components);

                const file_name_copy = try allocator.dupe(u8, file_name);
                errdefer allocator.free(file_name_copy);

                var file = std.ArrayList(u8).init(allocator);
                defer file.deinit();

                var file_off: usize = 0;
                while (true) {
                    if (buffer.len - start < 1024) {
                        const dest_end = end - start;
                        @memcpy(buffer[0..dest_end], buffer[start..end]);
                        end = dest_end;
                        start = 0;
                    }
                    // Ask for the rounded up file size + 512 for the next header.
                    // TODO: https://github.com/ziglang/zig/issues/14039
                    const ask = @as(usize, @intCast(@min(
                        buffer.len - end,
                        rounded_file_size + 512 - file_off -| (end - start),
                    )));
                    end += try reader.readAtLeast(buffer[end..], ask);
                    if (end - start < ask) return error.UnexpectedEndOfStream;
                    // TODO: https://github.com/ziglang/zig/issues/14039
                    const slice = buffer[start..@as(usize, @intCast(@min(file_size - file_off + start, end)))];
                    try file.writer().writeAll(slice);
                    file_off += slice.len;
                    start += slice.len;
                    if (file_off >= file_size) {
                        start += pad_len;
                        // Guaranteed since we use a buffer divisible by 512.
                        assert(start <= end);
                        const text = try file.toOwnedSlice();
                        errdefer allocator.free(text);

                        const local_header: *const tar.Header = @ptrCast(header.bytes);
                        _ = local_header;
                        try archive.files.put(allocator, file_name_copy, .{
                            .text = text,
                            .mode = 0o644,
                            //.mode = try local_header.get_mode(),
                        });
                        continue :header;
                    }
                }
            },
            .global_extended_header, .extended_header => {
                if (start + rounded_file_size > end) return error.TarHeadersTooBig;
                start = @as(usize, @intCast(start + rounded_file_size));
            },
            .hard_link => return error.TarUnsupportedFileType,
            .symbolic_link => return error.TarUnsupportedFileType,
            else => return error.TarUnsupportedFileType,
        }
    }

    return archive;
}

// TODO: thread pool it
pub fn read_from_fs(allocator: Allocator, dir: std.fs.IterableDir) !Archive {
    var archive = Archive{};
    errdefer archive.deinit(allocator);

    var timer = try std.time.Timer.start();
    defer {
        const nanos = timer.read();
        std.log.info("read_from_fs took {} nanoseconds", .{nanos});
    }

    var walker = try dir.walk(allocator);
    defer walker.deinit();

    while (try walker.next()) |entry| {
        if (entry.kind == .directory)
            continue;

        if (entry.kind != .file) {
            log.warn("skipping {}: {s}", .{ entry.kind, entry.path });
            continue;
        }

        if (try entry_should_be_skipped(entry.path))
            continue;

        const path_copy = try allocator.dupe(u8, entry.path);
        errdefer allocator.free(path_copy);

        const file = try entry.dir.openFile(entry.basename, .{});
        defer file.close();

        const text = try file.readToEndAlloc(allocator, std.math.maxInt(usize));
        errdefer allocator.free(text);

        const stat = try file.stat();
        try archive.files.put(allocator, path_copy, .{
            .text = text,
            .mode = stat.mode,
        });
    }

    return archive;
}

pub fn to_tar_gz(archive: Archive, allocator: Allocator) ![]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    var gzip = try zlib.gzip.compressor(arena.allocator(), buf.writer());
    defer gzip.deinit();

    for (archive.files.keys(), archive.files.values()) |path, file| {
        const padding = padding_from_size(file.text.len);
        const path_with_skipped_dir = try std.fs.path.join(arena.allocator(), &.{ "skip_me", path });
        const header = try tar.Header.init(.{
            .path = path_with_skipped_dir,
            .size = file.text.len,
            .typeflag = .regular,
            .mode = @intCast(file.mode),
        });

        try gzip.writer().writeAll(header.to_bytes());
        try gzip.writer().writeAll(file.text);
        try gzip.writer().writeByteNTimes(0, @as(usize, @intCast(padding)));
    }

    try gzip.writer().writeByteNTimes(0, 1024);

    try gzip.flush();
    return buf.toOwnedSlice();
}

fn path_less_than(_: void, lhs: []const u8, rhs: []const u8) bool {
    return std.mem.lessThan(u8, lhs, rhs);
}

pub const WhatToDoWithExecutableBit = enum {
    ignore_executable_bit,
    include_executable_bit,
};

fn is_executable(mode: std.fs.File.Mode, executable_bit: WhatToDoWithExecutableBit) bool {
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
        return (mode & std.os.S.IXUSR) != 0;
    }
}

// TODO: threadpool this
pub fn hash(
    archive: Archive,
    allocator: Allocator,
    executable_bit: WhatToDoWithExecutableBit,
) ![Hash.digest_length]u8 {
    var timer = try std.time.Timer.start();

    var paths = std.ArrayList([]const u8).init(allocator);
    defer paths.deinit();

    var hashes = std.ArrayList([Hash.digest_length]u8).init(allocator);
    defer hashes.deinit();

    try paths.appendSlice(archive.files.keys());
    try hashes.appendNTimes(undefined, paths.items.len);
    std.mem.sort([]const u8, paths.items, {}, path_less_than);

    for (paths.items, hashes.items) |path, *result| {
        const file = archive.files.get(path).?;
        var hasher = Hash.init(.{});
        hasher.update(path);
        hasher.update(&.{ 0, @intFromBool(is_executable(file.mode, executable_bit)) });
        hasher.update(file.text);
        hasher.final(result);
    }

    var hasher = Hash.init(.{});
    for (hashes.items) |file_hash|
        hasher.update(&file_hash);

    const timer_result = timer.read();
    log.info("hash took {} nanoseconds", .{timer_result});

    return hasher.finalResult();
}
