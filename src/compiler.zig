const Package = @import("compiler/Package.zig");
pub const compute_package_hash = Package.computePackageHash;
pub const package_hash_len = Package.Hash.digest_length;
