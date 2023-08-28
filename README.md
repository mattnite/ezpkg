# ezpkg: Edit Zig Package 

This program redirects dependencies to local directories for Zig package
development. Run it from the root of your project, and provide key value pairs
specifying what nodes in the dependency tree to redirect locally:

```sh
ezpkg my_dep=../local_copy_of_dep
```

## Nested Dependencies

ezpkg is also able to redirect nested dependencies, in order to specify a
redirect, use dot notation to traverse the dependency graph:

```sh
ezpkg my_dep.child=../some_other_path
```

## Multiple Redirects

ezpkg can redirect as many dependencies as you like, as long as there are no
conflicts:

```sh
ezpkg my_dep=../local_copy_of_dep my_dep.child=../some_other_path
```

## Deduplication

ezpkg will try to deduplicate nodes in the dependency graph, right now it uses
exact hash matching to do so. This means that if a package is depended on in
multiple places within the graph, and the user specifies a redirection, ezpkg
will automatically redirect these nodes.

## Building and Zig Version

ezpkg is meant for use in Zig 0.11.0 package development, and uses 0.11.0 to build.

```sh
zig build -Doptimize=ReleaseSafe
```

## Details

ezpkg:

- builds your dependency graph
- replaces nodes with specified redirections
- monitors filesystem for changes
- alters project zon file to point at local HTTP Server
- restores zon file on exit

## OS Support

- [x] macos
- [x] linux
- [ ] windows
