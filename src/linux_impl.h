typedef void (*zig_clear_paths_t)();
typedef void (*zig_add_path_t) (unsigned char* path_that_changed);
typedef void (*zig_handle_paths_t)();

void LI_init(zig_clear_paths_t clear_paths_cb, zig_add_path_t add_path_cb, zig_handle_paths_t zig_handle_paths_cb);
int LI_loop(int num_paths, unsigned char** paths);
void LI_errdefer_handler();

enum loop_errorset {
    NO_ERROR,
    E_CALLBACKS,
    E_INOTIFY_INIT,
    E_CALLOC,
    E_INOTIFY_WATCH,
    E_POLL,
};
