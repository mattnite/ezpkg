#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/inotify.h>
#include <unistd.h>
#include <string.h>

#include "linux_impl.h"

// callbacks to zig
zig_add_path_t zig_add_path = 0; 
zig_clear_paths_t zig_clear_paths = 0;
zig_handle_paths_t zig_handle_paths = 0;

// reggster the callbacks
void LI_init(zig_clear_paths_t clear_paths_cb, zig_add_path_t add_path_cb, zig_handle_paths_t zig_handle_paths_cb) {
    zig_add_path = add_path_cb;
    zig_clear_paths = clear_paths_cb;
    zig_handle_paths = zig_handle_paths_cb;
}


/* Read all available inotify events from the file descriptor 'fd'.
   wd is the table of watch descriptors for the directories in paths.
   num_paths is the length of wd and paths.
   paths is the list of watched directories.
*/

enum errorset_handle_events {
    HE_OK,
    HE_ERROR,
};

static int handle_events(int fd, int *wd, int num_paths, char* paths[])
{
    /* Some systems cannot read integer variables if they are not
       properly aligned. On other systems, incorrect alignment may
       decrease performance. Hence, the buffer used for reading from
       the inotify file descriptor should have the same alignment as
       struct inotify_event. */
    char buf[4096] __attribute__ ((aligned(__alignof__(struct inotify_event))));
    const struct inotify_event *event;
    ssize_t len;

    unsigned char have_new_stuff = 0;
    /* Loop while events can be read from inotify file descriptor. */
    for (;;) {

        /* Read some events. */
        len = read(fd, buf, sizeof(buf));
        if (len == -1 && errno != EAGAIN) {
            perror("read");
            return HE_ERROR;
        }

        /* If the nonblocking read() found no events to read, then
           it returns -1 with errno set to EAGAIN. In that case,
           we exit the loop. */
        if (len <= 0)
            break;

        /* Loop over all events in the buffer. */
        for (char *ptr = buf; ptr < buf + len; ptr += sizeof(struct inotify_event) + event->len) {
            event = (const struct inotify_event *) ptr;
            // we only care about changes to the filesystem
            if (event->mask & IN_CLOSE_WRITE || event->mask & IN_ISDIR) {
                for (size_t i = 0; i < num_paths; ++i) {
                    if (wd[i] == event->wd) {
                        char buf[4096];
                        // sprintf(buf, "%s/%s", paths[i], event->name);
                        // printf("    [C] adding path: %s\n", buf);


                        // printf("    [C] adding path: %s\n", paths[i]);
                        if(zig_add_path != 0) {
                            // zig_add_path(buf);
                            zig_add_path(paths[i]);
                            have_new_stuff = 1;
                        }
                        break;
                    }
                }
            } // else {
            //     printf("Wrong event for:  %s\n", event->name);
            // }
        }
    }
    if(have_new_stuff == 1) {
        zig_handle_paths();
        zig_clear_paths();
    }
    return HE_OK;
}


// global so we can errdefer
int fd = -1;
int *wd = 0;

int LI_loop(int num_paths, unsigned char** paths) {
    int i, poll_num;
    nfds_t nfds;
    struct pollfd poll_fd;

    if(zig_add_path == 0 || zig_clear_paths == 0 || zig_handle_paths == 0) {
        return E_CALLBACKS;
    }

    /* Create the file descriptor for accessing the inotify API. */
    fd = inotify_init1(IN_NONBLOCK);
    if (fd == -1) {
        perror("inotify_init1");
        return E_INOTIFY_INIT;
    }

    /* Allocate memory for watch descriptors. */
    wd = calloc(num_paths, sizeof(int));
    if (wd == NULL) {
        perror("calloc");
        return E_CALLOC;
    }

    /* Mark directories for events
       - file was opened
       - file was closed */
    for (i = 0; i < num_paths; i++) {
        wd[i] = inotify_add_watch(fd, paths[i], IN_OPEN | IN_CLOSE);
        if (wd[i] == -1) {
            fprintf(stderr, "Cannot watch '%s': %s\n", paths[i], strerror(errno));
            return E_INOTIFY_WATCH;
        }
    }

    /* Prepare for polling. */
    nfds = 1;
    poll_fd.fd = fd;                 /* Inotify input */
    poll_fd.events = POLLIN;

    /* Wait for events */
    printf("Listening for events.\n");
    while (1) {
        zig_clear_paths();
        poll_num = poll(&poll_fd, nfds, -1);
        if (poll_num == -1) {
            if (errno == EINTR)
                continue;
            // errdefer {
            close(fd);
            free(wd);
            // }
            perror("poll");
            return E_POLL;
        }

        if (poll_num > 0) {
            if (poll_fd.revents & POLLIN) {

                /* Inotify events are available. */
                if(handle_events(fd, wd, num_paths, paths) != HE_OK) {
                    // some error occured
                }
            }
        }
    }

    // UNREACHABLE:
    printf("Listening for events stopped.\n");
    close(fd);
    free(wd);
}

void LI_errdefer_handler() {
    if(fd > 0) {
        close(fd);
    }
    if(wd != 0) {
        free(wd);
    }
}
