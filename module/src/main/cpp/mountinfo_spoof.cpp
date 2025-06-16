#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <android/log.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <dlfcn.h>

#include "zygisk.hpp"
#include "log.h"
using zygisk::Api;

static ssize_t (*orig_read)(int, void*, size_t) = nullptr;
static int (*orig_open)(const char*, int, ...) = nullptr;
static int (*orig_close)(int) = nullptr;

#define MAX_HOOKED_FD 4
static int hooked_fds[MAX_HOOKED_FD] = {-1, -1, -1, -1};
static char *fd_data[MAX_HOOKED_FD] = {0};
static size_t fd_len[MAX_HOOKED_FD] = {0};
static size_t fd_offset[MAX_HOOKED_FD] = {0};

static bool is_mountinfo_path(const char *path) {
    return path && strstr(path, "/proc/") && strstr(path, "/mountinfo");
}

static int find_fd_index(int fd) {
    for (int i = 0; i < MAX_HOOKED_FD; ++i) {
        if (hooked_fds[i] == fd) return i;
    }
    return -1;
}

static void clear_fd(int index) {
    if (index >= 0 && index < MAX_HOOKED_FD) {
        free(fd_data[index]);
        fd_data[index] = NULL;
        fd_len[index] = 0;
        fd_offset[index] = 0;
        hooked_fds[index] = -1;
    }
}

static void spoof_mountinfo(int fd, const char *raw, size_t len) {
    char *buf = (char *)malloc(len + 1);
    if (!buf) return;
    memcpy(buf, raw, len);
    buf[len] = '\0';

    int fake_id = 1;
    for (size_t i = 0; i < len; ++i) {
        if (i == 0 || buf[i - 1] == '\n') {
            int n = snprintf(buf + i, len - i, "%d", fake_id++);
            i += (n > 0) ? (n - 1) : 0;
        }
    }

    for (int i = 0; i < MAX_HOOKED_FD; ++i) {
        if (hooked_fds[i] == -1) {
            hooked_fds[i] = fd;
            fd_data[i] = buf;
            fd_len[i] = len;
            fd_offset[i] = 0;
            LOGD("[mountinfo] spoofed and cached fd %d at slot %d", fd, i);
            return;
        }
    }
    free(buf);
}

ssize_t my_read(int fd, void *buf, size_t count) {
    static __thread bool in_hook = false;
    if (in_hook || !orig_read) return orig_read ? orig_read(fd, buf, count) : -1;
    in_hook = true;
    LOGD("[mountinfo] my_read invoked on fd %d", fd);
    int index = find_fd_index(fd);
    if (index != -1 && fd_data[index]) {
        size_t remain = fd_len[index] - fd_offset[index];
        size_t to_copy = (remain > count) ? count : remain;
        memcpy(buf, fd_data[index] + fd_offset[index], to_copy);
        fd_offset[index] += to_copy;
        in_hook = false;
        return (ssize_t)to_copy;
    }

    ssize_t ret = orig_read(fd, buf, count);
    in_hook = false;
    return ret;
}

int my_open(const char *path, int flags, ...) {
    static __thread bool in_hook = false;
    if (in_hook || !orig_open) return orig_open ? orig_open(path, flags) : -1;
    in_hook = true;
    LOGD("[mountinfo] my_open invoked on path: %s", path);
    int fd = orig_open(path, flags);
    if (fd >= 0 && is_mountinfo_path(path)) {
        char tmp[65536] = {0};
        lseek(fd, 0, SEEK_SET);
        ssize_t len = orig_read ? orig_read(fd, tmp, sizeof(tmp) - 1) : -1;
        LOGD("[mountinfo] read() in open-hook used orig_read on fd %d -> len %zd", fd, len);
        if (len > 0) {
            spoof_mountinfo(fd, tmp, (size_t)len);
        }
    }

    in_hook = false;
    return fd;
}

int my_close(int fd) {
    int index = find_fd_index(fd);
    if (index != -1) {
        clear_fd(index);
        LOGD("[mountinfo] closed and cleared fd %d", fd);
    }
    return orig_close ? orig_close(fd) : -1;
}

void install_mountinfo_hook(zygisk::Api *api, dev_t dev, ino_t ino) {
    api->pltHookRegister(dev, ino, "read", (void*)my_read, (void**)&orig_read);
    api->pltHookRegister(dev, ino, "open", (void*)my_open, (void**)&orig_open);
    api->pltHookRegister(dev, ino, "close", (void*)my_close, (void**)&orig_close);
    api->pltHookCommit();
    LOGD("[mountinfo] installed hooks and committed them");
}
