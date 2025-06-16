#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <android/log.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dlfcn.h>
#include <sys/uio.h>
#include <sys/mman.h>

#include "zygisk.hpp"
#include "log.h"

using zygisk::Api;

static int (*orig_open)(const char*, int, ...) = nullptr;
static int (*orig_openat)(int, const char*, int, ...) = nullptr;
static FILE *(*orig_fopen)(const char *, const char *) = nullptr;
static FILE *(*orig_fopen64)(const char *, const char *) = nullptr;
static ssize_t (*orig_read)(int, void*, size_t) = nullptr;
static ssize_t (*orig_pread)(int, void*, size_t, off_t) = nullptr;
static ssize_t (*orig_readv)(int, const struct iovec *, int) = nullptr;
static ssize_t (*orig_readlink)(const char *, char *, size_t) = nullptr;
static void* (*orig_mmap)(void *, size_t, int, int, int, off_t) = nullptr;
static int (*orig_access)(const char *, int) = nullptr;
static int (*orig_stat)(const char *, struct stat *) = nullptr;
static int (*orig_lstat)(const char *, struct stat *) = nullptr;

static bool is_mountinfo_path(const char *path) {
    if (!path) return false;
    if (strstr(path, "mountinfo")) {
        LOGD("[hook] mountinfo path matched: %s", path);
        return true;
    }
    return false;
}

static void generate_spoofed_mountinfo(char **data, size_t *length) {
    FILE *f = fopen("/proc/self/mountinfo", "r");
    if (!f) return;

    char *line = nullptr;
    size_t len = 0;
    size_t total = 0;
    char *result = (char *)malloc(65536);
    if (!result) {
        fclose(f);
        return;
    }

    int fake_id = 1;
    while (getline(&line, &len, f) != -1) {
        char *saveptr = nullptr;
        char *tokens[64];
        int tok_idx = 0;

        char *token = strtok_r(line, " ", &saveptr);
        while (token && tok_idx < 64) {
            tokens[tok_idx++] = token;
            token = strtok_r(nullptr, " ", &saveptr);
        }

        int sep = -1;
        for (int i = 0; i < tok_idx; ++i) {
            if (strcmp(tokens[i], "-") == 0) {
                sep = i;
                break;
            }
        }

        if (sep == -1 || sep < 6) continue;

        snprintf(tokens[0], strlen(tokens[0]) + 1, "%d", fake_id);
        snprintf(tokens[1], strlen(tokens[1]) + 1, "%d", fake_id);
        snprintf(tokens[2], strlen(tokens[2]) + 1, "0:1");

        for (int i = 0; i < tok_idx; ++i) {
            if (tokens[i][0] != '\0') {
                total += snprintf(result + total, 65536 - total, "%s%s", tokens[i], (i + 1 == tok_idx) ? "\n" : " ");
            }
        }

        ++fake_id;
    }

    if (line) free(line);
    fclose(f);
    *data = result;
    *length = total;
}

#define HOOK_LOG(fn, path) LOGD("[hook] %s(" #fn "): %s", __func__, path)

int my_open(const char *path, int flags, ...) {
    HOOK_LOG(open, path);
    return orig_open ? orig_open(path, flags) : -1;
}

int my_openat(int dirfd, const char *path, int flags, ...) {
    HOOK_LOG(openat, path);
    return orig_openat ? orig_openat(dirfd, path, flags) : -1;
}

FILE *my_fopen(const char *path, const char *mode) {
    HOOK_LOG(fopen, path);
    return orig_fopen ? orig_fopen(path, mode) : nullptr;
}

FILE *my_fopen64(const char *path, const char *mode) {
    HOOK_LOG(fopen64, path);
    return orig_fopen64 ? orig_fopen64(path, mode) : nullptr;
}

ssize_t my_read(int fd, void *buf, size_t count) {
    LOGD("[hook] read(fd=%d)", fd);
    return orig_read ? orig_read(fd, buf, count) : -1;
}

ssize_t my_pread(int fd, void *buf, size_t count, off_t offset) {
    LOGD("[hook] pread(fd=%d, offset=%ld)", fd, offset);
    return orig_pread ? orig_pread(fd, buf, count, offset) : -1;
}

ssize_t my_readv(int fd, const struct iovec *iov, int iovcnt) {
    LOGD("[hook] readv(fd=%d, iovcnt=%d)", fd, iovcnt);
    return orig_readv ? orig_readv(fd, iov, iovcnt) : -1;
}

ssize_t my_readlink(const char *path, char *buf, size_t bufsiz) {
    HOOK_LOG(readlink, path);
    return orig_readlink ? orig_readlink(path, buf, bufsiz) : -1;
}

void* my_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    char fdpath[PATH_MAX] = {}, target[PATH_MAX] = {};
    snprintf(fdpath, sizeof(fdpath), "/proc/self/fd/%d", fd);
    ssize_t len = readlink(fdpath, target, sizeof(target) - 1);
    if (len > 0) {
        target[len] = '\0';
        if (strstr(target, "mountinfo")) {
            LOGD("[hook] mmap: matched mountinfo fd=%d path=%s", fd, target);
            char *data = nullptr;
            size_t datalen = 0;
            generate_spoofed_mountinfo(&data, &datalen);
            if (!data || datalen == 0) return orig_mmap(addr, length, prot, flags, fd, offset);

            void *fake = mmap(nullptr, datalen, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (fake == MAP_FAILED) {
                free(data);
                return orig_mmap(addr, length, prot, flags, fd, offset);
            }
            memcpy(fake, data, datalen);
            mprotect(fake, datalen, PROT_READ);
            free(data);
            return fake;
        }
    }
    return orig_mmap(addr, length, prot, flags, fd, offset);
}

int my_access(const char *path, int mode) {
    HOOK_LOG(access, path);
    return orig_access ? orig_access(path, mode) : -1;
}

int my_stat(const char *path, struct stat *buf) {
    HOOK_LOG(stat, path);
    return orig_stat ? orig_stat(path, buf) : -1;
}

int my_lstat(const char *path, struct stat *buf) {
    HOOK_LOG(lstat, path);
    return orig_lstat ? orig_lstat(path, buf) : -1;
}

void install_mountinfo_hook(Api *api) {
    orig_open     = (int (*)(const char*, int, ...)) dlsym(RTLD_NEXT, "open");
    orig_openat   = (int (*)(int, const char*, int, ...)) dlsym(RTLD_NEXT, "openat");
    orig_fopen    = (FILE *(*)(const char *, const char *)) dlsym(RTLD_NEXT, "fopen");
    orig_fopen64  = (FILE *(*)(const char *, const char *)) dlsym(RTLD_NEXT, "fopen64");
    orig_read     = (ssize_t (*)(int, void*, size_t)) dlsym(RTLD_NEXT, "read");
    orig_pread    = (ssize_t (*)(int, void*, size_t, off_t)) dlsym(RTLD_NEXT, "pread");
    orig_readv    = (ssize_t (*)(int, const struct iovec *, int)) dlsym(RTLD_NEXT, "readv");
    orig_readlink = (ssize_t (*)(const char *, char *, size_t)) dlsym(RTLD_NEXT, "readlink");
    orig_mmap     = (void *(*)(void *, size_t, int, int, int, off_t)) dlsym(RTLD_NEXT, "mmap");
    orig_access   = (int (*)(const char *, int)) dlsym(RTLD_NEXT, "access");
    orig_stat     = (int (*)(const char *, struct stat *)) dlsym(RTLD_NEXT, "stat");
    orig_lstat    = (int (*)(const char *, struct stat *)) dlsym(RTLD_NEXT, "lstat");

    LOGD("[hook] mountinfo hooks installed");
}
