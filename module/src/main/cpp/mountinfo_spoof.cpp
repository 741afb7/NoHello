#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <android/log.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <limits.h>
#include <dlfcn.h>

#include "zygisk.hpp"
#include "log.h"

using zygisk::Api;

static int (*orig_open)(const char*, int, ...) = nullptr;
static int (*orig_openat)(int, const char*, int, ...) = nullptr;
static FILE *(*orig_fopen)(const char *, const char *) = nullptr;
static ssize_t (*orig_readlink)(const char *, char *, size_t) = nullptr;
static ssize_t (*orig_readlinkat)(int, const char *, char *, size_t) = nullptr;
static ssize_t (*orig_read)(int, void*, size_t) = nullptr;
static ssize_t (*orig_pread)(int, void*, size_t, off_t) = nullptr;
static FILE *(*orig_fopen64)(const char *, const char *) = nullptr;
static ssize_t (*orig_readv)(int, const struct iovec *, int) = nullptr;
static char *(*orig_fgets)(char *, int, FILE *) = nullptr;
static size_t (*orig_fread)(void *, size_t, size_t, FILE *) = nullptr;

static bool is_mountinfo_path(const char *path) {
    if (!path) return false;
    if (strstr(path, "/mountinfo")) {
        LOGD("[mountinfo] matched path: %s", path);
        return true;
    }
    LOGD("[mountinfo] opened file: %s", path);
    return false;
}

// generate mountinfo
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

        for (int i = 6; i < sep; ++i) {
            if (strstr(tokens[i], "shared:") || strstr(tokens[i], "master:") || strstr(tokens[i], "propagate_from:")) {
                tokens[i][0] = '\0';
            }
        }

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

// open()
int my_open(const char *path, int flags, ...) {
    if (!orig_open)
        return -1;

    int fd = orig_open(path, flags);
    if (fd < 0 || !is_mountinfo_path(path))
        return fd;

    char *data = nullptr;
    size_t len = 0;
    generate_spoofed_mountinfo(&data, &len);
    if (!data || len == 0) return fd;

    int pipefd[2];
    if (pipe(pipefd) != 0) {
        free(data);
        return fd;
    }

    write(pipefd[1], data, len);
    close(pipefd[1]);
    free(data);
    close(fd);
    return pipefd[0];
}

// openat()
int my_openat(int dirfd, const char *path, int flags, ...) {
    if (!orig_openat)
        return -1;

    int fd = orig_openat(dirfd, path, flags);
    if (fd < 0 || !is_mountinfo_path(path))
        return fd;

    char *data = nullptr;
    size_t len = 0;
    generate_spoofed_mountinfo(&data, &len);
    if (!data || len == 0) return fd;

    int pipefd[2];
    if (pipe(pipefd) != 0) {
        free(data);
        return fd;
    }

    write(pipefd[1], data, len);
    close(pipefd[1]);
    free(data);
    close(fd);
    return pipefd[0];
}

// fopen()
FILE *my_fopen(const char *path, const char *mode) {
    if (!orig_fopen)
        return nullptr;

    FILE *fp = orig_fopen(path, mode);
    if (!fp || !is_mountinfo_path(path))
        return fp;

    char *data = nullptr;
    size_t len = 0;
    generate_spoofed_mountinfo(&data, &len);
    if (!data || len == 0) return fp;

    int pipefd[2];
    if (pipe(pipefd) != 0) {
        free(data);
        return fp;
    }

    write(pipefd[1], data, len);
    close(pipefd[1]);
    free(data);
    fclose(fp);
    return fdopen(pipefd[0], mode);
}

// fopen64
FILE *my_fopen64(const char *path, const char *mode) {
    LOGD("[mountinfo] my_fopen64: path=%s", path);
    return orig_fopen64 ? my_fopen(path, mode) : nullptr;
}

// readlink()
ssize_t my_readlink(const char *path, char *buf, size_t bufsiz) {
    if (strstr(path, "/proc/") && strstr(path, "/fd/")) {
        LOGD("[mountinfo] readlink intercepted: %s", path);
    }
    return orig_readlink ? orig_readlink(path, buf, bufsiz) : -1;
}

ssize_t my_readlinkat(int dirfd, const char *path, char *buf, size_t bufsiz) {
    if (strstr(path, "/proc/") && strstr(path, "/fd/")) {
        LOGD("[mountinfo] readlinkat intercepted: %s", path);
    }
    return orig_readlinkat ? orig_readlinkat(dirfd, path, buf, bufsiz) : -1;
}

// read
ssize_t my_read(int fd, void *buf, size_t count) {
    char path[PATH_MAX] = {};
    snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
    char target[PATH_MAX] = {};
    ssize_t len = readlink(path, target, sizeof(target) - 1);
    if (len > 0) {
        target[len] = '\0';
        if (strstr(target, "mountinfo")) {
            LOGD("[mountinfo] spoofed via read(fd=%d): %s", fd, target);
            size_t flen = strlen(fake_mountinfo_str);
            size_t to_copy = (count < flen) ? count : flen;
            memcpy(buf, fake_mountinfo_str, to_copy);
            return to_copy;
        }
    }
    return orig_read ? orig_read(fd, buf, count) : -1;
}

// pread
ssize_t my_pread(int fd, void *buf, size_t count, off_t offset) {
    char path[PATH_MAX] = {};
    snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
    char target[PATH_MAX] = {};
    ssize_t len = readlink(path, target, sizeof(target) - 1);
    if (len > 0) {
        target[len] = '\0';
        if (strstr(target, "mountinfo")) {
            LOGD("[mountinfo] spoofed via pread(fd=%d, offset=%ld): %s", fd, offset, target);
            size_t flen = strlen(fake_mountinfo_str);
            if ((size_t)offset >= flen) return 0;
            size_t to_copy = (count < flen - offset) ? count : (flen - offset);
            memcpy(buf, fake_mountinfo_str + offset, to_copy);
            return to_copy;
        }
    }
    return orig_pread ? orig_pread(fd, buf, count, offset) : -1;
}

// readv
ssize_t my_readv(int fd, const struct iovec *iov, int iovcnt) {
    char linkpath[PATH_MAX] = {};
    snprintf(linkpath, sizeof(linkpath), "/proc/self/fd/%d", fd);
    char target[PATH_MAX] = {};
    ssize_t len = readlink(linkpath, target, sizeof(target) - 1);
    if (len > 0) {
        target[len] = '\0';
        if (strstr(target, "mountinfo")) {
            LOGD("[mountinfo] readv mountinfo fd=%d path=%s", fd, target);
        }
    }
    return orig_readv ? orig_readv(fd, iov, iovcnt) : -1;
}

// fgets()
char *my_fgets(char *s, int size, FILE *stream) {
    if (!orig_fgets)
        return nullptr;

    long pos = ftell(stream);
    char *ret = orig_fgets(s, size, stream);
    if (pos == 0 && ret && strstr(s, "mountinfo")) {
        strncpy(s, fake_mountinfo_str, size - 1);
        s[size - 1] = '\0';
    }
    return ret;
}

// fread()
size_t my_fread(void *ptr, size_t size, size_t nmemb, FILE *stream) {
    if (!orig_fread)
        return 0;

    long pos = ftell(stream);
    size_t ret = orig_fread(ptr, size, nmemb, stream);

    if (pos == 0 && strstr((char *)ptr, "mountinfo")) {
        strncpy((char *)ptr, fake_mountinfo_str, size * nmemb);
    }
    return ret;
}

void install_mountinfo_hook(Api *api) {
    orig_open     = (int (*)(const char*, int, ...)) dlsym(RTLD_NEXT, "open");
    orig_openat   = (int (*)(int, const char*, int, ...)) dlsym(RTLD_NEXT, "openat");
    orig_fopen    = (FILE *(*)(const char *, const char *)) dlsym(RTLD_NEXT, "fopen");
    orig_fopen64  = (FILE *(*)(const char *, const char *)) dlsym(RTLD_NEXT, "fopen64");
    orig_readlink = (ssize_t (*)(const char *, char *, size_t)) dlsym(RTLD_NEXT, "readlink");
    orig_readlinkat = (ssize_t (*)(int, const char *, char *, size_t)) dlsym(RTLD_NEXT, "readlinkat");
    orig_read     = (ssize_t (*)(int, void*, size_t)) dlsym(RTLD_NEXT, "read");
    orig_pread    = (ssize_t (*)(int, void*, size_t, off_t)) dlsym(RTLD_NEXT, "pread");
    orig_readv    = (ssize_t (*)(int, const struct iovec *, int)) dlsym(RTLD_NEXT, "readv");
    orig_fgets    = (char *(*)(char *, int, FILE *)) dlsym(RTLD_NEXT, "fgets");
    orig_fread    = (size_t (*)(void *, size_t, size_t, FILE *)) dlsym(RTLD_NEXT, "fread");

    LOGD("[mountinfo] hook installed: open/openat/fopen/fread/fgets/readlink/read/pread/readv");
}
