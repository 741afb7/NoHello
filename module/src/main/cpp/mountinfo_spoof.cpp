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

#include "zygisk.hpp"
#include "log.h"

using zygisk::Api;

static int (*orig_open)(const char*, int, ...) = nullptr;
static int (*orig_openat)(int, const char*, int, ...) = nullptr;
static FILE *(*orig_fopen)(const char *, const char *) = nullptr;

static bool is_mountinfo_path(const char *path) {
    if (!path) return false;
    if (strstr(path, "/mountinfo")) {
        LOGD("[mountinfo] matched path: %s", path);
        return true;
    }
    LOGD("[mountinfo] opened file: %s", path);  // log every open path
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

    int fixed_id = 1;
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

        snprintf(tokens[0], strlen(tokens[0]) + 1, "%d", fixed_id);
        snprintf(tokens[1], strlen(tokens[1]) + 1, "%d", fixed_id);
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
    }

    if (line) free(line);
    fclose(f);
    *data = result;
    *length = total;
}

int my_open(const char *path, int flags, ...) {
    if (!orig_open)
        return -1;

    int fd = orig_open(path, flags);
    if (fd < 0)
        return fd;

    if (!is_mountinfo_path(path))
        return fd;

    char *data = nullptr;
    size_t len = 0;
    generate_spoofed_mountinfo(&data, &len);
    if (!data || len == 0) {
        return fd;
    }

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

int my_openat(int dirfd, const char *path, int flags, ...) {
    if (!orig_openat)
        return -1;

    int fd = orig_openat(dirfd, path, flags);
    if (fd < 0)
        return fd;

    if (!is_mountinfo_path(path))
        return fd;

    // reuse spoof logic
    char *data = nullptr;
    size_t len = 0;
    generate_spoofed_mountinfo(&data, &len);
    if (!data || len == 0) {
        return fd;
    }

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

FILE *my_fopen(const char *path, const char *mode) {
    if (!orig_fopen)
        return nullptr;

    FILE *fp = orig_fopen(path, mode);
    if (!fp || !is_mountinfo_path(path))
        return fp;

    // mimic spoof
    int pipefd[2];
    char *data = nullptr;
    size_t len = 0;
    generate_spoofed_mountinfo(&data, &len);
    if (!data || pipe(pipefd) != 0) {
        free(data);
        return fp;
    }

    write(pipefd[1], data, len);
    close(pipefd[1]);
    free(data);
    fclose(fp); // close real file
    return fdopen(pipefd[0], mode);
}

void install_mountinfo_hook(Api *api) {
    orig_open = (int (*)(const char*, int, ...)) dlsym(RTLD_NEXT, "open");
    orig_openat = (int (*)(int, const char*, int, ...)) dlsym(RTLD_NEXT, "openat");
    orig_fopen = (FILE *(*)(const char *, const char *)) dlsym(RTLD_NEXT, "fopen");

    if (!orig_open)   LOGE("[mountinfo] dlsym failed for open");
    if (!orig_openat) LOGE("[mountinfo] dlsym failed for openat");
    if (!orig_fopen)  LOGE("[mountinfo] dlsym failed for fopen");

    LOGD("[mountinfo] hook ready: open, openat, fopen");
}
