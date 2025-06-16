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

static bool is_mountinfo_path(const char *path) {
    return path && strstr(path, "/proc/") && strstr(path, "/mountinfo");
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

        if (sep == -1 || sep < 6) continue; // 非法行

        snprintf(tokens[0], strlen(tokens[0]) + 1, "%d", fixed_id); // mount ID
        snprintf(tokens[1], strlen(tokens[1]) + 1, "%d", fixed_id); // parent ID
        snprintf(tokens[2], strlen(tokens[2]) + 1, "0:1");          // major:minor

        for (int i = 6; i < sep; ++i) {
            if (strstr(tokens[i], "shared:") || strstr(tokens[i], "master:") || strstr(tokens[i], "propagate_from:")) {
                tokens[i][0] = '\0';  // 清空该字段
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
    LOGD("[mountinfo] my_open intercepted path: %s", path);

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
        LOGW("[mountinfo] failed to spoof mountinfo, fallback to original");
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

    LOGD("[mountinfo] replaced mountinfo fd %d with pipe %d", fd, pipefd[0]);
    return pipefd[0];
}

void install_mountinfo_hook(Api *api) {
    orig_open = (int (*)(const char*, int, ...)) dlsym(RTLD_NEXT, "open");
    if (!orig_open) {
        LOGE("[mountinfo] dlsym failed for open");
        return;
    }

    LOGD("[mountinfo] ready to replace mountinfo file access dynamically");
}
