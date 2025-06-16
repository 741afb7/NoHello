#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <android/log.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/system_properties.h>
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
    char *result = (char *)malloc(65536);  // enough buffer
    if (!result) {
        fclose(f);
        return;
    }
    int id = 100;
    while (getline(&line, &len, f) != -1) {
        char *space = strchr(line, ' ');
        if (space) {
            int n = snprintf(result + total, 65536 - total, "%d%s", id++, space);
            total += n;
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

    // generate spoofed data
    char *data = nullptr;
    size_t len = 0;
    generate_spoofed_mountinfo(&data, &len);
    if (!data || len == 0) {
        LOGW("[mountinfo] failed to spoof mountinfo, fallback to original");
        return fd;
    }

    // create pipe
    int pipefd[2];
    if (pipe(pipefd) != 0) {
        free(data);
        return fd;
    }

    // write spoofed content
    write(pipefd[1], data, len);
    close(pipefd[1]);
    free(data);
    close(fd);  // close original mountinfo fd

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
