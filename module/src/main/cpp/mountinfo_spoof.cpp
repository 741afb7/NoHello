#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <dlfcn.h>
#include <android/log.h>
#include <utility> 

#include "zygisk.hpp"
#include "log.h"

static long (*orig_syscall)(long, ...) = nullptr;

static bool is_system_libc(const char *path) {
    return strstr(path, "/system/") || strstr(path, "/apex/");
}

static bool is_libc_path(const char* path) {
    if (!path) return false;
    return (strstr(path, "libc.so") && !strstr(path, "linker"));
}

bool generate_spoofed_mountinfo_content(char **out_data, size_t *out_len) {
    FILE *f = fopen("/proc/self/mountinfo", "r");
    if (!f) {
        LOGE("Failed to open mountinfo: %s", strerror(errno));
        return false;
    }

    char *line = nullptr;
    size_t len = 0;
    size_t total = 0;
    char *result = (char *)malloc(65536);
    if (!result) {
        fclose(f);
        LOGE("Memory allocation failed");
        return false;
    }

    int fake_id = 1000;
    std::unordered_map<std::string, int> shared_map;
    std::unordered_map<std::string, int> master_map;

    while (getline(&line, &len, f) != -1) {
        LOGD("[mountinfo] Original: %s", line);

        char *tokens[64];
        int tok_idx = 0;
        char *saveptr = nullptr;
        char *token = strtok_r(line, " ", &saveptr);
        while (token && tok_idx < 64) {
            tokens[tok_idx++] = token;
            token = strtok_r(nullptr, " ", &saveptr);
        }

        for (int i = 6; i < tok_idx; ++i) {
            if (strstr(tokens[i], "shared:")) {
                std::string original = tokens[i];
                if (!shared_map.count(original)) {
                    shared_map[original] = fake_id++;
                }
                snprintf(tokens[i], strlen(tokens[i]) + 1, "shared:%d", shared_map[original]);
            }

            if (strstr(tokens[i], "master:")) {
                std::string original = tokens[i];
                if (!master_map.count(original)) {
                    master_map[original] = fake_id++;
                }
                snprintf(tokens[i], strlen(tokens[i]) + 1, "master:%d", master_map[original]);
            }
        }

        for (int i = 0; i < tok_idx; ++i) {
            total += snprintf(result + total, 65536 - total, "%s%s", tokens[i], (i + 1 == tok_idx) ? "\n" : " ");
        }
    }

    free(line);
    fclose(f);

    *out_data = result;
    *out_len = total;

    LOGI("Generated spoofed mountinfo total size: %zu bytes", total);
    return true;
}

void install_mountinfo_hook(zygisk::Api *api, const char *process_name) {
    LOGI("[zygisk] Installing hook for process: %s", process_name);

    char *data = nullptr;
    size_t data_len = 0;
    if (!generate_spoofed_mountinfo_content(&data, &data_len)) {
        LOGE("[zygisk] Failed to generate spoofed mountinfo");
        return;
    }

    int memfd = syscall(SYS_memfd_create, "mountinfo_memfd", MFD_CLOEXEC);
    if (memfd < 0) {
        LOGE("[zygisk] memfd_create failed: %s", strerror(errno));
        free(data);
        return;
    }

    if (write(memfd, data, data_len) != (ssize_t)data_len) {
        LOGE("[zygisk] Failed to write spoofed mountinfo to memfd");
        close(memfd);
        free(data);
        return;
    }

    lseek(memfd, 0, SEEK_SET);

    free(data);

    char memfd_path[64];
    snprintf(memfd_path, sizeof(memfd_path), "/proc/self/fd/%d", memfd);
    int res = mount(memfd_path, "/proc/self/mountinfo", nullptr, MS_BIND, nullptr);

    if (res == 0) {
        LOGI("[zygisk] Successfully bind-mounted memfd -> /proc/self/mountinfo");
    } else {
        LOGE("[zygisk] Failed to bind mount memfd to /proc/self/mountinfo: %s", strerror(errno));
    }

    close(memfd);
}
