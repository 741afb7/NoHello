#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <android/log.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dlfcn.h>
#include <sys/mount.h>
#include <unordered_map>
#include <string>

#include "zygisk.hpp"
#include "log.h"

using zygisk::Api;

// 构造动态伪造的 mountinfo 内容
bool generate_spoofed_mountinfo_content(char **out_data, size_t *out_len) {
    FILE *f = fopen("/proc/self/mountinfo", "r");
    if (!f) {
        LOGE("[bind_mount] Unable to open /proc/self/mountinfo: %s", strerror(errno));
        return false;
    }

    char *line = nullptr;
    size_t len = 0;
    size_t total = 0;
    char *result = (char *)malloc(65536);
    if (!result) {
        fclose(f);
        LOGE("[bind_mount] Memory allocation failed");
        return false;
    }

    int fake_shared_id = 1;
    std::unordered_map<std::string, int> shared_map;

    while (getline(&line, &len, f) != -1) {
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
                    shared_map[original] = fake_shared_id++;
                }
                snprintf(tokens[i], strlen(tokens[i]) + 1, "shared:%d", shared_map[original]);
            }
        }

        for (int i = 0; i < tok_idx; ++i) {
            if (tokens[i][0] != '\0') {
                total += snprintf(result + total, 65536 - total, "%s%s", tokens[i], (i + 1 == tok_idx) ? "\n" : " ");
            }
        }
    }

    free(line);
    fclose(f);
    *out_data = result;
    *out_len = total;
    return true;
}

static void perform_bind_mount_spoof(const char *processName) {
    LOGI("[bind_mount] Attempting bind-mount spoof for process: %s", processName);

    const char *fake_path = "/data/adb/modules/zygisk_nohello/fake_mountinfo";
    char *spoofed_data = nullptr;
    size_t spoofed_len = 0;

    if (!generate_spoofed_mountinfo_content(&spoofed_data, &spoofed_len)) {
        LOGE("[bind_mount] Failed to generate spoofed mountinfo content");
        return;
    }

    FILE *fake_file = fopen(fake_path, "w");
    if (fake_file) {
        fwrite(spoofed_data, 1, spoofed_len, fake_file);
        fclose(fake_file);
        LOGI("[bind_mount] Wrote generated spoofed mountinfo to %s", fake_path);
    } else {
        LOGE("[bind_mount] Failed to write spoofed mountinfo to file: %s", strerror(errno));
        free(spoofed_data);
        return;
    }

    int res = mount(fake_path, "/proc/self/mountinfo", nullptr, MS_BIND, nullptr);
    if (res == 0) {
        LOGI("[bind_mount] Successfully bind-mounted %s -> /proc/self/mountinfo", fake_path);
    } else {
        LOGE("[bind_mount] Failed to bind mount: %s -> /proc/self/mountinfo (%s)", fake_path, strerror(errno));
    }

    free(spoofed_data);
}

void install_mountinfo_hook(Api *api, const char *processName) {
    LOGD("[zygisk] install_mountinfo_hook for process: %s", processName);
    perform_bind_mount_spoof(processName);
    LOGD("[zygisk] mountinfo bind spoof complete");
}
