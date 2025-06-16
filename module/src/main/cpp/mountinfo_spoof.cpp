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
#include <sys/mount.h>
#include <errno.h> 

#include "zygisk.hpp"
#include "log.h"

using zygisk::Api;

void perform_bind_mount_spoof(const char *processName) {
    LOGI("[bind_mount] Attempting bind-mount spoof for process: %s", processName);

    FILE *f = fopen("/proc/self/mountinfo", "r");
    if (!f) {
        LOGE("[bind_mount] Failed to open /proc/self/mountinfo: %s", strerror(errno));
        return;
    }

    char *line = nullptr;
    size_t len = 0;
    size_t total = 0;
    char *result = (char *)malloc(65536); 
    if (!result) {
        fclose(f);
        LOGE("[bind_mount] Failed to allocate memory for spoofed mountinfo");
        return;
    }

    int fake_id = 1; 
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
                snprintf(tokens[i], strlen(tokens[i]) + 1, "shared:%d", fake_id++);
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

    if (total > 0) {
        FILE *fake_file = fopen("/data/adb/nohello/fake_mountinfo", "w");
        if (fake_file) {
            fwrite(result, 1, total, fake_file);
            fclose(fake_file);
            LOGI("[bind_mount] Fake mountinfo successfully written to /data/adb/nohello/fake_mountinfo");
        } else {
            LOGE("[bind_mount] Failed to write spoofed mountinfo to file");
        }
    } else {
        LOGE("[bind_mount] No valid mountinfo data found to spoof");
    }

    int res = mount("/data/adb/nohello/fake_mountinfo", "/proc/self/mountinfo", nullptr, MS_BIND, nullptr);
    if (res == 0) {
        LOGI("[bind_mount] Successfully bind-mounted /data/adb/nohello/fake_mountinfo to /proc/self/mountinfo");
    } else {
        LOGE("[bind_mount] Failed to bind mount: %s -> %s (%s)", "/data/adb/nohello/fake_mountinfo", "/proc/self/mountinfo", strerror(errno));
    }

    free(result);
}

void install_mountinfo_hook(Api *api, const char *processName) {
    LOGD("[bind_mount] Attempting to perform mountinfo bind mount spoof...");
    perform_bind_mount_spoof(processName);
    LOGD("[hook] mountinfo hooks installed (plus bind mount spoof attempt)");
}
