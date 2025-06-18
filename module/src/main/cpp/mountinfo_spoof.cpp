#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <cstring>
#include <android/log.h>

#define TAG "NoHello"
#include "log.h"
#include "zygisk.hpp"

// 检查是否有 fd 指向 /proc/self/mountinfo
void detect_mountinfo_preopen() {
    DIR *dir = opendir("/proc/self/fd");
    if (!dir) {
        LOGE("[verify] Failed to open /proc/self/fd");
        return;
    }

    struct dirent *entry;
    char path[PATH_MAX];
    char target[PATH_MAX];
    bool found = false;

    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_type != DT_LNK) continue;

        snprintf(path, sizeof(path), "/proc/self/fd/%s", entry->d_name);
        ssize_t len = readlink(path, target, sizeof(target) - 1);
        if (len < 0) continue;
        target[len] = '\0';

        if (strstr(target, "/mountinfo")) {
            LOGW("[verify] ⚠ mountinfo was already opened via FD %s -> %s", entry->d_name, target);
            found = true;
        }
    }

    closedir(dir);

    if (!found) {
        LOGI("[verify] ✅ No pre-access to mountinfo detected at this stage");
    }
}
