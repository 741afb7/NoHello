#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <android/log.h>
#include <sys/mount.h>

#include "zygisk.hpp"
#include "log.h"

using zygisk::Api;

static void perform_bind_mount_spoof(const char *processName) {
    LOGI("[bind_mount] Attempting bind-mount spoof for process: %s", processName);

    const char *fake_path = "/data/adb/modules/zygisk_nohello/fake_mountinfo";

    if (access(fake_path, F_OK) != 0) {
        LOGE("[bind_mount] Spoof file does not exist: %s", fake_path);
        return;
    }

    int res = mount(fake_path, "/proc/self/mountinfo", nullptr, MS_BIND, nullptr);
    if (res == 0) {
        LOGI("[bind_mount] Successfully bind-mounted %s -> /proc/self/mountinfo", fake_path);
    } else {
        LOGE("[bind_mount] Failed to bind mount: %s -> /proc/self/mountinfo (%s)", fake_path, strerror(errno));
    }
}

void install_mountinfo_hook(Api *api, const char *processName) {
    LOGD("[zygisk] install_mountinfo_hook for process: %s", processName);
    perform_bind_mount_spoof(processName);
    LOGD("[zygisk] mountinfo bind spoof complete");
}
