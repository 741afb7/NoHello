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

static void perform_bind_mount_spoof(const char *processName) {
    LOGI("[bind_mount] Attempting bind-mount spoof for process: %s", processName);
    const char *fake_path = "/data/adb/nohello/fake_mountinfo";
    const char *target_path = "/proc/self/mountinfo";

    if (access(fake_path, F_OK) != 0) {
        LOGW("[bind_mount] Fake mountinfo not found: %s", fake_path);
        return;
    }

    int res = mount(fake_path, target_path, nullptr, MS_BIND, nullptr);
    if (res == 0) {
        LOGI("[bind_mount] Successfully bind-mounted %s -> %s", fake_path, target_path);
    } else {
        LOGE("[bind_mount] Failed to bind mount: %s -> %s (%s)", fake_path, target_path, strerror(errno));
    }
}

void install_mountinfo_hook(Api *api, const char *processName) {
    LOGD("[bind_mount] Attempting to perform mountinfo bind mount spoof...");
    perform_bind_mount_spoof(processName);
    LOGD("[hook] mountinfo hooks installed (plus bind mount spoof attempt)");
}
