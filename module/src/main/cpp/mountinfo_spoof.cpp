#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <dlfcn.h>
#include <android/log.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unordered_map>
#include <string>
#include <sys/stat.h>

#include "zygisk.hpp"
#include "log.h"

using zygisk::Api;

static int memfd_create(const char *name, unsigned int flags) {
    return syscall(SYS_memfd_create, name, flags);
}

bool generate_spoofed_mountinfo_content(char **out_data, size_t *out_len) {
    FILE *f = fopen("/proc/self/mountinfo", "r");
    if (!f) {
        LOGE("[memfd] Failed to open mountinfo: %s", strerror(errno));
        return false;
    }

    char *line = nullptr;
    size_t len = 0;
    size_t total = 0;
    char *result = (char *)malloc(65536);
    if (!result) {
        fclose(f);
        LOGE("[memfd] Memory allocation failed");
        return false;
    }

    int fake_id = 1;
    std::unordered_map<std::string, int> shared_map;

    while (getline(&line, &len, f) != -1) {
        LOGD("[memfd] Original line: %s", line);

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
        }

        for (int i = 0; i < tok_idx; ++i) {
            total += snprintf(result + total, 65536 - total, "%s%s", tokens[i], (i + 1 == tok_idx) ? "\n" : " ");
        }
    }

    free(line);
    fclose(f);
    *out_data = result;
    *out_len = total;
    LOGI("[memfd] Generated spoofed mountinfo total size: %zu bytes", total);
    return true;
}

void print_maps() {
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) {
        LOGE("Failed to open /proc/self/maps");
        return;
    }

    char line[512];
    while (fgets(line, sizeof(line), maps)) {
        if (strstr(line, "libc.so")) {
            LOGD("[maps] %s", line);
        }
    }
    fclose(maps);
}

static void perform_memfd_bind_mount_spoof(const char *processName) {
    LOGI("[memfd] Performing in-memory spoof for process: %s", processName);

    print_maps(); 

    void* libc_handle = dlopen("libc.so", RTLD_NOW);
    if (!libc_handle) {
        LOGE("[memfd] Failed to dlopen libc.so: %s", dlerror());
        return;
    }
    LOGD("[memfd] libc.so handle = %p", libc_handle);

    void* openat_sym = dlsym(libc_handle, "openat");
    if (!openat_sym) {
        LOGE("[memfd] Failed to find openat: %s", dlerror());
    } else {
        LOGD("[memfd] openat addr = %p", openat_sym);
    }

    dlclose(libc_handle);

    char *data = nullptr;
    size_t datalen = 0;

    if (!generate_spoofed_mountinfo_content(&data, &datalen)) {
        LOGE("[memfd] Failed to generate spoofed content");
        return;
    }

    int memfd = memfd_create("mountinfo_memfd", 0);
    if (memfd < 0) {
        LOGE("[memfd] memfd_create failed: %s", strerror(errno));
        free(data);
        return;
    }
    LOGD("[memfd] memfd_create successful: fd=%d", memfd);

    if (write(memfd, data, datalen) != (ssize_t)datalen) {
        LOGE("[memfd] write to memfd failed");
        close(memfd);
        free(data);
        return;
    }

    LOGI("[memfd] Written %zu bytes to memfd", datalen);
    free(data);

    char memfd_path[64];
    snprintf(memfd_path, sizeof(memfd_path), "/proc/self/fd/%d", memfd);
    LOGD("[memfd] memfd path: %s", memfd_path);

    struct stat st_memfd, st_target;
    if (stat(memfd_path, &st_memfd) == 0) {
        LOGD("[memfd] Source file exists, mode: %o", st_memfd.st_mode);
    }
    if (stat("/proc/self/mountinfo", &st_target) == 0) {
        LOGD("[memfd] Target file exists, mode: %o", st_target.st_mode);
    }

    int res = mount(memfd_path, "/proc/self/mountinfo", nullptr, MS_BIND, nullptr);
    if (res == 0) {
        LOGI("[memfd] Successfully bind-mounted memfd -> /proc/self/mountinfo");
    } else {
        LOGE("[memfd] Failed to bind mount memfd: %s", strerror(errno));
    }

    close(memfd);
}

void install_mountinfo_hook(Api *api, const char *processName) {
    LOGD("[zygisk] install_mountinfo_hook for process: %s", processName);
    perform_memfd_bind_mount_spoof(processName);
    LOGD("[zygisk] mountinfo spoof via memfd complete");
}
