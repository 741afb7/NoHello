#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <android/log.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <dirent.h>

#include <unordered_map>
#include <string>
#include <fstream>

#include "zygisk.hpp"
#include "log.h"

using zygisk::Api;

#define TAG "memfd"
#define MAX_BUF 65536

static int memfd_create(const char *name, unsigned int flags) {
    return syscall(SYS_memfd_create, name, flags);
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
    char *result = (char *)malloc(MAX_BUF);
    if (!result) {
        fclose(f);
        LOGE("Memory allocation failed");
        return false;
    }

    int fake_id = 1;
    std::unordered_map<std::string, int> shared_map;

    while (getline(&line, &len, f) != -1) {
        LOGD("Original line: %s", line);

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
            total += snprintf(result + total, MAX_BUF - total, "%s%s", tokens[i], (i + 1 == tok_idx) ? "\n" : " ");
        }
    }

    free(line);
    fclose(f);
    *out_data = result;
    *out_len = total;
    LOGI("Generated spoofed mountinfo total size: %zu bytes", total);
    return true;
}

bool stat_path(const char *path, struct stat *st) {
    if (stat(path, st) == 0) {
        LOGD("Path exists, mode: %o", st->st_mode);
        return true;
    } else {
        LOGE("Stat failed on %s: %s", path, strerror(errno));
        return false;
    }
}

void perform_memfd_bind_mount_spoof(const char *processName) {
    char *data = nullptr;
    size_t datalen = 0;

    if (!generate_spoofed_mountinfo_content(&data, &datalen)) {
        LOGE("Failed to generate spoofed content");
        return;
    }

    int memfd = memfd_create("mountinfo_memfd", 0);
    if (memfd < 0) {
        LOGE("memfd_create failed: %s", strerror(errno));
        free(data);
        return;
    }

    if (write(memfd, data, datalen) != (ssize_t)datalen) {
        LOGE("write to memfd failed");
        close(memfd);
        free(data);
        return;
    }

    free(data);
    LOGI("Written %zu bytes to memfd", datalen);

    char memfd_path[64];
    snprintf(memfd_path, sizeof(memfd_path), "/proc/self/fd/%d", memfd);
    LOGD("memfd path: %s", memfd_path);

    struct stat st_memfd, st_target;
    if (!stat_path(memfd_path, &st_memfd)) {
        close(memfd);
        return;
    }
    if (!stat_path("/proc/self/mountinfo", &st_target)) {
        close(memfd);
        return;
    }

    LOGD("Attempting to bind mount memfd to /proc/self/mountinfo");
    if (mount(memfd_path, "/proc/self/mountinfo", nullptr, MS_BIND, nullptr) == 0) {
        LOGI("Successfully bind-mounted memfd -> /proc/self/mountinfo");
    } else {
        LOGE("Failed to bind mount: %s", strerror(errno));
    }

    close(memfd);
}

void signal_handler(int sig, siginfo_t *info, void *ctx) {
    LOGE("Caught signal %d (%s), fault addr: %p", sig, strsignal(sig), info->si_addr);
    _exit(128 + sig);
}

void install_signal_handler() {
    struct sigaction sa = {};
    sa.sa_sigaction = signal_handler;
    sa.sa_flags = SA_SIGINFO | SA_RESETHAND;
    sigaction(SIGSEGV, &sa, nullptr);
    sigaction(SIGABRT, &sa, nullptr);
}

std::pair<dev_t, ino_t> devinobymap(const char *libname) {
    std::ifstream maps("/proc/self/maps");
    std::string line;
    while (std::getline(maps, line)) {
        if (line.find(libname) != std::string::npos) {
            std::string path = line.substr(line.find("/") != std::string::npos ? line.find("/") : 0);
            struct stat st{};
            if (stat(path.c_str(), &st) == 0) {
                return {st.st_dev, st.st_ino};
            }
        }
    }
    return {0, 0};
}

void install_mountinfo_hook(Api *api, const char *processName) {
    install_signal_handler();
    LOGD("install_mountinfo_hook for process: %s", processName);
    perform_memfd_bind_mount_spoof(processName);
    LOGD("mountinfo spoof via memfd complete");
}
