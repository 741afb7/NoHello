#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <android/log.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unordered_map>
#include <string>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <stdint.h>
#include <utility> 
#include <dlfcn.h>

#define LOG_TAG "NoHello"
#include "log.h"
#include "zygisk.hpp"

static int spoof_mountinfo_fd = -1;
static long (*original_syscall)(long, ...) = nullptr;

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

long hooked_syscall(long number, ...) {
    va_list args;
    va_start(args, number);

    if (number == SYS_openat) {
        int dirfd = va_arg(args, int);
        const char *pathname = va_arg(args, const char *);
        int flags = va_arg(args, int);
        mode_t mode = va_arg(args, int);

        if (pathname && strcmp(pathname, "/proc/self/mountinfo") == 0) {
            LOGI("Intercepted openat(\"/proc/self/mountinfo\")");
            if (spoof_mountinfo_fd >= 0) {
                int dupfd = dup(spoof_mountinfo_fd);
                va_end(args);
                return dupfd;
            }
        }

        long ret = syscall(number, dirfd, pathname, flags, mode);
        va_end(args);
        return ret;
    }

    long ret;
    if (original_syscall) {
        long arg1 = va_arg(args, long);
        long arg2 = va_arg(args, long);
        long arg3 = va_arg(args, long);
        long arg4 = va_arg(args, long);
        long arg5 = va_arg(args, long);
        long arg6 = va_arg(args, long);
        ret = original_syscall(number, arg1, arg2, arg3, arg4, arg5, arg6);
    } else {
        ret = syscall(number);
    }

    va_end(args);
    return ret;
}

bool install_syscall_hook() {
    void *handle = dlopen("libc.so", RTLD_NOW);
    if (!handle) {
        LOGE("dlopen libc.so failed");
        return false;
    }

    void *syscall_addr = dlsym(handle, "syscall");
    dlclose(handle);

    if (!syscall_addr) {
        LOGE("dlsym syscall failed");
        return false;
    }

    original_syscall = (long (*)(long, ...))malloc(16);
    memcpy(original_syscall, syscall_addr, 16);

    uintptr_t page_start = (uintptr_t)syscall_addr & ~(getpagesize() - 1);
    if (mprotect((void *)page_start, getpagesize(), PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        LOGE("mprotect failed");
        return false;
    }

    uint32_t stub[] = {
        0x58000050,  // ldr x16, #8
        0xd61f0200,  // br x16
    };
    void *hook_func = (void *)hooked_syscall;
    memcpy(syscall_addr, stub, sizeof(stub));
    memcpy((char *)syscall_addr + sizeof(stub), &hook_func, sizeof(void *));
    __builtin___clear_cache((char *)syscall_addr, (char *)syscall_addr + 32);

    LOGI("syscall hook installed");
    return true;
}

void install_mountinfo_hook(zygisk::Api *api, const char *process_name) {
    LOGI("[zygisk] Installing mountinfo spoof hook for: %s", process_name);

    if (spoof_mountinfo_fd >= 0) {
        close(spoof_mountinfo_fd);
        spoof_mountinfo_fd = -1;
    }

    char *data = nullptr;
    size_t len = 0;
    if (!generate_spoofed_mountinfo_content(&data, &len)) {
        return;
    }

    spoof_mountinfo_fd = syscall(SYS_memfd_create, "mountinfo_memfd", MFD_CLOEXEC);
    if (spoof_mountinfo_fd < 0) {
        LOGE("memfd_create failed: %s", strerror(errno));
        free(data);
        return;
    }

    if (write(spoof_mountinfo_fd, data, len) != (ssize_t)len) {
        LOGE("write memfd failed");
        close(spoof_mountinfo_fd);
        spoof_mountinfo_fd = -1;
        free(data);
        return;
    }

    lseek(spoof_mountinfo_fd, 0, SEEK_SET);
    free(data);

    install_syscall_hook();
}
