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
            LOGI("[hook] openat(\"%s\") intercepted", pathname);

            if (spoof_mountinfo_fd >= 0) {
                int dupfd = dup(spoof_mountinfo_fd);
                LOGI("[hook] Returning duped spoof memfd: %d", dupfd);
                va_end(args);
                return dupfd;
            } else {
                LOGW("[hook] spoof_mountinfo_fd is invalid");
                errno = ENOENT;
                va_end(args);
                return -1;
            }
        }

        // fallback
        long ret = syscall(number, dirfd, pathname, flags, mode);
        va_end(args);
        return ret;
    }

    // 拦截 read() 看是否读的是 spoof_mountinfo_fd
    if (number == SYS_read) {
        int fd = va_arg(args, int);
        void *buf = va_arg(args, void *);
        size_t count = va_arg(args, size_t);
        long res = syscall(number, fd, buf, count);

        if (fd == spoof_mountinfo_fd) {
            LOGI("[hook] read(%d) on spoofed mountinfo fd, read %ld bytes", fd, res);
        }

        va_end(args);
        return res;
    }

    if (original_syscall) {
        long a1 = va_arg(args, long);
        long a2 = va_arg(args, long);
        long a3 = va_arg(args, long);
        long a4 = va_arg(args, long);
        long a5 = va_arg(args, long);
        long a6 = va_arg(args, long);
        long ret = original_syscall(number, a1, a2, a3, a4, a5, a6);
        va_end(args);
        return ret;
    }

    va_end(args);
    return syscall(number);
}

void *find_syscall_in_libc() {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        LOGE("Failed to open /proc/self/maps");
        return nullptr;
    }

    uintptr_t base_addr = 0;
    char line[512], libc_path[256] = {};
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "r-xp") && strstr(line, "libc.so")) {
            sscanf(line, "%lx-%*lx %*s %*s %*s %*s %255s", &base_addr, libc_path);
            LOGI("Found libc.so mapped at: 0x%lx (%s)", base_addr, libc_path);
            break;
        }
    }
    fclose(fp);
    if (!base_addr) {
        LOGE("Failed to find base address of libc");
        return nullptr;
    }

    void *local_syscall = dlsym(RTLD_NEXT, "syscall");
    if (!local_syscall) {
        LOGE("dlsym syscall failed");
        return nullptr;
    }

    Dl_info info;
    if (!dladdr(local_syscall, &info)) {
        LOGE("dladdr failed");
        return nullptr;
    }

    uintptr_t local_base = (uintptr_t)info.dli_fbase;
    uintptr_t offset = (uintptr_t)local_syscall - local_base;

    void *real_syscall = (void *)(base_addr + offset);
    LOGI("Resolved syscall in app's libc.so at: %p", real_syscall);
    return real_syscall;
}

bool install_syscall_hook() {
    void *syscall_addr = find_syscall_in_libc();
    if (!syscall_addr) return false;

    void *trampoline = malloc(32);
    memcpy(trampoline, syscall_addr, 16);
    __builtin___clear_cache((char *)trampoline, (char *)trampoline + 32);
    original_syscall = (long (*)(long, ...))trampoline;

    uintptr_t page_start = (uintptr_t)syscall_addr & ~(getpagesize() - 1);
    if (mprotect((void *)page_start, getpagesize(), PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        LOGE("mprotect failed on syscall address");
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

    LOGI("syscall hook installed into target libc");
    return true;
}
