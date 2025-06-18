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
#include <sys/stat.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <stdarg.h>
#include <linux/memfd.h>

#define LOG_TAG "NoHello"
#include "log.h"
#include "zygisk.hpp"

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001
#endif

static int spoof_mountinfo_fd = -1;
static long (*original_syscall)(long, ...) = nullptr;

void *find_syscall_in_libc();

#include <unordered_map>
#include <string>

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

    int fake_master_id = 100;
    std::unordered_map<std::string, int> master_id_map;

    while (getline(&line, &len, f) != -1) {
        char *tokens[128];
        int tok_idx = 0;
        char *saveptr = nullptr;
        char *token = strtok_r(line, " ", &saveptr);
        while (token && tok_idx < 128) {
            tokens[tok_idx++] = token;
            token = strtok_r(nullptr, " ", &saveptr);
        }

        for (int i = 6; i < tok_idx; ++i) {
            if (strstr(tokens[i], "master:") == tokens[i]) {
                std::string original = tokens[i];
                if (!master_id_map.count(original)) {
                    master_id_map[original] = fake_master_id++;
                }
                snprintf(tokens[i], strlen(tokens[i]) + 1, "master:%d", master_id_map[original]);
            }
        }

        for (int i = 0; i < tok_idx; ++i) {
            total += snprintf(result + total, 65536 - total, "%s%s",
                              tokens[i], (i + 1 == tok_idx) ? "\n" : " ");
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
                LOGI("[hook] Returning spoof memfd: %d", dupfd);
                va_end(args);
                return dupfd;
            } else {
                errno = ENOENT;
                va_end(args);
                return -1;
            }
        }

        long ret = syscall(number, dirfd, pathname, flags, mode);
        va_end(args);
        return ret;
    }

    if (number == SYS_read) {
        int fd = va_arg(args, int);
        void *buf = va_arg(args, void *);
        size_t count = va_arg(args, size_t);
        long res = syscall(number, fd, buf, count);
        if (fd == spoof_mountinfo_fd) {
            LOGI("[hook] read(%d) on spoofed fd, got %ld bytes", fd, res);
        }
        va_end(args);
        return res;
    }

    if (number == SYS_readlink) {
        const char *path = va_arg(args, const char *);
        char *buf = va_arg(args, char *);
        size_t bufsiz = va_arg(args, size_t);

        if (path && strcmp(path, "/proc/self/ns/mnt") == 0) {
            LOGI("[hook] readlink(\"/proc/self/ns/mnt\") intercepted");
            const char *fake = "mnt:[4026531999]";
            size_t len = strlen(fake);
            if (bufsiz > len) {
                memcpy(buf, fake, len);
                buf[len] = '\0';
                va_end(args);
                return len;
            } else {
                errno = ENAMETOOLONG;
                va_end(args);
                return -1;
            }
        }

        long res = syscall(number, path, buf, bufsiz);
        va_end(args);
        return res;
    }

    if (number == SYS_newfstatat) {
        int dirfd = va_arg(args, int);
        const char *path = va_arg(args, const char *);
        struct stat *st = va_arg(args, struct stat *);
        int flags = va_arg(args, int);

        if (path && strcmp(path, "/proc/self/ns/mnt") == 0) {
            LOGI("[hook] stat(\"/proc/self/ns/mnt\") intercepted");
            long res = syscall(number, dirfd, path, st, flags);
            if (res == 0 && st) {
                LOGI("[hook] original st_ino: %lu", (unsigned long)st->st_ino);
                st->st_ino = 4026531999;
            }
            va_end(args);
            return res;
        }

        long res = syscall(number, dirfd, path, st, flags);
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
    if (!fp) return nullptr;

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
    if (!base_addr) return nullptr;

    void *local_syscall = dlsym(RTLD_NEXT, "syscall");
    if (!local_syscall) return nullptr;

    Dl_info info;
    if (!dladdr(local_syscall, &info)) return nullptr;

    uintptr_t offset = (uintptr_t)local_syscall - (uintptr_t)info.dli_fbase;
    return (void *)(base_addr + offset);
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

    LOGI("syscall hook installed into target libc");
    return true;
}

void install_mountinfo_hook(const char *process_name) {
    LOGI("[zygisk] Installing spoof hook for: %s", process_name);

    if (spoof_mountinfo_fd >= 0) close(spoof_mountinfo_fd);

    char *data = nullptr;
    size_t len = 0;
    if (!generate_spoofed_mountinfo_content(&data, &len)) {
        LOGE("Failed to generate spoofed content");
        return;
    }

    spoof_mountinfo_fd = syscall(SYS_memfd_create, "mountinfo", MFD_CLOEXEC);
    if (spoof_mountinfo_fd < 0) {
        LOGE("memfd_create failed");
        free(data);
        return;
    }

    fchmod(spoof_mountinfo_fd, 0444);
    if (write(spoof_mountinfo_fd, data, len) != (ssize_t)len) {
        LOGE("write to memfd failed");
        close(spoof_mountinfo_fd);
        spoof_mountinfo_fd = -1;
        free(data);
        return;
    }

    lseek(spoof_mountinfo_fd, 0, SEEK_SET);
    free(data);

    install_syscall_hook();
}
