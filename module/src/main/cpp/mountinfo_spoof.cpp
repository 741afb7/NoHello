#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <dlfcn.h>
#include <android/log.h>
#include <utility> 

#include "zygisk.hpp"
#include "log.h"

static long (*orig_syscall)(long, ...) = nullptr;

static bool is_system_libc(const char *path) {
    return strstr(path, "/system/") || strstr(path, "/apex/");
}

std::pair<dev_t, ino_t> devinobymap(const char *libname) {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return std::make_pair(0, 0);

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        if (!strstr(line, libname)) continue;

        char path[256];
        unsigned long start;
        if (sscanf(line, "%lx-%*lx %*s %*s %*s %*s %255s", &start, path) == 2) {
            if (is_system_libc(path)) continue;

            struct stat st;
            if (stat(path, &st) == 0) {
                fclose(fp);
                return {st.st_dev, st.st_ino};
            }
        }
    }
    fclose(fp);
    return {0, 0};
}

static long hooked_syscall(long number, ...) {
    va_list args;
    va_start(args, number);

    if (number == __NR_openat) {
        int dirfd = va_arg(args, int);
        const char *pathname = va_arg(args, const char *);
        int flags = va_arg(args, int);

        if (pathname && strcmp(pathname, "/proc/self/mountinfo") == 0) {
            LOGI("[hook] intercepted openat on /proc/self/mountinfo, returning fake FD");
            errno = ENOENT;
            return -1;
        }

        va_end(args);
        va_start(args, number);
    }

    long ret = orig_syscall(number, args);
    va_end(args);
    return ret;
}

void install_mountinfo_hook(zygisk::Api *api, const char *process_name) {
    auto [target_dev, target_ino] = devinobymap("libc.so");
    if (!target_dev || !target_ino) {
        LOGW("Unable to resolve valid dev/inode for libc.so in app process.");
        return;
    }

    LOGD("Resolved libc.so in app process: dev=%lu ino=%lu", (unsigned long)target_dev, (unsigned long)target_ino);

    DIR *dir = opendir("/proc/self/map_files");
    if (!dir) {
        LOGE("Failed to open /proc/self/map_files");
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_type != DT_LNK) continue;

        char fullpath[512];
        snprintf(fullpath, sizeof(fullpath), "/proc/self/map_files/%s", entry->d_name);

        char linkpath[512];
        ssize_t len = readlink(fullpath, linkpath, sizeof(linkpath) - 1);
        if (len <= 0) continue;
        linkpath[len] = '\0';

        struct stat st;
        if (stat(linkpath, &st) != 0) continue;

        if (st.st_dev == target_dev && st.st_ino == target_ino) {
            LOGD("Identified target libc.so map: %s", fullpath);

            unsigned long start_addr;
            if (sscanf(entry->d_name, "%lx-", &start_addr) != 1) continue;

            void *addr = (void *)start_addr;
            if (mprotect(addr, 4096, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
                LOGE("mprotect failed: %s", strerror(errno));
                continue;
            }

            orig_syscall = (long (*)(long, ...))addr;

            uint8_t jump_code[] = {
                0x48, 0xB8,                          // mov rax, <addr>
                0, 0, 0, 0, 0, 0, 0, 0,              // <hook addr>
                0xFF, 0xE0                           // jmp rax
            };
            void *hook_fn = (void *)hooked_syscall;
            memcpy(jump_code + 2, &hook_fn, sizeof(void *));
            memcpy(addr, jump_code, sizeof(jump_code));

            LOGI("Successfully hooked syscall at %p", addr);
            break;
        }
    }

    closedir(dir);
}
