#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <android/log.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stdarg.h>
#include <sys/syscall.h>
#include <dlfcn.h>
#include <unordered_map>
#include <string>
#include <vector>
#include <jni.h>
#include <errno.h>

#define TAG "NoHello"
#include "log.h"

#ifndef SYS_readlinkat
#define SYS_readlinkat 78
#endif

#ifndef SYS_newfstatat
#define SYS_newfstatat 79
#endif

static void *original_syscall = nullptr;
static std::string spoofed_mountinfo;
static bool mountinfo_access_detected = false;

static bool generate_spoofed_mountinfo_content(std::string &out) {
    FILE *fp = fopen("/proc/self/mountinfo", "r");
    if (!fp) {
        LOGE("Failed to open mountinfo: %s", strerror(errno));
        return false;
    }

    char *line = nullptr;
    size_t len = 0;
    std::vector<std::string> lines;
    while (getline(&line, &len, fp) != -1) {
        std::string s(line);
        // 可在此处对 master 字段做伪装（比如统一替换为 master:1）
        size_t pos = s.find(" master:");
        if (pos != std::string::npos) {
            size_t end = s.find(' ', pos + 1);
            if (end != std::string::npos) {
                s.replace(pos, end - pos, " master:999");
            }
        }
        lines.emplace_back(std::move(s));
    }
    free(line);
    fclose(fp);

    for (auto &l : lines)
        out += l;

    LOGI("Generated spoofed mountinfo total size: %zu bytes", out.size());
    return true;
}

extern "C" long hooked_syscall(long number, ...) {
    va_list args;
    va_start(args, number);

    if (number == SYS_readlinkat) {
        int dirfd = va_arg(args, int);
        const char *path = va_arg(args, const char *);
        char *buf = va_arg(args, char *);
        size_t bufsiz = va_arg(args, size_t);

        va_end(args);

        if (path && strstr(path, "mountinfo")) {
            mountinfo_access_detected = true;
            LOGI("[hook] Intercepted readlinkat: %s", path);
            const char *fake = "/proc/self/fake_mountinfo";
            strncpy(buf, fake, bufsiz);
            return strlen(fake);
        }
    }

    if (number == SYS_openat) {
        int dirfd = va_arg(args, int);
        const char *pathname = va_arg(args, const char *);
        int flags = va_arg(args, int);
        va_end(args);

        if (pathname && strstr(pathname, "mountinfo")) {
            mountinfo_access_detected = true;
            LOGI("[hook] Intercepted openat: %s", pathname);
            int pipefd[2];
            if (pipe(pipefd) == 0) {
                write(pipefd[1], spoofed_mountinfo.data(), spoofed_mountinfo.size());
                close(pipefd[1]);
                return pipefd[0];
            }
        }
    }

    if (number == SYS_read) {
        int fd = va_arg(args, int);
        void *buf = va_arg(args, void *);
        size_t count = va_arg(args, size_t);
        va_end(args);

        ssize_t r = ((decltype(&syscall))original_syscall)(SYS_read, fd, buf, count);
        return r;
    }

    if (number == SYS_newfstatat) {
        int dirfd = va_arg(args, int);
        const char *pathname = va_arg(args, const char *);
        struct stat *statbuf = va_arg(args, struct stat *);
        int flags = va_arg(args, int);
        va_end(args);

        if (pathname && strstr(pathname, "mountinfo")) {
            mountinfo_access_detected = true;
            LOGI("[hook] Intercepted newfstatat: %s", pathname);
            // 伪造一个正常文件属性
            memset(statbuf, 0, sizeof(struct stat));
            statbuf->st_mode = S_IFREG | 0444;
            statbuf->st_size = spoofed_mountinfo.size();
            return 0;
        }
    }

    va_end(args);
    return ((decltype(&syscall))original_syscall)(number);
}

void install_syscall_hook(const char *processName) {
    if (!generate_spoofed_mountinfo_content(spoofed_mountinfo)) {
        LOGE("Failed to generate spoofed mountinfo");
        return;
    }

    void *syscall_addr = dlsym(RTLD_DEFAULT, "syscall");
    if (!syscall_addr) {
        LOGE("Failed to resolve syscall address");
        return;
    }

    original_syscall = syscall_addr;

    uintptr_t page = (uintptr_t)syscall_addr & ~(getpagesize() - 1);
    if (mprotect((void *)page, getpagesize(), PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        LOGE("mprotect failed");
        return;
    }

    void *target = (void *)&hooked_syscall;
    memcpy(syscall_addr, &target, sizeof(void *));
    LOGI("syscall hook installed into target libc");

    LOGI("syscall hook installed into target libc");

    if (!mountinfo_access_detected) {
        LOGW("[zygisk] ⚠ no mountinfo access detected yet");
    }
}
