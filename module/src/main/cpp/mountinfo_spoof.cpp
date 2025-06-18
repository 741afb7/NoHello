#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <android/log.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <stdint.h>
#include <stdarg.h>
#include <sys/syscall.h>
#include <dlfcn.h>
#include <unordered_map>
#include <string>

#define TAG "NoHello"
#include "log.h"

static bool syscall_hook_installed = false;
static unsigned char original_syscall_code[16];
static char *spoofed_mountinfo = nullptr;
static size_t spoofed_size = 0;

bool generate_spoofed_mountinfo_content() {
    FILE *fp = fopen("/proc/self/mountinfo", "r");
    if (!fp) {
        LOGE("Failed to open /proc/self/mountinfo");
        return false;
    }

    std::unordered_map<std::string, int> master_map;
    int fake_id = 1;
    char *result = (char *)malloc(65536);
    if (!result) return false;
    size_t total = 0;

    char *line = nullptr;
    size_t len = 0;
    while (getline(&line, &len, fp) != -1) {
        char *tokens[64];
        int tok_idx = 0;
        char *saveptr = nullptr;
        char *token = strtok_r(line, " ", &saveptr);
        while (token && tok_idx < 64) {
            tokens[tok_idx++] = token;
            token = strtok_r(nullptr, " ", &saveptr);
        }

        for (int i = 0; i < tok_idx; ++i) {
            if (strstr(tokens[i], "master:")) {
                std::string orig = tokens[i];
                if (!master_map.count(orig)) {
                    master_map[orig] = fake_id++;
                }
                snprintf(tokens[i], strlen(tokens[i]) + 1, "master:%d", master_map[orig]);
            }
        }

        for (int i = 0; i < tok_idx; ++i) {
            total += snprintf(result + total, 65536 - total, "%s%s", tokens[i], (i + 1 == tok_idx) ? "\n" : " ");
        }
    }

    free(line);
    fclose(fp);

    spoofed_mountinfo = result;
    spoofed_size = total;
    LOGI("Generated spoofed mountinfo total size: %zu bytes", spoofed_size);
    return true;
}

extern "C" long hooked_syscall(long number, ...) {
    if (number == SYS_readlinkat) {
        va_list args;
        va_start(args, number);
        const char *path = va_arg(args, const char *);
        char *buf = va_arg(args, char *);
        size_t size = va_arg(args, size_t);
        va_end(args);

        if (path && strstr(path, "mountinfo")) {
            LOGI("[hook] Intercepted readlink: %s", path);
            return -1; // 可选行为
        }
    }

    if (number == SYS_openat || number == SYS_newfstatat || number == SYS_read || number == SYS_readlinkat) {
    }

    void *syscall_addr = reinterpret_cast<void *>(__builtin_return_address(0));
    memcpy(syscall_addr, original_syscall_code, sizeof(original_syscall_code));
    return syscall(number);
}

void install_syscall_hook(const char *process_name) {
    if (syscall_hook_installed) {
        LOGW("[zygisk] syscall hook already installed");
        return;
    }

    if (!generate_spoofed_mountinfo_content()) {
        LOGE("[zygisk] Failed to spoof mountinfo content");
        return;
    }

    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) {
        LOGE("[zygisk] Failed to open maps");
        return;
    }

    uintptr_t base_addr = 0;
    char line[512], path[256];
    while (fgets(line, sizeof(line), maps)) {
        if (strstr(line, "libc.so")) {
            sscanf(line, "%lx-%*lx %*s %*s %*s %*s %255s", &base_addr, path);
            break;
        }
    }
    fclose(maps);

    if (!base_addr) {
        LOGW("[zygisk] Failed to resolve libc.so base address");
        return;
    }
    LOGI("[zygisk] Found libc.so mapped at: 0x%lx (%s)", base_addr, path);

    void *syscall_addr = dlsym(RTLD_DEFAULT, "syscall");
    if (!syscall_addr) {
        LOGE("[zygisk] Failed to locate syscall address");
        return;
    }

    uintptr_t page = reinterpret_cast<uintptr_t>(syscall_addr) & ~(getpagesize() - 1);
    if (mprotect((void *)page, getpagesize(), PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        LOGE("[zygisk] mprotect failed");
        return;
    }

    memcpy(original_syscall_code, syscall_addr, sizeof(original_syscall_code));
    void *target = (void *)syscall_addr;
    void *hook_func = (void *)hooked_syscall;

    unsigned char jump_code[16];
    uintptr_t offset = (uintptr_t)hook_func;
    jump_code[0] = 0x48;
    jump_code[1] = 0xb8;
    memcpy(&jump_code[2], &offset, sizeof(void *));
    jump_code[10] = 0xff;
    jump_code[11] = 0xe0;

    memcpy(target, jump_code, 12);
    __builtin___clear_cache((char *)target, (char *)target + 12);

    syscall_hook_installed = true;
    LOGI("[zygisk] syscall hook installed into target libc");
}
