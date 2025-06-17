#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <string>
#include <cstring>
#include <dlfcn.h>
#include <android/log.h>
#include <stdint.h>
#include <cstdio>
#include <cstdarg>
#include <pthread.h>
#include <sys/mman.h>

#define LOG_TAG "NoHello"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

static const char *spoofed_mountinfo = 
    "21 32 0:1 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw\n"
    "99 21 0:44 / /proc/self/mountinfo rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw\n";

typedef long (*syscall_t)(long number, ...);
static syscall_t original_syscall = nullptr;

void *find_syscall_address() {
    void *handle = dlopen("libc.so", RTLD_NOW);
    if (!handle) {
        LOGE("dlopen libc.so failed");
        return nullptr;
    }

    void *addr = dlsym(handle, "syscall");
    dlclose(handle);

    if (!addr) {
        LOGE("dlsym for syscall failed");
        return nullptr;
    }

    LOGI("Found syscall() address at %p", addr);
    return addr;
}

long hooked_syscall(long number, ...) {
    va_list args;
    va_start(args, number);

    if (number == __NR_openat) {
        int dirfd = va_arg(args, int);
        const char *pathname = va_arg(args, const char *);
        int flags = va_arg(args, int);
        mode_t mode = va_arg(args, int); 

        if (pathname && strstr(pathname, "/proc/self/mountinfo")) {
            LOGI("Intercepted syscall(SYS_openat) for %s", pathname);

            int fd = syscall(__NR_memfd_create, "fake_mountinfo", MFD_CLOEXEC);
            if (fd >= 0) {
                write(fd, spoofed_mountinfo, strlen(spoofed_mountinfo));
                lseek(fd, 0, SEEK_SET);
                LOGI("Returned fake memfd for mountinfo");
                va_end(args);
                return fd;
            } else {
                LOGW("memfd_create failed, fallback to real openat");
            }
        }

        long result = original_syscall(number, dirfd, pathname, flags, mode);
        va_end(args);
        return result;
    }

    long result;
    if (original_syscall) {
        long arg1 = va_arg(args, long);
        long arg2 = va_arg(args, long);
        long arg3 = va_arg(args, long);
        long arg4 = va_arg(args, long);
        long arg5 = va_arg(args, long);
        long arg6 = va_arg(args, long);

        result = original_syscall(number, arg1, arg2, arg3, arg4, arg5, arg6);
    } else {
        result = -1;
    }

    va_end(args);
    return result;
}

bool inline_hook_syscall() {
    void *syscall_addr = find_syscall_address();
    if (!syscall_addr) return false;

    original_syscall = (syscall_t)malloc(32);
    if (!original_syscall) return false;

    memcpy(original_syscall, syscall_addr, 16);
    __builtin___clear_cache((char *)original_syscall, (char *)original_syscall + 16);

    uintptr_t page_start = (uintptr_t)syscall_addr & ~(getpagesize() - 1);
    if (mprotect((void *)page_start, getpagesize(), PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        LOGE("mprotect failed to unprotect syscall stub: %s", strerror(errno));
        return false;
    }

    uint32_t hook_stub[] = {
        0x58000050,  // ldr x16, #8
        0xd61f0200,  // br x16
    };
    memcpy(syscall_addr, hook_stub, sizeof(hook_stub));
    memcpy((char *)syscall_addr + sizeof(hook_stub), &hooked_syscall, sizeof(void *));
    __builtin___clear_cache((char *)syscall_addr, (char *)syscall_addr + 32);

    LOGI("syscall inline hook installed");
    return true;
}

void install_mountinfo_hook(zygisks::Api *api, const char *process_name) {
    LOGI("Installing syscall inline hook for %s", process_name);
    if (inline_hook_syscall()) {
        LOGI("Syscall hook installed successfully");
    } else {
        LOGE("Syscall hook failed to install");
    }
}
