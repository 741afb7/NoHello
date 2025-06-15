#include <unistd.h>
#include <fcntl.h>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <sstream>
#include <mutex>
#include <cstring>
#include <sys/types.h>
#include <sys/stat.h>
#include <android/log.h>

#include "log.h"
#include "zygisk.hpp"
using zygisk::Api;

static ssize_t (*orig_read)(int fd, void *buf, size_t count) = nullptr;
static int (*orig_open)(const char *pathname, int flags, ...) = nullptr;
static int (*orig_close)(int fd) = nullptr;

static std::unordered_map<int, std::string> mountinfo_cache;
static std::unordered_set<int> hooked_fds;
static std::mutex cache_mutex;

bool is_mountinfo_path(const char *path) {
    return path && strstr(path, "/proc/") && strstr(path, "/mountinfo");
}

std::string get_column(const std::string &line, int index) {
    std::istringstream iss(line);
    std::string token;
    for (int i = 0; i <= index; ++i) {
        if (!(iss >> token)) return "";
    }
    return token;
}

std::string remap_mountinfo(const std::string &orig) {
    std::istringstream iss(orig);
    std::ostringstream oss;
    std::string line;
    int next_id = 1;
    std::unordered_map<std::string, int> id_map;

    while (std::getline(iss, line)) {
        std::string mount_id = get_column(line, 0);
        std::string group_id = get_column(line, 3);

        if (mount_id.empty() || group_id.empty()) continue;

        if (!id_map.count(mount_id)) id_map[mount_id] = next_id++;
        if (!id_map.count(group_id)) id_map[group_id] = next_id++;

        size_t first = line.find(' ');
        size_t second = line.find(' ', first + 1);
        size_t third = line.find(' ', second + 1);
        size_t fourth = line.find(' ', third + 1);

        if (first == std::string::npos || fourth == std::string::npos) continue;

        std::ostringstream replaced;
        replaced << id_map[mount_id] << " ";
        replaced << line.substr(first + 1, third - first - 1) << " ";
        replaced << id_map[group_id] << line.substr(fourth);
        oss << replaced.str() << "\n";
    }
    return oss.str();
}

ssize_t my_hooked_read(int fd, void *buf, size_t count) {
    static thread_local bool in_hook = false;
    if (in_hook || !orig_read) return orig_read ? orig_read(fd, buf, count) : -1;
    in_hook = true;

    ssize_t result = 0;
    {
        std::lock_guard<std::mutex> lock(cache_mutex);
        if (hooked_fds.count(fd)) {
            std::string &data = mountinfo_cache[fd];
            if (data.empty()) {
                result = 0;
            } else {
                size_t len = std::min(count, data.size());
                memcpy(buf, data.data(), len);
                data.erase(0, len);
                result = static_cast<ssize_t>(len);
            }
            in_hook = false;
            return result;
        }
    }

    result = orig_read(fd, buf, count);
    in_hook = false;
    return result;
}

int my_hooked_open(const char *pathname, int flags, ...) {
    static thread_local bool in_hook = false;
    if (in_hook || !orig_open) return orig_open ? orig_open(pathname, flags) : -1;
    in_hook = true;

    int fd = orig_open(pathname, flags);
    if (fd >= 0 && is_mountinfo_path(pathname)) {
        char buffer[65536] = {0};
        lseek(fd, 0, SEEK_SET);
        ssize_t len = read(fd, buffer, sizeof(buffer) - 1);
        if (len > 0) {
            std::string orig(buffer, len);
            std::string spoofed = remap_mountinfo(orig);
            std::lock_guard<std::mutex> lock(cache_mutex);
            hooked_fds.insert(fd);
            mountinfo_cache[fd] = spoofed;
        }
    }

    in_hook = false;
    return fd;
}

int my_hooked_close(int fd) {
    static thread_local bool in_hook = false;
    if (in_hook || !orig_close) return orig_close ? orig_close(fd) : -1;
    in_hook = true;

    {
        std::lock_guard<std::mutex> lock(cache_mutex);
        hooked_fds.erase(fd);
        mountinfo_cache.erase(fd);
    }

    int result = orig_close(fd);
    in_hook = false;
    return result;
}

void init_mountinfo_hook(Api *api, dev_t libc_dev, ino_t libc_ino) {
    api->pltHookRegister(libc_dev, libc_ino, "read", (void *)my_hooked_read, (void **)&orig_read);
    api->pltHookRegister(libc_dev, libc_ino, "open", (void *)my_hooked_open, (void **)&orig_open);
    api->pltHookRegister(libc_dev, libc_ino, "close", (void *)my_hooked_close, (void **)&orig_close);
    LOGD("[mountinfo] installed read/open/close hooks via pltHookRegister");
}
