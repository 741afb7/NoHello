#include <unistd.h>
#include <fcntl.h>
#include <string>
#include <unordered_map>
#include <vector>
#include <sstream>
#include <mutex>
#include <cstring>
#include <sys/types.h>
#include <sys/stat.h>

#include "log.h"
#include "zygisk.hpp"

static ssize_t (*orig_read)(int fd, void *buf, size_t count) = nullptr;
static int (*orig_open)(const char *pathname, int flags, ...) = nullptr;

static std::unordered_map<int, std::string> mountinfo_cache;
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
    std::lock_guard<std::mutex> lock(cache_mutex);
    auto it = mountinfo_cache.find(fd);
    if (it != mountinfo_cache.end()) {
        std::string &data = it->second;
        if (data.empty()) return 0;
        size_t len = std::min(count, data.size());
        memcpy(buf, data.data(), len);
        data.erase(0, len);
        return len;
    }
    return orig_read ? orig_read(fd, buf, count) : -1;
}

int my_hooked_open(const char *pathname, int flags, ...) {
    if (is_mountinfo_path(pathname)) {
        int fd = orig_open ? orig_open(pathname, flags) : -1;
        if (fd >= 0) {
            char buffer[65536] = {0};
            ssize_t len = pread(fd, buffer, sizeof(buffer) - 1, 0);
            if (len > 0) {
                std::string orig(buffer, len);
                std::string spoofed = remap_mountinfo(orig);
                std::lock_guard<std::mutex> lock(cache_mutex);
                mountinfo_cache[fd] = spoofed;
            }
        }
        return fd;
    }
    return orig_open ? orig_open(pathname, flags) : -1;
}

void init_mountinfo_hook(Api *api, dev_t libc_dev, ino_t libc_ino) {
    api->pltHookRegister(libc_dev, libc_ino, "read", (void *)my_hooked_read, (void **)&orig_read);
    api->pltHookRegister(libc_dev, libc_ino, "open", (void *)my_hooked_open, (void **)&orig_open);
    LOGD("[mountinfo] installed read/open hooks via pltHookRegister");
}
