#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <sstream>
#include <cstring>
#include <mutex>

#include "log.h"
#include "Dobby/dobby.h"

static ssize_t (*orig_read)(int fd, void *buf, size_t count);
static int (*orig_open)(const char *pathname, int flags, ...);

static std::unordered_map<int, std::string> mountinfo_cache; // fd -> mapped content
static std::mutex cache_mutex;

// judge path /proc/*/mountinfo
bool is_mountinfo_path(const char *path) {
    if (!path) return false;
    return strstr(path, "/proc/") && strstr(path, "/mountinfo");
}

// extract list
std::string get_column(const std::string &line, int index) {
    std::istringstream iss(line);
    std::string token;
    for (int i = 0; i <= index; ++i) {
        if (!(iss >> token)) return "";
    }
    return token;
}

// replace field (mount ID and peer group ID) 
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

        if (id_map.count(mount_id) == 0)
            id_map[mount_id] = next_id++;
        if (id_map.count(group_id) == 0)
            id_map[group_id] = next_id++;

        // replace original ID
        size_t first_space = line.find(' ');
        size_t second_space = line.find(' ', first_space + 1);
        size_t third_space = line.find(' ', second_space + 1);
        size_t fourth_space = line.find(' ', third_space + 1);

        if (first_space == std::string::npos || fourth_space == std::string::npos) continue;

        std::ostringstream replaced;
        replaced << id_map[mount_id] << " ";
        replaced << line.substr(first_space + 1, third_space - first_space - 1) << " ";
        replaced << id_map[group_id] << line.substr(fourth_space);
        oss << replaced.str() << "\n";
    }
    return oss.str();
}

ssize_t hooked_read(int fd, void *buf, size_t count) {
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
    return orig_read(fd, buf, count);
}

int hooked_open(const char *pathname, int flags, ...) {
    if (is_mountinfo_path(pathname)) {
        int fd = orig_open(pathname, flags);
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
    return orig_open(pathname, flags);
}

void init_mountinfo_hook() {
    void *libc = dlopen("libc.so", RTLD_NOW);
    if (libc) {
        void *read_sym = dlsym(libc, "read");
        void *open_sym = dlsym(libc, "open");
        if (read_sym && open_sym) {
            DobbyHook(read_sym, (void *)hooked_read, (void **)&orig_read);
            DobbyHook(open_sym, (void *)hooked_open, (void **)&orig_open);
            LOGI("[mountinfo] hook installed");
        }
    }
}
