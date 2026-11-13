#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <cstring>
#include <signal.h>
#include <thread>

#include <unistd.h>

#include <cstdint>
#include <string>

#include <sys/types.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>

#include <chrono>
#include <vector>
#include <ctime>
#include <fstream>
#include <sstream>
#include <random>
#include <algorithm>

#include <dirent.h>
#include <iostream>
#include <iomanip>
#include <sys/stat.h>
#include <sys/system_properties.h>

#include "KittyMemoryMgr.hpp"

#include "Utils/Utils.hpp"
#include <KittyUtils.hpp>

#include "Utils/argsparse.hpp"

#include "Injector/KittyInjector.hpp"

#ifndef __NR_process_vm_readv
#define __NR_process_vm_readv 270
#endif

static ssize_t process_vm_readv(pid_t pid,
                                const struct iovec *local_iov, unsigned long liovcnt,
                                const struct iovec *remote_iov, unsigned long riovcnt,
                                unsigned long flags)
{
    return syscall(__NR_process_vm_readv, pid, local_iov, liovcnt, remote_iov, riovcnt, flags);
}

#define SLEEP_MICROS(x)                                                                                                \
    {                                                                                                                  \
        std::this_thread::sleep_for(std::chrono::microseconds(x));                                                     \
    }
#define SLEEP_SECONDS(x)                                                                                               \
    {                                                                                                                  \
        std::this_thread::sleep_for(std::chrono::seconds(x));                                                          \
    }

#define kPROGRAM_NAME "ZYDARK LOADER"
#define kPROGRAM_VER "7.0.0"

#define COLOR_CYAN "\033[36m"
#define COLOR_GREEN "\033[32m"
#define COLOR_RED "\033[31m"
#define COLOR_YELLOW "\033[33m"
#define COLOR_DIM "\033[2m"
#define COLOR_RESET "\033[0m"
#define COLOR_BOLD "\033[1m"

#define LOG_FILE "/data/local/tmp/zydark_loader.log"
#define STATE_FILE "/data/local/tmp/zydark_state.conf"
#define JSON_OUTPUT "/data/local/tmp/zydark_output.json"

static std::vector<std::string> g_anticheat_libs = {
    "libanogs.so", "libtersafe.so", "libtprt.so", "libACE.so",
    "libmsaoaidsec.so", "libSecurityGuard.so", "libNetEaseSecure.so"
};

static bool g_skip_check = false;
static bool g_experimental_hide = false;
static std::string g_output_json_path;

bool inject(int pid,
            const std::vector<std::string> &libs,
            inject_elf_config_t &cfg,
            std::vector<inject_elf_info_t> *out);
bool inject_watch(const std::vector<std::string> &libs, inject_elf_config_t &cfg, std::vector<inject_elf_info_t> *out);

std::chrono::duration<double, std::milli> inj_ms{};

static int g_term_width = 60;

static void log_to_file(const std::string &msg)
{
    std::ofstream f(LOG_FILE, std::ios::app);
    if (!f.is_open()) return;

    time_t now = std::time(nullptr);
    char time_buf[64] = {0};
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", localtime(&now));

    f << "[" << time_buf << "] " << msg << std::endl;
    f.close();
}

static void write_json_output(bool success, int pid, const std::string &package,
                              const std::vector<std::string> &libs, double ms,
                              const std::string &error)
{
    std::string path = g_output_json_path.empty() ? JSON_OUTPUT : g_output_json_path;
    std::ofstream f(path, std::ios::trunc);
    if (!f.is_open()) return;

    auto json_escape = [](const std::string &s) {
        std::string r;
        for (char c : s) {
            if (c == '"' || c == '\\') r += '\\';
            r += c;
        }
        return r;
    };

    time_t now = std::time(nullptr);
    char time_buf[64] = {0};
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%dT%H:%M:%S", localtime(&now));

    f << "{\n";
    f << "  \"timestamp\": \"" << time_buf << "\",\n";
    f << "  \"success\": " << (success ? "true" : "false") << ",\n";
    f << "  \"pid\": " << pid << ",\n";
    f << "  \"package\": \"" << json_escape(package) << "\",\n";
    f << "  \"time_ms\": " << std::fixed << std::setprecision(2) << ms << ",\n";
    f << "  \"error\": \"" << json_escape(error) << "\",\n";
    f << "  \"libraries\": [";
    for (size_t i = 0; i < libs.size(); i++) {
        f << "\"" << json_escape(libs[i]) << "\"";
        if (i + 1 < libs.size()) f << ", ";
    }
    f << "]\n";
    f << "}\n";
    f.close();
}

static void save_state(const std::string &package, const std::string &lib)
{
    std::ofstream f(STATE_FILE, std::ios::trunc);
    if (!f.is_open()) return;
    f << "package=" << package << "\n";
    f << "lib=" << lib << "\n";
    f.close();
}

static bool load_state(std::string &package, std::string &lib)
{
    std::ifstream f(STATE_FILE);
    if (!f.is_open()) return false;

    std::string line;
    bool has_pkg = false, has_lib = false;
    while (std::getline(f, line)) {
        if (line.rfind("package=", 0) == 0) {
            package = line.substr(8);
            has_pkg = true;
        } else if (line.rfind("lib=", 0) == 0) {
            lib = line.substr(4);
            has_lib = true;
        }
    }
    f.close();
    return has_pkg && has_lib;
}

static void detect_terminal_width()
{
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0)
    {
        g_term_width = ws.ws_col;
    }
    else
    {
        g_term_width = 60;
    }
    if (g_term_width > 80) g_term_width = 80;
    if (g_term_width < 30) g_term_width = 30;
}

static void printBanner()
{
    detect_terminal_width();

    char model[256] = {0};
    __system_property_get("ro.product.model", model);
    char android_ver[256] = {0};
    __system_property_get("ro.build.version.release", android_ver);

    time_t now = std::time(nullptr);
    char time_buf[64] = {0};
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", localtime(&now));

    std::cout << COLOR_DIM << "  ──────────────────────────────────────" << COLOR_RESET << std::endl;
    std::cout << "  " << COLOR_CYAN << COLOR_BOLD << "ZYDARK LOADER" << COLOR_RESET
              << COLOR_DIM << "  v" << kPROGRAM_VER << COLOR_RESET << std::endl;
    std::cout << COLOR_DIM << "  ──────────────────────────────────────" << COLOR_RESET << std::endl;
    std::cout << std::endl;

    std::cout << "  " << COLOR_GREEN << "Device " << COLOR_DIM << "│ " << COLOR_RESET << model << std::endl;
    std::cout << "  " << COLOR_GREEN << "Android" << COLOR_DIM << " │ " << COLOR_RESET << android_ver << std::endl;
    std::cout << "  " << COLOR_GREEN << "Time   " << COLOR_DIM << "│ " << COLOR_RESET << time_buf << std::endl;
    std::cout << std::endl;
}

static void printProgress(const std::string &label, int percent)
{
    int barWidth = g_term_width - 25;
    if (barWidth < 10) barWidth = 10;
    if (barWidth > 45) barWidth = 45;

    int filled = (percent * barWidth) / 100;

    static const char *spinner[] = {"|", "/", "-", "\\"};
    static int spin_idx = 0;

    const char* color;
    if (percent < 30) color = COLOR_RED;
    else if (percent < 70) color = COLOR_YELLOW;
    else color = COLOR_GREEN;

    std::cout << "\r\033[K  " << COLOR_DIM << "[" << COLOR_RESET;

    for (int i = 0; i < barWidth; i++)
    {
        if (i < filled)
            std::cout << color << "▬" << COLOR_RESET;
        else
            std::cout << COLOR_DIM << "─" << COLOR_RESET;
    }

    if (percent < 100)
        std::cout << COLOR_DIM << "] " << COLOR_RESET << color << spinner[spin_idx++ % 4] << " " << COLOR_RESET
                  << color << std::setw(3) << percent << "%" << COLOR_RESET
                  << "  " << COLOR_DIM << label << COLOR_RESET << std::flush;
    else
        std::cout << COLOR_DIM << "] " << COLOR_RESET
                  << color << std::setw(3) << percent << "%" << COLOR_RESET
                  << "  " << COLOR_DIM << label << COLOR_RESET << std::endl;
}

static void printLibraryTable(const std::vector<std::string> &libs)
{
    std::cout << std::endl;
    std::cout << "  " << COLOR_DIM << "┌────┬────────────────────────────────┬──────────┐" << COLOR_RESET << std::endl;
    std::cout << "  " << COLOR_DIM << "│ " << COLOR_CYAN << "#  " << COLOR_DIM << "│ "
              << COLOR_CYAN << "Library                        " << COLOR_DIM << "│ "
              << COLOR_CYAN << "Size     " << COLOR_DIM << "│" << COLOR_RESET << std::endl;
    std::cout << "  " << COLOR_DIM << "├────┼────────────────────────────────┼──────────┤" << COLOR_RESET << std::endl;

    for (size_t i = 0; i < libs.size(); i++)
    {
        struct stat st;
        stat(libs[i].c_str(), &st);
        std::string name = libs[i].substr(libs[i].find_last_of('/') + 1);
        if (name.length() > 30) name = name.substr(0, 27) + "...";

        std::cout << "  " << COLOR_DIM << "│ " << COLOR_CYAN << std::setw(2) << (i + 1) << " " << COLOR_DIM << "│ "
                  << COLOR_RESET << std::setw(30) << std::left << name << " "
                  << COLOR_DIM << "│ " << COLOR_RESET << std::setw(8) << st.st_size << " "
                  << COLOR_DIM << "│" << COLOR_RESET << std::endl;
    }
    std::cout << "  " << COLOR_DIM << "└────┴────────────────────────────────┴──────────┘" << COLOR_RESET << std::endl;
    std::cout << std::endl;
}

static void printSummary(bool success, int count, double ms)
{
    std::cout << std::endl;
    std::cout << "  " << COLOR_DIM << "──────────────────────────────────────" << COLOR_RESET << std::endl;
    if (success)
    {
        std::cout << "  " << COLOR_GREEN << COLOR_BOLD << "✓  INJECTION SUCCESSFUL" << COLOR_RESET << std::endl;
        std::cout << std::endl;
        std::cout << "  " << COLOR_GREEN << "Libraries " << COLOR_DIM << "│ " << COLOR_RESET << count << std::endl;
        std::cout << "  " << COLOR_GREEN << "Time      " << COLOR_DIM << "│ " << COLOR_RESET
                  << std::fixed << std::setprecision(2) << ms << " ms" << std::endl;
        log_to_file("SUCCESS | Libraries: " + std::to_string(count) + " | Time: " + std::to_string(ms) + "ms");
    }
    else
    {
        std::cout << "  " << COLOR_RED << COLOR_BOLD << "✕  INJECTION FAILED" << COLOR_RESET << std::endl;
        log_to_file("FAILED");
    }
    std::cout << "  " << COLOR_DIM << "──────────────────────────────────────" << COLOR_RESET << std::endl;
    std::cout << std::endl;
}

static bool check_tracer_pid(int pid)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    std::ifstream f(path);
    if (!f.is_open()) return false;

    std::string line;
    while (std::getline(f, line))
    {
        if (line.compare(0, 9, "TracerPid") == 0)
        {
            int tracer = 0;
            sscanf(line.c_str(), "TracerPid:\t%d", &tracer);
            f.close();
            return tracer == 0;
        }
    }
    f.close();
    return true;
}

static uint64_t hash_file(const std::string &path)
{
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open()) return 0;

    uint64_t hash = 14695981039346656037ULL;
    char buf[8192];
    while (f.read(buf, sizeof(buf)) || f.gcount() > 0)
    {
        std::streamsize n = f.gcount();
        for (std::streamsize i = 0; i < n; i++)
        {
            hash ^= (uint8_t)buf[i];
            hash *= 1099511628211ULL;
        }
    }
    f.close();
    return hash;
}

static bool check_abi(const std::string &lib_path)
{
    std::ifstream f(lib_path, std::ios::binary);
    if (!f.is_open()) return false;

    unsigned char ident[20] = {0};
    f.read((char*)ident, 20);
    f.close();

    if (ident[0] != 0x7f || ident[1] != 'E' || ident[2] != 'L' || ident[3] != 'F')
        return false;

    uint8_t ei_class = ident[4];
    uint8_t ei_data = ident[5];

    if (ei_class != 2) return false;
    if (ei_data != 1) return false;

    return true;
}

struct ProcMapInfo
{
    uintptr_t start;
    uintptr_t end;
    int perms;
};

static std::vector<ProcMapInfo> list_modules_with_name(int pid, const std::string &name)
{
    std::vector<ProcMapInfo> result;
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *fp = fopen(path, "r");
    if (!fp) return result;

    char line[512];
    while (fgets(line, sizeof(line), fp))
    {
        if (!strstr(line, name.c_str())) continue;

        ProcMapInfo info{};
        char perms[10] = {0};
        char dev[25] = {0};
        char pathname[256] = {0};

        unsigned long start = 0, end = 0, offset = 0, inode = 0;
        if (sscanf(line, "%lx-%lx %s %lx %s %lu %s",
                   &start, &end, perms, &offset, dev, &inode, pathname) < 7)
            continue;

        info.start = (uintptr_t)start;
        info.end = (uintptr_t)end;
        info.perms = 0;
        if (strchr(perms, 'r')) info.perms |= PROT_READ;
        if (strchr(perms, 'w')) info.perms |= PROT_WRITE;
        if (strchr(perms, 'x')) info.perms |= PROT_EXEC;

        result.push_back(info);
    }
    fclose(fp);
    return result;
}

static bool remap_library(int pid, const std::string &lib_path)
{
    std::string name = lib_path.substr(lib_path.find_last_of('/') + 1);
    if (name.empty()) return false;

    std::vector<ProcMapInfo> maps = list_modules_with_name(pid, name);
    if (maps.empty())
    {
        KITTY_LOGW("Remap: no maps found for %s", name.c_str());
        return false;
    }

    for (const auto &info : maps)
    {
        size_t size = info.end - info.start;

        void *new_map = mmap(nullptr, size, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (new_map == MAP_FAILED)
        {
            KITTY_LOGE("Remap: mmap failed for %p (size=%zu)", (void *)info.start, size);
            continue;
        }

        struct iovec local = { new_map, size };
        struct iovec remote = { (void *)info.start, size };
        ssize_t n = process_vm_readv(pid, &local, 1, &remote, 1, 0);
        if (n != (ssize_t)size)
        {
            KITTY_LOGE("Remap: readv failed for %p (got %zd, want %zu)", (void *)info.start, n, size);
            munmap(new_map, size);
            continue;
        }

        void *mremap_result = mremap(new_map, size, size,
                                     MREMAP_MAYMOVE | MREMAP_FIXED,
                                     (void *)info.start);
        if (mremap_result == MAP_FAILED)
        {
            KITTY_LOGE("Remap: mremap failed for %p (errno=%d)", (void *)info.start, errno);
            munmap(new_map, size);
            continue;
        }

        mprotect((void *)info.start, size, info.perms);
        KITTY_LOGI("Remap: successfully remapped %p-%p", (void *)info.start, (void *)info.end);
    }

    return true;
}

static bool detect_anticheat(int pid, const std::vector<std::string> &ac_libs)
{
    bool found = false;
    for (const auto &lib : ac_libs) {
        auto maps = KittyMemoryEx::getMaps(pid, EProcMapFilter::Contains, lib);
        if (!maps.empty()) {
            std::cout << "  " << COLOR_YELLOW << "⚠ " << COLOR_RESET
                      << "Anti-cheat detected: " << COLOR_DIM << lib << COLOR_RESET
                      << " @ " << maps[0].startAddress << std::endl;
            KITTY_LOGW("Anti-cheat detected: %s (pid=%d)", lib.c_str(), pid);
            log_to_file("ANTICHEAT DETECTED: " + lib + " in pid " + std::to_string(pid));
            found = true;
        }
    }
    return found;
}

static bool check_anticheat_threads(int pid, const std::vector<std::string> &ac_libs)
{
    char task_path[64];
    snprintf(task_path, sizeof(task_path), "/proc/%d/task", pid);
    DIR *dir = opendir(task_path);
    if (!dir) return false;

    bool found = false;
    struct dirent *ent;
    while ((ent = readdir(dir)) != nullptr) {
        if (ent->d_name[0] == '.') continue;
        char comm_path[128];
        snprintf(comm_path, sizeof(comm_path), "/proc/%d/task/%s/comm", pid, ent->d_name);
        std::ifstream cf(comm_path);
        if (!cf.is_open()) continue;
        std::string comm;
        std::getline(cf, comm);
        cf.close();
        for (const auto &lib : ac_libs) {
            std::string base = lib.substr(0, lib.find(".so"));
            if (comm.find(base) != std::string::npos || comm.find("ACE") != std::string::npos) {
                std::cout << "  " << COLOR_YELLOW << "⚠ " << COLOR_RESET
                          << "Anti-cheat thread active: " << COLOR_DIM << comm << COLOR_RESET << std::endl;
                found = true;
                break;
            }
        }
    }
    closedir(dir);
    return found;
}

static bool detect_hooks_in_lib(int pid, const std::vector<std::string> &ac_libs)
{
    bool found = false;
    for (const auto &lib : ac_libs) {
        auto maps = KittyMemoryEx::getMaps(pid, EProcMapFilter::Contains, lib);
        for (const auto &m : maps) {
            if (!(m.perms & PROT_EXEC)) continue;
            size_t size = m.endAddress - m.startAddress;
            if (size == 0 || size > 0x100000) continue;
            std::vector<uint8_t> buf(size);
            struct iovec local = { buf.data(), size };
            struct iovec remote = { (void *)m.startAddress, size };
            ssize_t n = process_vm_readv(pid, &local, 1, &remote, 1, 0);
            if (n <= 0) continue;
            for (size_t i = 0; i + 4 < (size_t)n; i += 4) {
                uint32_t ins = *(uint32_t *)(buf.data() + i);
                if ((ins & 0xFFFF0000) == 0x58000000 ||
                    (ins & 0xFFFF0000) == 0x18000000 ||
                    (ins & 0xFFE0001F) == 0xD61F0000) {
                    found = true;
                    break;
                }
            }
            if (found) break;
        }
        if (found) {
            std::cout << "  " << COLOR_YELLOW << "⚠ " << COLOR_RESET
                      << "Suspicious hook pattern in " << COLOR_DIM << lib << COLOR_RESET << std::endl;
            break;
        }
    }
    return found;
}

static void randomize_memfd_name(std::string &name)
{
    static const char *candidates[] = {
        "libutils.so", "libcutils.so", "libbinder.so",
        "libui.so", "libgui.so", "libsync.so",
        "libbase.so", "liblog.so", "libhardware.so"
    };
    std::mt19937 rng(std::random_device{}());
    std::uniform_int_distribution<size_t> dist(0, sizeof(candidates)/sizeof(candidates[0]) - 1);
    name = candidates[dist(rng)];
}

static void randomize_library_mappings(int pid, const std::string &lib)
{
    std::string name = lib.substr(lib.find_last_of('/') + 1);
    std::vector<ProcMapInfo> maps = list_modules_with_name(pid, name);
    if (maps.empty()) return;

    std::mt19937 rng(std::random_device{}());
    for (const auto &m : maps) {
        size_t size = m.end - m.start;
        if (size == 0) continue;
        std::uniform_int_distribution<uintptr_t> addr_dist(0x10000000, 0x70000000);
        void *hint = (void *)(addr_dist(rng) & ~0xFFF);
        void *p = mmap(hint, size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
        if (p != MAP_FAILED && p != hint) {
            munmap(p, size);
        }
    }
}

static bool try_reset_tracerpid(int pid)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    std::ifstream in(path);
    if (!in.is_open()) return false;
    std::string content((std::istreambuf_iterator<char>(in)),
                        std::istreambuf_iterator<char>());
    in.close();
    size_t pos = content.find("TracerPid:");
    if (pos == std::string::npos) return false;
    size_t end = content.find('\n', pos);
    if (end == std::string::npos) return false;
    return true;
}

static void print_tip(const std::string &msg)
{
    std::cout << "  " << COLOR_DIM << "› " << COLOR_RESET << COLOR_DIM << msg << COLOR_RESET << std::endl;
}

int main(int argc, char *args[])
{
    setbuf(stdout, nullptr);
    setbuf(stderr, nullptr);
    setbuf(stdin, nullptr);

    printBanner();

    log_to_file("=== ZYDARK LOADER STARTED ===");

    argparse::ArgumentParser program(kPROGRAM_NAME, kPROGRAM_VER);

    int target_pid = 0;
    inject_elf_config_t inj_cfg = {};

    inj_cfg.selinux_state = Utils::selinux_state();
    inj_cfg.sdk = KittyUtils::Android::getSDK();
    inj_cfg.seize = inj_cfg.sdk >= 24;
    inj_cfg.rtdl_flags = RTLD_LOCAL | RTLD_NOW;

    auto &proc_group = program.add_mutually_exclusive_group(true);
    {
        proc_group.add_argument("--pid")
            .help("Target process ID to inject into.")
            .store_into(target_pid)
            .metavar("<id>");

        proc_group.add_argument("--package")
            .help("Target package name to inject into.")
            .store_into(inj_cfg.package)
            .metavar("<name>");
    }

    std::vector<std::string> libs;
    program.add_argument("--libs")
        .help("Libraries path to be injected.")
        .required()
        .nargs(argparse::nargs_pattern::at_least_one)
        .store_into(libs)
        .metavar("<paths>");

    auto &pmon_group = program.add_mutually_exclusive_group(false);
    {
        pmon_group.add_argument("--launch").help("Launch process and inject.").store_into(inj_cfg.launch);

        pmon_group.add_argument("--watch").help("Watch for process start then inject.").store_into(inj_cfg.watch);
    }

    auto &bp_group = program.add_mutually_exclusive_group(false);
    {
        bp_group.add_argument("--bp-ld")
            .help("Inject after first native/emulated loadlibrary breakpoint hit.")
            .store_into(inj_cfg.bp);

        bp_group.add_argument("--bp-sym")
            .nargs(2)
            .metavar("<binary> <symbol>")
            .store_into(inj_cfg.bp_args)
            .help("Inject after first breakpoint on binary path and symbol name. (e.g., /libc.so malloc)");
    }

    program.add_argument("--delay")
        .help("Delay injection in microseconds.")
        .store_into(inj_cfg.delay)
        .metavar("<micros>");

    program.add_argument("--timeout")
        .help("Timeout for ptrace remote calls in milliseconds.")
        .store_into(inj_cfg.timeout)
        .metavar("<ms>");

    program.add_argument("--memfd").help("Use memfd dlopen.").store_into(inj_cfg.memfd);

    program.add_argument("--memfd-name").help("Custom memfd name instead of random.").store_into(inj_cfg.memfd_name);

    auto &free_hide_group = program.add_mutually_exclusive_group(false);
    {
        free_hide_group.add_argument("--free")
            .help("Unload library after entry point execution.")
            .store_into(inj_cfg.free);

        free_hide_group.add_argument("--hide")
            .help("Remove soinfo from solist/sonext, remap library to anonymouse memory and randomize ELF header.")
            .store_into(inj_cfg.hide);
    }

    program.add_argument("--skip-check")
        .help("Skip anti-cheat detection checks.")
        .store_into(g_skip_check)
        .default_value(false)
        .implicit_value(true);

    program.add_argument("--experimental-hide")
        .help("Enable experimental hiding (randomize memfd names, memory mappings).")
        .store_into(g_experimental_hide)
        .default_value(false)
        .implicit_value(true);

    program.add_argument("--retry")
        .help("Number of retry attempts on injection failure.")
        .store_into(inj_cfg.timeout)
        .default_value(0)
        .metavar("<n>");

    program.add_argument("--retry-delay")
        .help("Delay between retries in milliseconds.")
        .store_into(inj_cfg.delay)
        .default_value(1000)
        .metavar("<ms>");

    program.add_argument("--output-json")
        .help("Output structured JSON result to file.")
        .store_into(g_output_json_path)
        .metavar("<path>");

    program.add_argument("--dry-run")
        .help("Validate ABI and environment without injecting.")
        .default_value(false)
        .implicit_value(true);

    program.add_argument("--forget")
        .help("Forget last saved package/library.")
        .default_value(false)
        .implicit_value(true);

    bool interactive = (argc == 1);

    if (interactive)
    {
        printProgress("Reading target", 10);
        std::cout << std::endl;

        std::string saved_pkg, saved_lib;
        bool has_saved = load_state(saved_pkg, saved_lib);

        std::cout << "  " << COLOR_CYAN << "┌─────────────────────────────────────┐" << COLOR_RESET << std::endl;
        std::cout << "  " << COLOR_CYAN << "│ " << COLOR_RESET << COLOR_BOLD << "Select mode" << COLOR_RESET
                  << "                        " << COLOR_CYAN << "│" << COLOR_RESET << std::endl;
        std::cout << "  " << COLOR_CYAN << "├─────────────────────────────────────┤" << COLOR_RESET << std::endl;
        std::cout << "  " << COLOR_CYAN << "│ " << COLOR_RESET << "1. Enter new package name         "
                  << COLOR_CYAN << "│" << COLOR_RESET << std::endl;
        if (has_saved) {
            std::cout << "  " << COLOR_CYAN << "│ " << COLOR_RESET << "2. Continue with last session     "
                      << COLOR_CYAN << "│" << COLOR_RESET << std::endl;
            std::cout << "  " << COLOR_DIM << "│    Package: " << COLOR_RESET
                      << std::setw(23) << std::left << saved_pkg.substr(0, 23) << COLOR_CYAN << "│" << COLOR_RESET << std::endl;
        }
        std::cout << "  " << COLOR_CYAN << "└─────────────────────────────────────┘" << COLOR_RESET << std::endl;

        int mode = 0;
        std::cout << "  " << COLOR_CYAN << "› " << COLOR_RESET << "Choice: ";
        std::cin >> mode;
        std::cin.ignore();

        std::string pkg;
        if (mode == 2 && has_saved) {
            pkg = saved_pkg;
            print_tip("Using saved package: " + pkg);
        } else {
            std::cout << "  " << COLOR_CYAN << "› " << COLOR_RESET << "Package: ";
            std::getline(std::cin, pkg);
        }

        if (pkg.empty())
        {
            std::cout << "  " << COLOR_RED << "✕ " << COLOR_RESET << "Package name cannot be empty" << std::endl;
            log_to_file("FAILED: empty package name");
            return 1;
        }

        inj_cfg.package = pkg;
        log_to_file("Target package: " + pkg);

        printProgress("Scanning", 30);

        std::vector<std::string> found_libs;
        DIR *dir = opendir("/data/local/tmp");
        if (dir)
        {
            struct dirent *ent;
            while ((ent = readdir(dir)) != nullptr)
            {
                std::string name = ent->d_name;
                if (name.size() > 3 && name.substr(name.size() - 3) == ".so")
                {
                    found_libs.push_back("/data/local/tmp/" + name);
                }
            }
            closedir(dir);
        }

        if (found_libs.empty())
        {
            std::cout << "  " << COLOR_RED << "✕ " << COLOR_RESET << "No .so files found" << std::endl;
            log_to_file("FAILED: no .so files found");
            return 1;
        }

        printProgress("Libraries found", 50);
        printLibraryTable(found_libs);

        std::string selected_lib;
        if (mode == 2 && has_saved && !saved_lib.empty()) {
            std::ifstream t(saved_lib);
            if (t.good()) {
                selected_lib = saved_lib;
                print_tip("Using saved library: " + selected_lib);
            }
            t.close();
        }

        if (selected_lib.empty()) {
            int choice = 0;
            std::cout << "  " << COLOR_CYAN << "› " << COLOR_RESET << "Select: ";
            std::cin >> choice;

            if (choice < 1 || choice > (int)found_libs.size())
            {
                std::cout << "  " << COLOR_RED << "✕ " << COLOR_RESET << "Invalid choice" << std::endl;
                log_to_file("FAILED: invalid library choice");
                return 1;
            }
            selected_lib = found_libs[choice - 1];
        }

        printProgress("Validating ABI", 55);
        if (!check_abi(selected_lib))
        {
            std::cout << "  " << COLOR_RED << "✕ " << COLOR_RESET << "Invalid ABI (need arm64-v8a ELF)" << std::endl;
            log_to_file("FAILED: invalid ABI for " + selected_lib);
            return 1;
        }

        printProgress("Hashing library", 60);
        uint64_t lib_hash = hash_file(selected_lib);
        std::cout << "  " << COLOR_DIM << "Hash: " << COLOR_RESET
                  << std::hex << std::uppercase << lib_hash << std::dec << std::endl;
        log_to_file("Library: " + selected_lib + " | Hash: " + std::to_string(lib_hash));

        save_state(pkg, selected_lib);

        libs.push_back(selected_lib);
        inj_cfg.la
