// Vesper -- logging, error handling and small Win32 utilities shared by the
// shell side (bridge) and the engine side (inside Roblox).
#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <wincrypt.h>

#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace vesper {

enum class Level { Trace = 0, Debug, Info, Warn, Error };

namespace detail {
inline Level& min_level() {
    static Level level = Level::Info;
    return level;
}
inline std::wstring& log_path() {
    static std::wstring path;
    return path;
}
inline HANDLE& log_handle() {
    static HANDLE handle = INVALID_HANDLE_VALUE;
    return handle;
}
inline CRITICAL_SECTION& log_lock() {
    static CRITICAL_SECTION cs;
    static bool ready = false;
    if (!ready) {
        InitializeCriticalSection(&cs);
        ready = true;
    }
    return cs;
}
}  // namespace detail

inline void set_log_level(Level level) { detail::min_level() = level; }

// `path` is where the engine mirrors its log. Pass an empty path to log only to
// the attached console (used by the standalone injector and by tests).
inline void log_open(const std::wstring& path, bool attach_console) {
    detail::log_path() = path;
    if (attach_console && GetConsoleWindow() == nullptr) {
        if (AllocConsole()) {
            FILE* dummy = nullptr;
            freopen_s(&dummy, "CONOUT$", "w", stdout);
            freopen_s(&dummy, "CONOUT$", "w", stderr);
        }
    }
    if (!path.empty()) {
        detail::log_handle() = CreateFileW(path.c_str(), FILE_APPEND_DATA,
                                           FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                           OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    }
}

inline void log_close() {
    if (detail::log_handle() != INVALID_HANDLE_VALUE) {
        CloseHandle(detail::log_handle());
        detail::log_handle() = INVALID_HANDLE_VALUE;
    }
}

void log_line(Level level, const char* text);

inline void logf(Level level, const char* fmt, ...) {
    if (level < detail::min_level()) return;
    char buffer[2048];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);
    log_line(level, buffer);
}

inline std::string vformat(const char* fmt, ...) {
    char buffer[4096];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);
    return std::string(buffer);
}

#define VSP_TRACE(...) ::vesper::logf(::vesper::Level::Trace, __VA_ARGS__)
#define VSP_DEBUG(...) ::vesper::logf(::vesper::Level::Debug, __VA_ARGS__)
#define VSP_INFO(...)  ::vesper::logf(::vesper::Level::Info, __VA_ARGS__)
#define VSP_WARN(...)  ::vesper::logf(::vesper::Level::Warn, __VA_ARGS__)
#define VSP_ERROR(...) ::vesper::logf(::vesper::Level::Error, __VA_ARGS__)

// ------------------------------------------------------------------ paths --

inline std::wstring module_path(HMODULE module = nullptr) {
    wchar_t buffer[MAX_PATH * 4];
    const DWORD len = GetModuleFileNameW(module, buffer, static_cast<DWORD>(std::size(buffer)));
    if (len == 0) return {};
    return std::wstring(buffer, len);
}

inline std::wstring directory_of(const std::wstring& path) {
    const auto slash = path.find_last_of(L"\\/");
    return slash == std::wstring::npos ? std::wstring() : path.substr(0, slash);
}

inline std::wstring parent_name(const std::wstring& path) {
    const std::wstring dir = directory_of(path);
    const auto slash = dir.find_last_of(L"\\/");
    return slash == std::wstring::npos ? dir : dir.substr(slash + 1);
}

inline std::wstring file_name(const std::wstring& path) {
    const auto slash = path.find_last_of(L"\\/");
    return slash == std::wstring::npos ? path : path.substr(slash + 1);
}

inline bool file_exists(const std::wstring& path) {
    const DWORD attributes = GetFileAttributesW(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

inline bool directory_exists(const std::wstring& path) {
    const DWORD attributes = GetFileAttributesW(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

inline bool ensure_directory(const std::wstring& path) {
    if (directory_exists(path)) return true;
    return CreateDirectoryW(path.c_str(), nullptr) != 0 || GetLastError() == ERROR_ALREADY_EXISTS;
}

inline std::string narrow(const std::wstring& wide) {
    if (wide.empty()) return {};
    const int size = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), static_cast<int>(wide.size()),
                                         nullptr, 0, nullptr, nullptr);
    std::string out(static_cast<std::size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), static_cast<int>(wide.size()), out.data(), size,
                        nullptr, nullptr);
    return out;
}

inline std::wstring widen(const std::string& text) {
    if (text.empty()) return {};
    const int size = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()),
                                         nullptr, 0);
    std::wstring out(static_cast<std::size_t>(size), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), out.data(), size);
    return out;
}

inline std::vector<std::uint8_t> read_file(const std::wstring& path) {
    std::vector<std::uint8_t> data;
    const HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return data;
    LARGE_INTEGER size{};
    if (GetFileSizeEx(file, &size) && size.QuadPart > 0 && size.QuadPart < (1ll << 26)) {
        data.resize(static_cast<std::size_t>(size.QuadPart));
        DWORD read = 0;
        if (!ReadFile(file, data.data(), static_cast<DWORD>(data.size()), &read, nullptr)) data.clear();
        else data.resize(read);
    }
    CloseHandle(file);
    return data;
}

inline bool write_file(const std::wstring& path, const void* data, std::size_t len) {
    const HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                                    FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    const bool ok = WriteFile(file, data, static_cast<DWORD>(len), &written, nullptr) != 0;
    CloseHandle(file);
    return ok && written == len;
}

// ------------------------------------------------------------------- misc --

inline std::int64_t now_ms() {
    return static_cast<std::int64_t>(GetTickCount64());
}

inline std::string to_hex(std::uint64_t value) {
    char buffer[32];
    snprintf(buffer, sizeof(buffer), "%llx", static_cast<unsigned long long>(value));
    return std::string(buffer);
}

inline std::string random_token(std::size_t bytes) {
    std::vector<std::uint8_t> raw(bytes);
    if (bytes > 0) {
        HCRYPTPROV provider = 0;
        if (CryptAcquireContextW(&provider, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
            CryptGenRandom(provider, static_cast<DWORD>(bytes), raw.data());
            CryptReleaseContext(provider, 0);
        } else {
            for (std::size_t i = 0; i < bytes; ++i) {
                raw[i] = static_cast<std::uint8_t>((GetTickCount64() >> (i % 7)) ^ (i * 131));
            }
        }
    }
    static const char* alphabet = "abcdefghijklmnopqrstuvwxyz0123456789";
    std::string out;
    out.reserve(bytes * 2);
    for (std::uint8_t byte : raw) {
        out.push_back(alphabet[byte & 0x1f]);
        out.push_back(alphabet[(byte >> 5) & 0x1f]);
    }
    return out;
}

// -------------------------------------------------------- module scanning --

struct ModuleRange {
    std::uintptr_t base = 0;
    std::uintptr_t image_size = 0;
    std::uintptr_t text = 0;
    std::uintptr_t text_size = 0;

    bool valid() const { return base != 0 && image_size != 0; }
};

inline ModuleRange module_range(HMODULE module) {
    ModuleRange range;
    if (!module) return range;
    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(module);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return range;
    auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(reinterpret_cast<const std::uint8_t*>(module) +
                                                           dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return range;
    range.base = reinterpret_cast<std::uintptr_t>(module);
    range.image_size = nt->OptionalHeader.SizeOfImage;
    auto* sections = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        const char* name = reinterpret_cast<const char*>(sections[i].Name);
        if (std::strncmp(name, ".text", 5) == 0) {
            range.text = range.base + sections[i].VirtualAddress;
            range.text_size = sections[i].Misc.VirtualSize;
            break;
        }
    }
    return range;
}

// Reads through Roblox's page protection: Hyperion keeps code pages non
// readable until they are touched, so probing must be fault tolerant.
// True when every page in [address, address+len) is committed and readable.
// This is what replaces structured exception handling: it is a cheap, defined
// check rather than a fault-and-recover, and it tolerates Hyperion leaving code
// pages non-readable until they are touched.
inline bool address_readable(std::uintptr_t address, std::size_t len) {
    if (address == 0 || len == 0) return false;
    std::uintptr_t cursor = address;
    const std::uintptr_t end = address + len;
    if (end < address) return false;

    while (cursor < end) {
        MEMORY_BASIC_INFORMATION info{};
        if (VirtualQuery(reinterpret_cast<LPCVOID>(cursor), &info, sizeof(info)) == 0) return false;
        if (info.State != MEM_COMMIT) return false;
        if (info.Protect & (PAGE_NOACCESS | PAGE_GUARD)) return false;
        constexpr DWORD readable = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ |
                                   PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
        if ((info.Protect & readable) == 0) return false;
        const std::uintptr_t region_end =
            reinterpret_cast<std::uintptr_t>(info.BaseAddress) + info.RegionSize;
        if (region_end <= cursor) return false;
        cursor = region_end;
    }
    return true;
}

inline bool safe_read(const void* address, void* out, std::size_t len) {
    const std::uintptr_t source = reinterpret_cast<std::uintptr_t>(address);
    if (!address_readable(source, len)) return false;
    std::memcpy(out, address, len);
    return true;
}

template <typename T>
inline bool safe_read_value(std::uintptr_t address, T& out) {
    return safe_read(reinterpret_cast<const void*>(address), &out, sizeof(T));
}

}  // namespace vesper
