#include "util.hpp"

#include <ctime>

#include <windows.h>

namespace vesper::shell {

std::wstring widen(const std::string& text) {
    if (text.empty()) return {};
    const int size = MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
    if (size <= 0) return {};
    std::wstring out(static_cast<std::size_t>(size), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(), size);
    return out;
}

std::string narrow(const std::wstring& text) {
    if (text.empty()) return {};
    const int size = WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0,
                                         nullptr, nullptr);
    if (size <= 0) return {};
    std::string out(static_cast<std::size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(), size, nullptr,
                        nullptr);
    return out;
}

bool file_exists(const std::wstring& path) {
    const DWORD attributes = GetFileAttributesW(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

bool directory_exists(const std::wstring& path) {
    const DWORD attributes = GetFileAttributesW(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

std::vector<std::uint8_t> read_file(const std::wstring& path) {
    std::vector<std::uint8_t> data;
    const HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return data;

    LARGE_INTEGER size{};
    if (GetFileSizeEx(file, &size) && size.QuadPart > 0 && size.QuadPart < (64ll << 20)) {
        data.resize(static_cast<std::size_t>(size.QuadPart));
        DWORD read = 0;
        if (!ReadFile(file, data.data(), static_cast<DWORD>(data.size()), &read, nullptr)) data.clear();
        else data.resize(read);
    }
    CloseHandle(file);
    return data;
}

bool write_file(const std::wstring& path, const void* data, std::size_t size) {
    const HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                                    FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    const bool ok =
        size == 0 || WriteFile(file, data, static_cast<DWORD>(size), &written, nullptr);
    CloseHandle(file);
    return ok && written == size;
}

bool ensure_directory(const std::wstring& path) {
    if (path.empty() || directory_exists(path)) return true;
    ensure_directory(directory_of(path));
    if (CreateDirectoryW(path.c_str(), nullptr)) return true;
    return GetLastError() == ERROR_ALREADY_EXISTS;
}

std::wstring file_name(const std::wstring& path) {
    const std::size_t separator = path.find_last_of(L"\\/");
    return separator == std::wstring::npos ? path : path.substr(separator + 1);
}

std::wstring directory_of(const std::wstring& path) {
    const std::size_t separator = path.find_last_of(L"\\/");
    if (separator == std::wstring::npos) return {};
    if (separator == 0) return path.substr(0, 1);
    return path.substr(0, separator);
}

std::wstring app_directory() {
    wchar_t buffer[MAX_PATH * 2] = {};
    const DWORD length = GetModuleFileNameW(nullptr, buffer, static_cast<DWORD>(std::size(buffer)));
    if (length == 0) return L".";
    return directory_of(std::wstring(buffer, length));
}

std::int64_t now_ms() {
    return static_cast<std::int64_t>(GetTickCount64());
}

std::string format_timestamp(std::int64_t unix_seconds) {
    if (unix_seconds <= 0) return "unknown";
    const std::time_t stamp = static_cast<std::time_t>(unix_seconds);
    std::tm local{};
    if (localtime_s(&local, &stamp) != 0) return "unknown";
    char buffer[32] = {};
    std::strftime(buffer, sizeof(buffer), "%H:%M:%S", &local);
    return buffer;
}

}  // namespace vesper::shell
