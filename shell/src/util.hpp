// Vesper shell -- small platform helpers.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace vesper::shell {

std::wstring widen(const std::string& text);
std::string narrow(const std::wstring& text);

bool file_exists(const std::wstring& path);
bool directory_exists(const std::wstring& path);
std::vector<std::uint8_t> read_file(const std::wstring& path);
bool write_file(const std::wstring& path, const void* data, std::size_t size);
bool ensure_directory(const std::wstring& path);

std::wstring file_name(const std::wstring& path);
std::wstring directory_of(const std::wstring& path);

// Directory containing the running executable.
std::wstring app_directory();

std::int64_t now_ms();
std::string format_timestamp(std::int64_t unix_seconds);

}  // namespace vesper::shell
