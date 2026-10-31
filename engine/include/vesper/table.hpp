// Vesper -- the offset table.
//
// Every build-specific number the engine needs (host RVAs, structure field
// offsets and Luau field transforms) lives in a `Profile` loaded at attach
// time. Porting a Roblox update means compiling a new table, not rebuilding the
// engine.
//
// Lookup order for a build:
//   1. <engine dir>\vesper_offsets\<build>.vtb   (hot-updatable on disk)
//   2. <engine dir>\<build>.vtb
//   3. the tables embedded in this binary        (offline fallback)
#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include <vesper/common.hpp>

namespace vesper {

struct Profile {
    std::string build;
    std::string source;
    std::unordered_map<std::string, std::uint64_t> values;

    bool has(const char* key) const { return values.find(key) != values.end(); }

    std::uint64_t get(const char* key, std::uint64_t fallback = 0) const {
        const auto it = values.find(key);
        return it == values.end() ? fallback : it->second;
    }

    // Host module RVA -> absolute address inside the process.
    std::uintptr_t at(const char* key, std::uintptr_t module_base, std::uint64_t fallback = 0) const {
        const std::uint64_t value = get(key, fallback);
        return value == 0 ? 0 : module_base + static_cast<std::uintptr_t>(value);
    }

    // Structure field offset (absolute, not rebased).
    std::uintptr_t field(const char* key, std::uint64_t fallback = 0) const {
        return static_cast<std::uintptr_t>(get(key, fallback));
    }

    // Luau field transform id for `enc.*` keys.
    std::uint8_t transform(const char* key, std::uint8_t fallback) const {
        const auto it = values.find(key);
        if (it == values.end() || it->second > 4) return fallback;
        return static_cast<std::uint8_t>(it->second);
    }

    std::size_t size() const { return values.size(); }
};

// Decodes and authenticates a `VSPR` container. On failure `error` explains
// which check rejected it.
bool profile_parse(const std::uint8_t* data, std::size_t len, Profile& out, std::string& error);

// Directory the engine treats as its own (where the shell drops tables).
std::wstring default_engine_directory();

// Resolves `build` using the search order documented above. `from_disk` reports
// whether step 1/2 succeeded, which is what the shell surfaces in the UI so a
// stale embedded table is visible rather than silent.
bool profile_load(const std::string& build, Profile& out, std::string& error, bool* from_disk = nullptr);

// The `version-XXXXXXXXXXXX` identifier of the process the engine is running in,
// derived from the Roblox install directory name. Empty when undetectable.
std::string detect_build();

// Writes every embedded table to <dir>\vesper_offsets\. The shell does this on
// startup; it is how a freshly installed build learns about offsets it does not
// yet know about.
int profile_export_embedded(const std::wstring& directory);

// Names of the tables compiled into this binary.
std::vector<std::string> embedded_builds();

}  // namespace vesper
