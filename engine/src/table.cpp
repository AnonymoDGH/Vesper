#include <vesper/table.hpp>

#include <algorithm>
#include <cstdio>
#include <cwchar>

#include <vesper/crypto.hpp>

#include "generated/tables_blob.inc"

namespace vesper {

namespace {

// Must match MASTER_SECRET in tools/gen_offsets.py.
constexpr char kMasterSecret[] = "vesper::table::k1::7b1f0a5c9e3d2648";
constexpr std::uint16_t kFormat = 1;

HMODULE g_self_module = nullptr;

std::array<unsigned char, 32> derive_key(const std::string& build) {
    std::vector<unsigned char> material;
    material.insert(material.end(), kMasterSecret, kMasterSecret + sizeof(kMasterSecret) - 1);
    material.push_back(0);
    material.insert(material.end(), build.begin(), build.end());
    return crypto::sha256(material.data(), material.size());
}

}  // namespace

void set_self_module(HMODULE module) { g_self_module = module; }

std::wstring default_engine_directory() {
    if (g_self_module == nullptr) {
        g_self_module = GetModuleHandleW(L"Vesper.dll");
    }
    const std::wstring path = module_path(g_self_module);
    return path.empty() ? std::wstring() : directory_of(path);
}

bool profile_parse(const std::uint8_t* data, std::size_t len, Profile& out, std::string& error) {
    if (len < 9 + 4 + 16 + 32) {
        error = "table too small";
        return false;
    }
    if (std::memcmp(data, "VSPR", 4) != 0) {
        error = "bad magic";
        return false;
    }

    std::uint16_t format = 0;
    std::memcpy(&format, data + 4, sizeof(format));
    if (format != kFormat) {
        error = vformat("unsupported table format %u", format);
        return false;
    }

    const std::size_t build_len = data[8];
    if (len < 9 + build_len + 4 + 16 + 32) {
        error = "truncated header";
        return false;
    }

    const std::string build(reinterpret_cast<const char*>(data + 9), build_len);

    std::size_t cursor = 9 + build_len;
    std::uint32_t body_len = 0;
    std::memcpy(&body_len, data + cursor, sizeof(body_len));
    cursor += 4;

    const std::uint8_t* iv = data + cursor;
    cursor += 16;
    if (len < cursor + body_len + 32) {
        error = "truncated body";
        return false;
    }
    const std::uint8_t* body = data + cursor;
    cursor += body_len;
    const std::uint8_t* mac = data + cursor;

    const auto key = derive_key(build);

    std::vector<std::uint8_t> mac_input;
    mac_input.insert(mac_input.end(), data + 8, data + 8 + 1 + build_len + 4 + 16);
    mac_input.insert(mac_input.end(), body, body + body_len);
    const auto expected = crypto::hmac_sha256(key.data(), key.size(), mac_input.data(), mac_input.size());
    if (!crypto::constant_time_equal(mac, expected.data(), 32)) {
        error = "table authentication failed (tampered or wrong key generation)";
        return false;
    }

    std::vector<std::uint8_t> plain(body_len);
    const std::size_t plain_len = crypto::aes256_cbc_decrypt(key.data(), iv, body, body_len, plain.data());
    if (plain_len < 4) {
        error = "table decryption failed";
        return false;
    }

    std::uint32_t count = 0;
    std::memcpy(&count, plain.data(), 4);

    out.build = build;
    out.values.clear();
    out.values.reserve(count);

    std::size_t pos = 4;
    for (std::uint32_t i = 0; i < count; ++i) {
        if (pos + 2 > plain_len) {
            error = "entry header out of range";
            return false;
        }
        std::uint16_t name_len = 0;
        std::memcpy(&name_len, plain.data() + pos, 2);
        pos += 2;
        if (pos + name_len + 8 > plain_len) {
            error = "entry payload out of range";
            return false;
        }
        const std::string name(reinterpret_cast<const char*>(plain.data() + pos), name_len);
        pos += name_len;
        std::uint64_t value = 0;
        std::memcpy(&value, plain.data() + pos, 8);
        pos += 8;
        out.values[name] = value;
    }

    if (pos != plain_len) {
        error = "trailing bytes in entry table";
        return false;
    }
    if (out.values.empty()) {
        error = "empty entry table";
        return false;
    }

    out.source = "table";
    return true;
}

std::vector<std::string> embedded_builds() {
    std::vector<std::string> builds;
    for (std::size_t i = 0; i < tables::kTableCount; ++i) builds.emplace_back(tables::kTables[i].build);
    return builds;
}

bool profile_load(const std::string& build, Profile& out, std::string& error, bool* from_disk) {
    if (from_disk) *from_disk = false;
    if (build.empty()) {
        error = "no build identifier";
        return false;
    }

    const std::wstring engine_dir = default_engine_directory();
    if (!engine_dir.empty()) {
        const std::wstring candidates[] = {
            engine_dir + L"\\vesper_offsets\\" + widen(build) + L".vtb",
            engine_dir + L"\\" + widen(build) + L".vtb",
        };
        for (const auto& path : candidates) {
            const auto blob = read_file(path);
            if (blob.empty()) continue;
            std::string parse_error;
            if (profile_parse(blob.data(), blob.size(), out, parse_error)) {
                out.source = "disk";
                if (from_disk) *from_disk = true;
                VSP_INFO("offsets: loaded %s from disk (%zu entries)", build.c_str(), out.size());
                return true;
            }
            VSP_WARN("offsets: rejected %s: %s", narrow(path).c_str(), parse_error.c_str());
        }
    }

    for (std::size_t i = 0; i < tables::kTableCount; ++i) {
        const auto& entry = tables::kTables[i];
        if (build != entry.build) continue;
        std::string parse_error;
        if (profile_parse(entry.data, entry.len, out, parse_error)) {
            out.source = "embedded";
            VSP_INFO("offsets: loaded %s from embedded table (%zu entries)", build.c_str(), out.size());
            return true;
        }
        error = vformat("embedded table for %s rejected: %s", build.c_str(), parse_error.c_str());
        return false;
    }

    std::string known;
    for (const auto& name : embedded_builds()) {
        if (!known.empty()) known += ", ";
        known += name;
    }
    error = vformat("no offset table for build '%s' (embedded tables: %s)", build.c_str(),
                    known.empty() ? "none" : known.c_str());
    return false;
}

namespace {

// A build identifier is a `version-<hex>` path component. Extract it from any
// position, not only the immediate parent, because the path a suspended process
// publishes can still be the launcher's rather than the client's.
std::wstring build_component(const std::wstring& path) {
    std::size_t start = 0;
    while (start < path.size()) {
        const std::size_t sep = path.find(L'\\', start);
        const std::wstring part =
            path.substr(start, sep == std::wstring::npos ? std::wstring::npos : sep - start);
        if (part.rfind(L"version-", 0) == 0 && part.size() > 8) return part;
        if (sep == std::wstring::npos) break;
        start = sep + 1;
    }
    return {};
}

}  // namespace

std::string detect_build() {
    std::wstring build = build_component(module_path(nullptr));

    if (build.empty()) {
        // The loader has not published the executable path yet. Reading it from
        // the process itself works while it is still suspended.
        wchar_t path[MAX_PATH * 2] = {};
        DWORD size = static_cast<DWORD>(std::size(path));
        if (QueryFullProcessImageNameW(GetCurrentProcess(), 0, path, &size)) {
            build = build_component(std::wstring(path, size));
        }
    }

    // Deliberately not cached: during a suspended launch the first read can still
    // be the wrong path, and the two-second retry must be free to correct it.
    if (build.empty()) return {};
    return narrow(build);
}

int profile_export_embedded(const std::wstring& directory) {
    if (directory.empty()) return 0;
    const std::wstring target = directory + L"\\vesper_offsets";
    if (!ensure_directory(target)) {
        VSP_WARN("offsets: cannot create %s", narrow(target).c_str());
        return 0;
    }
    int written = 0;
    for (std::size_t i = 0; i < tables::kTableCount; ++i) {
        const auto& entry = tables::kTables[i];
        const std::wstring path = target + L"\\" + widen(entry.build) + L".vtb";
        const auto existing = read_file(path);
        if (existing.size() == entry.len && std::memcmp(existing.data(), entry.data, entry.len) == 0) {
            continue;
        }
        if (write_file(path, entry.data, entry.len)) {
            ++written;
            VSP_INFO("offsets: wrote %zu bytes to %s", entry.len, narrow(path).c_str());
        }
    }
    return written;
}

}  // namespace vesper
