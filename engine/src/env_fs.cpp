// Vesper -- executor libraries: filesystem, HTTP and system integration.
//
// The filesystem API is rooted at a per-user workspace; every path is resolved
// inside it and rejected when it tries to escape. Network access goes through
// WinHTTP rather than through the game, so it works regardless of what Roblox
// thinks is enabled.
#include <vesper/env.hpp>

#include <algorithm>
#include <cstring>
#include <string>
#include <vector>

#include <windows.h>
#include <wininet.h>

#include <lua.h>
#include <lualib.h>

#include <vesper/common.hpp>
#include <vesper/rbx.hpp>

namespace vesper::env {

namespace {

void reg(lua_State* L, const char* name, lua_CFunction fn) {
    lua_pushcclosure(L, fn, name, 0);
    lua_setglobal(L, name);
}

std::string check_string(lua_State* L, int index) {
    size_t len = 0;
    const char* text = luaL_checklstring(L, index, &len);
    if (text == nullptr) luaL_error(L, "expected a string argument");
    return std::string(text, len);
}

// ------------------------------------------------------------- path safety --

std::wstring workspace_root() {
    static std::wstring cached = rbx::workspace_directory();
    return cached;
}

bool path_is_safe(const std::string& relative) {
    if (relative.empty()) return false;
    if (relative.find("..") != std::string::npos) return false;
    if (relative.find(':') != std::string::npos) return false;
    if (relative.find("//") != std::string::npos) return false;
    return true;
}

std::wstring resolve(const std::string& relative) {
    if (!path_is_safe(relative)) return {};
    std::wstring out = workspace_root();
    std::wstring wide = widen(relative);
    for (auto& character : wide) {
        if (character == L'/') character = L'\\';
    }
    out += L"\\";
    out += wide;
    return out;
}

void ensure_parent(const std::wstring& path) {
    const std::wstring parent = directory_of(path);
    if (!parent.empty()) ensure_directory(parent);
}

// ---------------------------------------------------------- filesystem api --

int l_writefile(lua_State* L) {
    const std::string name = check_string(L, 1);
    const std::string content = check_string(L, 2);
    const std::wstring path = resolve(name);
    if (path.empty()) luaL_error(L, "invalid path: %s", name.c_str());
    ensure_parent(path);
    if (!write_file(path, content.data(), content.size())) {
        luaL_error(L, "could not write %s", name.c_str());
    }
    return 0;
}

int l_appendfile(lua_State* L) {
    const std::string name = check_string(L, 1);
    const std::string content = check_string(L, 2);
    const std::wstring path = resolve(name);
    if (path.empty()) luaL_error(L, "invalid path: %s", name.c_str());
    ensure_parent(path);

    const HANDLE file = CreateFileW(path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ, nullptr,
                                    OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) luaL_error(L, "could not open %s", name.c_str());
    DWORD written = 0;
    const BOOL ok = content.empty()
                        ? TRUE
                        : WriteFile(file, content.data(), static_cast<DWORD>(content.size()), &written,
                                    nullptr);
    CloseHandle(file);
    if (!ok) luaL_error(L, "could not append to %s", name.c_str());
    return 0;
}

int l_readfile(lua_State* L) {
    const std::string name = check_string(L, 1);
    const std::wstring path = resolve(name);
    if (path.empty()) luaL_error(L, "invalid path: %s", name.c_str());
    const auto data = read_file(path);
    lua_pushlstring(L, reinterpret_cast<const char*>(data.data()), data.size());
    return 1;
}

int l_isfile(lua_State* L) {
    const std::wstring path = resolve(check_string(L, 1));
    lua_pushboolean(L, !path.empty() && file_exists(path));
    return 1;
}

int l_isfolder(lua_State* L) {
    const std::wstring path = resolve(check_string(L, 1));
    lua_pushboolean(L, !path.empty() && directory_exists(path));
    return 1;
}

int l_makefolder(lua_State* L) {
    const std::wstring path = resolve(check_string(L, 1));
    if (path.empty()) luaL_error(L, "invalid path");
    ensure_directory(path);
    return 0;
}

int l_delfile(lua_State* L) {
    const std::wstring path = resolve(check_string(L, 1));
    if (path.empty()) luaL_error(L, "invalid path");
    DeleteFileW(path.c_str());
    return 0;
}

int l_delfolder(lua_State* L) {
    const std::wstring path = resolve(check_string(L, 1));
    if (path.empty()) luaL_error(L, "invalid path");
    RemoveDirectoryW(path.c_str());
    return 0;
}

int l_listfiles(lua_State* L) {
    const std::wstring path = resolve(check_string(L, 1));
    if (path.empty()) luaL_error(L, "invalid path");

    lua_newtable(L);
    int index = 1;

    WIN32_FIND_DATAW entry{};
    const std::wstring pattern = path + L"\\*";
    const HANDLE find = FindFirstFileW(pattern.c_str(), &entry);
    if (find == INVALID_HANDLE_VALUE) return 1;

    const std::wstring prefix = widen(check_string(L, 1));
    do {
        if (std::wcscmp(entry.cFileName, L".") == 0) continue;
        if (std::wcscmp(entry.cFileName, L"..") == 0) continue;
        const std::string base = narrow(prefix + L"\\" + entry.cFileName);
        lua_pushstring(L, base.c_str());
        lua_rawseti(L, -2, index++);
    } while (FindNextFileW(find, &entry));
    FindClose(find);
    return 1;
}

// ------------------------------------------------------------------ base64 --

const char kB64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string base64_encode(const std::string& input) {
    std::string out;
    out.reserve(((input.size() + 2) / 3) * 4);
    std::size_t i = 0;
    while (i + 2 < input.size()) {
        const unsigned value = (static_cast<unsigned char>(input[i]) << 16) |
                               (static_cast<unsigned char>(input[i + 1]) << 8) |
                               static_cast<unsigned char>(input[i + 2]);
        out.push_back(kB64[(value >> 18) & 63]);
        out.push_back(kB64[(value >> 12) & 63]);
        out.push_back(kB64[(value >> 6) & 63]);
        out.push_back(kB64[value & 63]);
        i += 3;
    }
    if (i < input.size()) {
        unsigned value = static_cast<unsigned char>(input[i]) << 16;
        const bool two = i + 1 < input.size();
        if (two) value |= static_cast<unsigned char>(input[i + 1]) << 8;
        out.push_back(kB64[(value >> 18) & 63]);
        out.push_back(kB64[(value >> 12) & 63]);
        out.push_back(two ? kB64[(value >> 6) & 63] : '=');
        out.push_back('=');
    }
    return out;
}

std::string base64_decode(const std::string& input) {
    int table[256];
    std::memset(table, -1, sizeof(table));
    for (int i = 0; i < 64; ++i) table[static_cast<unsigned char>(kB64[i])] = i;

    std::string out;
    unsigned buffer = 0;
    int bits = 0;
    for (unsigned char character : input) {
        if (character == '=') break;
        const int value = table[character];
        if (value < 0) continue;
        buffer = (buffer << 6) | static_cast<unsigned>(value);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<char>((buffer >> bits) & 0xff));
        }
    }
    return out;
}

int l_base64encode(lua_State* L) {
    const std::string text = check_string(L, 1);
    const std::string encoded = base64_encode(text);
    lua_pushlstring(L, encoded.data(), encoded.size());
    return 1;
}

int l_base64decode(lua_State* L) {
    const std::string text = check_string(L, 1);
    const std::string decoded = base64_decode(text);
    lua_pushlstring(L, decoded.data(), decoded.size());
    return 1;
}

// ------------------------------------------------------------------- HTTP --
//
// WinINet rather than WinHTTP, deliberately. The engine is loaded into a process
// it does not own, and that process's loader will not pull in a module that is not
// already there: winhttp.dll is exactly such a module, while wininet.dll is loaded
// by the client itself. Same handle-based shape, same HTTPS support, one fewer
// thing the host has to tolerate.

struct Url {
    std::wstring host;
    std::wstring path;
    std::uint16_t port = 0;
    bool secure = false;
};

bool parse_url(const std::string& url, Url& out, std::string& error) {
    const std::wstring wide = widen(url);
    URL_COMPONENTSW components{};
    components.dwStructSize = sizeof(components);
    components.dwSchemeLength = static_cast<DWORD>(-1);
    components.dwHostNameLength = static_cast<DWORD>(-1);
    components.dwUrlPathLength = static_cast<DWORD>(-1);
    // WinINet splits the query off the path, unlike WinHTTP where the path
    // component carries it; both halves have to be put back together.
    components.dwExtraInfoLength = static_cast<DWORD>(-1);

    if (!InternetCrackUrlW(wide.c_str(), static_cast<DWORD>(wide.size()), 0, &components)) {
        error = "malformed url";
        return false;
    }
    if (components.lpszHostName == nullptr || components.dwHostNameLength == 0) {
        error = "url has no host";
        return false;
    }

    out.host.assign(components.lpszHostName, components.dwHostNameLength);
    if (components.lpszUrlPath != nullptr) {
        out.path.assign(components.lpszUrlPath, components.dwUrlPathLength);
    }
    if (components.lpszExtraInfo != nullptr && components.dwExtraInfoLength > 0) {
        out.path.append(components.lpszExtraInfo, components.dwExtraInfoLength);
    }
    if (out.path.empty()) out.path = L"/";
    out.port = components.nPort;
    out.secure = components.nScheme == INTERNET_SCHEME_HTTPS;
    return true;
}

struct HttpResponse {
    int status = 0;
    std::string headers;
    std::string body;
};

bool http_request(const std::string& method, const std::string& url,
                  const std::vector<std::pair<std::string, std::string>>& headers,
                  const std::string& body, HttpResponse& out, std::string& error) {
    Url parsed;
    if (!parse_url(url, parsed, error)) return false;

    HINTERNET session =
        InternetOpenW(L"Vesper/3.0", INTERNET_OPEN_TYPE_PRECONFIG, nullptr, nullptr, 0);
    if (session == nullptr) {
        error = vformat("InternetOpen failed (%lu)", GetLastError());
        return false;
    }

    const struct {
        DWORD option;
        DWORD value;
    } timeouts[] = {
        {INTERNET_OPTION_CONNECT_TIMEOUT, 8000},
        {INTERNET_OPTION_SEND_TIMEOUT, 8000},
        {INTERNET_OPTION_RECEIVE_TIMEOUT, 15000},
    };
    for (const auto& entry : timeouts) {
        DWORD value = entry.value;
        InternetSetOptionW(session, entry.option, &value, sizeof(value));
    }

    const std::uint16_t port = parsed.port != 0
                                   ? parsed.port
                                   : static_cast<std::uint16_t>(parsed.secure ? INTERNET_DEFAULT_HTTPS_PORT
                                                                              : INTERNET_DEFAULT_HTTP_PORT);
    HINTERNET connection = InternetConnectW(session, parsed.host.c_str(), port, nullptr, nullptr,
                                            INTERNET_SERVICE_HTTP, 0, 0);
    if (connection == nullptr) {
        InternetCloseHandle(session);
        error = vformat("InternetConnect failed (%lu)", GetLastError());
        return false;
    }

    DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_UI;
    if (parsed.secure) flags |= INTERNET_FLAG_SECURE;

    const std::wstring method_wide = widen(method);
    HINTERNET request = HttpOpenRequestW(connection, method_wide.c_str(), parsed.path.c_str(),
                                         nullptr, nullptr, nullptr, flags, 0);
    if (request == nullptr) {
        InternetCloseHandle(connection);
        InternetCloseHandle(session);
        error = vformat("HttpOpenRequest failed (%lu)", GetLastError());
        return false;
    }

    std::wstring header_block;
    for (const auto& [key, value] : headers) {
        header_block += widen(key) + L": " + widen(value) + L"\r\n";
    }

    const BOOL sent = HttpSendRequestW(
        request, header_block.empty() ? nullptr : header_block.c_str(),
        static_cast<DWORD>(header_block.size()), body.empty() ? nullptr : const_cast<char*>(body.data()),
        static_cast<DWORD>(body.size()));

    if (!sent) {
        error = vformat("request failed (%lu)", GetLastError());
        InternetCloseHandle(request);
        InternetCloseHandle(connection);
        InternetCloseHandle(session);
        return false;
    }

    DWORD status = 0;
    DWORD status_size = sizeof(status);
    HttpQueryInfoW(request, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &status, &status_size,
                   nullptr);
    out.status = static_cast<int>(status);

    DWORD header_size = 0;
    HttpQueryInfoW(request, HTTP_QUERY_RAW_HEADERS_CRLF, nullptr, &header_size, nullptr);
    if (header_size > 0) {
        std::wstring raw(header_size / sizeof(wchar_t) + 1, L'\0');
        if (HttpQueryInfoW(request, HTTP_QUERY_RAW_HEADERS_CRLF, raw.data(), &header_size, nullptr)) {
            raw.resize(header_size / sizeof(wchar_t));
            out.headers = narrow(raw);
        }
    }

    char buffer[8192];
    DWORD read = 0;
    while (InternetReadFile(request, buffer, sizeof(buffer), &read) && read > 0) {
        out.body.append(buffer, read);
        if (out.body.size() > (16u << 20)) break;
    }

    InternetCloseHandle(request);
    InternetCloseHandle(connection);
    InternetCloseHandle(session);
    return true;
}

int l_request(lua_State* L) {
    luaL_checktype(L, 1, LUA_TTABLE);

    lua_getfield(L, 1, "Url");
    if (lua_isnil(L, -1)) {
        lua_pop(L, 1);
        lua_getfield(L, 1, "url");
    }
    std::string url;
    if (lua_isstring(L, -1)) url = lua_tostring(L, -1);
    lua_pop(L, 1);
    if (url.empty()) luaL_error(L, "request: Url is required");

    std::string method = "GET";
    lua_getfield(L, 1, "Method");
    if (lua_isnil(L, -1)) {
        lua_pop(L, 1);
        lua_getfield(L, 1, "method");
    }
    if (lua_isstring(L, -1)) method = lua_tostring(L, -1);
    lua_pop(L, 1);
    for (auto& character : method) character = static_cast<char>(toupper(character));

    std::string body;
    lua_getfield(L, 1, "Body");
    if (lua_isnil(L, -1)) {
        lua_pop(L, 1);
        lua_getfield(L, 1, "body");
    }
    if (lua_isstring(L, -1)) body = lua_tostring(L, -1);
    lua_pop(L, 1);

    std::vector<std::pair<std::string, std::string>> headers;
    lua_getfield(L, 1, "Headers");
    if (lua_isnil(L, -1)) {
        lua_pop(L, 1);
        lua_getfield(L, 1, "headers");
    }
    if (lua_istable(L, -1)) {
        lua_pushnil(L);
        while (lua_next(L, -2) != 0) {
            lua_pop(L, 1);
            const char* key = lua_tostring(L, -1);
            lua_pushvalue(L, -1);
            lua_gettable(L, -3);
            const char* value = lua_tostring(L, -1);
            if (key != nullptr && value != nullptr) headers.emplace_back(key, value);
            lua_pop(L, 2);
        }
    }
    lua_pop(L, 1);

    HttpResponse response;
    std::string error;
    if (!http_request(method, url, headers, body, response, error)) {
        lua_pushnil(L);
        lua_pushstring(L, error.c_str());
        return 2;
    }

    lua_newtable(L);
    lua_pushinteger(L, response.status);
    lua_setfield(L, -2, "StatusCode");
    lua_pushstring(L, "OK");
    lua_setfield(L, -2, "StatusMessage");
    lua_pushstring(L, response.headers.c_str());
    lua_setfield(L, -2, "Headers");
    lua_pushlstring(L, response.body.data(), response.body.size());
    lua_setfield(L, -2, "Body");
    lua_pushboolean(L, 1);
    lua_setfield(L, -2, "Success");
    return 1;
}

int l_getcustomasset(lua_State* L) {
    const std::string name = check_string(L, 1);
    const std::wstring path = resolve(name);
    if (path.empty() || !file_exists(path)) {
        luaL_error(L, "getcustomasset: %s does not exist in the workspace", name.c_str());
    }

    const std::uint16_t port = bridge_port();
    if (port == 0) {
        luaL_error(L, "getcustomasset: bridge is not listening");
    }

    // Assets are served from the workspace root, so the returned URL is just the
    // file the caller already named.
    std::string relative = name;
    for (auto& character : relative) {
        if (character == '\\') character = '/';
    }
    const std::string url = vformat("http://127.0.0.1:%u/asset/%s", port, relative.c_str());
    lua_pushstring(L, url.c_str());
    return 1;
}

// --------------------------------------------------------------- system api --

int l_setclipboard(lua_State* L) {
    const std::string text = check_string(L, 1);
    const std::wstring wide = widen(text);
    if (!OpenClipboard(nullptr)) return 0;
    EmptyClipboard();
    const std::size_t bytes = (wide.size() + 1) * sizeof(wchar_t);
    if (HGLOBAL memory = GlobalAlloc(GMEM_MOVEABLE, bytes)) {
        if (void* target = GlobalLock(memory)) {
            std::memcpy(target, wide.c_str(), bytes);
            GlobalUnlock(memory);
            SetClipboardData(CF_UNICODETEXT, memory);
        }
    }
    CloseClipboard();
    return 0;
}

int l_messagebox(lua_State* L) {
    const std::string text = check_string(L, 1);
    lua_pushinteger(L, MessageBoxW(nullptr, widen(text).c_str(), L"Vesper", MB_OK | MB_ICONINFORMATION));
    return 1;
}

}  // namespace

void register_filesystem(lua_State* L) {
    ensure_directory(workspace_root());

    reg(L, "writefile", l_writefile);
    reg(L, "appendfile", l_appendfile);
    reg(L, "readfile", l_readfile);
    reg(L, "isfile", l_isfile);
    reg(L, "isfolder", l_isfolder);
    reg(L, "makefolder", l_makefolder);
    reg(L, "delfile", l_delfile);
    reg(L, "delfolder", l_delfolder);
    reg(L, "listfiles", l_listfiles);
}

void register_network(lua_State* L) {
    reg(L, "request", l_request);
    reg(L, "http_request", l_request);
    reg(L, "getcustomasset", l_getcustomasset);
}

void register_system(lua_State* L) {
    reg(L, "setclipboard", l_setclipboard);
    reg(L, "toclipboard", l_setclipboard);
    reg(L, "messagebox", l_messagebox);
    reg(L, "base64encode", l_base64encode);
    reg(L, "base64decode", l_base64decode);
}

}  // namespace vesper::env
