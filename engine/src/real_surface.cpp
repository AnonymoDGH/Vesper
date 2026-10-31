// Real-compatible surface on top of Vesper (see real_surface.hpp).
#include <vesper/real_surface.hpp>

#include <windows.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <mutex>
#include <string>

#include <lua.h>
#include <lualib.h>

#include <vesper/common.hpp>

namespace vesper::realx {
namespace {

// ------------------------------------------------------------------ helpers --

void reg(lua_State* L, const char* name, lua_CFunction fn) {
    lua_pushcclosure(L, fn, name, 0);
    lua_setglobal(L, name);
}

void alias(lua_State* L, const char* from, const char* to) {
    lua_getglobal(L, from);
    if (lua_isfunction(L, -1)) lua_setglobal(L, to);
    else lua_pop(L, 1);
}

void empty_table(lua_State* L) { lua_newtable(L); }

std::string check_str(lua_State* L, int idx, const char* what) {
    size_t len = 0;
    const char* s = luaL_checklstring(L, idx, &len);
    if (!s) luaL_error(L, "%s expected", what);
    return std::string(s, len);
}

// ----------------------------------------------------------------- identity --

int l_identify(lua_State* L) {
    lua_pushstring(L, "Real");
    return 1;
}

int l_name(lua_State* L) {
    lua_pushstring(L, "Real");
    return 1;
}

int l_version(lua_State* L) {
    lua_pushstring(L, "2.7.10-vesper");
    return 1;
}

// -------------------------------------------------------------------- hwid --

std::wstring machine_guid() {
    wchar_t buf[128]{};
    DWORD size = sizeof(buf);
    if (RegGetValueW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", L"MachineGuid",
                     RRF_RT_REG_SZ, nullptr, buf, &size) == ERROR_SUCCESS)
        return buf;
    return L"";
}

std::wstring volume_serial() {
    DWORD serial = 0;
    if (GetVolumeInformationW(L"C:\\", nullptr, 0, &serial, nullptr, nullptr, nullptr, 0))
        return std::to_wstring(serial);
    return L"";
}

std::wstring computer_name() {
    wchar_t buf[256]{};
    DWORD size = 256;
    if (GetComputerNameW(buf, &size)) return std::wstring(buf, size);
    return L"";
}

std::uint64_t fnv1a64(const void* data, size_t len, std::uint64_t h = 1469598103934665603ull) {
    const unsigned char* p = static_cast<const unsigned char*>(data);
    for (size_t i = 0; i < len; ++i) {
        h ^= p[i];
        h *= 1099511628211ull;
    }
    return h;
}

std::string hex64(std::uint64_t v) {
    char buf[17];
    for (int i = 15; i >= 0; --i) {
        buf[i] = "0123456789ABCDEF"[v & 0xF];
        v >>= 4;
    }
    buf[16] = 0;
    return std::string(buf);
}

int l_hwid(lua_State* L) {
    std::wstring seed = machine_guid() + L"|" + volume_serial() + L"|" + computer_name();
    std::string id = hex64(fnv1a64(seed.data(), seed.size() * sizeof(wchar_t)));
    id += hex64(fnv1a64(seed.data(), seed.size() * sizeof(wchar_t), 0xcbf29ce484222325ull));
    lua_pushlstring(L, id.data(), id.size());
    return 1;
}

// -------------------------------------------------------------------- misc --

int l_pid(lua_State* L) {
    lua_pushinteger(L, static_cast<int>(GetCurrentProcessId()));
    return 1;
}

std::mutex g_mutex;
int g_fps_cap = 60;
std::string g_teleport_queue;
std::map<std::string, std::string> g_fflags;

int l_get_fpscap(lua_State* L) {
    std::lock_guard<std::mutex> lock(g_mutex);
    lua_pushinteger(L, g_fps_cap);
    return 1;
}

int l_set_fpscap(lua_State* L) {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_fps_cap = static_cast<int>(luaL_checkinteger(L, 1));
    return 0;
}

bool foreground_is_roblox() {
    HWND fg = GetForegroundWindow();
    if (!fg) return false;
    DWORD pid = 0;
    GetWindowThreadProcessId(fg, &pid);
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return false;
    wchar_t path[MAX_PATH]{};
    DWORD size = MAX_PATH;
    bool found = false;
    if (QueryFullProcessImageNameW(h, 0, path, &size)) {
        std::wstring p(path, size);
        found = p.find(L"RobloxPlayerBeta.exe") != std::wstring::npos ||
                p.find(L"Windows10Universal.exe") != std::wstring::npos;
    }
    CloseHandle(h);
    return found;
}

int l_isrbxactive(lua_State* L) {
    lua_pushboolean(L, foreground_is_roblox());
    return 1;
}

int l_queue_tp(lua_State* L) {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_teleport_queue = check_str(L, 1, "string");
    return 0;
}

int l_clear_queue(lua_State* L) {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_teleport_queue.clear();
    return 0;
}

int l_get_fflag(lua_State* L) {
    std::string name = check_str(L, 1, "string");
    std::lock_guard<std::mutex> lock(g_mutex);
    auto it = g_fflags.find(name);
    if (it == g_fflags.end()) {
        lua_pushnil(L);
        return 1;
    }
    lua_pushlstring(L, it->second.data(), it->second.size());
    return 1;
}

int l_set_fflag(lua_State* L) {
    std::string name = check_str(L, 1, "string");
    std::string value = check_str(L, 2, "string");
    std::lock_guard<std::mutex> lock(g_mutex);
    g_fflags[name] = value;
    return 0;
}

// ----------------------------------------------------------------- closures --

int l_compare(lua_State* L) {
    const void* a = lua_topointer(L, 1);
    const void* b = lua_topointer(L, 2);
    lua_pushboolean(L, a != nullptr && a == b);
    return 1;
}

int l_hash(lua_State* L) {
    const void* p = lua_topointer(L, 1);
    std::uint64_t h = fnv1a64(&p, sizeof(p));
    std::string hex = hex64(h);
    lua_pushlstring(L, hex.data(), hex.size());
    return 1;
}

// --------------------------------------------------------------------- lz4 --

bool lz4_decompress(const std::uint8_t* src, size_t n, std::string& out, size_t max_out) {
    size_t i = 0;
    while (i < n) {
        std::uint8_t token = src[i++];
        size_t lit = token >> 4;
        if (lit == 15) {
            std::uint8_t b;
            do {
                if (i >= n) return false;
                b = src[i++];
                lit += b;
            } while (b == 255);
        }
        if (i + lit > n || out.size() + lit > max_out) return false;
        out.append(reinterpret_cast<const char*>(src) + i, lit);
        i += lit;
        if (i == n) break;
        if (i + 2 > n) return false;
        size_t offset = static_cast<size_t>(src[i]) | (static_cast<size_t>(src[i + 1]) << 8);
        i += 2;
        if (offset == 0 || offset > out.size()) return false;
        size_t match = token & 0xF;
        if (match == 15) {
            std::uint8_t b;
            do {
                if (i >= n) return false;
                b = src[i++];
                match += b;
            } while (b == 255);
        }
        match += 4;
        if (out.size() + match > max_out) return false;
        size_t start = out.size() - offset;
        for (size_t k = 0; k < match; ++k) out.push_back(out[start + k]);
    }
    return true;
}

std::string lz4_compress_literals(const std::string& in) {
    std::string out;
    size_t lit = in.size();
    out.push_back(static_cast<char>((lit < 15 ? lit : 15) << 4));
    if (lit >= 15) {
        size_t rest = lit - 15;
        while (rest >= 255) {
            out.push_back(static_cast<char>(255));
            rest -= 255;
        }
        out.push_back(static_cast<char>(rest));
    }
    out.append(in);
    return out;
}

int l_lz4_compress(lua_State* L) {
    std::string in = check_str(L, 1, "string");
    std::string out = lz4_compress_literals(in);
    lua_pushlstring(L, out.data(), out.size());
    return 1;
}

int l_lz4_decompress(lua_State* L) {
    size_t len = 0;
    const char* s = luaL_checklstring(L, 1, &len);
    size_t max_out = static_cast<size_t>(luaL_optinteger(L, 2, 1 << 26));
    std::string out;
    if (!lz4_decompress(reinterpret_cast<const std::uint8_t*>(s), len, out, max_out))
        luaL_error(L, "invalid LZ4 block");
    lua_pushlstring(L, out.data(), out.size());
    return 1;
}

// ------------------------------------------------------------------- stubs --

int l_nil(lua_State* L) {
    lua_pushnil(L);
    return 1;
}

int l_noop(lua_State* L) { return 0; }

int l_empty(lua_State* L) {
    lua_newtable(L);
    return 1;
}

int l_drawing_new(lua_State* L) {
    lua_pushnil(L);
    return 1;
}

}  // namespace

// ------------------------------------------------------------------- install --

void install(lua_State* L) {
    if (L == nullptr) return;

    // Identity: this build answers as Real on top of the Vesper engine.
    reg(L, "identifyexecutor", l_identify);
    reg(L, "getexecutorname", l_name);
    reg(L, "getexecutorversion", l_version);
    reg(L, "getversion", l_version);

    // snake_case aliases of what Vesper already implements.
    alias(L, "getgenv", "get_genv");
    alias(L, "getrenv", "get_renv");
    alias(L, "getthreadidentity", "get_thread_identity");
    alias(L, "setthreadidentity", "set_thread_identity");
    alias(L, "iscclosure", "is_c_closure");
    alias(L, "islclosure", "is_l_closure");
    alias(L, "isexecutorclosure", "is_executor_closure");
    alias(L, "clonefunction", "clone_function");
    alias(L, "hookfunction", "hook_function");
    alias(L, "newcclosure", "new_c_closure");
    alias(L, "getrawmetatable", "get_raw_metatable");
    alias(L, "setreadonly", "set_readonly");
    alias(L, "isreadonly", "is_readonly");
    alias(L, "hookmetamethod", "hook_meta_method");
    alias(L, "getnamecallmethod", "get_namecall_method");
    alias(L, "setnamecallmethod", "set_namecall_method");
    alias(L, "readfile", "read_file");
    alias(L, "writefile", "write_file");
    alias(L, "appendfile", "append_file");
    alias(L, "isfile", "is_file");
    alias(L, "isfolder", "is_folder");
    alias(L, "listfiles", "list_files");
    alias(L, "delfile", "del_file");
    alias(L, "delfolder", "del_folder");
    alias(L, "setclipboard", "set_clipboard");
    alias(L, "base64encode", "base64_encode");
    alias(L, "base64decode", "base64_decode");

    // New names from the Real surface.
    reg(L, "gettenv", [](lua_State* S) {
        lua_pushvalue(S, LUA_GLOBALSINDEX);
        return 1;
    });
    reg(L, "getreg", [](lua_State* S) {
        lua_pushvalue(S, LUA_REGISTRYINDEX);
        return 1;
    });
    reg(L, "getregistry", [](lua_State* S) {
        lua_pushvalue(S, LUA_REGISTRYINDEX);
        return 1;
    });

    reg(L, "gethwid", l_hwid);
    reg(L, "get_hwid", l_hwid);
    reg(L, "getpid", l_pid);
    reg(L, "get_pid", l_pid);
    reg(L, "getprocessidentifier", l_pid);
    reg(L, "getfpscap", l_get_fpscap);
    reg(L, "get_fps_cap", l_get_fpscap);
    reg(L, "setfpscap", l_set_fpscap);
    reg(L, "set_fps_cap", l_set_fpscap);
    reg(L, "isrbxactive", l_isrbxactive);
    reg(L, "is_rbx_active", l_isrbxactive);
    reg(L, "isgameactive", l_isrbxactive);
    reg(L, "iswindowactive", l_isrbxactive);
    reg(L, "queue_on_teleport", l_queue_tp);
    reg(L, "queueonteleport", l_queue_tp);
    reg(L, "queue_on_tp", l_queue_tp);
    reg(L, "clear_teleport_queue", l_clear_queue);
    reg(L, "clearteleportqueue", l_clear_queue);
    reg(L, "getfflag", l_get_fflag);
    reg(L, "setfflag", l_set_fflag);
    reg(L, "comparefunctions", l_compare);
    reg(L, "compare_functions", l_compare);
    reg(L, "getfunctionhash", l_hash);
    reg(L, "get_function_hash", l_hash);
    reg(L, "lz4compress", l_lz4_compress);
    reg(L, "lz4_compress", l_lz4_compress);
    reg(L, "lz4decompress", l_lz4_decompress);
    reg(L, "lz4_decompress", l_lz4_decompress);

    // Collections that need the garbage collector / script registry. Empty
    // rather than nil so `for _, v in ipairs(getgc())` still works.
    reg(L, "getgc", l_empty);
    reg(L, "get_gc", l_empty);
    reg(L, "get_gc_objects", l_empty);
    reg(L, "filtergc", l_empty);
    reg(L, "filter_gc", l_empty);
    reg(L, "getloadedmodules", l_empty);
    reg(L, "get_loaded_modules", l_empty);
    reg(L, "getrunningscripts", l_empty);
    reg(L, "get_running_scripts", l_empty);
    reg(L, "getscripts", l_empty);
    reg(L, "get_scripts", l_empty);
    reg(L, "getinstances", l_empty);
    reg(L, "getnilinstances", l_empty);
    reg(L, "get_nil_instances", l_empty);
    reg(L, "getscriptglobals", l_empty);
    reg(L, "get_script_globals", l_empty);

    // Roblox internals not bridged yet: registered as nil-returning stubs.
    const char* nil_names[] = {
        "getscriptbytecode", "get_script_bytecode", "getscriptclosure", "get_script_closure",
        "getscripthash", "get_script_hash", "getscriptfunction", "getcallingscript",
        "get_calling_script", "getscriptthread", "get_script_thread", "decompile", "dumpstring",
        "getconnections", "get_connections", "firesignal", "fire_signal", "firetouchinterest",
        "fire_touch_interest", "fireclickdetector", "fire_click_detector",
        "fireproximityprompt", "fire_proximity_prompt",
        "getrenderproperty", "get_render_property", "setrenderproperty", "set_render_property",
        "isrenderobj", "is_render_obj", "gethiddenui", "gethui",
    };
    for (const char* n : nil_names) reg(L, n, l_nil);


    // Drawing: the surface exists, the renderer lives in Vesper's shell overlay.
    lua_newtable(L);
    lua_pushcclosure(L, l_drawing_new, "new", 0);
    lua_setfield(L, -2, "new");
    lua_pushcclosure(L, l_noop, "cleardrawcache", 0);
    lua_setfield(L, -2, "cleardrawcache");
    lua_setglobal(L, "Drawing");

    VSP_INFO("realx: Real surface installed on the Vesper engine");
}

}  // namespace vesper::realx
