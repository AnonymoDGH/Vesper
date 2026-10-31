// Vesper -- executor environment: runtime, closures, identity and console.
//
// Layout mirrors the proven arrangement: the thread's globals become a proxy
// that reads through to Roblox's real globals, libraries are registered into the
// first proxy and then a second proxy is installed over the top. The registered
// functions therefore become effectively read-only while user scripts still get
// a writable global table of their own.
#include <vesper/env.hpp>

#include <map>
#include <mutex>
#include <string>
#include <vector>

#include <lua.h>
#include <lualib.h>
#include <lstate.h>
#include <lobject.h>
#include <lapi.h>
#include <ldo.h>
#include <lfunc.h>
#include <lstring.h>

#include <vesper/common.hpp>
#include <vesper/guard.hpp>
#include <vesper/real_surface.hpp>
#include <vesper/rbx.hpp>

namespace vesper::env {

// Implemented in env_fs.cpp.
void register_filesystem(lua_State* L);
void register_network(lua_State* L);
void register_system(lua_State* L);

namespace {

lua_State* g_thread = nullptr;
lua_State* g_main = nullptr;

// Registry key for the shared executor globals.
char g_genv_key = 'v';
char g_thread_key = 't';

std::mutex g_output_mutex;
std::map<std::string, std::string> g_output;
std::string g_current_tag;

std::mutex g_result_mutex;
std::map<std::string, Outcome> g_results;

std::uint16_t g_bridge_port = 0;

// ------------------------------------------------------------------ helpers --

void reg(lua_State* L, const char* name, lua_CFunction fn) {
    lua_pushcclosure(L, fn, name, 0);
    lua_setglobal(L, name);
}

std::string to_string_at(lua_State* L, int index) {
    switch (lua_type(L, index)) {
        case LUA_TNIL:
            return "nil";
        case LUA_TBOOLEAN:
            return lua_toboolean(L, index) ? "true" : "false";
        case LUA_TNUMBER:
        case LUA_TSTRING: {
            const char* text = lua_tostring(L, index);
            return text ? text : "";
        }
        default: {
            const char* text = lua_typename(L, lua_type(L, index));
            char buffer[64];
            snprintf(buffer, sizeof(buffer), "%s: %p", text ? text : "?",
                     lua_topointer(L, index));
            return buffer;
        }
    }
}

std::string check_string(lua_State* L, int index, const char* name) {
    size_t len = 0;
    const char* text = luaL_checklstring(L, index, &len);
    if (text == nullptr) luaL_error(L, "%s must be a string", name);
    return std::string(text, len);
}

bool closure_is_c(Closure* closure) { return closure != nullptr && closure->isC != 0; }

Closure* closure_at(lua_State* L, int index) {
    if (lua_type(L, index) != LUA_TFUNCTION) return nullptr;
    const TValue* value = luaA_toobject(L, index);
    return value == nullptr ? nullptr : clvalue(value);
}

void append_output(const std::string& text) {
    std::lock_guard<std::mutex> guard(g_output_mutex);
    if (g_current_tag.empty()) return;
    std::string& sink = g_output[g_current_tag];
    if (sink.size() > (1u << 20)) return;
    sink += text;
    sink += "\n";
}

// --------------------------------------------------------------- libraries --

int l_identifyexecutor(lua_State* L) {
    lua_pushstring(L, "Vesper");
    lua_pushstring(L, "3.0.0");
    return 2;
}

int l_getexecutorname(lua_State* L) {
    lua_pushstring(L, "Vesper");
    return 1;
}

int l_getversion(lua_State* L) {
    lua_pushstring(L, "3.0.0");
    return 1;
}

int l_getgenv(lua_State* L) {
    lua_pushlightuserdata(L, &g_genv_key);
    lua_gettable(L, LUA_REGISTRYINDEX);
    if (!lua_istable(L, -1)) {
        lua_pop(L, 1);
        lua_newtable(L);
        lua_pushvalue(L, -1);
        lua_pushlightuserdata(L, &g_genv_key);
        lua_insert(L, -2);
        lua_settable(L, LUA_REGISTRYINDEX);
    }
    return 1;
}

int l_getrenv(lua_State* L) {
    lua_State* source = g_main != nullptr ? g_main : L;
    lua_pushvalue(source, LUA_GLOBALSINDEX);
    return 1;
}

int l_getthreadidentity(lua_State* L) {  // luacheck: ignore
    const int identity = rbx::get_thread_identity(L);
    if (identity < 0) {
        lua_pushinteger(L, 2);
        return 1;
    }
    lua_pushinteger(L, identity);
    return 1;
}

int l_setthreadidentity(lua_State* L) {  // luacheck: ignore
    const int identity = static_cast<int>(luaL_checkinteger(L, 1));
    if (!rbx::set_thread_identity(L, identity)) {
        lua_pushboolean(L, 0);
        return 1;
    }
    lua_pushboolean(L, 1);
    return 1;
}

int l_checkcaller(lua_State* L) {  // luacheck: ignore
    lua_pushboolean(L, L == g_thread);
    return 1;
}

int l_iscclosure(lua_State* L) {
    Closure* closure = closure_at(L, 1);
    lua_pushboolean(L, closure != nullptr && closure_is_c(closure));
    return 1;
}

int l_islclosure(lua_State* L) {
    Closure* closure = closure_at(L, 1);
    lua_pushboolean(L, closure != nullptr && !closure_is_c(closure));
    return 1;
}

int l_isexecutorclosure(lua_State* L) {
    Closure* closure = closure_at(L, 1);
    if (closure == nullptr || closure_is_c(closure)) {
        lua_pushboolean(L, 0);
        return 1;
    }
    // A closure belongs to the executor when its environment chain reaches the
    // registration proxy rather than Roblox's own globals.
    lua_pushboolean(L, closure->env != nullptr);
    return 1;
}

int l_clonefunction(lua_State* L) {
    luaL_checktype(L, 1, LUA_TFUNCTION);
    // Luau's own clone shares the prototype and copies the value slots, so the
    // clone can write its own upvalues without disturbing the original.
    lua_pushvalue(L, 1);
    lua_clonefunction(L, -1);
    return 1;
}

int l_hookfunction(lua_State* L) {
    luaL_checktype(L, 1, LUA_TFUNCTION);
    luaL_checktype(L, 2, LUA_TFUNCTION);

    Closure* target = closure_at(L, 1);
    Closure* hook = closure_at(L, 2);
    if (target == nullptr || hook == nullptr) {
        luaL_error(L, "hookfunction expects two functions");
    }

    lua_pushvalue(L, 2);  // copy of the hook, becomes the returned original
    const TValue* copy_value = luaA_toobject(L, -1);
    Closure* copy = copy_value == nullptr ? nullptr : clvalue(copy_value);
    if (copy == nullptr) luaL_error(L, "hookfunction could not copy the hook");

    const bool target_is_c = closure_is_c(target);
    if (target_is_c != closure_is_c(hook)) {
        luaL_error(L, "hookfunction requires both closures to be of the same kind");
    }

    if (target_is_c) {
        lua_CFunction original = target->c.f;
        const char* name = target->c.debugname;
        target->c.f = hook->c.f;
        copy->c.f = original;
        copy->c.debugname = name;
    } else {
        Proto* original = target->l.p;
        LuaTable* env = target->env;
        target->l.p = hook->l.p;
        copy->l.p = original;
        copy->env = env;
    }

    return 1;
}

int l_newcclosure_call(lua_State* L) {
    const int count = lua_gettop(L);
    lua_pushvalue(L, lua_upvalueindex(1));
    lua_insert(L, 1);
    lua_call(L, count, LUA_MULTRET);
    return lua_gettop(L);
}

int l_newcclosure(lua_State* L) {
    luaL_checktype(L, 1, LUA_TFUNCTION);
    if (lua_type(L, 1) == LUA_TFUNCTION && closure_is_c(closure_at(L, 1))) {
        lua_pushvalue(L, 1);
        return 1;
    }
    lua_pushvalue(L, 1);
    lua_pushcclosure(L, l_newcclosure_call, "newcclosure", 1);
    return 1;
}

int l_getrawmetatable(lua_State* L) {
    luaL_checkany(L, 1);
    if (!lua_getmetatable(L, 1)) lua_pushnil(L);
    return 1;
}

int l_setreadonly(lua_State* L) {
    luaL_checkany(L, 1);
    lua_setreadonly(L, 1, lua_toboolean(L, 2));
    lua_pushvalue(L, 1);
    return 1;
}

int l_isreadonly(lua_State* L) {
    luaL_checkany(L, 1);
    lua_pushboolean(L, lua_getreadonly(L, 1));
    return 1;
}

int l_hookmetamethod(lua_State* L) {
    luaL_checkany(L, 1);
    const std::string name = check_string(L, 2, "metamethod");
    luaL_checktype(L, 3, LUA_TFUNCTION);

    if (!lua_getmetatable(L, 1)) {
        lua_pushnil(L);
        return 1;
    }

    const bool was_readonly = lua_getreadonly(L, -1) != 0;
    lua_setreadonly(L, -1, false);

    lua_getfield(L, -1, name.c_str());
    if (lua_type(L, -1) != LUA_TFUNCTION) {
        lua_pop(L, 1);
        lua_pushvalue(L, 3);
        lua_setfield(L, -2, name.c_str());
        lua_pushnil(L);
    } else {
        Closure* original = closure_at(L, -1);
        Closure* hook = closure_at(L, 3);
        lua_remove(L, -2);  // metatable
        if (original != nullptr && hook != nullptr &&
            closure_is_c(original) == closure_is_c(hook)) {
            if (closure_is_c(original)) {
                original->c.f = hook->c.f;
            } else {
                original->l.p = hook->l.p;
            }
        }
    }

    if (was_readonly) lua_setreadonly(L, -1, true);
    return 1;
}

int l_getnamecallmethod(lua_State* L) {
    if (L->namecall == nullptr) {
        lua_pushnil(L);
        return 1;
    }
    lua_pushstring(L, L->namecall->data);
    return 1;
}

int l_setnamecallmethod(lua_State* L) {
    const std::string name = check_string(L, 1, "method");
    lua_pushstring(L, name.c_str());
    L->namecall = tsvalue(luaA_toobject(L, -1));
    lua_pop(L, 1);
    return 0;
}

int l_print(lua_State* L) {
    const int count = lua_gettop(L);
    std::string line;
    for (int i = 1; i <= count; ++i) {
        if (i > 1) line += '\t';
        line += to_string_at(L, i);
    }
    append_output(line);

    lua_pushvalue(L, lua_upvalueindex(1));
    lua_insert(L, 1);
    lua_call(L, count, 0);
    return 0;
}

int l_warn(lua_State* L) {
    const int count = lua_gettop(L);
    std::string line;
    for (int i = 1; i <= count; ++i) {
        if (i > 1) line += ' ';
        line += to_string_at(L, i);
    }
    append_output(line);
    return 0;
}

int l_rconsoleprint(lua_State* L) {
    const int count = lua_gettop(L);
    std::string text;
    for (int i = 1; i <= count; ++i) text += to_string_at(L, i);
    append_output(text);
    VSP_INFO("[script] %s", text.c_str());
    return 0;
}

int l_rconsolewarn(lua_State* L) {
    const int count = lua_gettop(L);
    std::string text;
    for (int i = 1; i <= count; ++i) text += to_string_at(L, i);
    append_output(text);
    VSP_WARN("[script] %s", text.c_str());
    return 0;
}

int l_rconsoleerr(lua_State* L) {
    const int count = lua_gettop(L);
    std::string text;
    for (int i = 1; i <= count; ++i) text += to_string_at(L, i);
    append_output(text);
    VSP_ERROR("[script] %s", text.c_str());
    return 0;
}

int l_rconsoleclear(lua_State* L) {
    (void)L;
    return 0;
}

int l_rconsolename(lua_State* L) {
    (void)L;
    return 0;
}

int l_begin(lua_State* L) {
    const std::string tag = check_string(L, 1, "tag");
    {
        std::lock_guard<std::mutex> guard(g_output_mutex);
        g_current_tag = tag;
        g_output[tag].clear();
    }
    return 0;
}

int l_finish(lua_State* L) {
    const std::string tag = check_string(L, 1, "tag");
    const bool ok = lua_toboolean(L, 2) != 0;
    std::string message;
    if (lua_gettop(L) >= 3 && !lua_isnil(L, 3)) message = to_string_at(L, 3);

    std::string captured;
    {
        std::lock_guard<std::mutex> guard(g_output_mutex);
        const auto it = g_output.find(tag);
        if (it != g_output.end()) captured = it->second;
        if (g_current_tag == tag) g_current_tag.clear();
    }

    Outcome outcome;
    outcome.done = true;
    outcome.ok = ok;
    outcome.message = captured;
    if (!ok) {
        if (!message.empty()) outcome.message = message;
        else if (captured.empty()) outcome.message = "script failed";
    } else if (captured.empty()) {
        outcome.message = message;
    }
    outcome.finished_at = now_ms();

    {
        std::lock_guard<std::mutex> guard(g_result_mutex);
        g_results[tag] = outcome;
    }
    return 0;
}

void register_core(lua_State* L) {
    reg(L, "identifyexecutor", l_identifyexecutor);
    reg(L, "getexecutorname", l_getexecutorname);
    reg(L, "getversion", l_getversion);

    reg(L, "getgenv", l_getgenv);
    reg(L, "getrenv", l_getrenv);
    reg(L, "getthreadidentity", l_getthreadidentity);
    reg(L, "setthreadidentity", l_setthreadidentity);
    reg(L, "getidentity", l_getthreadidentity);
    reg(L, "setidentity", l_setthreadidentity);
    reg(L, "checkcaller", l_checkcaller);

    reg(L, "iscclosure", l_iscclosure);
    reg(L, "islclosure", l_islclosure);
    reg(L, "isexecutorclosure", l_isexecutorclosure);
    reg(L, "checkclosure", l_isexecutorclosure);
    reg(L, "clonefunction", l_clonefunction);
    reg(L, "hookfunction", l_hookfunction);
    reg(L, "newcclosure", l_newcclosure);
    reg(L, "getrawmetatable", l_getrawmetatable);
    reg(L, "setreadonly", l_setreadonly);
    reg(L, "isreadonly", l_isreadonly);
    reg(L, "hookmetamethod", l_hookmetamethod);
    reg(L, "getnamecallmethod", l_getnamecallmethod);
    reg(L, "setnamecallmethod", l_setnamecallmethod);

    reg(L, "rconsoleprint", l_rconsoleprint);
    reg(L, "rconsolewarn", l_rconsolewarn);
    reg(L, "rconsoleerr", l_rconsoleerr);
    reg(L, "rconsoleclear", l_rconsoleclear);
    reg(L, "rconsolename", l_rconsolename);

    // Internal: driven by the dispatch wrapper.
    reg(L, "__vesper_begin", l_begin);
    reg(L, "__vesper_finish", l_finish);
}

// `print` is replaced by a tee so script output is both captured and forwarded
// to the host console the user normally reads.
void install_print(lua_State* L) {
    lua_getglobal(L, "print");
    if (lua_type(L, -1) != LUA_TFUNCTION) {
        lua_pop(L, 1);
        lua_pushnil(L);
    }
    lua_pushcclosure(L, l_print, "print", 1);
    lua_setglobal(L, "print");

    lua_pushcclosure(L, l_warn, "warn", 0);
    lua_setglobal(L, "warn");
}

}  // namespace

// ------------------------------------------------------------------ public --

lua_State* exploit_thread() { return g_thread; }

void set_bridge_port(std::uint16_t port) { g_bridge_port = port; }
std::uint16_t bridge_port() { return g_bridge_port; }

void set_pending(const std::string& tag) {
    Outcome outcome;
    outcome.finished_at = now_ms();  // doubles as the dispatch timestamp
    std::lock_guard<std::mutex> guard(g_result_mutex);
    g_results[tag] = outcome;
}

bool take_outcome(const std::string& tag, Outcome& out) {
    std::lock_guard<std::mutex> guard(g_result_mutex);
    const auto it = g_results.find(tag);
    if (it == g_results.end() || !it->second.done) return false;
    out = it->second;
    g_results.erase(it);
    return true;
}

void complete(const std::string& tag, bool ok, const std::string& message) {
    Outcome outcome;
    outcome.done = true;
    outcome.ok = ok;
    outcome.message = message;
    outcome.finished_at = now_ms();
    std::lock_guard<std::mutex> guard(g_result_mutex);
    g_results[tag] = outcome;
}

void expire_pending(std::int64_t older_than_ms) {
    const std::int64_t now = now_ms();
    std::lock_guard<std::mutex> guard(g_result_mutex);
    for (auto it = g_results.begin(); it != g_results.end();) {
        if (!it->second.done && now - it->second.finished_at > older_than_ms) it = g_results.erase(it);
        else ++it;
    }
}

std::string take_output(const std::string& tag) {
    std::lock_guard<std::mutex> guard(g_output_mutex);
    const auto it = g_output.find(tag);
    if (it == g_output.end()) return {};
    std::string text = it->second;
    g_output.erase(it);
    return text;
}

void install(lua_State* L) {
    if (L == nullptr) return;
    if (g_thread != nullptr) return;

    g_main = L;

    lua_State* thread = lua_newthread(L);
    lua_pop(L, 1);
    if (thread == nullptr) {
        VSP_ERROR("env: lua_newthread failed");
        return;
    }
    g_thread = thread;

    luaL_sandboxthread(thread);

    register_core(thread);
    register_filesystem(thread);
    register_network(thread);
    register_system(thread);

    luaL_sandboxthread(thread);

    lua_newtable(thread);
    lua_setglobal(thread, "_G");

    lua_newtable(thread);
    lua_setglobal(thread, "shared");

    install_print(thread);

    realx::install(thread);

    rbx::set_thread_identity(thread, 8);

    VSP_INFO("env: executor thread ready (%p, identity %d)",
             static_cast<void*>(thread), rbx::get_thread_identity(thread));
}

}  // namespace vesper::env
