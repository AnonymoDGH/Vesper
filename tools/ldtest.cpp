// ldtest: compile a Luau file with the vendored compiler and load it with the
// vendored `luau_load` (raw, no opcode encoding). Isolates wire-format problems
// (child protos / CLOSURE constants) from the client's opcode decode.
#include "lua.h"
#include "Luau/Compiler.h"

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

static void* alloc(void*, void* ptr, size_t, size_t nsize) {
    if (nsize == 0) { std::free(ptr); return nullptr; }
    return std::realloc(ptr, nsize);
}

int main(int argc, char** argv) {
    if (argc < 2) { std::printf("usage: ldtest file.lua\n"); return 2; }
    FILE* f = std::fopen(argv[1], "rb");
    if (!f) { std::printf("cannot open %s\n", argv[1]); return 2; }
    std::string source; char buf[4096]; size_t n;
    while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0) source.append(buf, n);
    std::fclose(f);

    Luau::CompileOptions options{};
    options.optimizationLevel = 1;
    options.debugLevel = 2;
    static const char* kCommonGlobals[] = {"Game", "Workspace", "game", "plugin", "script",
                                           "shared", "workspace", "_G", "_ENV", nullptr};
    options.mutableGlobals = kCommonGlobals;
    options.vectorLib = "Vector3"; options.vectorCtor = "new"; options.vectorType = "Vector3";

    std::string bytecode = Luau::compile(source, options, {});
    std::printf("bytecode %zu bytes\n", bytecode.size());
    std::fflush(stdout);

    lua_State* L = lua_newstate(alloc, nullptr);
    std::printf("newstate %p\n", (void*)L);
    std::fflush(stdout);
    if (!L) { std::printf("no state\n"); return 2; }
    const int rc = luau_load(L, "=test", bytecode.data(), bytecode.size(), 0);
    std::printf("luau_load rc=%d top=%d\n", rc, lua_gettop(L));
    if (rc != 0 && lua_gettop(L) >= 1) {
        const char* s = lua_tostring(L, -1);
        std::printf("error: %s\n", s ? s : "(non-string)");
    }
    lua_close(L);
    return rc == 0 ? 0 : 1;
}
