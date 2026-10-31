// Vesper -- Roblox runtime ABI binding for the statically linked Luau VM.
//
// The Luau sources this project links are Roblox's own (patched) sources: they
// are written against Roblox's internal object layouts. Instead of hardcoding
// the per-build numbers the patches originally expected, every build-specific
// symbol below is an ordinary variable that `vesper::abi::bind()` fills in at
// attach time from the loaded offset table.
//
// The two data anchors and the interpreter entry point are the *entire*
// surface where the linked VM touches the host build. That is what makes the
// same binary work across Roblox updates.
#pragma once

#include <cstdint>

struct lua_State;

namespace Offsets::Luau {
// Address of the host build's shared nil object (`luaO_nilobject`). Luau
// compares against this pointer, so it must be the host's instance and not the
// copy the linked VM defines.
inline std::uintptr_t LuaO_NilObject = 0;

// Address of the host build's shared dummy hash node (`luaH_dummynode`).
inline std::uintptr_t LuaH_DummyNode = 0;
}  // namespace Offsets::Luau

namespace Roblox {
// The host build's bytecode interpreter. `luau_execute` in the linked VM is a
// trampoline onto this so that execution always runs Roblox's own
// implementation against Roblox's own Proto layout.
inline void (*Luau_Execute)(lua_State*) = nullptr;
}  // namespace Roblox
