// Real-compatible API surface on top of the Vesper engine.
//
// Vesper already owns the hard part (attach, ABI, hooks, execution in the
// client). This file adds the names recovered from Real.dll (build 182) that
// Vesper does not provide, plus the snake_case aliases the Real surface exposes.
// Self-contained functions are implemented; Roblox-internal ones are registered
// as safe stubs so scripts fail on behaviour, not on a missing global.
#pragma once

struct lua_State;

namespace vesper::realx {

void install(lua_State* L);

}  // namespace vesper::realx
