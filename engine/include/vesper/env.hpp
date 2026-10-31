// Vesper -- the executor environment.
//
// One persistent sandboxed Luau thread is created per session. Every script runs
// on that thread so globals (`getgenv`, `shared`) are stable across executions
// and closures resolve to the executor rather than to a throwaway thread.
#pragma once

#include <cstdint>
#include <string>

struct lua_State;

namespace vesper::env {

// Called with the game's main `lua_State`. Creates the executor thread, installs
// every library and registers the output sink. Safe to call more than once.
void install(lua_State* L);

// The sandboxed thread scripts execute on. Null until `install` succeeds.
lua_State* exploit_thread();

// ------------------------------------------------------------------ results --
//
// Scripts are dispatched through `task.defer`, so results arrive asynchronously.
// The engine tags each dispatch and collects the outcome here; the bridge reads
// it back to answer `/execute_script` synchronously when possible and to stream
// output to the UI.

struct Outcome {
    bool done = false;
    bool ok = false;
    std::string message;  // error text or captured output
    std::int64_t finished_at = 0;
};

void set_pending(const std::string& tag);
void complete(const std::string& tag, bool ok, const std::string& message);
bool take_outcome(const std::string& tag, Outcome& out);
void expire_pending(std::int64_t older_than_ms);

// Text produced by the script's own `print` during the most recent execution.
std::string take_output(const std::string& tag);

// ------------------------------------------------------------------- assets --
void set_bridge_port(std::uint16_t port);
std::uint16_t bridge_port();

}  // namespace vesper::env
