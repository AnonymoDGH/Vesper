// Vesper -- Roblox side of the engine.
//
// Resolution is expressed as *candidate strategies* rather than a single
// hardcoded path. Each candidate is validated against the live process before
// it is accepted, so a build whose layout shifted degrades into "this strategy
// did not validate" instead of a silent bad pointer.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <vesper/table.hpp>

struct lua_State;

namespace vesper::rbx {

// Absolute addresses resolved from the profile. Zero means "absent on this
// build"; every consumer must treat zero as unavailable rather than fatal.
struct Bindings {
    std::uintptr_t module_base = 0;
    std::uintptr_t fake_data_model = 0;
    std::uintptr_t task_scheduler = 0;
    std::uintptr_t get_global_state = 0;
    std::uintptr_t opcode_lookup = 0;
    // Companion byte table at 0x7144260: `class_table[internal] == vendored`.
    std::uintptr_t opcode_class = 0;
    std::uintptr_t luau_load = 0;
    std::uintptr_t luau_execute = 0;
    std::uintptr_t nil_object = 0;
    std::uintptr_t dummy_node = 0;
    std::uintptr_t rbx_print = 0;
    std::uintptr_t instance_new = 0;
    std::uintptr_t push_instance = 0;
    std::uintptr_t sc_resume = 0;
    std::uintptr_t enable_load_module = 0;

    // Structure field offsets.
    std::uintptr_t fdm_to_real = 0;
    std::uintptr_t dm_children = 0;
    std::uintptr_t dm_script_context = 0;
    // Absolute address of the host's ScriptContext vtable. A context candidate is
    // compared against it before the host is asked about it: `get_global_state`
    // asserts (and the client dies) on anything that is not a script context.
    std::uintptr_t sc_vtable = 0;
    // The job slot that points back at the DataModel the job belongs to. It is
    // what tells the place's own script context apart from the clone the engine
    // keeps alive for another context.
    std::uintptr_t ts_job_data_model = 0;
    // ScriptContext field the host reads before handing out a state; it takes a
    // crash path when the value is >= 3, so it is checked before any call.
    std::uintptr_t sc_guard = 0;
    std::uintptr_t dm_game_loaded = 0;
    std::uintptr_t dm_place_id = 0;
    std::uintptr_t dm_job_id = 0;
    std::uintptr_t ts_job_start = 0;
    std::uintptr_t ts_job_end = 0;
    std::uintptr_t ts_job_name = 0;
    std::uintptr_t ts_job_script_context = 0;
    std::uintptr_t es_require_bypass = 0;
    std::uintptr_t es_identity = 0;
    std::uintptr_t es_capabilities = 0;
};

enum class Strategy {
    Direct,        // *(data_model + script_context)
    ViaChildren,   // *(*(data_model + children) + script_context)
    InlineObj,     // data_model + script_context already points at the object
    ViaJobs,       // TaskScheduler -> WaitingHybridScriptsJob -> script context
    Unknown,
};

const char* to_string(Strategy strategy);

struct Status {
    bool has_profile = false;
    bool has_module = false;
    bool has_bindings = false;
    bool has_lua_state = false;
    bool abi_verified = false;
    bool in_game = false;
    bool environment_ready = false;
    bool ready = false;

    std::string build;
    std::string profile_source;
    std::string profile_error;
    std::string abi_report;
    std::string error;

    std::uintptr_t data_model = 0;
    std::uintptr_t script_context = 0;
    std::uintptr_t lua_state = 0;
    Strategy strategy = Strategy::Unknown;
    int thread_identity = -1;
    std::uintptr_t identity_field = 0;
    int pending_scripts = 0;
    int executed_scripts = 0;
    int failed_scripts = 0;
};

// Called once per injected process. Loads the table for the detected build,
// locates the host module, binds the ABI and installs the frame pump.
bool attach(std::string& error);

// Re-resolves the game pointers. Cheap enough to call on a timer; safe to call
// while no place is loaded.
bool refresh();

// Installs the executor environment and the frame pump. Must be called once the
// game is running, from the worker thread that owns session startup.
bool setup();

bool ready();
lua_State* state();

// Diagnostics for the "run on the game's own thread" lane: where a C closure's function
// pointer lives, whether that memory is writable, and whether a same-value write sticks.
// Reads the globals table; the only write is of the value already there.
void probe_global_closure();

// Creates a thread with the client's own `lua_newthread` and compares its bytes with the
// thread the exec lane synthesises, field by field. Diagnostic only.
void probe_thread_layout();

// Reads `task` and `task.defer` out of the client's globals through raw 9ac8 structures,
// without calling any of our own Luau with a client pointer. Diagnostic only.
void probe_defer_lookup();
const Status& status();
const Profile& profile();

// Machine readable status for the bridge / UI.
std::string status_json();

// Queue a script for execution on the game's main thread. Returns the tag the
// outcome will be filed under, which is what `env::take_outcome` looks up.
std::string push_request(std::string source, std::string chunk_name, std::string tag = {});

// Runs on the game thread from the installed frame hook.
void pump();

// Bookkeeping for the outcome the bridge collected.
void record_result(bool ok);

// Copies the `lua_State` view of the process: layout checks, scheme
// verification and (when possible) automatic scheme repair.
std::string probe_abi(bool allow_repair);

// Walks the client's own Lua C API one call at a time, assuming no `lua_State`
// layout at all. Returns the live layout report.
//
// `allow_live_calls` adds the steps that mount a CallInfo frame on the *game's*
// own state. Every one of them was measured to kill the client within
// milliseconds, so they are opt-in and off by default; the private-thread steps
// (which need nothing that is not already proven) run either way.
std::string hostapi_probe(bool allow_live_calls = false);

// Outcome of one private-thread execution, as the bridge reports it back.
struct ExecOutcome {
    bool ok = false;
    std::string value;   // the chunk's return value, rendered
    std::string error;   // compile / load / call error
    std::string report;  // the full engine-log style trace
};

// Compiles `source` with the vendored Luau, builds a private thread on the
// client's own allocator, loads the chunk on it and runs it with the client's
// `lua_pcall`. Nothing is mounted on the game's live state except a single
// pure push (the same kind of call `hostapi_probe` step A proves is safe), so
// this is safe to call from the bridge thread.
//
// `use_encoder` selects the host opcode-remapping encoder (`compile`) over the
// plain compiler output (`hostapi_probe` step B). Loading cannot tell the two
// apart, so both are available until one is measured to execute correctly.
//
// `encoder_mode` selects the opcode transform: 0 = plain compiler output,
// 1 = `lookup[opcode * 227]` (the encoder the public bases use), 2 = `opcode *=
// 227` and nothing else. A `%LOCALAPPDATA%\Vesper\encoder` marker file holding a
// single digit overrides it for the next call, so all three can be measured on
// one client.
ExecOutcome exec_source(const std::string& source, const std::string& chunk,
                        int encoder_mode = 1);

// Same, against a caller-supplied state. `out.report` is the log text.
bool exec_on_private_thread(lua_State* parent, const std::string& source, const std::string& chunk,
                            ExecOutcome& out, int encoder_mode = 1);

// Read-only snapshot of the live thread: the raw `lua_State` words, every
// candidate per-thread `RobloxExtraSpace`, the game's own call frames (with the
// instruction words the client's compiler produced) and the bytes the host
// exposes as `rva.opcode_lookup_table`. Used to measure the identity field and
// the opcode space instead of guessing either.
std::string diag_probe();

// ---------------------------------------------------------------- hook lane --
//
// Execution has to start on the game's own Lua thread; a host call made from the
// bridge thread wedges the client (see `hostapi_probe`). `hook_install` puts a
// detour on the VM entry (`rva.luau.execute`) and `hook_queue_probe` asks it to
// run one probe job on that thread -- the detour is transparent and does no work
// at all while nothing is queued.
//
// Nothing here is reached by a normal attach: only the `/hooktest` route and the
// `VESPER_HOOKTEST` self-test call it, so an ordinary session installs no hook.
std::string hook_install();
std::string hook_remove();
std::string hook_status();
bool hook_active();

// Bridge side only: stage one job for the hook to run. Enqueue only -- these
// never touch the VM and must only be called from the bridge / HTTP threads.
bool hook_queue_probe();
bool hook_queue_load_and_run(std::string source, std::string chunk);

// Called only from the hook, i.e. on the game's own Lua thread, and from the
// bridge's `/exec` route. Builds the chunk on a private thread and runs it.
void hostapi_load_and_run(lua_State* L, const char* source, std::size_t size);

// Compiles without executing. Used by the UI's "compile" action so syntax
// errors surface without touching the game.
bool compile(const std::string& source, std::string& bytecode, std::string& error);

// ------------------------------------------------------------------ support --

// Identity/capabilities of a thread. Returns false when the build exposes no
// usable path (in which case scripts still run, just with the attaching
// identity).
bool set_thread_identity(lua_State* L, int identity);
int get_thread_identity(lua_State* L);

// Paths the executor filesystem API is rooted at.
std::wstring workspace_directory();

}  // namespace vesper::rbx
