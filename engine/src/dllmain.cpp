// Vesper -- engine entry point.
//
// The engine is a single DLL with two roles: injected into Roblox it becomes the
// executor, and loaded into any other process it still brings up the bridge so
// the shell can show diagnostics instead of failing silently.
#include <atomic>
#include <string>
#include <thread>

#include <vesper/bridge.hpp>
#include <vesper/common.hpp>
#include <vesper/env.hpp>
#include <vesper/rbx.hpp>
#include <vesper/stage.hpp>
#include <vesper/table.hpp>
#include <vesper/vendor/json.hpp>

// The C runtime's own entry point. A manual mapper maps this image without the
// loader, so nothing has run the CRT: no runtime initialisation, no static
// constructors, no TLS callbacks. `DllMainCRTStartup` is precisely that work,
// followed by the call into `DllMain` below.
extern "C" BOOL WINAPI DllMainCRTStartup(HINSTANCE module, DWORD reason, LPVOID reserved);

namespace {

// The first instruction of a loader-free entry, before anything that could fail
// first: a named event proves the code ran, in a place a log file cannot, because a
// payload that dies in its own startup has no chance to write one.
// One named event per stage, `Local\vesper_probe_<tag>_<pid>`. Kernel objects only: this
// is called from an APC and from a thread that may not survive, so it cannot log.
// `detail` is folded into the name, which is how a GetLastError() travels out of a
// process nobody can read a log from.
void stage_event(const wchar_t* tag, unsigned long detail) {
    wchar_t name[112] = {};
    wsprintfW(name, L"Local\\vesper_probe_%ls_%lu_%lu", tag, GetCurrentProcessId(), detail);
    const HANDLE event = CreateEventW(nullptr, TRUE, FALSE, name);
    if (event != nullptr) SetEvent(event);
}

void announce_entry() {
    wchar_t name[96] = {};
    wsprintfW(name, L"Local\\vesper_probe_entry_%lu", GetCurrentProcessId());
    const HANDLE announced = CreateEventW(nullptr, TRUE, FALSE, name);
    if (announced != nullptr) SetEvent(announced);
}

// The exception record is captured, not printed. A vectored handler runs on the
// thread that faulted and may be holding a lock the client needs: formatting a line
// and writing it to a file there is how the client froze for seconds after attach.
// The handler therefore does the only thing it can do safely -- copy six words into
// a fixed ring -- and a normal thread flushes it.
//
// It also filters. Hyperion raises 0x80000003 / 0x80000004 / 0xC000001D routinely on
// its own threads while checking its integrity; those are noise, and any fixed line
// budget burns out on them within a second, leaving real faults invisible. What
// matters is a fault whose instruction pointer lies inside the host image or inside
// this one.
struct ExcRecord {
    DWORD code;
    DWORD tid;
    void* where;
    void* rip;
    void* rsp;
};

constexpr int kExcRing = 16;
ExcRecord g_exc_ring[kExcRing] = {};
volatile LONG g_exc_written = 0;
volatile LONG g_exc_total = 0;

std::atomic<std::uintptr_t> g_self_base{0};
std::atomic<std::uintptr_t> g_self_end{0};
std::atomic<std::uintptr_t> g_host_base{0};
std::atomic<std::uintptr_t> g_host_end{0};

bool inside(std::uintptr_t value, std::uintptr_t base, std::uintptr_t end) {
    return base != 0 && end > base && value >= base && value < end;
}

// SizeOfImage straight from the headers: no loader, no lock, works for an image the
// loader never saw.
std::uintptr_t image_span(void* image_base) {
    auto* dos = static_cast<IMAGE_DOS_HEADER*>(image_base);
    if (dos == nullptr || dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(static_cast<std::uint8_t*>(image_base) +
                                                     dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    return nt->OptionalHeader.SizeOfImage;
}

LONG WINAPI note_exception(EXCEPTION_POINTERS* info) {
    if (info == nullptr || info->ExceptionRecord == nullptr) return EXCEPTION_CONTINUE_SEARCH;

    const DWORD code = info->ExceptionRecord->ExceptionCode;
    if (code != 0xC0000005 && code != 0xC0000409 && code != 0xC000001D) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    const auto* context = reinterpret_cast<CONTEXT*>(info->ContextRecord);
    const std::uintptr_t rip = context != nullptr ? context->Rip : 0;
    if (!inside(rip, g_self_base.load(std::memory_order_relaxed),
                g_self_end.load(std::memory_order_relaxed)) &&
        !inside(rip, g_host_base.load(std::memory_order_relaxed),
                g_host_end.load(std::memory_order_relaxed))) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    const LONG slot = InterlockedIncrement(&g_exc_total) - 1;
    if (slot < kExcRing) {
        ExcRecord& record = g_exc_ring[slot];
        record.code = code;
        record.tid = GetCurrentThreadId();
        record.where = info->ExceptionRecord->ExceptionAddress;
        record.rip = reinterpret_cast<void*>(rip);
        record.rsp = context != nullptr ? reinterpret_cast<void*>(context->Rsp) : nullptr;
        InterlockedIncrement(&g_exc_written);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

// Called from a thread we own, never from the handler.
void flush_exceptions() {
    const LONG total = g_exc_total;
    const LONG kept = g_exc_written < kExcRing ? g_exc_written : kExcRing;
    for (LONG i = 0; i < kept; ++i) {
        const ExcRecord& record = g_exc_ring[i];
        VSP_INFO("veh: 0x%08lX tid=%lu at %p rip=%p rsp=%p", static_cast<unsigned long>(record.code),
                 static_cast<unsigned long>(record.tid), record.where, record.rip, record.rsp);
    }
    if (total > kept) VSP_INFO("veh: %ld further fault(s) not recorded", total - kept);
}

// The engine helpers live in `vesper::`; this translation unit is deliberately
// at global scope because `DllMain` has to be.
using vesper::default_engine_directory;
using vesper::ensure_directory;
using vesper::log_close;
using vesper::log_open;
using vesper::module_path;
using vesper::narrow;
using vesper::profile_export_embedded;
using vesper::widen;

std::atomic<bool> g_started{false};
std::atomic<bool> g_shutting_down{false};
std::uint16_t g_port = 0;

// MEASURED on 9ac8: the client terminates a thread that is executing code from this mapped
// image. It happened mid-attach (tid 7244: the game stayed at 1.8 s of CPU per 2 s while our
// thread was simply gone), so a one-shot startup can die half-way and never be retried, and
// a command that dies mid-run leaves its busy flag set forever. Both claims therefore carry
// their owner's thread id, and a later delivery takes over when that thread no longer exists.
volatile LONG g_attach_owner_tid = 0;
volatile LONG g_attach_done = 0;

bool thread_alive(DWORD tid) {
    if (tid == 0) return false;
    const HANDLE thread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, tid);
    if (thread == nullptr) return false;
    DWORD code = 0;
    const bool alive = GetExitCodeThread(thread, &code) && code == STILL_ACTIVE;
    CloseHandle(thread);
    return alive;
}

struct ApcRequest {
    char command[512];
    char* out;
    int out_len;
    int result;
};

// An image the loader never saw is also absent from the tables the runtime uses
// to attribute a code address and to unwind a stack through it. This registers
// the image's own unwind data, so a frame inside it unwinds exactly like a frame
// in any other module instead of looking like a hole in the process.
void register_unwind_tables(void* image_base) {
    auto* dos = static_cast<IMAGE_DOS_HEADER*>(image_base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;

    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(static_cast<std::uint8_t*>(image_base) +
                                                     dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;

    const IMAGE_DATA_DIRECTORY& directory =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (directory.VirtualAddress == 0 || directory.Size < sizeof(RUNTIME_FUNCTION)) return;

    using AddFunctionTableFn = BOOLEAN(NTAPI*)(PRUNTIME_FUNCTION, DWORD, DWORD64);
    const auto add = reinterpret_cast<AddFunctionTableFn>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlAddFunctionTable"));
    if (add == nullptr) return;

    auto* table = reinterpret_cast<PRUNTIME_FUNCTION>(static_cast<std::uint8_t*>(image_base) +
                                                      directory.VirtualAddress);
    const DWORD count = directory.Size / sizeof(RUNTIME_FUNCTION);
    if (add(table, count, reinterpret_cast<DWORD64>(image_base))) {
        VSP_INFO("engine: registered %lu unwind entries for a mapped image", count);
    }
}

bool environment_flag(const wchar_t* name) {
    wchar_t value[8] = {};
    const DWORD len = GetEnvironmentVariableW(name, value, static_cast<DWORD>(std::size(value)));
    return len > 0 && (value[0] == L'1' || value[0] == L't' || value[0] == L'T');
}

std::wstring log_path() {
    wchar_t local[MAX_PATH * 2];
    const DWORD len = GetEnvironmentVariableW(L"LOCALAPPDATA", local, static_cast<DWORD>(std::size(local)));
    std::wstring root = len > 0 ? std::wstring(local, len) : vesper::default_engine_directory();
    root += L"\\Vesper\\logs";
    ensure_directory(root);
    return root + L"\\engine-" + widen(std::to_string(GetCurrentProcessId())) + L".log";
}

// Can a code page of the client be made writable at all? Decides whether a hook on the
// client's own VM entry is possible. Enabled by a 'P' in the stage file. It reads the
// region, asks for PAGE_EXECUTE_READWRITE, and puts the old protection straight back:
// not one byte of the client is written.
void probe_one(const char* name, std::uintptr_t address) {
    MEMORY_BASIC_INFORMATION info{};
    if (VirtualQuery(reinterpret_cast<void*>(address), &info, sizeof(info)) == 0) {
        VSP_INFO("probe[%s]: VirtualQuery failed (%lu)", name, GetLastError());
        return;
    }
    VSP_INFO("probe[%s]: %p state=0x%lX protect=0x%lX type=0x%lX region=0x%llX", name,
             reinterpret_cast<void*>(address), static_cast<unsigned long>(info.State),
             static_cast<unsigned long>(info.Protect), static_cast<unsigned long>(info.Type),
             static_cast<unsigned long long>(info.RegionSize));

    DWORD old = 0;
    SetLastError(0);
    const BOOL opened = VirtualProtect(reinterpret_cast<void*>(address), 0x1000, PAGE_EXECUTE_READWRITE, &old);
    const DWORD error = opened ? 0 : GetLastError();
    if (opened) {
        DWORD ignored = 0;
        const BOOL restored = VirtualProtect(reinterpret_cast<void*>(address), 0x1000, old, &ignored);
        VSP_INFO("probe[%s]: VirtualProtect(RWX) OK, old=0x%lX, restored=%d", name,
                 static_cast<unsigned long>(old), restored ? 1 : 0);
    } else {
        VSP_INFO("probe[%s]: VirtualProtect(RWX) FAILED, error %lu", name, static_cast<unsigned long>(error));
    }
}

void probe_code_protection() {
    const auto base = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
    const auto& profile = vesper::rbx::profile();
    probe_one("resume_continue", profile.at("rva.luau.resume_continue", base));
    probe_one("luau_execute", profile.at("rva.luau.execute", base));
}

std::atomic<bool> g_starting{false};

int start_session(std::string& error) {
    // `g_started` is only set once the session is actually complete. A startup thread the
    // client terminates half-way therefore leaves the claim retryable instead of leaving the
    // engine permanently "started" with nothing behind it.
    if (g_started.load()) return static_cast<int>(g_port);
    if (g_starting.exchange(true)) return static_cast<int>(g_port);

    // Writing tables back next to the client is a debugging aid; it stays off
    // unless asked for explicitly so attaching leaves no artifacts behind.
    if (environment_flag(L"VESPER_EXPORT_TABLES")) {
        const std::wstring engine_dir = default_engine_directory();
        const int exported = profile_export_embedded(engine_dir);
        if (exported > 0) {
            VSP_INFO("session: exported %d offset table(s) to disk", exported);
        }
    }

    // Attaching is best effort: a build without a table still gets a bridge so
    // the failure is visible in the UI rather than silent.
    if (!vesper::rbx::attach(error)) {
        VSP_ERROR("session: attach failed: %s", error.c_str());
    }

    if (vesper::stage_skips('P')) probe_code_protection();
    if (vesper::stage_skips('G')) vesper::rbx::probe_global_closure();
    if (vesper::stage_skips('T')) vesper::rbx::probe_thread_layout();
    if (vesper::stage_skips('L')) vesper::rbx::probe_defer_lookup();

    if (vesper::engine_stage() < 3) {
        VSP_INFO("engine: stage %d -- attached, no bridge: commands arrive as APCs",
                 vesper::engine_stage());
        // The shell finds this process by its record; the record says there is no socket.
        if (vesper::engine_stage() == 2) vesper::bridge::publish_apc_record();
        g_started.store(true);
        g_starting.store(false);
        return 0;
    }

    vesper::bridge::Config config;
    wchar_t port_override[16] = {};
    if (GetEnvironmentVariableW(L"VESPER_PORT", port_override, static_cast<DWORD>(std::size(port_override))) > 0) {
        config.port = static_cast<std::uint16_t>(std::stoi(port_override));
    }
    config.token = environment_flag(L"VESPER_FIXED_TOKEN") ? std::string("vesper") : std::string();

    std::uint16_t bound = 0;
    std::string bridge_error;
    if (!vesper::bridge::start(config, bound, bridge_error)) {
        error = "bridge failed: " + bridge_error;
        VSP_ERROR("session: %s", error.c_str());
        g_starting.store(false);
        return 0;
    }
    g_port = bound;
    g_started.store(true);
    g_starting.store(false);
    return static_cast<int>(bound);
}

// ---------------------------------------------------------------- command channel --
//
// Nothing of this image stays resident in the client except the mapped pages: every
// persistent mechanism tried here (own threads, a pool timer, the HTTP server) stopped
// running within seconds of attach, and a timer callback in this image is what stopped
// the game. So the shell queues an APC per command. The APC lands on whichever game
// thread is alertable, finds the request in the inbox, runs it on the private-thread
// lane and answers through the outbox, then returns. Between commands nothing runs.
std::atomic<bool> g_engine_ready{false};
volatile LONG g_command_busy = 0;
volatile LONG g_command_owner_tid = 0;
std::atomic<std::uint64_t> g_command_started_ms{0};

std::wstring data_root() {
    wchar_t local[MAX_PATH * 2];
    const DWORD len = GetEnvironmentVariableW(L"LOCALAPPDATA", local, static_cast<DWORD>(std::size(local)));
    return (len > 0 ? std::wstring(local, len) : default_engine_directory()) + L"\\Vesper";
}

void run_command(const std::wstring& root, const std::wstring& pid, const std::wstring& running) {
    static volatile LONG sequence = 0;
    const LONG seq = InterlockedIncrement(&sequence);
    const auto data = vesper::read_file(running);
    DeleteFileW(running.c_str());
    const std::string source(data.begin(), data.end());
    // One line per command, before anything can go wrong, with the thread that took it:
    // a second command nobody sent shows up here with its own sequence number.
    VSP_INFO("command #%ld: claimed on tid %lu, %zu bytes", static_cast<long>(seq),
             GetCurrentThreadId(), source.size());

    nlohmann::json reply;
    if (source.empty()) {
        reply = {{"ok", false}, {"error", "empty script"}};
    } else {
        // Cheap when the bound state still validates; re-resolves it after a place change.
        VSP_INFO("command #%ld: refresh begin", static_cast<long>(seq));
        vesper::rbx::refresh();
        VSP_INFO("command #%ld: refresh done, has_lua_state=%d", static_cast<long>(seq),
                 vesper::rbx::status().has_lua_state ? 1 : 0);
        if (!vesper::rbx::status().has_lua_state) {
            reply = {{"ok", false}, {"error", "engine has no lua_State yet"}};
        } else {
            VSP_INFO("command #%ld: exec_source begin", static_cast<long>(seq));
            const vesper::rbx::ExecOutcome outcome = vesper::rbx::exec_source(source, "cli", 0);
            VSP_INFO("command #%ld: exec_source returned ok=%d", static_cast<long>(seq),
                     outcome.ok ? 1 : 0);
            vesper::rbx::record_result(outcome.ok);
            reply = {{"ok", outcome.ok},
                     {"value", outcome.value},
                     {"output", outcome.value},
                     {"error", outcome.error}};
        }
    }

    const std::wstring outbox = root + L"\\outbox";
    ensure_directory(outbox);
    const std::string text = reply.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
    const std::wstring temp = outbox + L"\\" + pid + L".tmp";
    const std::wstring answer = outbox + L"\\" + pid + L".json";
    // Written aside and moved into place so the shell never reads half an answer.
    if (vesper::write_file(temp, text.data(), text.size())) {
        MoveFileExW(temp.c_str(), answer.c_str(), MOVEFILE_REPLACE_EXISTING);
    }
    VSP_INFO("command #%ld: answered", static_cast<long>(seq));
}

void command_pump() {
    // Kernel-object marks only (no file I/O, no allocation of ours) so a run that goes
    // quiet still says how far a command APC got: pump_<n> = the n-th delivery reached
    // here; ready_0/1 = the engine flag; req = a request file was visible; claim = taken.
    static volatile LONG deliveries = 0;
    const LONG n = InterlockedIncrement(&deliveries);
    if (n <= 40) stage_event(L"pump", static_cast<unsigned long>(n));

    if (!g_engine_ready.load()) {
        static volatile LONG not_ready = 0;
        if (InterlockedCompareExchange(&not_ready, 1, 0) == 0) stage_event(L"ready", 0);
        return;
    }

    const std::wstring root = data_root();
    const std::wstring pid = std::to_wstring(GetCurrentProcessId());
    const std::wstring request = root + L"\\inbox\\" + pid + L".req";
    // Every APC the shell queues lands on many threads; all but one find nothing.
    if (GetFileAttributesW(request.c_str()) == INVALID_FILE_ATTRIBUTES) return;
    static volatile LONG req_seen = 0;
    if (InterlockedCompareExchange(&req_seen, 1, 0) == 0) stage_event(L"req", 1);
    // A request is visible: from here every outcome is written down, so a delivery that
    // sees it and then does nothing leaves a line saying why.
    if (InterlockedCompareExchange(&g_command_busy, 1, 0) != 0) {
        // If the thread running the command is gone, it was terminated mid-run (MEASURED:
        // tid 11524 disappeared while a command was executing and the flag stayed set,
        // which blocked every later command). Take the flag over: the request file is
        // still there because the rename happened before the thread died.
        const LONG owner = g_command_owner_tid;
        const DWORD tid = static_cast<DWORD>(owner);
        const bool stale = owner != 0 && !thread_alive(tid);
        VSP_INFO("pump #%ld: request visible on tid %lu, busy held by tid %ld (alive=%d)",
                 static_cast<long>(n), GetCurrentThreadId(), owner, stale ? 0 : 1);
        if (!stale) return;
        VSP_WARN("pump: command thread %ld is gone; taking the busy flag over", owner);
        g_command_busy = 0;
        if (InterlockedCompareExchange(&g_command_busy, 1, 0) != 0) return;
    }
    InterlockedExchange(&g_command_owner_tid, static_cast<LONG>(GetCurrentThreadId()));
    g_command_started_ms.store(GetTickCount64());
    VSP_INFO("pump #%ld: request visible on tid %lu, taking it", static_cast<long>(n), GetCurrentThreadId());

    // Renaming is the claim: only one thread can move the file.
    const std::wstring running = root + L"\\inbox\\" + pid + L".run";
    if (MoveFileExW(request.c_str(), running.c_str(), MOVEFILE_REPLACE_EXISTING)) {
        stage_event(L"claim", GetCurrentThreadId());
        try {
            run_command(root, pid, running);
        } catch (...) {
            // An APC must never unwind into the thread it borrowed.
            VSP_ERROR("pump: a C++ exception escaped run_command");
        }
    } else {
        VSP_INFO("pump #%ld: lost the claim (MoveFileEx error %lu)", static_cast<long>(n), GetLastError());
    }
    InterlockedExchange(&g_command_owner_tid, 0);
    InterlockedExchange(&g_command_busy, 0);
    VSP_INFO("pump #%ld: returning to the game's thread", static_cast<long>(n));
}

// Runs the whole session on the thread that entered the image (the APC's thread, or the
// loader's own when injected with LoadLibrary). No thread is created for it: a thread this
// image creates is exactly the kind the client terminates, and the work has to run somewhere
// that is already alive. If this thread is killed half-way, a later APC calls this again and
// `start_session` is a no-op only once it has actually completed.
void run_session_inline() {
    std::string error;
    start_session(error);
    g_engine_ready.store(true);
    InterlockedExchange(&g_attach_done, 1);
    VSP_INFO("engine: startup thread %lu finished the session", GetCurrentThreadId());

    // MEASURED (9ac8): after the attach burst, command APCs may never run again -- the
    // client can go minutes without a thread entering an alertable wait. The one execution
    // that is reliable is this one: the APC that carried the startup. So this thread stays
    // and serves the inbox for a bounded window, which is what turns "attach, then hope for
    // a delivery" into "attach and the command runs". Plain Sleep between checks: an
    // alertable wait here would consume the very APCs this loop exists to replace.
    const std::uint64_t started = GetTickCount64();
    int served = 0;
    for (;;) {
        if (GetTickCount64() - started > 90000) break;
        const std::wstring request = data_root() + L"\\inbox\\" +
                                     std::to_wstring(GetCurrentProcessId()) + L".req";
        if (GetFileAttributesW(request.c_str()) == INVALID_FILE_ATTRIBUTES) {
            Sleep(150);
            continue;
        }
        VSP_INFO("serve: a request is visible; running it on the startup thread");
        command_pump();
        if (++served >= 4) break;
        Sleep(150);
    }
    if (served != 0) VSP_INFO("serve: %d request(s) handled on the startup thread", served);
}

}  // namespace

// VesperEnter is defined further down; the APC entry calls it.
extern "C" __declspec(dllexport) unsigned long WINAPI VesperEnter();

extern "C" __declspec(dllexport) int VesperStart(const char* command) {
    (void)command;
    std::string error;
    return start_session(error);
}

extern "C" __declspec(dllexport) int VesperPort() {
    return static_cast<int>(vesper::bridge::port());
}

extern "C" __declspec(dllexport) const char* VesperUrl() {
    static std::string cached;
    cached = vesper::bridge::url();
    return cached.c_str();
}

extern "C" __declspec(dllexport) const char* VesperToken() {
    static std::string cached;
    cached = vesper::bridge::token();
    return cached.c_str();
}

extern "C" __declspec(dllexport) const char* VesperStatus() {
    static std::string cached;
    cached = vesper::rbx::status_json();
    return cached.c_str();
}

extern "C" __declspec(dllexport) void VesperStop() {
    if (g_shutting_down.exchange(true)) return;
    vesper::bridge::stop();
}

// APC entry. Same rule as VesperAttach: signal and leave. The request the shell
// allocated is answered with "0, no URL yet" because there is no URL yet -- the
// bridge does not exist until our own thread has started it, and it is not this
// thread's job to wait for that.
extern "C" __declspec(dllexport) void VesperApcEntry(void* param) {
    auto* request = static_cast<ApcRequest*>(param);
    if (request != nullptr) {
        request->result = 0;
        if (request->out != nullptr && request->out_len > 0) request->out[0] = '\0';
    }
    VesperEnter();
}

// Loader-free entry. The shell maps this image as a file-backed section and calls
// this export from inside the mapped image, handing it the base it used.
//
// This runs as an APC on an arbitrary client thread, and that is the whole reason
// this function is four statements long. Anything that takes the loader lock here --
// GetModuleHandleExW, RtlAddFunctionTable, the CRT's own init -- can deadlock
// against a thread that already holds it, and a client thread blocked while holding
// the loader lock freezes every other thread that needs a module. That was the
// freeze. The APC now only claims the entry once and hands the work to a thread we
// own; CreateThread does not touch the loader lock in the caller.
//
// An APC can be queued on every thread of the host, so several threads may arrive
// here at the same time, and several may arrive on a thread the mapper started.
// The whole startup is claimed exactly once; every later thread is a no-op.
DWORD WINAPI loader_free_entry(void* image_base) {
    announce_entry();

    // One engine per client. MEASURED: a second mapping calls DllMainCRTStartup again and the
    // client's CRT answers R6031 ("attempt to initialize the CRT more than once") with a
    // modal dialog on the thread that ran the APC -- that thread then waits for a button
    // press, which looks exactly like a frozen game. The first image that gets here claims a
    // named mutex scoped to this process and keeps the handle for the life of the process; any
    // later image sees the name taken and does nothing at all.
    static HANDLE crt_claim = nullptr;  // deliberately never closed
    const std::wstring claim_name = L"Local\\VesperCrt_" + std::to_wstring(GetCurrentProcessId());
    crt_claim = CreateMutexW(nullptr, FALSE, claim_name.c_str());
    if (crt_claim != nullptr && GetLastError() == ERROR_ALREADY_EXISTS) {
        stage_event(L"refused", 0);
        return 0;
    }

    std::uintptr_t span = image_span(image_base);
    g_self_base.store(reinterpret_cast<std::uintptr_t>(image_base), std::memory_order_relaxed);
    g_self_end.store(reinterpret_cast<std::uintptr_t>(image_base) + span, std::memory_order_relaxed);

    // The loader never saw this image, so it is absent from the tables the runtime
    // uses to attribute a code address and unwind a stack through it.
    stage_event(L"thread", 0);
    // Opt-in with a 'U'. Not isolated on its own: every healthy run on 9ac8 had it off.
    if (vesper::stage_skips('U')) register_unwind_tables(image_base);
    stage_event(L"unwind", 0);

    DllMainCRTStartup(static_cast<HINSTANCE>(image_base), DLL_PROCESS_ATTACH, nullptr);
    stage_event(L"crt", 0);
    run_session_inline();
    return 0;
}

extern "C" __declspec(dllexport) unsigned long WINAPI VesperAttach(void* image_base) {
    // Stage marker 1: the APC itself ran. A kernel event is the one thing safe to make
    // here (no loader lock, no allocation we own), and it is what tells "the APC was
    // never delivered" apart from "it was delivered and the thread it starts died".
    // The shell queues one APC per command, so only the first leaves an event behind.
    static volatile LONG apc_seen = 0;
    if (InterlockedCompareExchange(&apc_seen, 1, 0) == 0) stage_event(L"apc", 0);

    // Delivery-only mode, for telling "the way the image gets in" apart from "what the
    // engine does once it runs": with %LOCALAPPDATA%\Vesper\noop present the APC
    // returns here and nothing else of this image ever executes.
    {
        wchar_t path[MAX_PATH] = {};
        const DWORD n = GetEnvironmentVariableW(L"LOCALAPPDATA", path, MAX_PATH - 16);
        if (n > 0 && n < MAX_PATH - 16) {
            lstrcatW(path, L"\\Vesper\\noop");
            if (GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES) {
                stage_event(L"noop", 0);
                return 0;
            }
        }
    }

    static volatile LONG entry_claimed = 0;
    if (InterlockedCompareExchange(&entry_claimed, 1, 0) != 0) {
        // Already claimed. If the thread that took it is gone and the startup never
        // finished, the claim is stale: take it over and run the startup again.
        const LONG owner = g_attach_owner_tid;
        if (InterlockedCompareExchange(&g_attach_done, 0, 0) == 0 && !thread_alive(static_cast<DWORD>(owner))) {
            VSP_WARN("entry: startup thread %ld is gone before finishing; taking the claim over", owner);
            InterlockedExchange(&g_attach_owner_tid, static_cast<LONG>(GetCurrentThreadId()));
            loader_free_entry(image_base);
            return 0;
        }
        // Already started: this delivery is a command.
        command_pump();
        return 0;
    }
    InterlockedExchange(&g_attach_owner_tid, static_cast<LONG>(GetCurrentThreadId()));

    if (image_base == nullptr) return 1;

    // MEASURED on 9ac8 (pid 11340): the APC ran, CreateThread returned a handle, and the
    // thread never executed its first instruction -- no thread with a start inside this
    // image was alive afterwards. A worker whose start address is in an unbacked image
    // does not survive here, so the startup runs inline on the APC's thread, as it did
    // when this executor last ran Lua. Each stage leaves an event so the next run says
    // how far it got. Set VESPER_ENTRY_THREAD=1 in the target to use the thread again.
    if (environment_flag(L"VESPER_ENTRY_THREAD")) {
        const HANDLE worker = CreateThread(nullptr, 0, &loader_free_entry, image_base, 0, nullptr);
        stage_event(L"ct", worker != nullptr ? 0UL : GetLastError());
        if (worker != nullptr) {
            CloseHandle(worker);
            return 0;
        }
    } else {
        loader_free_entry(image_base);
        return 0;
    }

    // No thread, no session: release the claim so a later delivery can try again.
    InterlockedExchange(&entry_claimed, 0);
    return 1;
}

// The same entry with nothing to hand it. An entrance that can only pass a thread
// parameter -- an APC's `dwData`, say -- may be zero, so this variant finds the
// image by walking back from its own code to the image header: the header sits at
// the base, and every page between here and there belongs to this image.
extern "C" __declspec(dllexport) unsigned long WINAPI VesperEnter() {
    std::uintptr_t page = reinterpret_cast<std::uintptr_t>(&VesperEnter) &
                          ~static_cast<std::uintptr_t>(0xFFF);
    for (int steps = 0; steps < 0x2000 && page >= 0x10000; ++steps, page -= 0x1000) {
        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(page);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) continue;
        auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(page + dos->e_lfanew);
        if (nt->Signature == IMAGE_NT_SIGNATURE) {
            return VesperAttach(reinterpret_cast<void*>(page));
        }
    }
    return 1;
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID) {
    switch (reason) {
        case DLL_PROCESS_ATTACH: {
            DisableThreadLibraryCalls(module);

            const bool console = environment_flag(L"VESPER_CONSOLE");
            vesper::log_open(log_path(), console);

            // The log file is named by pid and appended. Pids are reused across
            // reboots, so three days later a new process can inherit the file and
            // its history -- two sessions in one log with no date between them is
            // how a stale run gets read as a fresh one. The banner is the divider.
            SYSTEMTIME stamp{};
            GetLocalTime(&stamp);
            VSP_INFO("engine: session %04u-%02u-%02uT%02u:%02u:%02u (pid %lu, module %s)",
                     stamp.wYear, stamp.wMonth, stamp.wDay, stamp.wHour, stamp.wMinute,
                     stamp.wSecond, GetCurrentProcessId(),
                     vesper::narrow(vesper::module_path(module)).c_str());

            // Remember the host's address span before any fault can arrive: the
            // handler keeps a record only when the instruction pointer is inside the
            // host or inside this image, and nothing else can tell it that later.
            const auto host = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
            g_host_base.store(host, std::memory_order_relaxed);
            g_host_end.store(host + image_span(reinterpret_cast<void*>(host)),
                             std::memory_order_relaxed);

            // OFF unless the stage file carries a 'V'. MEASURED on 9ac8: with this handler
            // installed the client stops dead 35-45 s after attach (CPU 0, every thread
            // parked, no thread of ours alive), and with everything else identical but
            // the handler left out it ran 93 s at normal load. A vectored handler is the
            // first entry in a chain Hyperion walks, and this one points into an image
            // that has no file. It only ever recorded faults for diagnosis.
            if (vesper::stage_skips('V')) AddVectoredExceptionHandler(1, note_exception);

            VSP_INFO("engine: stage %d", vesper::engine_stage());
            // The session runs on the entry thread (see loader_free_entry); nothing is
            // started here, so a terminated thread cannot leave the engine half-initialised.
            break;
        }
        case DLL_PROCESS_DETACH: {
            if (g_shutting_down.exchange(true)) break;
            const std::wstring record = vesper::bridge::clients_directory() + L"\\" +
                                        vesper::widen(std::to_string(GetCurrentProcessId())) + L".json";
            DeleteFileW(record.c_str());
            vesper::log_close();
            break;
        }
        default:
            break;
    }
    return TRUE;
}
