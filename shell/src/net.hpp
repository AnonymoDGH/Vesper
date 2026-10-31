// Vesper -- shell side networking and process plumbing.
//
// Everything the shell needs from the outside world: discovering injected
// clients by their record files, talking to an engine's bridge, and getting the
// engine into a process in the first place.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace vesper::shell {

struct ClientInfo {
    int pid = 0;
    int port = 0;
    std::string token;
    std::string url;
    std::string build;
    std::string profile;
    std::string exe;
    std::string mode;  // "apc": no server in the client, commands travel as APC + files
    std::string record;
    std::int64_t started = 0;
    std::int64_t record_time = 0;

    // Filled in by the shell as it probes.
    bool alive = false;
    bool reachable = false;
    bool ready = false;
    bool in_game = false;
    int thread_identity = -1;
    std::string detail;
};

struct EngineState {
    bool valid = false;
    std::string build;
    std::string profile;
    std::string data_model;
    std::string script_context;
    std::string lua_state;
    std::string strategy;
    std::string identity_field;
    std::string error;
    int thread_identity = -1;
    bool in_game = false;
    bool environment = false;
    bool ready = false;
    bool abi_verified = false;
    int pending = 0;
    int executed = 0;
    int failed = 0;
    int port = 0;
    int sockets = 0;
    int pid = 0;
};

std::wstring clients_directory();
std::vector<ClientInfo> list_clients();
// Live-and-newest selection; `only_pid` forces a specific record.
ClientInfo* select_client(std::vector<ClientInfo>& clients, int only_pid);
bool probe_client(ClientInfo& client);

bool fetch_state(const ClientInfo& client, EngineState& state, std::string& error);
bool fetch_report(const ClientInfo& client, const char* route, std::string& report, std::string& error);
bool run_script(const ClientInfo& client, const std::string& source, const std::string& name,
                int timeout_ms, std::string& output, bool& still_pending, std::string& error);

// The same, for a client in "apc" mode: the script goes into the client's inbox file, an
// APC wakes the engine, and the answer is read back from its outbox file. No socket.
bool run_script_apc(const ClientInfo& client, const std::string& source, int timeout_ms,
                    std::string& output, std::string& error);

bool pid_alive(int pid);
std::vector<int> find_roblox_pids();

// Path of the engine DLL that ships next to the shell.
std::wstring engine_dll_path();

struct InjectOutcome {
    bool ok = false;
    int pid = 0;
    std::string detail;
};

// Injects `dll_path` into `pid`. Uses an APC on an existing thread; if the
// remote loader has not reported in by `wait_ms`, a remote thread is tried as a
// documented fallback (some processes have no alertable thread at all).
//
// Note that a running, anti-tamper protected game will refuse the module no
// matter which path is used; see `launch_and_inject` for that case.
InjectOutcome inject(int pid, const std::wstring& dll_path, int wait_ms = 9000);

// Every RobloxPlayerBeta.exe under %LOCALAPPDATA%\Roblox\Versions, and the one
// that best matches a build (newest if none matches).
std::vector<std::wstring> installed_client_paths();
std::wstring preferred_client_path(const std::wstring& preferred_build);

struct LaunchOutcome {
    bool ok = false;
    int pid = 0;
    std::string detail;
    std::wstring exe;
    std::wstring command_line;
};

struct ProbeOutcome {
    bool loaded = false;
    int pid = 0;
    std::string detail;
};

// Starts the client suspended and tries to load `dll_path` into it, then kills the
// process. Answers whether the client's loader accepts a foreign module at all.
// With a non-zero `pid` the given process is used instead, which is the control
// case; with LOAD_LIBRARY_AS_DATAFILE in `flags` the image is only mapped, and
// with `direct` the load is requested from the loader's own code.
ProbeOutcome probe_load(const std::wstring& dll_path, int pid = 0, std::uint32_t flags = 0,
                        bool direct = false);

struct ExecOutcome {
    bool ran = false;
    int pid = 0;
    std::string detail;
};

// Runs a stub written into private memory in the target, to find out whether the
// target will execute code from a page that is not backed by a module image.
ExecOutcome probe_exec(int pid = 0);

struct ApcProbeOutcome {
    bool loaded = false;
    int pid = 0;
    std::string detail;
};

// Asks the target to load `dll_path` by both delivery routes and reports whether
// either lands. Point it at a signed module: the client refuses unsigned ones on
// principle, which would hide the answer about delivery.
ApcProbeOutcome probe_apc(const std::wstring& dll_path, int pid);

// Starts the client with CREATE_SUSPENDED, loads the engine into it before any of
// the game's own code runs, then resumes it. This is the only injection point the
// anti-tamper does not already own: once the game is running its loader refuses
// foreign modules, so the engine has to be present first.
//
// `argument` is passed to the client verbatim (a place URL, or nothing).
LaunchOutcome launch_and_inject(const std::wstring& dll_path, const std::wstring& argument,
                                int wait_ms = 20000, const std::wstring& build = {});

}  // namespace vesper::shell
