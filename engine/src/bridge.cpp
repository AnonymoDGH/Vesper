#include <vesper/bridge.hpp>

#include <atomic>
#include <ctime>
#include <mutex>
#include <thread>

#include <vesper/common.hpp>
#include <vesper/env.hpp>
#include <vesper/http.hpp>
#include <vesper/rbx.hpp>
#include <vesper/stage.hpp>
#include <vesper/vendor/json.hpp>

namespace vesper::bridge {

namespace {

using json = nlohmann::json;

http::Server g_server;
Config g_config;
std::uint16_t g_port = 0;
std::string g_token;
std::thread g_loop;
std::atomic<bool> g_stop{false};
std::mutex g_state_mutex;
std::string g_last_state;
std::atomic<unsigned long long> g_exec_sequence{0};

std::wstring client_record_path() {
    const std::wstring directory = clients_directory();
    return directory + L"\\" + widen(std::to_string(GetCurrentProcessId())) + L".json";
}

json state_object() {
    json state;
    state["build"] = rbx::status().build;
    state["profile"] = rbx::status().profile_source;
    state["dataModel"] = vformat("0x%llx", static_cast<unsigned long long>(rbx::status().data_model));
    state["scriptContext"] =
        vformat("0x%llx", static_cast<unsigned long long>(rbx::status().script_context));
    state["luaState"] = vformat("0x%llx", static_cast<unsigned long long>(rbx::status().lua_state));
    state["strategy"] = rbx::to_string(rbx::status().strategy);
    state["threadIdentity"] = rbx::status().thread_identity;
    state["identityField"] =
        vformat("0x%llx", static_cast<unsigned long long>(rbx::status().identity_field));
    state["inGame"] = rbx::status().in_game;
    state["environment"] = rbx::status().environment_ready;
    state["ready"] = rbx::status().ready;
    state["abiVerified"] = rbx::status().abi_verified;
    state["pending"] = rbx::status().pending_scripts;
    state["executed"] = rbx::status().executed_scripts;
    state["failed"] = rbx::status().failed_scripts;
    state["error"] = rbx::status().error;
    state["port"] = g_port;
    state["sockets"] = static_cast<int>(g_server.socket_count());
    state["pid"] = static_cast<int>(GetCurrentProcessId());
    return state;
}

json envelope(const json& state) {
    return json{{"ok", true}, {"type", "state"}, {"state", state}};
}

std::string content_type_for(const std::wstring& path) {
    const std::wstring extension = [&path] {
        const auto dot = path.find_last_of(L'.');
        return dot == std::wstring::npos ? std::wstring() : path.substr(dot + 1);
    }();
    if (extension == L"png") return "image/png";
    if (extension == L"jpg" || extension == L"jpeg") return "image/jpeg";
    if (extension == L"gif") return "image/gif";
    if (extension == L"ogg") return "audio/ogg";
    if (extension == L"mp3") return "audio/mpeg";
    if (extension == L"wav") return "audio/wav";
    if (extension == L"json") return "application/json; charset=utf-8";
    if (extension == L"lua" || extension == L"txt") return "text/plain; charset=utf-8";
    if (extension == L"fbx") return "application/octet-stream";
    if (extension == L"ttf") return "font/ttf";
    return "application/octet-stream";
}

// ------------------------------------------------------------------- routes --

http::Response handle_ping(const http::Request&) {
    return http::Response::json(json{{"ok", true}, {"name", "Vesper"}, {"version", "3.0.0"},
                                     {"pid", GetCurrentProcessId()}, {"port", g_port}}
                                    .dump());
}

http::Response handle_state(const http::Request&) {
    return http::Response::json(envelope(state_object()).dump());
}

http::Response handle_abi(const http::Request&) {
    const std::string report = rbx::probe_abi(false);
    return http::Response::json(json{{"ok", true}, {"report", report}}.dump());
}

http::Response handle_abi_repair(const http::Request&) {
    const std::string report = rbx::probe_abi(true);
    return http::Response::json(json{{"ok", true}, {"report", report}}.dump());
}

http::Response handle_hostprobe(const http::Request& request) {
    // `?live=1` adds the steps that mount a CallInfo frame on the game's own
    // state. Every one of them was measured to kill the client, so the default
    // probe stays on the private-thread lane.
    const std::string live = request.param("live");
    const std::string report = rbx::hostapi_probe(live == "1" || live == "true");
    return http::Response::json(json{{"ok", true}, {"report", report}}.dump());
}

// The real execution route: compile in-process, build a private thread out of
// the client's own allocator, load and run there. Safe to call from the bridge
// thread -- nothing is mounted on the game's live state except the one-slot push
// the client itself does when it makes a thread.
//
//   POST {"script": "<source>", "name": "=chunk"}   -> {"ok", "value", "error", "report"}
//   GET  /exec?path=<local file>                    -> same, source read from disk
http::Response handle_exec(const http::Request& request) {
    std::string source;
    std::string name = "bridge";

    const std::string body = request.body;
    bool parsed = false;
    if (!body.empty() && body[0] == '{') {
        try {
            const json payload = json::parse(body);
            if (payload.contains("script")) source = payload["script"].get<std::string>();
            if (payload.contains("source")) source = payload["source"].get<std::string>();
            if (payload.contains("name")) name = payload["name"].get<std::string>();
            parsed = true;
        } catch (const std::exception&) {
            parsed = false;
        }
    }
    if (!parsed) source = body;

    const std::string path = request.param("path");
    if (!path.empty()) {
        const auto data = read_file(widen(path));
        if (data.empty()) {
            return http::Response::json(
                json{{"ok", false}, {"error", "cannot read " + path}}.dump());
        }
        source.assign(data.begin(), data.end());
        name = path;
    }

    if (source.empty()) {
        return http::Response::json(json{{"ok", false}, {"error", "empty script"}}.dump());
    }
    if (!rbx::status().has_lua_state) {
        return http::Response::json(
            json{{"ok", false}, {"error", "engine has no lua_State yet"}, {"state", state_object()}}
                .dump());
    }

    const std::string encode = request.param("encode");
    const bool use_encoder = encode == "1" || encode == "true";
    const rbx::ExecOutcome outcome = rbx::exec_source(source, name, use_encoder);
    rbx::record_result(outcome.ok);
    json reply{{"ok", outcome.ok},
               {"name", name},
               {"encoder", use_encoder ? "host" : "plain"},
               {"value", outcome.value},
               {"output", outcome.value},
               {"error", outcome.error},
               {"report", outcome.report}};
    broadcast_state();
    return http::Response::json(reply.dump());
}

// The explicit trigger for the VM-hook lane. A normal attach never installs a
// hook; this route (and the `VESPER_HOOKTEST` self-test) is the only way in.
//
//   (no action) install the detour and queue one probe
//   ?action=probe   queue one more probe on the installed hook
//   ?action=run     queue a load-and-run job (the engine side is a documented TODO)
//   ?action=remove  restore the original bytes
//   ?action=status  report the lane's state and counters
//
// The probe itself runs asynchronously, on the game's Lua thread inside the
// hook, and reports through the engine log.
http::Response handle_hooktest(const http::Request& request) {
    const std::string action = request.param("action");
    std::string report;
    bool ok = true;

    if (action == "status") {
        report = rbx::hook_status();
    } else if (action == "remove") {
        report = rbx::hook_remove();
    } else if (action == "probe") {
        report = rbx::hook_status();
        report += rbx::hook_queue_probe()
                      ? "\nprobe: queued; the hook runs one job and logs it\n"
                      : "\nprobe: not queued (no hook installed, or a job is already in flight)\n";
    } else if (action == "run") {
        report = rbx::hook_status();
        report += rbx::hook_queue_load_and_run("return 41 + 1", "=vesper_hooktest")
                      ? "\nrun: queued; the hook runs one job and logs it\n"
                      : "\nrun: not queued (no hook installed, or a job is already in flight)\n";
    } else if (action == "install") {
        // Install without queueing anything. This isolates the redirect itself from
        // the work the detour would then do, so a client that dies here is telling
        // us about the vtable swap and nothing else.
        report = rbx::hook_install();
        if (!rbx::hook_active()) ok = false;
    } else {
        report = rbx::hook_install();
        if (rbx::hook_active()) {
            report += rbx::hook_queue_probe()
                          ? "\nprobe: queued; the hook logs thread id, L, top and ci\n"
                          : "\nprobe: not queued (a job is already in flight)\n";
        } else {
            ok = false;
        }
    }

    return http::Response::json(
        json{{"ok", ok}, {"report", report}, {"hook", rbx::hook_status()}}.dump());
}

http::Response handle_execute(const http::Request& request) {
    std::string source;
    std::string name = "bridge";

    const std::string body = request.body;
    bool parsed = false;
    if (!body.empty() && body[0] == '{') {
        try {
            const json payload = json::parse(body);
            if (payload.contains("script")) source = payload["script"].get<std::string>();
            if (payload.contains("source")) source = payload["source"].get<std::string>();
            if (payload.contains("name")) name = payload["name"].get<std::string>();
            parsed = true;
        } catch (const std::exception&) {
            parsed = false;
        }
    }
    if (!parsed) source = body;

    if (source.empty()) {
        return http::Response::json(json{{"ok", false}, {"error", "empty script"}}.dump());
    }
    if (!rbx::status().has_lua_state) {
        return http::Response::json(
            json{{"ok", false}, {"error", "engine is not attached to a running place yet"},
                 {"state", state_object()}}
                .dump());
    }

    // The scheduler hand-off (task.defer on the game's own thread) is not wired
    // yet, so this is the private-thread lane: compile here, build a thread out
    // of the client's allocator, run there and report what came back. Same
    // response shape as the queued lane so the UI and the shell do not care.
    const std::string tag =
        vformat("exec-%llu", static_cast<unsigned long long>(now_ms() ^ (++g_exec_sequence * 7919)));
    const rbx::ExecOutcome outcome = rbx::exec_source(source, name.empty() ? "bridge" : name);
    rbx::record_result(outcome.ok);
    broadcast_state();
    return http::Response::json(
        json{{"ok", outcome.ok},
             {"id", tag},
             {"lane", "private-thread"},
             {"output", outcome.value},
             {"value", outcome.value},
             {"error", outcome.error},
             {"report", outcome.report}}
            .dump());
}

http::Response handle_result(const http::Request& request) {
    const std::string tag = request.param("id");
    if (tag.empty()) {
        return http::Response::json(json{{"ok", false}, {"error", "id is required"}}.dump());
    }
    env::Outcome outcome;
    if (!env::take_outcome(tag, outcome)) {
        return http::Response::json(json{{"ok", true}, {"pending", true}, {"id", tag}}.dump());
    }
    rbx::record_result(outcome.ok);
    return http::Response::json(json{{"ok", outcome.ok},
                                     {"id", tag},
                                     {"output", outcome.message},
                                     {"error", outcome.ok ? "" : outcome.message}}
                                    .dump());
}

http::Response handle_clients(const http::Request&) {
    json clients = json::array();
    WIN32_FIND_DATAW entry{};
    const std::wstring pattern = clients_directory() + L"\\*.json";
    const HANDLE find = FindFirstFileW(pattern.c_str(), &entry);
    if (find != INVALID_HANDLE_VALUE) {
        do {
            const std::wstring path = clients_directory() + L"\\" + entry.cFileName;
            const auto data = read_file(path);
            if (data.empty()) continue;
            try {
                json record = json::parse(std::string(data.begin(), data.end()));
                record["record"] = narrow(path);
                clients.push_back(record);
            } catch (const std::exception&) {
            }
        } while (FindNextFileW(find, &entry));
        FindClose(find);
    }
    return http::Response::json(
        json{{"ok", true}, {"self", GetCurrentProcessId()}, {"clients", clients}}.dump());
}

http::Response handle_asset(const http::Request& request) {
    std::string relative = request.path;
    const std::string prefix = "/asset/";
    if (relative.rfind(prefix, 0) == 0) relative = relative.substr(prefix.size());
    if (relative.empty()) return http::Response::status_only(404, "no asset requested");
    if (relative.find("..") != std::string::npos) {
        return http::Response::status_only(400, "invalid asset path");
    }

    std::wstring wide = widen(relative);
    for (auto& character : wide) {
        if (character == L'/') character = L'\\';
    }
    const std::wstring path = rbx::workspace_directory() + L"\\" + wide;
    const auto data = read_file(path);
    if (data.empty()) return http::Response::status_only(404, "asset not found");

    http::Response response;
    response.status = 200;
    response.content_type = content_type_for(path);
    response.body.assign(reinterpret_cast<const char*>(data.data()), data.size());
    response.headers.emplace_back("Cache-Control", "no-store");
    return response;
}

http::Response handle_index(const http::Request&) {
    const std::string page =
        "<!doctype html><meta charset=utf-8><title>Vesper</title>"
        "<body style=\"font:14px/1.5 ui-monospace,Consolas,monospace;background:#0b0d10;color:#c9d1d9;"
        "padding:24px\"><h1 style=\"font:600 20px system-ui;margin:0 0 12px\">Vesper bridge</h1>"
        "<p>This endpoint speaks to the shell UI. Live state: <a style=\"color:#5ac8fa\" "
        "href=\"/state\">/state</a></p>"
        "<pre id=out style=\"white-space:pre-wrap\"></pre>"
        "<script>fetch('/state').then(r=>r.json()).then(j=>{document.getElementById('out')"
        ".textContent=JSON.stringify(j.state,null,2)})</script></body>";
    return http::Response{200, "text/html; charset=utf-8", page, {}};
}

// ------------------------------------------------------------- runtime loop --

bool g_apc_mode = false;

void write_client_record() {
    json record;
    record["mode"] = g_apc_mode ? "apc" : "http";
    record["pid"] = GetCurrentProcessId();
    record["port"] = g_port;
    record["token"] = g_token;
    record["url"] = url();
    record["build"] = rbx::status().build;
    record["profile"] = rbx::status().profile_source;
    record["exe"] = narrow(module_path(nullptr));
    record["started"] = static_cast<std::int64_t>(time(nullptr));
    record["version"] = "3.0.0";

    const std::string text = record.dump(2);
    const std::wstring path = client_record_path();
    if (write_file(path, text.data(), text.size())) {
        VSP_INFO("bridge: client record written to %s", narrow(path).c_str());
    } else {
        VSP_WARN("bridge: could not write %s", narrow(path).c_str());
    }
}

void remove_client_record() {
    const std::wstring path = client_record_path();
    DeleteFileW(path.c_str());
}

// Opt-in self-test for the VM-hook lane. With `VESPER_HOOKTEST=1` in the
// client's environment, the first tick that sees a live `lua_State` installs the
// detour and queues exactly one probe. Without the variable this makes no call
// at all, so a normal session never touches the VM entry.
void maybe_run_hook_selftest() {
    static bool decided = false;
    if (decided) return;

    wchar_t value[8] = {};
    const DWORD length = GetEnvironmentVariableW(L"VESPER_HOOKTEST", value, 8);
    const bool requested =
        length > 0 && (value[0] == L'1' || value[0] == L't' || value[0] == L'T');
    if (!requested) {
        decided = true;  // remember the answer; never look again
        return;
    }
    if (!rbx::status().in_game || !rbx::status().has_lua_state) return;

    decided = true;
    VSP_INFO("hooktest: %s", rbx::hook_install().c_str());
    if (rbx::hook_active()) {
        VSP_INFO("hooktest: probe %s",
                 rbx::hook_queue_probe() ? "queued" : "not queued (a job is in flight)");
    }
}

// The tick runs on a timer-queue thread from the system pool rather than on a thread we
// create. Measured: a std::thread we start is gone ~8 s after attach -- a heartbeat file
// written from its loop stops growing at exactly that point and the thread count drops --
// while the client itself keeps running. A pool thread belongs to ntdll/kernel32 and does
// not carry our module as its start address, which is the difference that matters here.
HANDLE g_tick_timer = nullptr;

void CALLBACK runtime_tick(void* /*unused*/, BOOLEAN /*timer_or_wait*/) {
    // A heartbeat that deliberately does not go through the logger. If this file keeps
    // growing while the engine log stops, the tick is alive and the logging is what
    // broke; if neither grows, the tick itself is gone. That distinction is what showed
    // the thread was being terminated rather than the log wedging.
    static HANDLE heartbeat = [] {
        wchar_t directory[MAX_PATH] = {};
        if (GetTempPathW(MAX_PATH, directory) == 0) return INVALID_HANDLE_VALUE;
        std::wstring path(directory);
        path += L"vesper_heartbeat.txt";
        return CreateFileW(path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    }();

    if (g_stop.load()) return;

    // A client that was launched suspended and had the engine mapped in before it ran
    // has no place yet, so the first attach legitimately fails. The session guard in
    // start_session is one-shot, so without this the failure would stick for the whole
    // life of the process and the executor would sit there doing nothing. Retry slowly,
    // and once there are bindings stop asking.
    if (!rbx::status().has_bindings) {
        static std::uint64_t last_attempt = 0;
        static bool reported = false;
        const std::uint64_t now = GetTickCount64();
        if (now - last_attempt > 2000) {
            last_attempt = now;
            std::string retry_error;
            if (rbx::attach(retry_error)) {
                VSP_INFO("attach: retry succeeded");
                reported = false;
            } else if (!reported) {
                reported = true;
                VSP_INFO("attach: retry still failing (%s); will keep trying every 2 s",
                         retry_error.c_str());
            }
        }
    }

    if (heartbeat != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        WriteFile(heartbeat, ".", 1, &written, nullptr);
    }
    if (rbx::status().has_bindings) {
        rbx::refresh();
        if (!rbx::status().environment_ready && rbx::status().in_game) {
            rbx::setup();
            if (rbx::status().environment_ready) write_client_record();
        }
        maybe_run_hook_selftest();
    }

    // State is broadcast on change rather than on every tick so the UI is not
    // flooded while a place is loading.
    static int ticks = 0;
    ++ticks;
    if (ticks % 4 == 0 || g_server.socket_count() > 0) {
        const std::string snapshot = state_object().dump();
        bool changed = false;
        {
            std::lock_guard<std::mutex> guard(g_state_mutex);
            changed = snapshot != g_last_state;
            if (changed) g_last_state = snapshot;
        }
        if (changed) {
            g_server.broadcast(json{{"ok", true}, {"type", "state"},
                                    {"state", json::parse(snapshot)}}
                                  .dump());
        }
    }
}

}  // namespace

std::wstring clients_directory() {
    wchar_t local[MAX_PATH * 2];
    const DWORD len = GetEnvironmentVariableW(L"LOCALAPPDATA", local, static_cast<DWORD>(std::size(local)));
    std::wstring root = len > 0 ? std::wstring(local, len) : default_engine_directory();
    root += L"\\Vesper\\clients";
    ensure_directory(root);
    return root;
}

std::uint16_t port() { return g_port; }

std::string url() { return vformat("http://127.0.0.1:%u", g_port); }

const std::string& token() { return g_token; }

bool start(const Config& config, std::uint16_t& port_out, std::string& error) {
    g_config = config;
    g_token = config.token.empty() ? random_token(16) : config.token;

    g_server.set_token(g_token);
    g_server.route("/", handle_index);
    g_server.route("/ping", handle_ping);
    g_server.route("/state", handle_state);
    g_server.route("/abi", handle_abi);
    g_server.route("/abi/repair", handle_abi_repair);
    g_server.route("/hostprobe", handle_hostprobe);
    g_server.route("/exec", handle_exec);
    g_server.route("/hooktest", handle_hooktest);
    g_server.route("/execute_script", handle_execute);
    g_server.route("/result", handle_result);
    g_server.route("/client_manager", handle_clients);

    g_server.on_message([&](const std::string& payload) {
        VSP_DEBUG("ws: %s", payload.c_str());
        if (payload.find("\"state\"") != std::string::npos) broadcast_state();
    });

    if (!g_server.start("127.0.0.1", config.port, error)) {
        // A port collision is common enough to be worth one retry on a free port.
        if (config.port != 0) {
            std::string retry_error;
            if (g_server.start("127.0.0.1", 0, retry_error)) {
                g_port = g_server.port();
                env::set_bridge_port(g_port);
                VSP_WARN("bridge: port %u was busy, using %u", config.port, g_port);
            } else {
                error = retry_error;
                return false;
            }
        } else {
            return false;
        }
    }

    g_port = g_server.port();
    env::set_bridge_port(g_port);

    VSP_INFO("bridge: listening on %s (token %s)", url().c_str(), g_token.c_str());
    VSP_INFO("[BRIDGE] Ready on 127.0.0.1:%u", g_port);

    g_stop.store(false);
    if (engine_stage() >= 4) {
        if (!CreateTimerQueueTimer(&g_tick_timer, nullptr, runtime_tick, nullptr, 250, 250,
                                   WT_EXECUTEDEFAULT)) {
            VSP_WARN("bridge: could not start the tick timer (error %lu)", GetLastError());
        }
    } else {
        VSP_INFO("bridge: stage %d -- no tick timer", engine_stage());
    }

    write_client_record();
    port_out = g_port;
    return true;
}

void stop() {
    // Log before touching anything: if the join below ever hangs, this line is the only
    // evidence that a stop was *requested*, and without it a wedged stop is
    // indistinguishable from the engine being killed outright.
    VSP_INFO("bridge: stop requested (thread %lu)", GetCurrentThreadId());
    g_stop.store(true);
    if (g_tick_timer != nullptr) {
        DeleteTimerQueueTimer(nullptr, g_tick_timer, nullptr);
        g_tick_timer = nullptr;
    }
    g_server.stop();
    remove_client_record();
    VSP_INFO("bridge: stopped");
}

void publish_apc_record() {
    g_apc_mode = true;
    write_client_record();
}

void broadcast_state() {
    if (g_port == 0) return;
    g_server.broadcast(envelope(state_object()).dump());
}

}  // namespace vesper::bridge
