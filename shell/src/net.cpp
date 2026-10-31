#include "net.hpp"

#include "mapper.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <winhttp.h>

#include "util.hpp"

namespace vesper::shell {

namespace {

// ------------------------------------------------------------------- json --
//
// The engine's records and replies are flat objects of strings and numbers, so a
// scanner over that exact shape is enough. Anything nested is pulled out with
// `json_extract_object` and parsed with the same flat rules.

std::string unescape(const std::string& text) {
    std::string out;
    out.reserve(text.size());
    for (std::size_t i = 0; i < text.size(); ++i) {
        if (text[i] != '\\' || i + 1 >= text.size()) {
            out.push_back(text[i]);
            continue;
        }
        const char next = text[++i];
        switch (next) {
            case 'n': out.push_back('\n'); break;
            case 't': out.push_back('\t'); break;
            case 'r': out.push_back('\r'); break;
            case 'b': out.push_back('\b'); break;
            case 'f': out.push_back('\f'); break;
            case 'u': {
                if (i + 4 < text.size()) i += 4;
                out.push_back('?');
                break;
            }
            default: out.push_back(next); break;
        }
    }
    return out;
}

}  // namespace

std::string json_escape(const std::string& text) {
    std::string out;
    out.reserve(text.size() + 16);
    for (unsigned char character : text) {
        switch (character) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (character < 0x20) {
                    char buffer[8];
                    std::snprintf(buffer, sizeof(buffer), "\\u%04x", character);
                    out += buffer;
                } else {
                    out.push_back(static_cast<char>(character));
                }
                break;
        }
    }
    return out;
}

namespace {

std::size_t find_key(const std::string& text, const std::string& key) {
    const std::string needle = "\"" + key + "\"";
    std::size_t position = text.find(needle);
    while (position != std::string::npos) {
        std::size_t cursor = position + needle.size();
        while (cursor < text.size() && std::isspace(static_cast<unsigned char>(text[cursor]))) ++cursor;
        if (cursor < text.size() && text[cursor] == ':') return cursor + 1;
        position = text.find(needle, position + 1);
    }
    return std::string::npos;
}

}  // namespace

namespace {

bool json_get(const std::string& text, const std::string& key, std::string& value) {
    std::size_t cursor = find_key(text, key);
    if (cursor == std::string::npos) return false;
    while (cursor < text.size() && std::isspace(static_cast<unsigned char>(text[cursor]))) ++cursor;
    if (cursor >= text.size()) return false;

    if (text[cursor] == '"') {
        ++cursor;
        std::string raw;
        for (; cursor < text.size(); ++cursor) {
            if (text[cursor] == '\\' && cursor + 1 < text.size()) {
                raw.push_back(text[cursor]);
                raw.push_back(text[cursor + 1]);
                ++cursor;
                continue;
            }
            if (text[cursor] == '"') break;
            raw.push_back(text[cursor]);
        }
        value = unescape(raw);
        return true;
    }

    const std::size_t end = text.find_first_of(",}\r\n", cursor);
    value = text.substr(cursor, end == std::string::npos ? std::string::npos : end - cursor);
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back()))) value.pop_back();
    return true;
}

bool json_get_int(const std::string& text, const std::string& key, long long& value) {
    std::string raw;
    if (!json_get(text, key, raw) || raw.empty()) return false;
    try {
        value = std::stoll(raw);
    } catch (const std::exception&) {
        return false;
    }
    return true;
}

bool json_get_bool(const std::string& text, const std::string& key, bool& value) {
    std::string raw;
    if (!json_get(text, key, raw)) return false;
    value = raw == "true";
    return true;
}

bool json_extract_object(const std::string& text, const std::string& key, std::string& out) {
    std::size_t cursor = find_key(text, key);
    if (cursor == std::string::npos) return false;
    while (cursor < text.size() && std::isspace(static_cast<unsigned char>(text[cursor]))) ++cursor;
    if (cursor >= text.size() || text[cursor] != '{') return false;

    int depth = 0;
    bool in_string = false;
    const std::size_t start = cursor;
    for (; cursor < text.size(); ++cursor) {
        const char character = text[cursor];
        if (in_string) {
            if (character == '\\') {
                ++cursor;
            } else if (character == '"') {
                in_string = false;
            }
            continue;
        }
        if (character == '"') {
            in_string = true;
        } else if (character == '{') {
            ++depth;
        } else if (character == '}') {
            if (--depth == 0) {
                out = text.substr(start, cursor - start + 1);
                return true;
            }
        }
    }
    return false;
}

// -------------------------------------------------------------------- http --

struct HttpResponse {
    bool ok = false;
    int status = 0;
    std::string body;
    std::string error;
};

HttpResponse http_call(const std::string& method, const std::string& url, const std::string& body,
                       const std::string& token, int timeout_ms) {
    HttpResponse response;

    const std::wstring wide_url = widen(url);
    URL_COMPONENTS components{};
    components.dwStructSize = sizeof(components);
    wchar_t host[256] = {};
    wchar_t path[2048] = {};
    components.lpszHostName = host;
    components.dwHostNameLength = static_cast<DWORD>(std::size(host));
    components.lpszUrlPath = path;
    components.dwUrlPathLength = static_cast<DWORD>(std::size(path));
    if (!WinHttpCrackUrl(wide_url.c_str(), static_cast<DWORD>(wide_url.size()), 0, &components)) {
        response.error = "malformed url";
        return response;
    }

    HINTERNET session =
        WinHttpOpen(L"VesperShell/3.0", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME,
                    WINHTTP_NO_PROXY_BYPASS, 0);
    if (session == nullptr) {
        response.error = "WinHttpOpen failed";
        return response;
    }
    WinHttpSetTimeouts(session, timeout_ms, timeout_ms, timeout_ms, timeout_ms);

    const std::wstring host_name(host, components.dwHostNameLength);
    std::wstring url_path(path, components.dwUrlPathLength);
    if (url_path.empty()) url_path = L"/";

    HINTERNET connection = WinHttpConnect(session, host_name.c_str(), components.nPort, 0);
    if (connection == nullptr) {
        WinHttpCloseHandle(session);
        response.error = "cannot reach the bridge";
        return response;
    }

    const std::wstring method_wide = widen(method);
    HINTERNET request = WinHttpOpenRequest(connection, method_wide.c_str(), url_path.c_str(), nullptr,
                                           WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (request == nullptr) {
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);
        response.error = "WinHttpOpenRequest failed";
        return response;
    }

    std::wstring headers;
    if (!token.empty()) headers += L"X-Vesper-Token: " + widen(token) + L"\r\n";
    if (!body.empty()) headers += L"Content-Type: application/json\r\n";

    const BOOL sent = WinHttpSendRequest(
        request, headers.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : headers.c_str(),
        headers.empty() ? 0 : static_cast<DWORD>(headers.size()),
        body.empty() ? WINHTTP_NO_REQUEST_DATA : const_cast<char*>(body.data()),
        static_cast<DWORD>(body.size()), static_cast<DWORD>(body.size()), 0);

    if (!sent || !WinHttpReceiveResponse(request, nullptr)) {
        response.error = "no response from the bridge";
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);
        return response;
    }

    DWORD status = 0;
    DWORD status_size = sizeof(status);
    WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &status, &status_size, WINHTTP_NO_HEADER_INDEX);
    response.status = static_cast<int>(status);

    for (;;) {
        DWORD available = 0;
        if (!WinHttpQueryDataAvailable(request, &available) || available == 0) break;
        std::string chunk(available, '\0');
        DWORD read = 0;
        if (!WinHttpReadData(request, chunk.data(), available, &read)) break;
        chunk.resize(read);
        response.body += chunk;
        if (response.body.size() > (16u << 20)) break;
    }

    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connection);
    WinHttpCloseHandle(session);
    response.ok = response.status >= 200 && response.status < 300;
    if (!response.ok && response.status == 401) response.error = "token rejected";
    return response;
}

// ----------------------------------------------------------------- process --

std::uintptr_t remote_module_base(HANDLE process, const wchar_t* module_name) {
    HMODULE modules[1024];
    DWORD needed = 0;
    if (!EnumProcessModulesEx(process, modules, sizeof(modules), &needed, LIST_MODULES_ALL)) return 0;
    const DWORD count = needed / sizeof(HMODULE);
    for (DWORD i = 0; i < count && i < std::size(modules); ++i) {
        wchar_t path[MAX_PATH * 2] = {};
        if (GetModuleFileNameExW(process, modules[i], path, static_cast<DWORD>(std::size(path))) == 0) {
            continue;
        }
        const std::wstring file = file_name(path);
        if (_wcsicmp(file.c_str(), module_name) == 0) {
            return reinterpret_cast<std::uintptr_t>(modules[i]);
        }
    }
    return 0;
}

std::uintptr_t export_rva(HMODULE module, const char* name) {
    const auto address = reinterpret_cast<std::uintptr_t>(GetProcAddress(module, name));
    if (address == 0) return 0;
    return address - reinterpret_cast<std::uintptr_t>(module);
}

bool record_exists(int pid) {
    const std::wstring path =
        clients_directory() + L"\\" + std::to_wstring(pid) + L".json";
    return file_exists(path);
}

struct RemoteBlock {
    void* address = nullptr;
    std::size_t size = 0;
};

RemoteBlock remote_write(HANDLE process, const void* data, std::size_t size) {
    RemoteBlock block;
    block.address = VirtualAllocEx(process, nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (block.address == nullptr) return block;
    SIZE_T written = 0;
    if (!WriteProcessMemory(process, block.address, data, size, &written) || written != size) {
        VirtualFreeEx(process, block.address, 0, MEM_RELEASE);
        block.address = nullptr;
        return block;
    }
    block.size = size;
    return block;
}

std::vector<DWORD> threads_of(int pid) {
    std::vector<DWORD> threads;
    const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return threads;
    THREADENTRY32 entry{};
    entry.dwSize = sizeof(entry);
    if (Thread32First(snapshot, &entry)) {
        do {
            if (entry.th32OwnerProcessID == static_cast<DWORD>(pid)) threads.push_back(entry.th32ThreadID);
        } while (Thread32Next(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return threads;
}

// Queues LoadLibraryW with the remote path on every thread of the target. This is
// the primary injection path: no CreateRemoteThread, no new thread object in the
// target, and the loader runs in a thread that already exists.
bool inject_with_apc(HANDLE process, std::uintptr_t load_library, const RemoteBlock& path_block,
                     int pid) {
    const auto routine = reinterpret_cast<PAPCFUNC>(load_library);
    bool queued = false;
    for (DWORD thread_id : threads_of(pid)) {
        const HANDLE thread = OpenThread(THREAD_SET_CONTEXT, FALSE, thread_id);
        if (thread == nullptr) continue;
        if (QueueUserAPC(routine, thread, reinterpret_cast<ULONG_PTR>(path_block.address))) queued = true;
        CloseHandle(thread);
    }
    (void)process;
    return queued;
}

}  // namespace

std::wstring clients_directory() {
    // Must resolve to the same place the engine publishes its record into:
    // %LOCALAPPDATA%\Vesper\clients, with the engine's own fallback if the
    // environment variable is missing.
    wchar_t local[MAX_PATH * 2] = {};
    const DWORD length = GetEnvironmentVariableW(L"LOCALAPPDATA", local, static_cast<DWORD>(std::size(local)));
    std::wstring root = length > 0 ? std::wstring(local, length) : app_directory();
    root += L"\\Vesper\\clients";
    ensure_directory(root);
    return root;
}

std::wstring engine_dll_path() {
    const std::wstring beside = app_directory() + L"\\Vesper.dll";
    if (file_exists(beside)) return beside;
    const std::wstring in_out = app_directory() + L"\\out\\Vesper.dll";
    if (file_exists(in_out)) return in_out;
    return beside;
}

bool pid_alive(int pid) {
    if (pid <= 0) return false;
    const HANDLE process = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                                       static_cast<DWORD>(pid));
    if (process == nullptr) return false;
    DWORD code = 0;
    const bool alive = GetExitCodeProcess(process, &code) && code == STILL_ACTIVE;
    CloseHandle(process);
    return alive;
}

std::vector<int> find_roblox_pids() {
    std::vector<int> pids;
    const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return pids;

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snapshot, &entry)) {
        do {
            const std::wstring name = entry.szExeFile;
            if (name == L"RobloxPlayerBeta.exe" || name == L"RobloxStudioBeta.exe") {
                pids.push_back(static_cast<int>(entry.th32ProcessID));
            }
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return pids;
}

std::vector<ClientInfo> list_clients() {
    std::vector<ClientInfo> clients;
    const std::wstring directory = clients_directory();
    ensure_directory(directory);

    WIN32_FIND_DATAW entry{};
    const std::wstring pattern = directory + L"\\*.json";
    const HANDLE find = FindFirstFileW(pattern.c_str(), &entry);
    if (find == INVALID_HANDLE_VALUE) return clients;

    do {
        const std::wstring path = directory + L"\\" + entry.cFileName;
        const auto data = read_file(path);
        if (data.empty()) continue;
        const std::string text(data.begin(), data.end());

        ClientInfo client;
        client.record = narrow(path);
        client.record_time =
            (static_cast<std::int64_t>(entry.ftLastWriteTime.dwHighDateTime) << 32) |
            static_cast<std::int64_t>(entry.ftLastWriteTime.dwLowDateTime);
        long long number = 0;
        json_get_int(text, "pid", number);
        client.pid = static_cast<int>(number);
        if (json_get_int(text, "port", number)) client.port = static_cast<int>(number);
        if (json_get_int(text, "started", number)) client.started = number;
        json_get(text, "token", client.token);
        json_get(text, "url", client.url);
        json_get(text, "build", client.build);
        json_get(text, "profile", client.profile);
        json_get(text, "exe", client.exe);
        json_get(text, "mode", client.mode);

        client.alive = pid_alive(client.pid);
        if (client.url.empty() && client.port != 0) {
            client.url = "http://127.0.0.1:" + std::to_string(client.port);
        }
        clients.push_back(client);
    } while (FindNextFileW(find, &entry));
    FindClose(find);

    // A dead instance keeps its record: the engine only deletes it on a clean
    // detach. Live clients come first, and among those the newest one wins, so a
    // stale 21:27 record can never shadow the client a later --launch created.
    auto when = [](const ClientInfo& client) {
        return client.started > 0 ? client.started : client.record_time;
    };
    std::sort(clients.begin(), clients.end(), [&](const ClientInfo& a, const ClientInfo& b) {
        if (a.alive != b.alive) return a.alive;
        return when(a) > when(b);
    });
    return clients;
}

ClientInfo* select_client(std::vector<ClientInfo>& clients, int only_pid) {
    ClientInfo* dead = nullptr;
    for (ClientInfo& client : clients) {
        if (only_pid != 0 && client.pid != only_pid) continue;
        if (client.alive) return &client;
        if (dead == nullptr) dead = &client;
    }
    // No live candidate: return the newest dead one so the failure still names
    // the client the user meant instead of saying "none".
    return dead;
}

bool probe_client(ClientInfo& client) {
    std::string body;
    std::string error;
    const HttpResponse response = http_call("GET", client.url + "/ping", {}, client.token, 1500);
    if (!response.ok) {
        client.reachable = false;
        client.detail = response.error.empty() ? "unreachable" : response.error;
        return false;
    }
    client.reachable = true;
    client.detail = "engine online";

    EngineState state;
    if (fetch_state(client, state, error)) {
        client.ready = state.ready;
        client.in_game = state.in_game;
        client.thread_identity = state.thread_identity;
        if (!state.build.empty()) client.build = state.build;
        if (!state.profile.empty()) client.profile = state.profile;
        client.detail = state.ready ? "ready" : (state.in_game ? "in game, attaching" : "waiting for a place");
    }
    return true;
}

bool fetch_state(const ClientInfo& client, EngineState& state, std::string& error) {
    const HttpResponse response = http_call("GET", client.url + "/state", {}, client.token, 4000);
    if (!response.ok) {
        error = response.error.empty() ? "state request failed" : response.error;
        return false;
    }

    std::string payload;
    if (!json_extract_object(response.body, "state", payload)) {
        error = "malformed state payload";
        return false;
    }

    state.valid = true;
    json_get(payload, "build", state.build);
    json_get(payload, "profile", state.profile);
    json_get(payload, "dataModel", state.data_model);
    json_get(payload, "scriptContext", state.script_context);
    json_get(payload, "luaState", state.lua_state);
    json_get(payload, "strategy", state.strategy);
    json_get(payload, "identityField", state.identity_field);
    json_get(payload, "error", state.error);
    json_get_bool(payload, "inGame", state.in_game);
    json_get_bool(payload, "environment", state.environment);
    json_get_bool(payload, "ready", state.ready);
    json_get_bool(payload, "abiVerified", state.abi_verified);

    long long number = 0;
    if (json_get_int(payload, "threadIdentity", number)) state.thread_identity = static_cast<int>(number);
    if (json_get_int(payload, "pending", number)) state.pending = static_cast<int>(number);
    if (json_get_int(payload, "executed", number)) state.executed = static_cast<int>(number);
    if (json_get_int(payload, "failed", number)) state.failed = static_cast<int>(number);
    if (json_get_int(payload, "port", number)) state.port = static_cast<int>(number);
    if (json_get_int(payload, "sockets", number)) state.sockets = static_cast<int>(number);
    if (json_get_int(payload, "pid", number)) state.pid = static_cast<int>(number);
    return true;
}

bool fetch_report(const ClientInfo& client, const char* route, std::string& report,
                  std::string& error) {
    const HttpResponse response = http_call("POST", client.url + route, "{}", client.token, 8000);
    if (!response.ok) {
        error = response.error.empty() ? "request failed" : response.error;
        return false;
    }
    if (!json_get(response.body, "report", report)) {
        error = "malformed report";
        return false;
    }
    return true;
}

bool run_script(const ClientInfo& client, const std::string& source, const std::string& name,
                int timeout_ms, std::string& output, bool& still_pending, std::string& error) {
    std::string body = "{\"script\":\"" + json_escape(source) + "\",\"name\":\"" + json_escape(name) +
                       "\"}";

    // `/exec` is the private-thread lane: the client compiles the chunk, builds
    // a thread out of its own allocator and runs it there, then answers with the
    // value the chunk returned. `/execute_script` keeps its queued-lane shape for
    // the UI and now answers the same way.
    const HttpResponse response =
        http_call("POST", client.url + "/exec", body, client.token, timeout_ms + 4000);
    if (!response.ok) {
        error = response.error.empty() ? "execute request failed" : response.error;
        return false;
    }

    if (!json_get(response.body, "output", output)) output.clear();
    std::string message;
    if (json_get(response.body, "error", message)) {
        if (!message.empty() && output.empty()) output = message;
        error.clear();  // the body carries a verdict, not a transport failure
    }
    json_get_bool(response.body, "pending", still_pending);
    return true;
}

bool run_script_apc(const ClientInfo& client, const std::string& source, int timeout_ms,
                    std::string& output, std::string& error) {
    // <root>\Vesper\clients -> <root>\Vesper
    const std::wstring clients = clients_directory();
    const std::wstring root = clients.substr(0, clients.rfind(L'\\'));
    const std::wstring inbox = root + L"\\inbox";
    const std::wstring outbox = root + L"\\outbox";
    ensure_directory(inbox);
    ensure_directory(outbox);

    const std::wstring pid = std::to_wstring(client.pid);
    const std::wstring request = inbox + L"\\" + pid + L".req";
    const std::wstring temp = inbox + L"\\" + pid + L".tmp";
    const std::wstring answer = outbox + L"\\" + pid + L".json";

    // A leftover answer would be mistaken for this command's.
    DeleteFileW(answer.c_str());

    // Written aside and moved into place, so the engine never reads half a script.
    if (!write_file(temp, source.data(), source.size()) ||
        !MoveFileExW(temp.c_str(), request.c_str(), MOVEFILE_REPLACE_EXISTING)) {
        error = "could not write the request file";
        return false;
    }

    // Delivery is a matter of waiting for some thread of the client to become alertable, and
    // MEASURED on 9ac8 that can take from a second to longer than twenty. So the window is
    // long and the APC is re-queued on every pass: a delivery that finds the request already
    // taken does nothing, and the rename in the engine makes a second run impossible.
    const std::int64_t deadline = now_ms() + timeout_ms;
    std::int64_t next_apc = 0;
    int rounds = 0;
    int last_delivered = 0;
    while (now_ms() < deadline) {
        // An APC runs only when a thread of the client is alertable, so one is queued
        // again every second and a half until the engine has taken the request. The
        // extra ones find an empty inbox and return.
        if (now_ms() >= next_apc) {
            const int delivered = deliver_command_apc(client.pid);
            if (delivered < 0) {
                DeleteFileW(request.c_str());
                error = "no gate stub is recorded for this client; attach it with --map ... --gate --apc";
                return false;
            }
            ++rounds;
            last_delivered = delivered;
            next_apc = now_ms() + 1000;
        }

        const auto data = read_file(answer);
        if (!data.empty()) {
            const std::string text(data.begin(), data.end());
            DeleteFileW(answer.c_str());
            std::string message;
            if (!json_get(text, "value", output)) output.clear();
            if (json_get(text, "error", message) && !message.empty() && output.empty()) output = message;
            return true;
        }
        if (!pid_alive(client.pid)) {
            DeleteFileW(request.c_str());
            error = "the client exited before answering";
            return false;
        }
        Sleep(100);
    }

    // Never leave a request behind to run later, unasked.
    DeleteFileW(request.c_str());
    error = "no answer within " + std::to_string(timeout_ms) + " ms (" + std::to_string(rounds) +
            " APC rounds, last one accepted by " + std::to_string(last_delivered) + " threads)";
    return false;
}

InjectOutcome inject(int pid, const std::wstring& dll_path, int wait_ms) {
    InjectOutcome outcome;
    outcome.pid = pid;

    if (!file_exists(dll_path)) {
        outcome.detail = "engine dll not found: " + narrow(dll_path);
        return outcome;
    }
    if (!pid_alive(pid)) {
        outcome.detail = "target process is not running";
        return outcome;
    }

    const HANDLE process = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
                                           PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | SYNCHRONIZE,
                                       FALSE, static_cast<DWORD>(pid));
    if (process == nullptr) {
        outcome.detail = "OpenProcess failed (" + std::to_string(GetLastError()) +
                         ") - run the shell as administrator";
        return outcome;
    }

    const std::uintptr_t kernel32 = remote_module_base(process, L"kernel32.dll");
    if (kernel32 == 0) {
        CloseHandle(process);
        outcome.detail = "could not locate kernel32 in the target";
        return outcome;
    }
    const std::uintptr_t load_rva = export_rva(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
    if (load_rva == 0) {
        CloseHandle(process);
        outcome.detail = "could not resolve LoadLibraryW";
        return outcome;
    }
    const std::uintptr_t remote_load_library = kernel32 + load_rva;

    const std::wstring path_copy = dll_path;
    const RemoteBlock path_block =
        remote_write(process, path_copy.c_str(), (path_copy.size() + 1) * sizeof(wchar_t));
    if (path_block.address == nullptr) {
        CloseHandle(process);
        outcome.detail = "could not allocate in the target";
        return outcome;
    }

    bool queued = inject_with_apc(process, remote_load_library, path_block, pid);
    if (queued) outcome.detail = "APC queued";

    const std::int64_t deadline = now_ms() + std::max(1500, wait_ms);
    while (now_ms() < deadline) {
        if (record_exists(pid)) {
            outcome.ok = true;
            outcome.detail = queued ? "loaded via APC" : "loaded";
            CloseHandle(process);
            return outcome;
        }
        if (!pid_alive(pid)) {
            CloseHandle(process);
            outcome.ok = false;
            outcome.detail = "the target exited during injection";
            return outcome;
        }
        Sleep(120);
    }

    // Fallback: some processes keep no alertable thread, so the APC sits in the
    // queue forever. A remote thread is louder but it is the only remaining path,
    // and it doubles as the diagnostic: LoadLibraryW's return value says whether
    // the target's loader accepted the module at all.
    const HANDLE thread =
        CreateRemoteThread(process, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(remote_load_library),
                           path_block.address, 0, nullptr);
    if (thread != nullptr) {
        DWORD loaded = 0;
        WaitForSingleObject(thread, 8000);
        GetExitCodeThread(thread, &loaded);
        CloseHandle(thread);

        if (loaded == 0) {
            CloseHandle(process);
            outcome.ok = false;
            outcome.detail = "the target's loader refused the module (LoadLibraryW returned NULL)";
            return outcome;
        }

        char hex[32] = {};
        std::snprintf(hex, sizeof(hex), "%#lx", static_cast<unsigned long>(loaded));
        outcome.detail = std::string("mapped at ") + hex + " but the engine did not report";

        const std::int64_t second = now_ms() + 6000;
        while (now_ms() < second) {
            if (record_exists(pid)) {
                outcome.ok = true;
                outcome.detail = std::string("loaded via remote thread at ") + hex;
                CloseHandle(process);
                return outcome;
            }
            Sleep(150);
        }
    } else {
        outcome.detail = "APC queued but never ran, and the remote thread failed (" +
                         std::to_string(GetLastError()) + ")";
    }

    CloseHandle(process);
    if (!outcome.ok && outcome.detail.empty()) outcome.detail = "injection did not take";
    return outcome;
}

std::vector<std::wstring> installed_client_paths() {
    std::vector<std::wstring> paths;

    wchar_t local[MAX_PATH * 2] = {};
    const DWORD length = GetEnvironmentVariableW(L"LOCALAPPDATA", local, static_cast<DWORD>(std::size(local)));
    if (length == 0) return paths;

    const std::wstring versions = std::wstring(local, length) + L"\\Roblox\\Versions";
    WIN32_FIND_DATAW entry{};
    const HANDLE find = FindFirstFileW((versions + L"\\version-*").c_str(), &entry);
    if (find == INVALID_HANDLE_VALUE) return paths;

    do {
        if ((entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) continue;
        const std::wstring exe = versions + L"\\" + entry.cFileName + L"\\RobloxPlayerBeta.exe";
        if (file_exists(exe)) paths.push_back(exe);
    } while (FindNextFileW(find, &entry));
    FindClose(find);
    return paths;
}

std::wstring preferred_client_path(const std::wstring& preferred_build) {
    const std::vector<std::wstring> paths = installed_client_paths();
    if (paths.empty()) return {};

    if (!preferred_build.empty()) {
        for (const std::wstring& path : paths) {
            if (path.find(preferred_build) != std::wstring::npos) return path;
        }
    }

    std::wstring newest;
    FILETIME best{};
    for (const std::wstring& path : paths) {
        WIN32_FILE_ATTRIBUTE_DATA data{};
        if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &data)) continue;
        if (newest.empty() || CompareFileTime(&data.ftLastWriteTime, &best) > 0) {
            best = data.ftLastWriteTime;
            newest = path;
        }
    }
    return newest;
}

std::string loader_error_name(std::uintptr_t code) {
    switch (code) {
        case 2: return "ERROR_FILE_NOT_FOUND";
        case 5: return "ERROR_ACCESS_DENIED";
        case 87: return "ERROR_INVALID_PARAMETER";
        case 126: return "ERROR_MOD_NOT_FOUND (a dependency could not be loaded)";
        case 127: return "ERROR_PROC_NOT_FOUND (a dependency lacks an import)";
        case 193: return "ERROR_BAD_EXE_FORMAT";
        case 998: return "ERROR_NOACCESS";
        case 1114: return "ERROR_DLL_INIT_FAILED (DllMain or CRT init refused)";
        case 1150: return "ERROR_OLD_WIN_VERSION";
        default: return "unrecognised";
    }
}

// A thread exit code alone cannot say whether a load failed, because a module
// handle and an error code are both just numbers. This stub therefore writes both
// into a slot the caller owns and only puts the loader's error there on failure:
//
//   slot[0] = the module handle, 0 when the load failed
//   slot[1] = GetLastError() from this same thread, only when it failed
//
// The thread parameter (RCX) is the slot address; rbx carries it across the calls.
std::vector<std::uint8_t> load_probe_stub(std::uintptr_t path_address, std::uintptr_t load_library,
                                          std::uintptr_t get_last_error, std::uint32_t flags) {
    std::vector<std::uint8_t> code;
    const auto emit = [&code](std::initializer_list<std::uint8_t> bytes) {
        code.insert(code.end(), bytes);
    };
    const auto emit64 = [&code](std::uintptr_t value) {
        for (int i = 0; i < 8; ++i) {
            code.push_back(static_cast<std::uint8_t>((value >> (i * 8)) & 0xFF));
        }
    };
    const auto emit32 = [&code](std::uint32_t value) {
        for (int i = 0; i < 4; ++i) {
            code.push_back(static_cast<std::uint8_t>((value >> (i * 8)) & 0xFF));
        }
    };

    emit({0x48, 0x83, 0xEC, 0x28});              // sub rsp, 0x28
    emit({0x48, 0x89, 0xCB});                    // mov rbx, rcx        -- the slot
    // A marker first, so "the stub never ran" is distinguishable from "the load
    // failed": slot[0] still holding this means the thread died before the call.
    emit({0x48, 0xB8}); emit64(0x53545542ULL);   // mov rax, 'STUB'
    emit({0x48, 0x89, 0x03});                    // mov [rbx], rax
    emit({0x48, 0xB9}); emit64(path_address);    // mov rcx, path
    emit({0x31, 0xD2});                          // xor edx, edx        -- hFile
    emit({0x41, 0xB8}); emit32(flags);           // mov r8d, flags
    emit({0x48, 0xB8}); emit64(load_library);    // mov rax, LoadLibraryExW
    emit({0xFF, 0xD0});                          // call rax
    emit({0x48, 0x89, 0x03});                    // mov [rbx], rax
    emit({0x48, 0x85, 0xC0});                    // test rax, rax
    emit({0x75, 0x10});                          // jnz +0x10           -- leave slot[1] alone
    emit({0x48, 0xB8}); emit64(get_last_error);  // mov rax, GetLastError
    emit({0xFF, 0xD0});                          // call rax
    emit({0x48, 0x89, 0x43, 0x08});              // mov [rbx+8], rax
    emit({0x48, 0x83, 0xC4, 0x28});              // add rsp, 0x28
    emit({0xC3});                                // ret
    return code;
}

// Whether a module is present in a process right now.
bool remote_module_present(DWORD pid, const std::wstring& module_name) {
    const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (snapshot == INVALID_HANDLE_VALUE) return false;

    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    bool found = false;
    if (Module32FirstW(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szModule, module_name.c_str()) == 0) {
                found = true;
                break;
            }
        } while (Module32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return found;
}

// Delivery test: ask the target to load a module that is *signed* but not present,
// by both routes, and see whether either lands. A signed module is used because
// the client refuses unsigned ones outright, so only this tells us whether the
// delivery mechanism itself -- an APC on an existing thread, or a remote thread --
// still works once the game is running.
ApcProbeOutcome probe_apc(const std::wstring& dll_path, int pid) {
    ApcProbeOutcome outcome;
    const std::wstring module_name = file_name(dll_path);

    HANDLE process = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
                                     PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                                 FALSE, static_cast<DWORD>(pid));
    if (process == nullptr) {
        outcome.detail = "OpenProcess failed (" + std::to_string(GetLastError()) + ")";
        return outcome;
    }
    outcome.pid = pid;

    const std::uintptr_t kernel32 = remote_module_base(process, L"kernel32.dll");
    const HMODULE local_kernel32 = GetModuleHandleW(L"kernel32.dll");
    const std::uintptr_t load_rva = kernel32 != 0 ? export_rva(local_kernel32, "LoadLibraryW") : 0;
    const std::uintptr_t remote_load_library = load_rva != 0 ? kernel32 + load_rva : 0;

    if (remote_load_library == 0) {
        CloseHandle(process);
        outcome.detail = "could not resolve LoadLibraryW in the target";
        return outcome;
    }

    const RemoteBlock path_block =
        remote_write(process, dll_path.c_str(), (dll_path.size() + 1) * sizeof(wchar_t));
    if (path_block.address == nullptr) {
        CloseHandle(process);
        outcome.detail = "could not allocate in the target";
        return outcome;
    }

    if (remote_module_present(static_cast<DWORD>(pid), module_name)) {
        outcome.detail = "already loaded before the test";
        outcome.loaded = true;
        CloseHandle(process);
        return outcome;
    }

    const bool queued = inject_with_apc(process, remote_load_library, path_block, pid);
    for (int attempt = 0; attempt < 40; ++attempt) {
        Sleep(250);
        if (remote_module_present(static_cast<DWORD>(pid), module_name)) {
            outcome.loaded = true;
            outcome.detail = "an APC on an existing thread loaded it";
            CloseHandle(process);
            return outcome;
        }
        if (!pid_alive(pid)) {
            outcome.detail = "the target died";
            CloseHandle(process);
            return outcome;
        }
    }

    const HANDLE thread =
        CreateRemoteThread(process, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(remote_load_library),
                           path_block.address, 0, nullptr);
    if (thread != nullptr) {
        WaitForSingleObject(thread, 10000);
        CloseHandle(thread);
        for (int attempt = 0; attempt < 20; ++attempt) {
            Sleep(250);
            if (remote_module_present(static_cast<DWORD>(pid), module_name)) {
                outcome.loaded = true;
                outcome.detail = "an APC did not land, but a remote thread loaded it";
                CloseHandle(process);
                return outcome;
            }
        }
    }

    char text[192] = {};
    std::snprintf(text, sizeof(text), "neither route loaded it (apc %s, target %s)",
                  queued ? "queued" : "could not be queued", pid_alive(pid) ? "alive" : "dead");
    outcome.detail = text;
    CloseHandle(process);
    return outcome;
}

// A stub that proves private memory can be executed at all: it writes a marker
// into the slot it is handed, then calls a kernel32 function from that page and
// writes the answer next to it. If the marker lands, the target runs code from a
// private page; if the call result lands too, it also lets that code call out.
std::vector<std::uint8_t> exec_probe_stub(std::uintptr_t api_address) {
    std::vector<std::uint8_t> code;
    const auto emit = [&code](std::initializer_list<std::uint8_t> bytes) {
        code.insert(code.end(), bytes);
    };
    const auto emit64 = [&code](std::uintptr_t value) {
        for (int i = 0; i < 8; ++i) {
            code.push_back(static_cast<std::uint8_t>((value >> (i * 8)) & 0xFF));
        }
    };

    emit({0x48, 0x83, 0xEC, 0x28});              // sub rsp, 0x28
    emit({0x48, 0x89, 0xCB});                    // mov rbx, rcx        -- the slot
    emit({0x48, 0xB8}); emit64(0x52554E32ULL);   // mov rax, 'RUN'
    emit({0x48, 0x89, 0x03});                    // mov [rbx], rax
    emit({0x48, 0xB8}); emit64(api_address);     // mov rax, GetCurrentProcessId
    emit({0xFF, 0xD0});                          // call rax
    emit({0x48, 0x89, 0x43, 0x08});              // mov [rbx+8], rax
    emit({0x48, 0x83, 0xC4, 0x28});              // add rsp, 0x28
    emit({0xC3});                                // ret
    return code;
}

// Runs a private-memory stub in the target and reports what it managed to do.
ExecOutcome probe_exec(int pid) {
    ExecOutcome outcome;

    HANDLE process = nullptr;
    HANDLE main_thread = nullptr;
    bool launched = false;

    if (pid == 0) {
        const std::wstring exe = preferred_client_path(L"");
        if (exe.empty()) {
            outcome.detail = "no client installed";
            return outcome;
        }

        std::wstring command = L"\"" + exe + L"\"";
        std::vector<wchar_t> mutable_command(command.begin(), command.end());
        mutable_command.push_back(L'\0');

        STARTUPINFOW startup{};
        startup.cb = sizeof(startup);
        PROCESS_INFORMATION info{};
        if (!CreateProcessW(exe.c_str(), mutable_command.data(), nullptr, nullptr, FALSE,
                            CREATE_SUSPENDED, nullptr, directory_of(exe).c_str(), &startup, &info)) {
            outcome.detail = "CreateProcess failed (" + std::to_string(GetLastError()) + ")";
            return outcome;
        }
        process = info.hProcess;
        main_thread = info.hThread;
        outcome.pid = static_cast<int>(info.dwProcessId);
        launched = true;
    } else {
        process = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
                                  PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                              FALSE, static_cast<DWORD>(pid));
        if (process == nullptr) {
            outcome.detail = "OpenProcess failed (" + std::to_string(GetLastError()) + ")";
            return outcome;
        }
        outcome.pid = pid;
    }

    const HMODULE local_kernel32 = GetModuleHandleW(L"kernel32.dll");
    const std::uintptr_t process_id_api =
        reinterpret_cast<std::uintptr_t>(GetProcAddress(local_kernel32, "GetCurrentProcessId"));

    const std::uint8_t zero_slot[16] = {};
    const RemoteBlock slot = remote_write(process, zero_slot, sizeof(zero_slot));

    if (slot.address == nullptr) {
        outcome.detail = "could not allocate in the target";
    } else {
        const std::vector<std::uint8_t> stub = exec_probe_stub(process_id_api);
        const RemoteBlock code = remote_write(process, stub.data(), stub.size());

        if (code.address == nullptr) {
            outcome.detail = "could not write the stub";
        } else {
            DWORD previous = 0;
            VirtualProtectEx(process, code.address, code.size, PAGE_EXECUTE_READ, &previous);

            const HANDLE thread =
                CreateRemoteThread(process, nullptr, 0,
                                   reinterpret_cast<LPTHREAD_START_ROUTINE>(code.address),
                                   slot.address, 0, nullptr);
            if (thread == nullptr) {
                outcome.detail = "CreateRemoteThread failed (" + std::to_string(GetLastError()) + ")";
            } else {
                const DWORD waited = WaitForSingleObject(thread, 8000);
                DWORD exit_code = 0;
                GetExitCodeThread(thread, &exit_code);
                CloseHandle(thread);

                std::uintptr_t values[2] = {};
                SIZE_T got = 0;
                if (!ReadProcessMemory(process, slot.address, values, sizeof(values), &got) ||
                    got != sizeof(values)) {
                    outcome.detail = "could not read the slot back";
                } else if (values[0] != 0x52554E32ULL) {
                    char text[128] = {};
                    std::snprintf(text, sizeof(text), "the stub never ran (wait %s, exit %lu)",
                                  waited == WAIT_TIMEOUT ? "timed out" : "signalled",
                                  static_cast<unsigned long>(exit_code));
                    outcome.detail = text;
                } else if (values[1] != static_cast<std::uintptr_t>(outcome.pid)) {
                    char text[128] = {};
                    std::snprintf(text, sizeof(text), "code ran but the call returned %llu",
                                  static_cast<unsigned long long>(values[1]));
                    outcome.detail = text;
                } else {
                    outcome.ran = true;
                    outcome.detail = "code ran and called kernel32 from the private page";
                }
            }
        }
    }

    if (launched) {
        TerminateProcess(process, 0);
        CloseHandle(main_thread);
    }
    CloseHandle(process);
    return outcome;
}

// Hands the loader one path and reads the answer out of the remote thread, in any
// process: with `pid` 0 a fresh client is started suspended for the attempt (and
// killed afterwards), otherwise the given process is used. With `flags` set to
// LOAD_LIBRARY_AS_DATAFILE the image is mapped without resolving imports or
// running DllMain, which splits "the loader refused this image" from "the image
// failed to initialise".
//
// `direct` calls the loader as the thread's own start routine instead of calling
// it from a private page. That distinction matters: the client tolerates a load
// requested from image memory and cancels one requested from shellcode.
ProbeOutcome probe_load(const std::wstring& dll_path, int pid, std::uint32_t flags, bool direct) {
    ProbeOutcome outcome;

    if (!file_exists(dll_path)) {
        outcome.detail = "not found: " + narrow(dll_path);
        return outcome;
    }

    HANDLE process = nullptr;
    HANDLE main_thread = nullptr;
    bool launched = false;

    if (pid == 0) {
        const std::wstring exe = preferred_client_path(L"");
        if (exe.empty()) {
            outcome.detail = "no client installed";
            return outcome;
        }

        std::wstring command = L"\"" + exe + L"\"";
        std::vector<wchar_t> mutable_command(command.begin(), command.end());
        mutable_command.push_back(L'\0');

        STARTUPINFOW startup{};
        startup.cb = sizeof(startup);
        PROCESS_INFORMATION info{};
        if (!CreateProcessW(exe.c_str(), mutable_command.data(), nullptr, nullptr, FALSE,
                            CREATE_SUSPENDED, nullptr, directory_of(exe).c_str(), &startup, &info)) {
            outcome.detail = "CreateProcess failed (" + std::to_string(GetLastError()) + ")";
            return outcome;
        }
        process = info.hProcess;
        main_thread = info.hThread;
        outcome.pid = static_cast<int>(info.dwProcessId);
        launched = true;
    } else {
        process = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
                                  PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                              FALSE, static_cast<DWORD>(pid));
        if (process == nullptr) {
            outcome.detail = "OpenProcess failed (" + std::to_string(GetLastError()) + ")";
            return outcome;
        }
        outcome.pid = pid;
    }

    const HMODULE local_kernel32 = GetModuleHandleW(L"kernel32.dll");
    const std::uintptr_t load_library =
        reinterpret_cast<std::uintptr_t>(GetProcAddress(local_kernel32, "LoadLibraryExW"));
    const std::uintptr_t get_last_error =
        reinterpret_cast<std::uintptr_t>(GetProcAddress(local_kernel32, "GetLastError"));

    const RemoteBlock path_block =
        remote_write(process, dll_path.c_str(), (dll_path.size() + 1) * sizeof(wchar_t));
    const std::uint8_t zero_slot[16] = {};
    const RemoteBlock slot = remote_write(process, zero_slot, sizeof(zero_slot));

    if (path_block.address == nullptr || slot.address == nullptr) {
        outcome.detail = "could not allocate in the target";
    } else if (direct) {
        // The loader's own code is the thread's start routine, so the request
        // arrives from image memory rather than from a page we wrote.
        const std::uintptr_t plain =
            reinterpret_cast<std::uintptr_t>(GetProcAddress(local_kernel32, "LoadLibraryW"));
        const HANDLE thread =
            CreateRemoteThread(process, nullptr, 0,
                               reinterpret_cast<LPTHREAD_START_ROUTINE>(plain), path_block.address,
                               0, nullptr);
        if (thread == nullptr) {
            outcome.detail = "CreateRemoteThread failed (" + std::to_string(GetLastError()) + ")";
        } else {
            const DWORD waited = WaitForSingleObject(thread, 15000);
            DWORD exit_code = 0;
            GetExitCodeThread(thread, &exit_code);
            CloseHandle(thread);

            if (exit_code == 0) {
                outcome.detail = "refused (the loader returned NULL)";
            } else {
                outcome.loaded = true;
                char hex[32] = {};
                std::snprintf(hex, sizeof(hex), "%#lx", static_cast<unsigned long>(exit_code));
                outcome.detail = std::string("accepted, loader returned ") + hex;
                if (waited == WAIT_TIMEOUT) outcome.detail += " (thread still busy)";
            }
        }
    } else {
        const std::vector<std::uint8_t> stub = load_probe_stub(
            reinterpret_cast<std::uintptr_t>(path_block.address), load_library, get_last_error, flags);
        const RemoteBlock code = remote_write(process, stub.data(), stub.size());

        if (code.address == nullptr) {
            outcome.detail = "could not write the probe stub";
        } else {
            DWORD previous = 0;
            VirtualProtectEx(process, code.address, code.size, PAGE_EXECUTE_READ, &previous);

            const HANDLE thread =
                CreateRemoteThread(process, nullptr, 0,
                                   reinterpret_cast<LPTHREAD_START_ROUTINE>(code.address),
                                   slot.address, 0, nullptr);
            if (thread == nullptr) {
                outcome.detail = "CreateRemoteThread failed (" + std::to_string(GetLastError()) + ")";
            } else {
                const DWORD waited = WaitForSingleObject(thread, 15000);
                DWORD exit_code = 0;
                GetExitCodeThread(thread, &exit_code);
                CloseHandle(thread);

                std::uintptr_t values[2] = {};
                SIZE_T got = 0;
                if (!ReadProcessMemory(process, slot.address, values, sizeof(values), &got) ||
                    got != sizeof(values)) {
                    outcome.detail = "the probe stub never reported";
                } else if (values[0] == 0x53545542ULL) {
                    char text[160] = {};
                    std::snprintf(text, sizeof(text),
                                  "the stub ran but the loader never returned (wait %s, thread %s)",
                                  waited == WAIT_TIMEOUT ? "timed out" : "signalled",
                                  exit_code == 259 ? "still active" : "exited");
                    outcome.detail = text;
                } else if (values[0] != 0) {
                    outcome.loaded = true;
                    char hex[32] = {};
                    std::snprintf(hex, sizeof(hex), "%#llx",
                                  static_cast<unsigned long long>(values[0]));
                    outcome.detail = std::string("accepted, mapped at ") + hex;
                } else {
                    char text[128] = {};
                    std::snprintf(text, sizeof(text), "refused -- loader error %llu (%s)",
                                  static_cast<unsigned long long>(values[1]),
                                  loader_error_name(values[1]).c_str());
                    outcome.detail = text;
                }
            }
        }
    }

    if (launched) {
        TerminateProcess(process, 0);
        CloseHandle(main_thread);
    }
    CloseHandle(process);
    return outcome;
}

LaunchOutcome launch_and_inject(const std::wstring& dll_path, const std::wstring& argument, int wait_ms,
                                const std::wstring& build) {
    LaunchOutcome outcome;

    if (!file_exists(dll_path)) {
        outcome.detail = "engine dll not found: " + narrow(dll_path);
        return outcome;
    }

    // With a build named, that exact install is used, and nothing else. Without one
    // the newest install wins, which can be a build no offset table exists for yet.
    std::wstring exe = preferred_client_path(build);
    // preferred_client_path falls back to the newest install when the named build is
    // absent; for an explicit request that silent fallback is the bug, so refuse it.
    if (!build.empty() && exe.find(build) == std::wstring::npos) exe.clear();
    if (exe.empty()) {
        outcome.detail = build.empty() ? "no RobloxPlayerBeta.exe under %LOCALAPPDATA%\\Roblox\\Versions"
                                       : "no installed client matches " + narrow(build);
        return outcome;
    }
    outcome.exe = exe;

    std::wstring command = L"\"" + exe + L"\"";
    if (!argument.empty()) command += L" " + argument;
    outcome.command_line = command;

    std::vector<wchar_t> mutable_command(command.begin(), command.end());
    mutable_command.push_back(L'\0');

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION info{};

    // CREATE_SUSPENDED is the entire point. The process exists, its loader has
    // finished, and not one instruction of the game has run yet -- so the
    // anti-tamper has not installed whatever it is that refuses foreign modules.
    if (!CreateProcessW(exe.c_str(), mutable_command.data(), nullptr, nullptr, FALSE, CREATE_SUSPENDED,
                        nullptr, directory_of(exe).c_str(), &startup, &info)) {
        outcome.detail = "CreateProcess failed (" + std::to_string(GetLastError()) + ")";
        return outcome;
    }
    outcome.pid = static_cast<int>(info.dwProcessId);

    // A never-run process cannot be enumerated with a toolhelp module snapshot --
    // the loader has finished but the snapshot still reports nothing usable. It
    // also does not need to be enumerated: system DLLs are mapped at the same base
    // in every process for the life of a boot, so the local kernel32 address is
    // already the remote one. The remote enumeration is kept as the second choice
    // because it is the more general answer.
    std::uintptr_t remote_load_library = 0;
    const HMODULE local_kernel32 = GetModuleHandleW(L"kernel32.dll");
    if (local_kernel32 != nullptr) {
        remote_load_library =
            reinterpret_cast<std::uintptr_t>(GetProcAddress(local_kernel32, "LoadLibraryW"));
    }
    if (remote_load_library == 0) {
        const std::uintptr_t kernel32 = remote_module_base(info.hProcess, L"kernel32.dll");
        const std::uintptr_t load_rva =
            kernel32 != 0 ? export_rva(local_kernel32, "LoadLibraryW") : 0;
        remote_load_library = load_rva != 0 ? kernel32 + load_rva : 0;
    }
    if (remote_load_library == 0) {
        TerminateProcess(info.hProcess, 0);
        CloseHandle(info.hThread);
        CloseHandle(info.hProcess);
        outcome.detail = "could not resolve LoadLibraryW";
        return outcome;
    }

    const RemoteBlock path_block = remote_write(info.hProcess, dll_path.c_str(),
                                                (dll_path.size() + 1) * sizeof(wchar_t));
    if (path_block.address == nullptr) {
        TerminateProcess(info.hProcess, 0);
        CloseHandle(info.hThread);
        CloseHandle(info.hProcess);
        outcome.detail = "could not allocate in the suspended client";
        return outcome;
    }

    // A suspended process has no alertable thread to queue an APC on, so this is
    // the one case where a remote thread is the correct instrument.
    const HANDLE thread = CreateRemoteThread(
        info.hProcess, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(remote_load_library),
        path_block.address, 0, nullptr);

    DWORD loaded = 0;
    if (thread != nullptr) {
        WaitForSingleObject(thread, 15000);
        GetExitCodeThread(thread, &loaded);
        CloseHandle(thread);
    } else {
        outcome.detail = "CreateRemoteThread failed (" + std::to_string(GetLastError()) + ")";
    }

    ResumeThread(info.hThread);
    CloseHandle(info.hThread);
    CloseHandle(info.hProcess);

    if (loaded == 0 && outcome.detail.empty()) {
        outcome.detail = "the client's loader refused the module before it started";
        return outcome;
    }

    // The client now boots with the engine inside it. It takes tens of seconds to
    // reach a place, so this waits properly rather than sampling once.
    const std::int64_t deadline = now_ms() + std::max(5000, wait_ms);
    while (now_ms() < deadline) {
        if (record_exists(outcome.pid)) {
            outcome.ok = true;
            outcome.detail = "engine loaded before the client started";
            return outcome;
        }
        if (!pid_alive(outcome.pid)) {
            outcome.detail = "the client exited during startup";
            return outcome;
        }
        Sleep(200);
    }

    if (!outcome.detail.empty()) return outcome;
    outcome.detail = "the client is running but the engine did not report";
    return outcome;
}

}  // namespace vesper::shell
