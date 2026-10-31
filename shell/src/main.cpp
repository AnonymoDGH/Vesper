// Vesper -- shell window.
//
// A borderless Direct2D-hosted window: hand-drawn chrome, a hand-drawn client
// list, and two native edit controls for the script and the output. Native edits
// are a deliberate choice -- selection, caret motion, IME, undo and clipboard are
// solved problems, and re-solving them badly would cost the user more than
// theming them costs us.
//
// Answering commands must never block the window, so the only long operation the
// UI thread performs is a loopback HTTP call with a short timeout; everything
// else is a message.
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>
#include <commdlg.h>
#include <dwmapi.h>
#include <shellapi.h>
#include <uxtheme.h>

#include "draw.hpp"
#include "mapper.hpp"
#include "net.hpp"
#include "theme.hpp"
#include "util.hpp"

namespace {

using namespace vesper::shell;
namespace ui = vesper::ui;

constexpr int kEditorId = 1001;
constexpr int kConsoleId = 1002;
constexpr UINT_PTR kPollTimer = 1;
constexpr UINT kPollIntervalMs = 700;

enum Command {
    kNone = 0,
    kRun,
    kClear,
    kCopyOutput,
    kClearConsole,
    kSaveScript,
    kOpenScript,
    kInject,
    kAttach,
    kAbi,
    kRefresh,
    kMinimize,
    kMaximize,
    kClose,
};

struct Hit {
    D2D1_RECT_F rect{};
    Command command = kNone;
    int row = -1;  // client row index, -1 for buttons
};

struct Shell {
    HWND window = nullptr;
    HWND editor = nullptr;
    HWND console = nullptr;
    HFONT mono_font = nullptr;
    HFONT ui_font = nullptr;
    HBRUSH editor_brush = nullptr;
    HBRUSH console_brush = nullptr;

    ui::Render render;

    std::vector<ClientInfo> clients;
    std::vector<Hit> hits;
    int selected = -1;
    Command hover = kNone;
    Command pressed = kNone;
    int hover_row = -1;

    EngineState state;
    std::string status = "Starting up";
    std::wstring script_path;

    float scale = 1.0f;
    UINT last_width = 0;
    UINT last_height = 0;
};

Shell g;

// -------------------------------------------------------------------- helpers --

float S(float value) { return value * g.scale; }

D2D1_RECT_F rect_of(float left, float top, float right, float bottom) {
    return D2D1::RectF(left, top, right, bottom);
}

bool inside(const D2D1_RECT_F& box, POINT point) {
    const float x = static_cast<float>(point.x);
    const float y = static_cast<float>(point.y);
    return x >= box.left && x < box.right && y >= box.top && y < box.bottom;
}

std::string normalize_newlines(const std::string& text) {
    std::string out;
    out.reserve(text.size() + 32);
    for (char character : text) {
        if (character == '\r') continue;
        if (character == '\n') {
            out += "\r\n";
            continue;
        }
        out.push_back(character);
    }
    return out;
}

std::vector<std::string> split_lines(const std::string& text) {
    std::vector<std::string> lines;
    std::string current;
    for (char character : text) {
        if (character == '\n') {
            lines.push_back(current);
            current.clear();
        } else if (character != '\r') {
            current.push_back(character);
        }
    }
    if (!current.empty()) lines.push_back(current);
    return lines;
}

// ------------------------------------------------------------------- console --

void append_console(const std::string& text) {
    if (g.console == nullptr || text.empty()) return;

    std::string line = normalize_newlines(text);
    if (line.size() < 2 || line.compare(line.size() - 2, 2, "\r\n") != 0) line += "\r\n";

    if (GetWindowTextLengthW(g.console) > 190000) {
        SendMessageW(g.console, EM_SETSEL, 0, 60000);
        SendMessageW(g.console, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(L""));
    }
    SendMessageW(g.console, EM_SETSEL, static_cast<WPARAM>(-1), static_cast<LPARAM>(-1));
    SendMessageW(g.console, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(widen(line).c_str()));
    SendMessageW(g.console, EM_SCROLLCARET, 0, 0);
}

void log_line(const std::string& text) {
    SYSTEMTIME now{};
    GetLocalTime(&now);
    char stamp[16] = {};
    std::snprintf(stamp, sizeof(stamp), "%02u:%02u:%02u", now.wHour, now.wMinute, now.wSecond);
    append_console(std::string(stamp) + "  " + text);
}

void set_status(const std::string& text) {
    g.status = text;
    if (g.window != nullptr) InvalidateRect(g.window, nullptr, FALSE);
}

const ClientInfo* selected_client() {
    if (g.selected < 0 || g.selected >= static_cast<int>(g.clients.size())) return nullptr;
    return &g.clients[static_cast<std::size_t>(g.selected)];
}

std::wstring client_label(const ClientInfo& client) {
    return L"Roblox  " + std::to_wstring(client.pid);
}

std::wstring client_state_text(const ClientInfo& client) {
    if (!client.alive) return L"process closed";
    if (!client.reachable) return L"no bridge";
    if (client.ready) return L"ready";
    if (client.in_game) return L"attaching";
    return L"waiting for a place";
}

ui::Color client_state_color(const ClientInfo& client) {
    const ui::Palette& palette = ui::palette();
    if (!client.alive) return palette.text_faint;
    if (!client.reachable) return palette.bad;
    if (client.ready) return palette.good;
    if (client.in_game) return palette.warn;
    return palette.text_dim;
}

// ----------------------------------------------------------------- data flow --

void refresh_clients(bool probe) {
    const std::vector<ClientInfo> previous = g.clients;
    g.clients = list_clients();

    int wanted_pid = 0;
    if (const ClientInfo* current = selected_client()) wanted_pid = current->pid;

    for (ClientInfo& client : g.clients) {
        if (probe && client.alive) {
            probe_client(client);
            continue;
        }
        // Without a probe, carry forward what the last probe learned.
        for (const ClientInfo& old : previous) {
            if (old.pid != client.pid) continue;
            client.reachable = old.reachable;
            client.ready = old.ready;
            client.in_game = old.in_game;
            client.thread_identity = old.thread_identity;
            client.detail = old.detail;
            break;
        }
    }

    g.selected = -1;
    for (std::size_t i = 0; i < g.clients.size(); ++i) {
        if (g.clients[i].pid == wanted_pid) {
            g.selected = static_cast<int>(i);
            break;
        }
    }
    if (g.selected < 0 && !g.clients.empty()) g.selected = 0;

    g.state = EngineState{};
    if (const ClientInfo* client = selected_client()) {
        std::string error;
        if (!fetch_state(*client, g.state, error)) g.state = EngineState{};
    }
}

// Defined with the command line below; the window's Inject button uses the same
// choice so both paths put the engine in the same place.
int pick_injection_target(const std::vector<int>& pids, const std::vector<ClientInfo>& existing);

void do_inject() {
    const std::wstring dll = engine_dll_path();
    if (!file_exists(dll)) {
        set_status("Engine DLL not found next to the shell");
        log_line("inject: expected " + narrow(dll));
        return;
    }

    const std::vector<int> pids = find_roblox_pids();
    if (pids.empty()) {
        set_status("No Roblox process found - open a place first");
        log_line("inject: no RobloxPlayerBeta.exe or RobloxStudioBeta.exe is running");
        return;
    }

        // Prefer a process that is not already carrying an engine.
        const int target = pick_injection_target(pids, list_clients());

    set_status("Injecting into pid " + std::to_string(target) + "...");
    InvalidateRect(g.window, nullptr, FALSE);
    log_line("inject: " + narrow(file_name(dll)) + " -> pid " + std::to_string(target));

    const InjectOutcome outcome = inject(target, dll);
    if (outcome.ok) {
        set_status("Injected into pid " + std::to_string(target) + " - waiting for the bridge");
        log_line("inject: " + outcome.detail);
        refresh_clients(false);
    } else {
        set_status("Injection failed: " + outcome.detail);
        log_line("inject: failed - " + outcome.detail);
    }
    InvalidateRect(g.window, nullptr, FALSE);
}

std::string editor_text() {
    const int length = GetWindowTextLengthW(g.editor);
    if (length <= 0) return {};
    std::wstring buffer(static_cast<std::size_t>(length) + 1, L'\0');
    GetWindowTextW(g.editor, buffer.data(), length + 1);
    buffer.resize(static_cast<std::size_t>(length));
    return narrow(buffer);
}

void set_editor_text(const std::string& text) { SetWindowTextW(g.editor, widen(text).c_str()); }

void do_run() {
    const ClientInfo* client = selected_client();
    if (client == nullptr) {
        set_status("Select a client first");
        return;
    }
    if (!client->reachable) {
        set_status("That client has no reachable bridge");
        return;
    }

    const std::string source = editor_text();
    if (source.empty()) {
        set_status("Nothing to run");
        return;
    }

    set_status("Running...");
    InvalidateRect(g.window, nullptr, FALSE);
    log_line("run: " + std::to_string(source.size()) + " bytes -> pid " + std::to_string(client->pid));

    std::string output;
    std::string error;
    bool pending = false;
    if (!run_script(*client, source, "shell", 8000, output, pending, error)) {
        set_status("Run failed: " + error);
        log_line("run: " + error);
        return;
    }

    for (const std::string& line : split_lines(output)) log_line("  " + line);

    if (pending) {
        log_line("run: still running (yielded, or waiting on something)");
        set_status("Script is still running");
    } else {
        set_status("Script finished");
    }

    refresh_clients(true);
    InvalidateRect(g.window, nullptr, FALSE);
}

void do_abi() {
    const ClientInfo* client = selected_client();
    if (client == nullptr || !client->reachable) {
        set_status("No reachable client to probe");
        return;
    }

    set_status("Probing the ABI...");
    InvalidateRect(g.window, nullptr, FALSE);

    std::string report;
    std::string error;
    if (!fetch_report(*client, "/abi/repair", report, error)) {
        set_status("ABI probe failed: " + error);
        log_line("abi: " + error);
        return;
    }

    log_line("abi report:");
    for (const std::string& line : split_lines(report)) log_line("  " + line);
    set_status("ABI probe complete");
    refresh_clients(true);
}

void do_save() {
    wchar_t path[MAX_PATH] = L"script.lua";
    if (!g.script_path.empty()) {
        const std::wstring name = file_name(g.script_path);
        if (name.size() < MAX_PATH) lstrcpynW(path, name.c_str(), MAX_PATH);
    }

    OPENFILENAMEW dialog{};
    dialog.lStructSize = sizeof(dialog);
    dialog.hwndOwner = g.window;
    dialog.lpstrFilter = L"Luau scripts\0*.lua;*.luau;*.txt\0All files\0*.*\0";
    dialog.lpstrFile = path;
    dialog.nMaxFile = MAX_PATH;
    dialog.lpstrDefExt = L"lua";
    dialog.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
    if (!GetSaveFileNameW(&dialog)) return;

    const std::string text = editor_text();
    if (write_file(path, text.data(), text.size())) {
        g.script_path = path;
        set_status("Saved " + narrow(path));
        log_line("save: " + narrow(path));
    } else {
        set_status("Could not write " + narrow(path));
    }
}

void do_open() {
    wchar_t path[MAX_PATH] = L"";

    OPENFILENAMEW dialog{};
    dialog.lStructSize = sizeof(dialog);
    dialog.hwndOwner = g.window;
    dialog.lpstrFilter = L"Luau scripts\0*.lua;*.luau;*.txt\0All files\0*.*\0";
    dialog.lpstrFile = path;
    dialog.nMaxFile = MAX_PATH;
    dialog.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    if (!GetOpenFileNameW(&dialog)) return;

    const std::vector<std::uint8_t> data = read_file(path);
    if (data.empty()) {
        set_status("Could not read " + narrow(path));
        return;
    }

    set_editor_text(std::string(data.begin(), data.end()));
    g.script_path = path;
    set_status("Opened " + narrow(path));
    log_line("open: " + narrow(path));
}

void do_copy_output() {
    const int length = GetWindowTextLengthW(g.console);
    if (length <= 0) {
        set_status("Nothing to copy");
        return;
    }

    std::wstring buffer(static_cast<std::size_t>(length) + 1, L'\0');
    GetWindowTextW(g.console, buffer.data(), length + 1);
    buffer.resize(static_cast<std::size_t>(length));

    if (!OpenClipboard(g.window)) return;
    EmptyClipboard();
    const std::size_t bytes = (buffer.size() + 1) * sizeof(wchar_t);
    if (HGLOBAL memory = GlobalAlloc(GMEM_MOVEABLE, bytes)) {
        if (void* target = GlobalLock(memory)) {
            std::memcpy(target, buffer.c_str(), bytes);
            GlobalUnlock(memory);
            SetClipboardData(CF_UNICODETEXT, memory);
        }
    }
    CloseClipboard();
    set_status("Output copied");
}

void run_command(Command command) {
    switch (command) {
        case kRun: do_run(); break;
        case kClear:
            set_editor_text({});
            set_status("Editor cleared");
            break;
        case kCopyOutput: do_copy_output(); break;
        case kClearConsole:
            SetWindowTextW(g.console, L"");
            set_status("Output cleared");
            break;
        case kSaveScript: do_save(); break;
        case kOpenScript: do_open(); break;
        case kInject: do_inject(); break;
        case kAttach:
            refresh_clients(true);
            set_status(g.clients.empty() ? "No injected clients found" : "Clients refreshed");
            break;
        case kAbi: do_abi(); break;
        case kRefresh:
            refresh_clients(true);
            set_status("Refreshed");
            break;
        case kMinimize: ShowWindow(g.window, SW_MINIMIZE); break;
        case kMaximize: ShowWindow(g.window, IsZoomed(g.window) ? SW_RESTORE : SW_MAXIMIZE); break;
        case kClose: PostMessageW(g.window, WM_CLOSE, 0, 0); break;
        default: break;
    }
    InvalidateRect(g.window, nullptr, FALSE);
}

// -------------------------------------------------------------------- layout --

struct Panel {
    float left = 0.0f;
    float right = 0.0f;
    float editor_top = 0.0f;
    float editor_bottom = 0.0f;
    float console_top = 0.0f;
    float console_bottom = 0.0f;
};

struct Layout {
    float width = 0.0f;
    float height = 0.0f;
    float title_bar = 0.0f;
    float sidebar = 0.0f;
    float body_top = 0.0f;
    float body_bottom = 0.0f;
    Panel panel;
};

Layout compute_layout(HWND window) {
    RECT client{};
    GetClientRect(window, &client);

    const ui::Metrics& metrics = ui::metrics();
    Layout layout;
    layout.width = static_cast<float>(client.right);
    layout.height = static_cast<float>(client.bottom);
    layout.title_bar = S(metrics.title_bar);
    layout.sidebar = S(metrics.sidebar);
    layout.body_top = layout.title_bar;
    layout.body_bottom = layout.height - S(metrics.status_bar);

    const float console_height = S(metrics.console_height);
    layout.panel.left = layout.sidebar + S(metrics.pad);
    layout.panel.right = layout.width - S(metrics.pad);
    layout.panel.console_bottom = layout.body_bottom - S(metrics.pad);
    layout.panel.console_top = layout.panel.console_bottom - console_height;
    layout.panel.editor_top = layout.body_top + S(96.0f);
    layout.panel.editor_bottom = layout.panel.console_top - S(34.0f);
    return layout;
}

void layout_controls(HWND window) {
    const Layout layout = compute_layout(window);
    const int left = static_cast<int>(layout.panel.left);
    const int width = static_cast<int>(layout.panel.right - layout.panel.left);

    if (g.editor != nullptr) {
        SetWindowPos(g.editor, nullptr, left, static_cast<int>(layout.panel.editor_top), width,
                     static_cast<int>(layout.panel.editor_bottom - layout.panel.editor_top), SWP_NOZORDER);
    }
    if (g.console != nullptr) {
        SetWindowPos(g.console, nullptr, left, static_cast<int>(layout.panel.console_top), width,
                     static_cast<int>(layout.panel.console_bottom - layout.panel.console_top), SWP_NOZORDER);
    }
}

// The hit list is rebuilt from the layout rather than remembered from the last
// paint, so it is correct even for the first click after a resize.
void build_hits(HWND window) {
    g.hits.clear();
    const Layout layout = compute_layout(window);
    const ui::Metrics& metrics = ui::metrics();

    // Window buttons, right to left.
    const float button_width = S(36.0f);
    float x = layout.width - button_width;
    auto window_button = [&](Command command) {
        Hit hit;
        hit.rect = rect_of(x, 0.0f, x + button_width, layout.title_bar);
        hit.command = command;
        g.hits.push_back(hit);
        x -= button_width;
    };
    window_button(kClose);
    window_button(kMaximize);
    window_button(kMinimize);

    // One row per client.
    float row_y = layout.body_top + S(38.0f);
    for (std::size_t i = 0; i < g.clients.size(); ++i) {
        Hit hit;
        hit.rect = rect_of(S(10.0f), row_y, layout.sidebar - S(10.0f), row_y + S(48.0f));
        hit.row = static_cast<int>(i);
        g.hits.push_back(hit);
        row_y += S(54.0f);
    }

    // Sidebar footer: the two commands that need no client selected yet.
    const float footer_y = layout.body_bottom - S(54.0f);
    const float half = (layout.sidebar - S(28.0f)) / 2.0f;
    {
        Hit hit;
        hit.rect = rect_of(S(10.0f), footer_y, S(10.0f) + half, footer_y + S(34.0f));
        hit.command = kInject;
        g.hits.push_back(hit);

        hit.rect = rect_of(S(18.0f) + half, footer_y, layout.sidebar - S(10.0f), footer_y + S(34.0f));
        hit.command = kAttach;
        g.hits.push_back(hit);
    }

    // Toolbar, left to right, sitting under the status chips.
    float action_x = layout.panel.left;
    const float action_y = layout.body_top + S(48.0f);
    for (const std::pair<Command, float>& action :
         {std::pair<Command, float>{kRefresh, 92.0f}, {kAbi, 108.0f}, {kOpenScript, 88.0f},
          {kSaveScript, 88.0f}, {kClear, 88.0f}}) {
        Hit hit;
        hit.rect = rect_of(action_x, action_y, action_x + S(action.second), action_y + S(34.0f));
        hit.command = action.first;
        g.hits.push_back(hit);
        action_x += S(action.second) + S(8.0f);
    }
    {
        Hit hit;
        hit.rect = rect_of(action_x, action_y, action_x + S(124.0f), action_y + S(34.0f));
        hit.command = kRun;
        g.hits.push_back(hit);
    }

    // Console header actions, right aligned just above the console.
    const float header_y = layout.panel.console_top - S(26.0f);
    {
        Hit hit;
        hit.rect = rect_of(layout.panel.right - S(116.0f), header_y, layout.panel.right - S(62.0f),
                           header_y + S(24.0f));
        hit.command = kCopyOutput;
        g.hits.push_back(hit);

        hit.rect = rect_of(layout.panel.right - S(56.0f), header_y, layout.panel.right, header_y + S(24.0f));
        hit.command = kClearConsole;
        g.hits.push_back(hit);
    }
    (void)metrics;
}

const char* command_label(Command command) {
    switch (command) {
        case kRun: return "Run";
        case kClear: return "Clear";
        case kCopyOutput: return "Copy";
        case kClearConsole: return "Clear";
        case kSaveScript: return "Save";
        case kOpenScript: return "Open";
        case kInject: return "Inject";
        case kAttach: return "Rescan";
        case kAbi: return "Check ABI";
        case kRefresh: return "Refresh";
        default: return "";
    }
}

// --------------------------------------------------------------------- paint --

void draw_button(const Hit& hit, Command command) {
    const ui::Palette& palette = ui::palette();
    const bool primary = command == kRun || command == kInject;
    const bool hovered = g.hover == command;
    const bool pressed = g.pressed == command;
    const float radius = S(ui::metrics().radius_small);

    ui::Color fill;
    ui::Color text;
    if (primary) {
        fill = hovered || pressed ? palette.accent_press : palette.accent;
        text = ui::Color::hex(0x141019);
    } else {
        fill = pressed ? palette.overlay : (hovered ? palette.raised : palette.surface);
        text = hovered ? palette.text : palette.text_dim;
    }

    g.render.rounded(hit.rect, radius, fill);
    if (!primary) g.render.rounded_stroke(hit.rect, radius, palette.hairline, 1.0f);

    ui::TextStyle style;
    style.size = S(12.5f);
    style.bold = primary;
    const D2D1_RECT_F box = rect_of(hit.rect.left, hit.rect.top, hit.rect.right, hit.rect.bottom - S(1.0f));
    g.render.text(widen(command_label(command)), box, text, style, DWRITE_TEXT_ALIGNMENT_CENTER,
                  DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
}

void draw_chip(float& cursor_x, float y, const std::wstring& text, const ui::Color& tone) {
    ui::TextStyle style;
    style.size = S(11.0f);
    const float height = S(26.0f);
    const float text_width = g.render.measure_width(text, style);
    const float width = text_width + S(28.0f);

    const D2D1_RECT_F box = rect_of(cursor_x, y, cursor_x + width, y + height);
    g.render.rounded(box, height / 2.0f, tone.with_alpha(0.12f));
    g.render.rounded_stroke(box, height / 2.0f, tone.with_alpha(0.32f), 1.0f);
    g.render.circle(cursor_x + S(12.0f), y + height / 2.0f, S(3.0f), tone);
    g.render.text(text, rect_of(cursor_x + S(20.0f), y, cursor_x + width, y + height), tone, style,
                  DWRITE_TEXT_ALIGNMENT_LEADING, DWRITE_PARAGRAPH_ALIGNMENT_CENTER);

    cursor_x += width + S(8.0f);
}

void paint(HWND window) {
    RECT client{};
    GetClientRect(window, &client);
    const UINT width = static_cast<UINT>(client.right);
    const UINT height = static_cast<UINT>(client.bottom);
    if (width == 0 || height == 0) return;

    if (!g.render.valid() && !g.render.create(window)) return;
    if (width != g.last_width || height != g.last_height) {
        if (!g.render.resize(width, height)) return;
        g.last_width = width;
        g.last_height = height;
    }

    const ui::Palette& palette = ui::palette();
    const ui::Metrics& metrics = ui::metrics();
    const Layout layout = compute_layout(window);
    const float w = static_cast<float>(width);
    const float h = static_cast<float>(height);

    build_hits(window);
    g.render.begin();
    g.render.rect(rect_of(0.0f, 0.0f, w, h), palette.base);

    // ------------------------------------------------------------- title bar --
    g.render.rect(rect_of(0.0f, 0.0f, w, layout.title_bar), palette.surface);
    g.render.line(0.0f, layout.title_bar, w, layout.title_bar, palette.hairline, 1.0f);

    const float mark_x = S(metrics.pad) + S(5.0f);
    const float mark_y = layout.title_bar / 2.0f;
    g.render.circle(mark_x, mark_y, S(4.5f), palette.accent);
    g.render.ring(mark_x, mark_y, S(8.5f), palette.violet.with_alpha(0.55f), 1.0f);

    ui::TextStyle wordmark;
    wordmark.size = S(13.5f);
    wordmark.bold = true;
    g.render.text(L"Vesper", rect_of(mark_x + S(17.0f), 0.0f, mark_x + S(110.0f), layout.title_bar - 1.0f),
                  palette.text, wordmark, DWRITE_TEXT_ALIGNMENT_LEADING, DWRITE_PARAGRAPH_ALIGNMENT_CENTER);

    ui::TextStyle subtle;
    subtle.size = S(11.5f);
    std::wstring subtitle = L"no client selected";
    if (const ClientInfo* client = selected_client()) {
        subtitle = L"pid " + std::to_wstring(client->pid);
        if (!client->build.empty()) subtitle += L"  \x2022  " + widen(client->build);
        if (client->port != 0) subtitle += L"  \u2022  :" + std::to_wstring(client->port);
    }
    g.render.text(subtitle, rect_of(mark_x + S(82.0f), 0.0f, w - S(140.0f), layout.title_bar - 1.0f),
                  palette.text_faint, subtle, DWRITE_TEXT_ALIGNMENT_LEADING,
                  DWRITE_PARAGRAPH_ALIGNMENT_CENTER);

    for (const Hit& hit : g.hits) {
        const bool window_button =
            hit.command == kMinimize || hit.command == kMaximize || hit.command == kClose;
        if (!window_button) continue;

        const bool hovered = g.hover == hit.command;
        const float center_x = (hit.rect.left + hit.rect.right) / 2.0f;
        const float center_y = (hit.rect.top + hit.rect.bottom) / 2.0f;
        const ui::Color glyph =
            hit.command == kClose && hovered ? palette.bad : (hovered ? palette.text : palette.text_faint);
        if (hovered) g.render.rect(hit.rect, palette.raised);

        if (hit.command == kMinimize) {
            g.render.line(center_x - S(5.0f), center_y, center_x + S(5.0f), center_y, glyph, S(1.2f));
        } else if (hit.command == kMaximize) {
            g.render.rounded_stroke(
                rect_of(center_x - S(5.0f), center_y - S(5.0f), center_x + S(5.0f), center_y + S(5.0f)),
                S(2.0f), glyph, S(1.1f));
        } else {
            g.render.line(center_x - S(5.0f), center_y - S(5.0f), center_x + S(5.0f), center_y + S(5.0f), glyph,
                          S(1.2f));
            g.render.line(center_x + S(5.0f), center_y - S(5.0f), center_x - S(5.0f), center_y + S(5.0f), glyph,
                          S(1.2f));
        }
    }

    // -------------------------------------------------------------- sidebar --
    g.render.rect(rect_of(0.0f, layout.body_top, layout.sidebar, layout.body_bottom), palette.surface);
    g.render.line(layout.sidebar, layout.body_top, layout.sidebar, layout.body_bottom, palette.hairline, 1.0f);

    ui::TextStyle section;
    section.size = S(10.5f);
    section.bold = true;
    g.render.text(L"CLIENTS",
                  rect_of(S(metrics.pad), layout.body_top + S(12.0f), layout.sidebar - S(metrics.pad),
                          layout.body_top + S(30.0f)),
                  palette.text_faint, section, DWRITE_TEXT_ALIGNMENT_LEADING,
                  DWRITE_PARAGRAPH_ALIGNMENT_CENTER);

    if (g.clients.empty()) {
        ui::TextStyle empty;
        empty.size = S(12.0f);
        g.render.paragraph(L"No client yet.\n\nOpen Roblox, then press Inject.",
                           S(metrics.pad), layout.body_top + S(58.0f), layout.sidebar - S(metrics.pad) * 2.0f,
                           palette.text_faint, empty, S(18.0f));
    }

    for (const Hit& hit : g.hits) {
        if (hit.row < 0) continue;
        const ClientInfo& client = g.clients[static_cast<std::size_t>(hit.row)];
        const bool selected = hit.row == g.selected;
        const bool hovered = hit.row == g.hover_row;
        const float radius = S(metrics.radius_small);

        if (selected) {
            g.render.rounded(hit.rect, radius, palette.overlay);
            g.render.rounded_stroke(hit.rect, radius, palette.violet_dim, 1.0f);
        } else if (hovered) {
            g.render.rounded(hit.rect, radius, palette.raised);
        }

        const float dot_x = hit.rect.left + S(15.0f);
        const float dot_y = hit.rect.top + S(19.0f);
        const ui::Color tone = client_state_color(client);
        g.render.circle(dot_x, dot_y, S(3.5f), tone);
        if (client.ready) g.render.ring(dot_x, dot_y, S(7.0f), palette.good.with_alpha(0.35f), 1.0f);

        ui::TextStyle name;
        name.size = S(12.5f);
        name.bold = selected;
        g.render.text(client_label(client),
                      rect_of(dot_x + S(13.0f), hit.rect.top + S(6.0f), hit.rect.right - S(6.0f),
                              hit.rect.top + S(25.0f)),
                      selected ? palette.text : palette.text_dim, name, DWRITE_TEXT_ALIGNMENT_LEADING,
                      DWRITE_PARAGRAPH_ALIGNMENT_CENTER);

        ui::TextStyle detail;
        detail.size = S(11.0f);
        g.render.text(client_state_text(client),
                      rect_of(dot_x + S(13.0f), hit.rect.top + S(25.0f), hit.rect.right - S(6.0f),
                              hit.rect.bottom - S(5.0f)),
                      tone, detail, DWRITE_TEXT_ALIGNMENT_LEADING, DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
    }

    for (const Hit& hit : g.hits) {
        if (hit.command == kInject || hit.command == kAttach) draw_button(hit, hit.command);
    }

    // -------------------------------------------------------------- toolbar --
    for (const Hit& hit : g.hits) {
        if (hit.command == kNone || hit.row >= 0) continue;
        if (hit.command == kInject || hit.command == kAttach || hit.command == kCopyOutput ||
            hit.command == kClearConsole || hit.command == kMinimize || hit.command == kMaximize ||
            hit.command == kClose) {
            continue;
        }
        draw_button(hit, hit.command);
    }

    // Run sits at the end of the toolbar and is labelled with its shortcut.
    {
        const float run_x = layout.panel.left;
        float cursor = run_x;
        for (const std::pair<Command, float>& action :
             {std::pair<Command, float>{kRefresh, 92.0f}, {kAbi, 108.0f}, {kOpenScript, 88.0f},
              {kSaveScript, 88.0f}, {kClear, 88.0f}}) {
            cursor += S(action.second) + S(8.0f);
        }
        const D2D1_RECT_F run_box = rect_of(cursor, layout.body_top + S(48.0f), cursor + S(124.0f),
                                            layout.body_top + S(82.0f));
        const bool hovered = g.hover == kRun;
        const bool pressed = g.pressed == kRun;
        g.render.rounded(run_box, S(metrics.radius_small), hovered || pressed ? palette.accent_press : palette.accent);
        ui::TextStyle style;
        style.size = S(12.5f);
        style.bold = true;
        g.render.text(L"Run   F5", rect_of(run_box.left, run_box.top, run_box.right, run_box.bottom - S(1.0f)),
                      ui::Color::hex(0x141019), style, DWRITE_TEXT_ALIGNMENT_CENTER,
                      DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
    }

    // Status chips, right of the toolbar.
    {
        float chip_x = layout.panel.left;
        const float chip_y = layout.body_top + S(14.0f);
        if (const ClientInfo* client = selected_client()) {
            if (!client->alive) {
                draw_chip(chip_x, chip_y, L"process closed", palette.text_faint);
            } else if (!client->reachable) {
                std::wstring detail = client->detail.empty() ? std::wstring(L"no bridge") : widen(client->detail);
                draw_chip(chip_x, chip_y, detail, palette.bad);
            } else if (g.state.ready) {
                draw_chip(chip_x, chip_y, L"attached", palette.good);
            } else if (g.state.in_game) {
                draw_chip(chip_x, chip_y, L"in game", palette.warn);
            } else {
                draw_chip(chip_x, chip_y, L"waiting for a place", palette.warn);
            }

            if (g.state.ready) {
                draw_chip(chip_x, chip_y, L"identity " + std::to_wstring(g.state.thread_identity), palette.violet);
                draw_chip(chip_x, chip_y, L"executed " + std::to_wstring(g.state.executed), palette.text_dim);
                if (g.state.failed > 0) {
                    draw_chip(chip_x, chip_y, L"failed " + std::to_wstring(g.state.failed), palette.bad);
                }
            }
            if (!g.state.strategy.empty() && g.state.strategy != "unknown") {
                draw_chip(chip_x, chip_y, widen(g.state.strategy), palette.text_dim);
            }
        } else {
            draw_chip(chip_x, chip_y, L"no client", palette.text_faint);
        }
    }

    // --------------------------------------------------------------- panels --
    const D2D1_RECT_F editor_frame =
        rect_of(layout.panel.left - S(3.0f), layout.panel.editor_top - S(3.0f),
                layout.panel.right + S(3.0f), layout.panel.editor_bottom + S(3.0f));
    g.render.rounded(editor_frame, S(metrics.radius), palette.editor);
    g.render.rounded_stroke(editor_frame, S(metrics.radius), palette.hairline, 1.0f);

    const D2D1_RECT_F console_frame =
        rect_of(layout.panel.left - S(3.0f), layout.panel.console_top - S(3.0f),
                layout.panel.right + S(3.0f), layout.panel.console_bottom + S(3.0f));
    g.render.rounded(console_frame, S(metrics.radius), palette.console);
    g.render.rounded_stroke(console_frame, S(metrics.radius), palette.hairline, 1.0f);

    ui::TextStyle header;
    header.size = S(10.5f);
    header.bold = true;
    g.render.text(L"OUTPUT",
                  rect_of(layout.panel.left, layout.panel.console_top - S(24.0f), layout.panel.left + S(120.0f),
                          layout.panel.console_top - S(2.0f)),
                  palette.text_faint, header, DWRITE_TEXT_ALIGNMENT_LEADING,
                  DWRITE_PARAGRAPH_ALIGNMENT_CENTER);

    for (const Hit& hit : g.hits) {
        if (hit.command == kCopyOutput || hit.command == kClearConsole) draw_button(hit, hit.command);
    }

    // ----------------------------------------------------------- status bar --
    g.render.rect(rect_of(0.0f, layout.body_bottom, w, h), palette.surface);
    g.render.line(0.0f, layout.body_bottom, w, layout.body_bottom, palette.hairline, 1.0f);

    ui::TextStyle status_style;
    status_style.size = S(11.5f);
    g.render.text(widen(g.status),
                  rect_of(S(metrics.pad), layout.body_bottom, w - S(280.0f), h), palette.text_dim,
                  status_style, DWRITE_TEXT_ALIGNMENT_LEADING, DWRITE_PARAGRAPH_ALIGNMENT_CENTER);

    const std::wstring right = L"Vesper 3.0.0   \u2022   " + std::to_wstring(g.clients.size()) + L" client(s)";
    g.render.text(right, rect_of(w - S(270.0f), layout.body_bottom, w - S(metrics.pad), h), palette.text_faint,
                  status_style, DWRITE_TEXT_ALIGNMENT_TRAILING, DWRITE_PARAGRAPH_ALIGNMENT_CENTER);

    g.render.reset_clips();
    g.render.end();
}

// --------------------------------------------------------------- window setup --

UINT system_dpi() {
    HDC screen = GetDC(nullptr);
    const int dpi = screen != nullptr ? GetDeviceCaps(screen, LOGPIXELSX) : 96;
    if (screen != nullptr) ReleaseDC(nullptr, screen);
    return dpi > 0 ? static_cast<UINT>(dpi) : 96U;
}

UINT window_dpi(HWND window) {
    // GetDpiForWindow only exists from Windows 10 1607; fall back to the system
    // DPI rather than refusing to run.
    if (HMODULE user32 = GetModuleHandleW(L"user32.dll")) {
        using GetDpiForWindowFn = UINT(WINAPI*)(HWND);
        if (auto function = reinterpret_cast<GetDpiForWindowFn>(GetProcAddress(user32, "GetDpiForWindow"))) {
            const UINT dpi = function(window);
            if (dpi != 0) return dpi;
        }
    }
    return system_dpi();
}

void enable_dpi_awareness() {
    // Declared locally rather than taken from the headers so the source does not
    // depend on a recent SDK: the per-monitor-v2 context is the pseudo-handle -4.
    using SetProcessDpiAwarenessContextFn = BOOL(WINAPI*)(void*);
    const std::intptr_t per_monitor_v2 = -4;

    if (HMODULE user32 = LoadLibraryW(L"user32.dll")) {
        if (auto function = reinterpret_cast<SetProcessDpiAwarenessContextFn>(
                GetProcAddress(user32, "SetProcessDpiAwarenessContext"))) {
            function(reinterpret_cast<void*>(per_monitor_v2));
            return;
        }
        using SetProcessDPIAwareFn = BOOL(WINAPI*)();
        if (auto legacy = reinterpret_cast<SetProcessDPIAwareFn>(GetProcAddress(user32, "SetProcessDPIAware"))) {
            legacy();
        }
    }
}

void apply_dark_mode(HWND window) {
    const HMODULE uxtheme = LoadLibraryW(L"uxtheme.dll");
    if (uxtheme == nullptr) return;

    // The dark-mode opt-in is not a documented API. Both ordinals are stable
    // across Windows 10 1809 through 11; a missing ordinal is simply ignored.
    using PreferredAppModeFn = int(WINAPI*)(int);
    using AllowDarkModeFn = BOOL(WINAPI*)(HWND, BOOL);

    if (auto set_mode =
            reinterpret_cast<PreferredAppModeFn>(GetProcAddress(uxtheme, MAKEINTRESOURCEA(135)))) {
        set_mode(1);  // AllowDark
    }
    if (auto allow = reinterpret_cast<AllowDarkModeFn>(GetProcAddress(uxtheme, MAKEINTRESOURCEA(133)))) {
        allow(window, TRUE);
    }
    if (g.editor != nullptr) SetWindowTheme(g.editor, L"DarkMode_Explorer", nullptr);
    if (g.console != nullptr) SetWindowTheme(g.console, L"DarkMode_Explorer", nullptr);
}

HFONT create_mono_font() {
    return CreateFontW(-static_cast<int>(S(15.0f)), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                       OUT_TT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN,
                       L"Consolas");
}

void create_controls(HWND window) {
    // Colours are literals rather than palette lookups because Win32 takes them
    // as COLORREF (0x00BBGGRR), not as the palette's 0xRRGGBB.
    g.editor_brush = CreateSolidBrush(RGB(0x0D, 0x0D, 0x14));
    g.console_brush = CreateSolidBrush(RGB(0x0B, 0x0B, 0x11));
    g.mono_font = create_mono_font();

    g.editor = CreateWindowExW(
        0, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL |
            ES_WANTRETURN | ES_NOHIDESEL,
        0, 0, 10, 10, window, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kEditorId)), nullptr, nullptr);

    g.console = CreateWindowExW(0, L"EDIT", L"",
                                WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL |
                                    ES_READONLY,
                                0, 0, 10, 10, window, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kConsoleId)),
                                nullptr, nullptr);

    const HWND controls[] = {g.editor, g.console};
    for (HWND control : controls) {
        if (control == nullptr) continue;
        SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(g.mono_font), TRUE);
        SendMessageW(control, EM_SETLIMITTEXT, 4u * 1024u * 1024u, 0);
        SendMessageW(control, EM_SETMARGINS, EC_LEFTMARGIN | EC_RIGHTMARGIN, MAKELPARAM(10, 10));
    }

    apply_dark_mode(window);
}

LRESULT handle_hit_test(HWND window, POINT screen_point) {
    RECT bounds{};
    GetWindowRect(window, &bounds);

    const int border = static_cast<int>(S(6.0f));
    const bool left = screen_point.x < bounds.left + border;
    const bool right = screen_point.x >= bounds.right - border;
    const bool top = screen_point.y < bounds.top + border;
    const bool bottom = screen_point.y >= bounds.bottom - border;

    if (top && left) return HTTOPLEFT;
    if (top && right) return HTTOPRIGHT;
    if (bottom && left) return HTBOTTOMLEFT;
    if (bottom && right) return HTBOTTOMRIGHT;
    if (top) return HTTOP;
    if (bottom) return HTBOTTOM;
    if (left) return HTLEFT;
    if (right) return HTRIGHT;

    POINT point = screen_point;
    ScreenToClient(window, &point);
    build_hits(window);

    for (const Hit& hit : g.hits) {
        if (hit.command != kNone && inside(hit.rect, point)) return HTCLIENT;
    }
    if (point.y < static_cast<LONG>(S(ui::metrics().title_bar))) return HTCAPTION;
    return HTCLIENT;
}

LRESULT CALLBACK EditorProc(HWND window, UINT message, WPARAM wparam, LPARAM lparam, UINT_PTR,
                            DWORD_PTR) {
    if (message == WM_KEYDOWN) {
        const bool control = (GetKeyState(VK_CONTROL) & 0x8000) != 0;
        if (wparam == VK_F5 || (control && wparam == 'R')) {
            run_command(kRun);
            return 0;
        }
        if (control && wparam == 'S') {
            run_command(kSaveScript);
            return 0;
        }
        if (control && wparam == 'O') {
            run_command(kOpenScript);
            return 0;
        }
    }
    if (message == WM_CHAR && wparam == '\r' && (GetKeyState(VK_CONTROL) & 0x8000) != 0) {
        run_command(kRun);
        return 0;
    }
    return DefSubclassProc(window, message, wparam, lparam);
}

LRESULT CALLBACK WindowProc(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
    switch (message) {
        case WM_CREATE:
            g.window = window;
            g.scale = static_cast<float>(window_dpi(window)) / 96.0f;
            create_controls(window);
            layout_controls(window);
            g.render.create(window);
            apply_dark_mode(window);
            log_line("Vesper 3.0.0 shell ready");
            log_line("Clients directory: " + narrow(clients_directory()));
            refresh_clients(false);
            SetTimer(window, kPollTimer, kPollIntervalMs, nullptr);
            return 0;

        case WM_TIMER:
            if (wparam == kPollTimer && !IsIconic(window)) {
                refresh_clients(true);
                InvalidateRect(window, nullptr, FALSE);
            }
            return 0;

        case WM_PAINT: {
            PAINTSTRUCT paint_struct{};
            BeginPaint(window, &paint_struct);
            paint(window);
            EndPaint(window, &paint_struct);
            return 0;
        }

        case WM_ERASEBKGND:
            return 1;

        case WM_SIZE:
            layout_controls(window);
            InvalidateRect(window, nullptr, FALSE);
            return 0;

        case WM_DPICHANGED: {
            g.scale = static_cast<float>(HIWORD(wparam)) / 96.0f;
            const RECT* suggested = reinterpret_cast<const RECT*>(lparam);
            SetWindowPos(window, nullptr, suggested->left, suggested->top, suggested->right - suggested->left,
                         suggested->bottom - suggested->top, SWP_NOZORDER | SWP_NOACTIVATE);

            if (g.mono_font != nullptr) DeleteObject(g.mono_font);
            g.mono_font = create_mono_font();
            const HWND controls[] = {g.editor, g.console};
            for (HWND control : controls) {
                if (control != nullptr) SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(g.mono_font), TRUE);
            }

            g.last_width = 0;
            g.last_height = 0;
            layout_controls(window);
            InvalidateRect(window, nullptr, FALSE);
            return 0;
        }

        case WM_NCCALCSIZE:
            if (wparam == 0) return 0;
            DefWindowProcW(window, message, wparam, lparam);
            if (IsZoomed(window)) {
                auto* params = reinterpret_cast<NCCALCSIZE_PARAMS*>(lparam);
                params->rgrc[0].top += GetSystemMetrics(SM_CXSIZEFRAME);
                params->rgrc[0].bottom -= GetSystemMetrics(SM_CXSIZEFRAME);
                params->rgrc[0].left += GetSystemMetrics(SM_CXSIZEFRAME);
                params->rgrc[0].right -= GetSystemMetrics(SM_CXSIZEFRAME);
            }
            return 0;

        case WM_NCHITTEST: {
            const LRESULT result = handle_hit_test(window, POINT{GET_X_LPARAM(lparam), GET_Y_LPARAM(lparam)});
            if (result != HTCLIENT) return result;
            break;
        }

        case WM_GETMINMAXINFO: {
            auto* info = reinterpret_cast<MINMAXINFO*>(lparam);
            info->ptMinTrackSize.x = static_cast<LONG>(S(960.0f));
            info->ptMinTrackSize.y = static_cast<LONG>(S(620.0f));
            return 0;
        }

        case WM_MOUSEMOVE: {
            const POINT point{GET_X_LPARAM(lparam), GET_Y_LPARAM(lparam)};
            Command hovered = kNone;
            int row = -1;
            for (const Hit& hit : g.hits) {
                if (!inside(hit.rect, point)) continue;
                if (hit.row >= 0) {
                    row = hit.row;
                } else {
                    hovered = hit.command;
                }
                break;
            }
            if (hovered != g.hover || row != g.hover_row) {
                g.hover = hovered;
                g.hover_row = row;
                InvalidateRect(window, nullptr, FALSE);
            }

            TRACKMOUSEEVENT track{};
            track.cbSize = sizeof(track);
            track.dwFlags = TME_LEAVE;
            track.hwndTrack = window;
            TrackMouseEvent(&track);
            return 0;
        }

        case WM_MOUSELEAVE:
            g.hover = kNone;
            g.hover_row = -1;
            InvalidateRect(window, nullptr, FALSE);
            return 0;

        case WM_LBUTTONDOWN: {
            const POINT point{GET_X_LPARAM(lparam), GET_Y_LPARAM(lparam)};
            build_hits(window);
            for (const Hit& hit : g.hits) {
                if (!inside(hit.rect, point)) continue;
                if (hit.row >= 0) {
                    g.selected = hit.row;
                    refresh_clients(true);
                    if (const ClientInfo* client = selected_client()) {
                        set_status("Selected pid " + std::to_string(client->pid));
                    }
                } else {
                    g.pressed = hit.command;
                }
                break;
            }
            InvalidateRect(window, nullptr, FALSE);
            return 0;
        }

        case WM_LBUTTONUP: {
            const POINT point{GET_X_LPARAM(lparam), GET_Y_LPARAM(lparam)};
            const Command pressed = g.pressed;
            g.pressed = kNone;
            if (pressed != kNone) {
                for (const Hit& hit : g.hits) {
                    if (hit.command != pressed) continue;
                    if (inside(hit.rect, point)) run_command(pressed);
                    break;
                }
            }
            InvalidateRect(window, nullptr, FALSE);
            return 0;
        }

        case WM_SETCURSOR:
            if (LOWORD(lparam) == HTCLIENT) {
                POINT point{};
                GetCursorPos(&point);
                ScreenToClient(window, &point);
                bool over_control = false;
                for (const Hit& hit : g.hits) {
                    if (hit.command != kNone && inside(hit.rect, point)) {
                        over_control = true;
                        break;
                    }
                }
                SetCursor(LoadCursorW(nullptr, over_control ? IDC_HAND : IDC_ARROW));
                return TRUE;
            }
            break;

        case WM_CTLCOLOREDIT:
        case WM_CTLCOLORSTATIC: {
            const HWND control = reinterpret_cast<HWND>(lparam);
            const HDC dc = reinterpret_cast<HDC>(wparam);
            if (control == g.console) {
                SetTextColor(dc, RGB(0xC6, 0xC6, 0xD8));
                SetBkColor(dc, RGB(0x0B, 0x0B, 0x11));
                return reinterpret_cast<LRESULT>(g.console_brush);
            }
            SetTextColor(dc, RGB(0xE8, 0xE8, 0xF2));
            SetBkColor(dc, RGB(0x0D, 0x0D, 0x14));
            return reinterpret_cast<LRESULT>(g.editor_brush);
        }

        case WM_COMMAND:
            if (HIWORD(wparam) == EN_ERRSPACE) {
                set_status("The output buffer is full - press Clear");
            }
            return 0;

        case WM_CLOSE:
            KillTimer(window, kPollTimer);
            DestroyWindow(window);
            return 0;

        case WM_DESTROY:
            if (g.mono_font != nullptr) DeleteObject(g.mono_font);
            if (g.editor_brush != nullptr) DeleteObject(g.editor_brush);
            if (g.console_brush != nullptr) DeleteObject(g.console_brush);
            g.render.destroy();
            PostQuitMessage(0);
            return 0;

        default:
            break;
    }
    return DefWindowProcW(window, message, wparam, lparam);
}

// -------------------------------------------------------------- headless CLI --
//
// The same operations the buttons perform, exposed on the command line. This is
// how the shell is scripted and how it is exercised without a desktop session.
// Output goes to whatever stdout already is -- a redirected file, or the parent
// console when the caller had one -- so `Vesper.exe --inject > log.txt` behaves.

int pick_injection_target(const std::vector<int>& pids, const std::vector<ClientInfo>& existing) {
    int target = pids.front();
    for (int pid : pids) {
        bool known = false;
        for (const ClientInfo& client : existing) {
            if (client.pid == pid && client.alive) known = true;
        }
        if (!known) return pid;
        target = pid;
    }
    return target;
}

void ensure_output() {
    const HANDLE existing = GetStdHandle(STD_OUTPUT_HANDLE);
    if (existing != nullptr && existing != INVALID_HANDLE_VALUE) return;
    if (!AttachConsole(ATTACH_PARENT_PROCESS)) return;
    freopen("CONOUT$", "w", stdout);
    freopen("CONOUT$", "w", stderr);
    SetConsoleOutputCP(CP_UTF8);
}

std::wstring newest_engine_log() {
    wchar_t local[MAX_PATH * 2] = {};
    const DWORD length = GetEnvironmentVariableW(L"LOCALAPPDATA", local, static_cast<DWORD>(std::size(local)));
    if (length == 0) return {};

    const std::wstring directory = std::wstring(local, length) + L"\\Vesper\\logs";
    WIN32_FIND_DATAW entry{};
    const HANDLE find = FindFirstFileW((directory + L"\\engine-*.log").c_str(), &entry);
    if (find == INVALID_HANDLE_VALUE) return {};

    std::wstring newest;
    FILETIME best{};
    do {
        const std::wstring path = directory + L"\\" + entry.cFileName;
        if (newest.empty() || CompareFileTime(&entry.ftLastWriteTime, &best) > 0) {
            best = entry.ftLastWriteTime;
            newest = path;
        }
    } while (FindNextFileW(find, &entry));
    FindClose(find);
    return newest;
}

void print_log_tail(int pid, int lines) {
    std::wstring path;
    if (pid != 0) {
        wchar_t local[MAX_PATH * 2] = {};
        const DWORD length =
            GetEnvironmentVariableW(L"LOCALAPPDATA", local, static_cast<DWORD>(std::size(local)));
        if (length > 0) {
            path = std::wstring(local, length) + L"\\Vesper\\logs\\engine-" + std::to_wstring(pid) + L".log";
        }
    }
    if (path.empty() || !file_exists(path)) path = newest_engine_log();
    if (path.empty() || !file_exists(path)) {
        std::printf("engine log  : none yet\n");
        return;
    }

    const std::vector<std::uint8_t> data = read_file(path);
    const std::string text(data.begin(), data.end());
    const std::vector<std::string> all = split_lines(text);
    std::printf("--- %s (%d lines) ---\n", narrow(file_name(path)).c_str(), static_cast<int>(all.size()));
    const std::size_t start = all.size() > static_cast<std::size_t>(lines) ? all.size() - lines : 0;
    for (std::size_t i = start; i < all.size(); ++i) std::printf("%s\n", all[i].c_str());
}

void print_state(const EngineState& state) {
    std::printf("build       : %s\n", state.build.c_str());
    std::printf("profile     : %s\n", state.profile.c_str());
    std::printf("strategy    : %s\n", state.strategy.c_str());
    std::printf("data model  : %s\n", state.data_model.c_str());
    std::printf("script ctx  : %s\n", state.script_context.c_str());
    std::printf("lua_State   : %s\n", state.lua_state.c_str());
    std::printf("identity at : %s\n", state.identity_field.c_str());
    std::printf("identity    : %d\n", state.thread_identity);
    std::printf("in game     : %s\n", state.in_game ? "yes" : "no");
    std::printf("enviro      : %s\n", state.environment ? "installed" : "not installed");
    std::printf("ready       : %s\n", state.ready ? "yes" : "no");
    std::printf("abi         : %s\n", state.abi_verified ? "verified" : "unverified");
    std::printf("executed    : %d  failed: %d  pending: %d\n", state.executed, state.failed, state.pending);
    if (!state.error.empty()) std::printf("error       : %s\n", state.error.c_str());
}

const ClientInfo* first_client_with(const std::vector<ClientInfo>& clients, int pid) {
    for (const ClientInfo& client : clients) {
        if (pid == 0 || client.pid == pid) return &client;
    }
    return nullptr;
}

int run_headless(int argc, wchar_t** argv) {
    ensure_output();

    std::vector<std::wstring> args;
    for (int i = 1; i < argc; ++i) args.emplace_back(argv[i]);
    if (args.empty()) return 1;

    const std::wstring command = args[0];
    int wait_seconds = 25;
    int only_pid = 0;
    std::wstring requested_build;
    for (std::size_t i = 1; i < args.size(); ++i) {
        if (args[i] == L"--wait" && i + 1 < args.size()) wait_seconds = _wtoi(args[i + 1].c_str());
        if (args[i] == L"--pid" && i + 1 < args.size()) only_pid = _wtoi(args[i + 1].c_str());
        if (args[i] == L"--build" && i + 1 < args.size()) requested_build = args[i + 1];
    }

    if (command == L"--help" || command == L"-h") {
        std::printf(
            "Vesper 3.0.0\n"
            "  --launch [arg] [--wait N] [--build version-xxxx]\n"
            "                        start the client suspended, load the engine before it runs,\n"
            "                        then resume; waits for the engine to report\n"
            "  --inject [--wait N]   inject into a running client (blocked by the anti-tamper\n"
            "                        once the game is up; useful for diagnostics)\n"
            "  --clients             list installed clients and mark the one the offsets match\n"
            "  --list                list known clients\n"
            "  --status [--pid N]    print one client's engine state\n"
            "  --abi    [--pid N]    run the ABI probe and print the report\n"
            "  --hooktest [--pid N]  install the VM-entry detour and queue one probe\n"
            "                        [--probe] [--run] [--status] [--remove]\n"
            "                        the probe runs on the game's Lua thread (see --log)\n"
            "  --exec <file>         run a Luau file on the selected client\n"
            "  --map <dll> [--pid N] map a module without the loader and enter it\n"
            "                        [--entry NAME] [--marker FILE] [--in-place] [--wait N]\n"
            "                        [--apc] deliver the entry as an APC to the target's threads\n"
            "                        [--trampoline] [--probe-event]\n"
            "  --map-launch <dll>    start the client suspended, map the module into it before\n"
            "                        any of the game runs, then resume [--entry NAME] [--marker FILE]\n"
            "                        [--hijack [--return ADDR]]  enter it from the client's own thread\n"
            "                        [--apc] deliver the entry to the client's own threads\n"
            "  --log    [--pid N]    tail the engine log\n"
            "  --modules --pid N     list the modules a process has loaded\n"
            "  --regions --pid N     list a process's executable memory regions\n"
            "  --dump --pid N <base> <size> <file>\n"
            "                        copy a byte range out of a process into a file\n"
            "  --gate [path]         enter through a stub inside a signed image (default\n"
            "                        C:\\Windows\\System32\\fltlib.dll) instead of an address\n"
            "                        outside every image, which is refused\n"
            "  --open [placeId]      hand a place link to Roblox and wait for the client\n");
        return 0;
    }

    if (command == L"--inject") {
        const std::wstring dll = engine_dll_path();
        std::printf("engine dll  : %s\n", narrow(dll).c_str());
        if (!file_exists(dll)) {
            std::printf("engine dll  : not found\n");
            return 2;
        }

        const std::vector<int> roblox = find_roblox_pids();
        std::vector<int> pids = roblox;
        if (only_pid != 0 && std::find(pids.begin(), pids.end(), only_pid) == pids.end()) {
            pids.push_back(only_pid);
        }
        if (pids.empty()) {
            std::printf("targets     : no Roblox process running\n");
            return 3;
        }
        std::printf("targets     :");
        for (int pid : pids) std::printf(" %d", pid);
        std::printf("\n");

        const int target = only_pid != 0 ? only_pid : pick_injection_target(pids, list_clients());
        std::printf("injecting   : pid %d\n", target);

        const InjectOutcome outcome = inject(target, dll);
        std::printf("injection   : %s (%s)\n", outcome.ok ? "queued" : "failed", outcome.detail.c_str());
        if (!outcome.ok) return 4;

        bool reported = false;
        for (int attempt = 0; attempt < wait_seconds * 2; ++attempt) {
            Sleep(500);
            std::vector<ClientInfo> clients = list_clients();
            for (ClientInfo& client : clients) {
                if (client.pid != target) continue;
                if (client.port == 0) continue;
                reported = true;

                probe_client(client);
                std::printf("record      : port %d  %s\n", client.port, client.url.c_str());
                std::printf("bridge      : %s (%s)\n", client.reachable ? "reachable" : "unreachable",
                            client.detail.c_str());

                EngineState state;
                std::string error;
                if (fetch_state(client, state, error)) print_state(state);
                else std::printf("state       : %s\n", error.c_str());

                print_log_tail(target, 40);
                return state.ready ? 0 : 5;
            }
        }

        std::printf("record      : never appeared after %d s\n", wait_seconds);
        print_log_tail(target, 60);
        return reported ? 5 : 6;
    }

    if (command == L"--clients") {
        const std::vector<std::wstring> paths = installed_client_paths();
        if (paths.empty()) {
            std::printf("no installed client under %%LOCALAPPDATA%%\\Roblox\\Versions\n");
            return 1;
        }
        // Marks the client --launch would pick: the named build, else the newest.
        const std::wstring preferred = preferred_client_path(requested_build);
        for (const std::wstring& path : paths) {
            std::printf("%s %s\n", path == preferred ? "->" : "  ", narrow(path).c_str());
        }
        return 0;
    }

    if (command == L"--launch") {
        const std::wstring dll = engine_dll_path();
        std::printf("engine dll  : %s\n", narrow(dll).c_str());
        if (!file_exists(dll)) {
            std::printf("engine dll  : not found\n");
            return 2;
        }

        std::wstring argument;
        if (args.size() > 1 && args[1][0] != L'-') argument = args[1];

        const LaunchOutcome outcome =
            launch_and_inject(dll, argument, wait_seconds * 1000, requested_build);
        std::printf("client      : %s\n", narrow(outcome.exe).c_str());
        std::printf("command     : %s\n", narrow(outcome.command_line).c_str());
        std::printf("started     : pid %d\n", outcome.pid);
        std::printf("result      : %s (%s)\n", outcome.ok ? "ok" : "failed", outcome.detail.c_str());
        if (outcome.pid != 0) print_log_tail(outcome.pid, 60);
        return outcome.ok ? 0 : 4;
    }

    if (command == L"--probe-load") {
        if (args.size() < 2) {
            std::printf("usage: --probe-load <path.dll> [--pid N] [--datafile] [--direct]\n");
            return 1;
        }
        std::uint32_t flags = 0;
        bool direct = false;
        for (std::size_t i = 1; i < args.size(); ++i) {
            if (args[i] == L"--datafile") flags = 0x00000002;  // LOAD_LIBRARY_AS_DATAFILE
            if (args[i] == L"--direct") direct = true;
        }
        const ProbeOutcome outcome = probe_load(args[1], only_pid, flags, direct);
        std::printf("probe       : %s%s%s%s\n", narrow(args[1]).c_str(),
                    flags != 0 ? "  (datafile)" : "", direct ? "  (direct call site)" : "",
                    only_pid != 0 ? "  (explicit pid)" : "");
        std::printf("target pid  : %d%s\n", outcome.pid, only_pid == 0 ? " (killed)" : "");
        std::printf("loader      : %s\n", outcome.detail.c_str());
        return outcome.loaded ? 0 : 4;
    }

    if (command == L"--probe-apc") {
        if (args.size() < 2 || only_pid == 0) {
            std::printf("usage: --probe-apc <path.dll> --pid N\n");
            return 1;
        }
        const ApcProbeOutcome outcome = probe_apc(args[1], only_pid);
        std::printf("probe       : %s (signed module expected)\n", narrow(args[1]).c_str());
        std::printf("target pid  : %d\n", outcome.pid);
        std::printf("delivery    : %s\n", outcome.detail.c_str());
        return outcome.loaded ? 0 : 4;
    }

    if (command == L"--probe-exec") {
        const ExecOutcome outcome = probe_exec(only_pid);
        std::printf("target pid  : %d%s\n", outcome.pid, only_pid == 0 ? " (killed)" : "");
        std::printf("private code: %s\n", outcome.detail.c_str());
        return outcome.ran ? 0 : 4;
    }

    if (command == L"--map") {
        if (args.size() < 2) {
            std::printf(
                "usage: --map <path.dll> [--pid N] [--entry NAME] [--marker FILE] [--in-place]\n"
                "                       [--wait N]\n");
            return 1;
        }

        MapOptions options;
        options.dll_path = args[1];
        options.wait_ms = wait_seconds * 1000;
        for (std::size_t i = 1; i < args.size(); ++i) {
            if (args[i] == L"--entry" && i + 1 < args.size()) options.entry_export = narrow(args[i + 1]);
            if (args[i] == L"--marker" && i + 1 < args.size()) options.wait_file = args[i + 1];
            if (args[i] == L"--in-place") options.copy_first = false;
            if (args[i] == L"--probe-event") options.probe_event = true;
            if (args[i] == L"--trampoline") options.trampoline = true;
            if (args[i] == L"--apc") options.apc = true;
            if (args[i] == L"--private") options.private_image = true;
            if (args[i] == L"--pagefile") options.pagefile_section = true;
            if (args[i] == L"--cleanup") options.cleanup = true;
            if (args[i] == L"--gate") {
                options.gate_path = L"C:\\Windows\\System32\\fltlib.dll";
                if (i + 1 < args.size() && !args[i + 1].empty() && args[i + 1][0] != L'-') {
                    options.gate_path = args[i + 1];
                }
            }
        }

        std::vector<int> pids = find_roblox_pids();
        if (only_pid != 0) {
            pids.clear();
            pids.push_back(only_pid);
        }
        if (pids.empty()) {
            std::printf("targets     : no Roblox process running (--pid picks any process)\n");
            return 3;
        }
        options.pid = only_pid != 0 ? only_pid : pick_injection_target(pids, list_clients());

        // The engine announces itself by writing its client record, so a payload of
        // the engine's name is observed by waiting for that file. A stale record
        // from an earlier attempt would answer for the new one, so it goes first.
        if (options.wait_file.empty() &&
            _wcsicmp(file_name(options.dll_path).c_str(), L"Vesper.dll") == 0) {
            options.wait_file =
                clients_directory() + L"\\" + std::to_wstring(options.pid) + L".json";
            DeleteFileW(options.wait_file.c_str());
        }

        std::printf("payload     : %s\n", narrow(options.dll_path).c_str());
        std::printf("target pid  : %d\n", options.pid);
        std::printf("entry       : %s\n",
                    options.entry_export.empty() ? "(the image's own entry point)"
                                                : options.entry_export.c_str());

        const MapOutcome outcome = map_module(options);
        if (options.private_image) {
            std::printf("image       : private pages (pagefile-backed, no file behind them)\n");
        } else if (options.pagefile_section) {
            std::printf("image       : a pagefile-backed section (mapped pages, no file name)\n");
        } else {
            std::printf("image copy  : %s\n", narrow(outcome.image_path).c_str());
        }
        std::printf("mapped      : %s  base 0x%llX  %llu bytes  preferred 0x%llX\n",
                    outcome.mapped ? "yes" : "no",
                    static_cast<unsigned long long>(outcome.base),
                    static_cast<unsigned long long>(outcome.image_size),
                    static_cast<unsigned long long>(outcome.preferred_base));
        std::printf("relocations : %d applied\n", outcome.relocations_applied);
        std::printf("imports     : %d/%d resolved\n", outcome.imports_resolved, outcome.imports_total);
        if (outcome.trampoline_address != 0) {
            std::printf("trampoline  : 0x%llX (a genuine entry point in a trusted module)\n",
                        static_cast<unsigned long long>(outcome.trampoline_address));
        }
        if (!options.gate_path.empty()) {
            std::printf("gate        : %s\n", narrow(options.gate_path).c_str());
            std::printf("  view      : %s  base 0x%llX\n", outcome.gate_open ? "mapped" : "not mapped",
                        static_cast<unsigned long long>(outcome.gate_base));
            if (outcome.gate_open) {
                std::printf("  stub      : 0x%llX (inside the image, between its sections)\n",
                            static_cast<unsigned long long>(outcome.gate_stub));
                std::printf("  cfgnote   : %s\n",
                            outcome.gate_registered
                                ? "the stub's page is registered as a valid call target"
                                : "the stub's page could not be registered as a call target");
            } else {
                std::printf("  detail    : %s\n", outcome.gate_detail.c_str());
            }
        }
        if (outcome.apc_queued != 0) {
            std::printf("apc         : queued to %d thread(s) of the target\n", outcome.apc_queued);
        }
        if (!outcome.preloaded.empty()) {
            std::string names;
            for (const std::string& name : outcome.preloaded) {
                if (!names.empty()) names += ", ";
                names += name;
            }
            std::printf("preloaded   : %s\n", names.c_str());
        }
        if (options.apc) {
            std::printf("entry       : %s (delivered to a thread the target started itself)\n",
                        outcome.entry_event_seen ? "ran" : "not observed");
        } else {
            std::printf("entry       : %s  ->  0x%08lX  %s\n",
                        outcome.entry_called ? "called" : "not called",
                        static_cast<unsigned long>(outcome.thread_exit),
                        map_status_name(outcome.thread_exit));
        }
        if (!options.wait_file.empty()) {
            std::printf("marker      : %s\n",
                        outcome.wait_file_seen ? "appeared" : "never appeared");
        }
        if (options.probe_event) {
            std::printf("entry event : %s\n",
                        outcome.entry_event_seen ? "signalled" : "never signalled");
        }
        if (options.cleanup) {
            std::printf("unmapped    : %s\n", outcome.unmapped ? "yes" : "no");
            if (options.probe_event) {
                std::printf("payload     : %s\n",
                            outcome.payload_finished
                                ? "finished, its image was freed afterwards"
                                : "no done event (its image was freed after a grace period)");
            }
        }
        std::printf("result      : %s (%s)\n", outcome.ok ? "ok" : "failed", outcome.detail.c_str());
        if (!outcome.ok) print_log_tail(options.pid, 60);
        return outcome.ok ? 0 : 4;
    }

    if (command == L"--map-launch") {
        if (args.size() < 2) {
            std::printf(
                "usage: --map-launch <path.dll> [client args] [--entry NAME] [--marker FILE]\n"
                "                                   [--wait N]\n"
                "  the client is started suspended, the payload is mapped into it before any of\n"
                "  the game's code has run, and only then is the client resumed\n");
            return 1;
        }

        LaunchMapOptions options;
        options.dll_path = args[1];
        options.build = requested_build;
        options.wait_ms = wait_seconds * 1000;
        for (std::size_t i = 1; i < args.size(); ++i) {
            if (args[i] == L"--entry" && i + 1 < args.size()) options.entry_export = narrow(args[i + 1]);
            if (args[i] == L"--marker" && i + 1 < args.size()) options.wait_file = args[i + 1];
            if (args[i] == L"--hijack") options.hijack = true;
            if (args[i] == L"--probe-event") options.probe_event = true;
            if (args[i] == L"--trampoline") options.trampoline = true;
            if (args[i] == L"--apc") options.apc = true;
            if (args[i] == L"--private") options.private_image = true;
            if (args[i] == L"--pagefile") options.pagefile_section = true;
            if (args[i] == L"--cleanup") options.cleanup = true;
            if (args[i] == L"--return" && i + 1 < args.size()) {
                options.hijack_return = static_cast<std::uintptr_t>(
                    _wcstoui64(args[i + 1].c_str(), nullptr, 0));
            }
        }
        // Anything that is not a flag is handed to the client, as with --launch.
        // Only the flags that take a value may swallow the token after them.
        const auto takes_value = [](const std::wstring& flag) {
            return flag == L"--entry" || flag == L"--marker" || flag == L"--return" ||
                   flag == L"--wait" || flag == L"--pid" || flag == L"--build";
        };
        for (std::size_t i = 2; i < args.size(); ++i) {
            if (args[i].compare(0, 2, L"--") == 0) {
                if (takes_value(args[i])) ++i;
                continue;
            }
            options.argument = args[i];
            break;
        }

        const bool engine = _wcsicmp(file_name(options.dll_path).c_str(), L"Vesper.dll") == 0;
        if (options.wait_file.empty() && engine) {
            options.wait_file = clients_directory() + L"\\%pid%.json";
        }

        std::printf("payload     : %s\n", narrow(options.dll_path).c_str());
        std::printf("entry       : %s\n",
                    options.entry_export.empty() ? "(the image's own entry point)"
                                                : options.entry_export.c_str());

        const LaunchMapOutcome outcome = launch_and_map(options);

        // The launched pid is only known once the client exists, so a marker that
        // names itself with %pid% is resolved here.
        std::printf("client      : %s\n", narrow(outcome.exe).c_str());
        std::printf("started     : pid %d\n", outcome.pid);
        std::printf("mapped      : %s  base 0x%llX  %llu bytes\n",
                    outcome.map.mapped ? "yes" : "no",
                    static_cast<unsigned long long>(outcome.map.base),
                    static_cast<unsigned long long>(outcome.map.image_size));
        if (options.private_image) {
            std::printf("image       : private pages (pagefile-backed, no file behind them)\n");
        } else if (options.pagefile_section) {
            std::printf("image       : a pagefile-backed section (mapped pages, no file name)\n");
        } else {
            std::printf("image copy  : %s\n", narrow(outcome.map.image_path).c_str());
        }
        std::printf("imports     : %d/%d resolved\n", outcome.map.imports_resolved,
                    outcome.map.imports_total);
        if (outcome.map.trampoline_address != 0) {
            std::printf("trampoline  : 0x%llX (a genuine entry point in a trusted module)\n",
                        static_cast<unsigned long long>(outcome.map.trampoline_address));
        }
        if (outcome.map.apc_queued != 0) {
            std::printf("apc         : queued to %d thread(s) of the client\n", outcome.map.apc_queued);
        }
        if (!outcome.map.preloaded.empty()) {
            std::string names;
            for (const std::string& name : outcome.map.preloaded) {
                if (!names.empty()) names += ", ";
                names += name;
            }
            std::printf("preloaded   : %s\n", names.c_str());
        }
        if (options.apc) {
            std::printf("entry       : %s (delivered to a thread the client started itself)\n",
                        outcome.map.entry_event_seen ? "ran" : "not observed");
        } else {
            std::printf("entry       : %s  ->  0x%08lX  %s\n",
                        outcome.map.entry_called ? "called" : "not called",
                        static_cast<unsigned long>(outcome.map.thread_exit),
                        map_status_name(outcome.map.thread_exit));
        }
        std::printf("hijacked    : %s\n",
                    outcome.hijacked ? "yes (the client's own main thread)" : "no");
        if (options.probe_event) {
            std::printf("entry event : %s\n",
                        outcome.entry_event_seen ? "signalled" : "never signalled");
        }
        std::printf("resumed     : %s\n", outcome.resumed ? "yes" : "no");
        std::string liveness = outcome.process_alive ? "alive" : "gone";
        if (outcome.process_alive && outcome.threads_after != 0) {
            liveness += " (" + std::to_string(outcome.threads_after) + " threads)";
        }
        std::printf("client now  : %s\n", liveness.c_str());
        std::printf("result      : %s (%s)\n", outcome.ok ? "ok" : "failed", outcome.detail.c_str());
        if (!outcome.ok) print_log_tail(outcome.pid, 60);
        return outcome.ok ? 0 : 4;
    }

    if (command == L"--open") {
        // Hand a place link to Roblox's own handler. The client that comes up is
        // started by Roblox, with Roblox's own arguments: nothing about how it is
        // started is ours, which is the point of having this at all.
        std::wstring place = L"4483381587";
        if (args.size() >= 2 && !args[1].empty()) place = args[1];

        const std::wstring url = L"roblox://experiences/start?placeId=" + place;
        std::printf("place       : %s\n", narrow(place).c_str());
        const HINSTANCE opened =
            ShellExecuteW(nullptr, L"open", url.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
        if (reinterpret_cast<std::intptr_t>(opened) <= 32) {
            std::printf("result      : nothing accepted the link (code %lld)\n",
                        static_cast<long long>(reinterpret_cast<std::intptr_t>(opened)));
            return 5;
        }

        int found = 0;
        for (int waited = 0; waited < 180000 && found == 0; waited += 500) {
            const std::vector<int> pids = find_roblox_pids();
            if (!pids.empty()) found = pids.front();
            if (found == 0) Sleep(500);
        }
        if (found == 0) {
            std::printf("result      : the link was accepted, no client appeared\n");
            return 5;
        }
        std::printf("client      : pid %d\n", found);
        std::printf("result      : joined (give it a moment to reach the place)\n");
        return 0;
    }

    if (command == L"--modules") {
        if (only_pid == 0) {
            std::printf("usage: --modules --pid N\n");
            return 1;
        }
        print_remote_modules(only_pid);
        return 0;
    }

    if (command == L"--regions") {
        if (only_pid == 0) {
            std::printf("usage: --regions --pid N\n");
            return 1;
        }
        print_remote_regions(only_pid);
        return 0;
    }

    if (command == L"--dump") {
        std::vector<std::wstring> positional;
        for (std::size_t i = 1; i < args.size(); ++i) {
            if (args[i] == L"--pid" || args[i] == L"--wait") {
                ++i;
                continue;
            }
            positional.push_back(args[i]);
        }
        if (only_pid == 0 || positional.size() < 3) {
            std::printf("usage: --dump --pid N <hex-base> <hex-size> <out-file>\n");
            return 1;
        }
        const std::uintptr_t base =
            static_cast<std::uintptr_t>(_wcstoui64(positional[0].c_str(), nullptr, 16));
        const std::size_t size =
            static_cast<std::size_t>(_wcstoui64(positional[1].c_str(), nullptr, 16));
        if (base == 0 || size == 0) {
            std::printf("dump        : base and size must be non-zero hex values\n");
            return 1;
        }
        std::printf("process     : %d\n", only_pid);
        std::printf("range       : 0x%llX + 0x%llX\n", static_cast<unsigned long long>(base),
                    static_cast<unsigned long long>(size));
        dump_remote_image(only_pid, base, size, positional[2]);
        return 0;
    }

    if (command == L"--list") {
        std::vector<ClientInfo> clients = list_clients();
        if (clients.empty()) {
            std::printf("no client records in %s\n", narrow(clients_directory()).c_str());
            return 1;
        }
        for (ClientInfo& client : clients) {
            probe_client(client);
            std::printf("pid %-6d port %-6d %-12s build %-22s %s\n", client.pid, client.port,
                        client.reachable ? "reachable" : "unreachable", client.build.c_str(),
                        client.detail.c_str());
        }
        return 0;
    }

    if (command == L"--hooktest") {
        std::vector<ClientInfo> clients = list_clients();
        ClientInfo* chosen = select_client(clients, only_pid);
        if (chosen == nullptr) {
            std::printf("no client selected\n");
            return 1;
        }
        probe_client(*chosen);
        // A live pid is not the same as a live bridge: a record can outlive its
        // process (pid reuse) or the engine can be gone while the client stays.
        // With several live records, take the first one that actually answers.
        if (!chosen->reachable) {
            for (ClientInfo& candidate : clients) {
                if (&candidate == chosen) continue;
                if (only_pid != 0 && candidate.pid != only_pid) continue;
                if (!candidate.alive) continue;
                probe_client(candidate);
                if (candidate.reachable) {
                    chosen = &candidate;
                    break;
                }
            }
        }
        std::printf("pid         : %d\n", chosen->pid);
        std::printf("bridge      : %s (%s)\n", chosen->reachable ? "reachable" : "unreachable",
                    chosen->detail.c_str());
        if (!chosen->reachable) {
            print_log_tail(chosen->pid, 40);
            return 1;
        }

        // The route installs the detour and queues one job by default; the flags
        // below select the other verbs the route understands.
        std::string action;
        for (std::size_t i = 1; i < args.size(); ++i) {
            if (args[i] == L"--probe") action = "probe";
            else if (args[i] == L"--install") action = "install";
            else if (args[i] == L"--run") action = "run";
            else if (args[i] == L"--status") action = "status";
            else if (args[i] == L"--remove") action = "remove";
        }
        std::string route = "/hooktest";
        if (!action.empty()) route += "?action=" + action;

        std::string report;
        std::string error;
        if (!fetch_report(*chosen, route.c_str(), report, error)) {
            std::printf("hooktest    : %s\n", error.c_str());
            return 1;
        }
        std::printf("--- hook report ---\n%s\n", report.c_str());
        std::printf("note        : the probe runs asynchronously on the game's Lua thread;\n"
                    "              run '--log --pid %d' to read its hook: lines\n",
                    chosen->pid);
        return 0;
    }

    if (command == L"--status" || command == L"--abi" || command == L"--exec") {
        std::vector<ClientInfo> clients = list_clients();
        ClientInfo* chosen = select_client(clients, only_pid);
        if (chosen == nullptr) {
            std::printf("no client selected\n");
            return 1;
        }

        // A client in APC mode has no server to probe: it is reached through its inbox.
        if (chosen->mode == "apc" && chosen->alive) {
            std::printf("pid         : %d\n", chosen->pid);
            std::printf("channel     : apc + files (no socket in the client)\n");
            if (command == L"--status") {
                std::printf("build       : %s\nprofile     : %s\n", chosen->build.c_str(),
                            chosen->profile.c_str());
                return 0;
            }
            if (command != L"--exec") {
                std::printf("%s is not available on an APC-mode client\n", narrow(command).c_str());
                return 1;
            }
            if (args.size() < 2) {
                std::printf("usage: --exec <file.lua>\n");
                return 1;
            }
            const std::vector<std::uint8_t> data = read_file(args[1]);
            if (data.empty()) {
                std::printf("script      : cannot read %s\n", narrow(args[1]).c_str());
                return 1;
            }
            const std::string source(data.begin(), data.end());
            std::printf("script      : %d bytes from %s\n", static_cast<int>(source.size()),
                        narrow(file_name(args[1])).c_str());
            std::string output;
            std::string error;
            if (!run_script_apc(*chosen, source, 120000, output, error)) {
                std::printf("run         : failed - %s\n", error.c_str());
                print_log_tail(chosen->pid, 20);
                return 1;
            }
            std::printf("run         : finished\n--- output ---\n%s\n", output.c_str());
            return 0;
        }

        probe_client(*chosen);
        // A live pid is not the same as a live bridge: a record can outlive its
        // process (pid reuse) or the engine can be gone while the client stays.
        // With several live records, take the first one that actually answers.
        if (!chosen->reachable) {
            for (ClientInfo& candidate : clients) {
                if (&candidate == chosen) continue;
                if (only_pid != 0 && candidate.pid != only_pid) continue;
                if (!candidate.alive) continue;
                probe_client(candidate);
                if (candidate.reachable) {
                    chosen = &candidate;
                    break;
                }
            }
        }
        std::printf("pid         : %d\n", chosen->pid);
        std::printf("bridge      : %s (%s)\n", chosen->reachable ? "reachable" : "unreachable",
                    chosen->detail.c_str());
        if (!chosen->reachable) {
            print_log_tail(chosen->pid, 40);
            return 1;
        }

        if (command == L"--status") {
            EngineState state;
            std::string error;
            if (!fetch_state(*chosen, state, error)) {
                std::printf("state       : %s\n", error.c_str());
                return 1;
            }
            print_state(state);
            return 0;
        }

        if (command == L"--abi") {
            std::string report;
            std::string error;
            if (!fetch_report(*chosen, "/abi/repair", report, error)) {
                std::printf("abi probe   : %s\n", error.c_str());
                return 1;
            }
            std::printf("--- abi report ---\n%s\n", report.c_str());
            return 0;
        }

        // --exec
        if (args.size() < 2) {
            std::printf("usage: --exec <file.lua>\n");
            return 1;
        }
        const std::vector<std::uint8_t> data = read_file(args[1]);
        if (data.empty()) {
            std::printf("script      : cannot read %s\n", narrow(args[1]).c_str());
            return 1;
        }
        const std::string source(data.begin(), data.end());
        std::printf("script      : %d bytes from %s\n", static_cast<int>(source.size()),
                    narrow(file_name(args[1])).c_str());

        std::string output;
        std::string error;
        bool pending = false;
        if (!run_script(*chosen, source, "cli", 15000, output, pending, error)) {
            std::printf("run         : failed - %s\n", error.c_str());
            print_log_tail(chosen->pid, 30);
            return 1;
        }
        std::printf("run         : %s\n", pending ? "still running" : "finished");
        std::printf("--- output ---\n%s\n", output.c_str());
        return 0;
    }

    if (command == L"--log") {
        print_log_tail(only_pid, 120);
        return 0;
    }

    std::printf("unknown command; try --help\n");
    return 1;
}

}  // namespace

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int show_command) {
    int argc = 0;
    wchar_t** argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv != nullptr) {
        // Anything that starts with a dash is a command, not a document: run it
        // and exit without ever creating a window.
        if (argc > 1 && argv[1][0] == L'-') {
            const int result = run_headless(argc, argv);
            LocalFree(argv);
            return result;
        }
        LocalFree(argv);
    }

    enable_dpi_awareness();

    INITCOMMONCONTROLSEX controls{};
    controls.dwSize = sizeof(controls);
    controls.dwICC = ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&controls);

    WNDCLASSEXW window_class{};
    window_class.cbSize = sizeof(window_class);
    window_class.style = CS_HREDRAW | CS_VREDRAW | CS_DBLCLKS;
    window_class.lpfnWndProc = WindowProc;
    window_class.hInstance = instance;
    window_class.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    window_class.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    window_class.lpszClassName = L"VesperShellWindow";
    window_class.hIconSm = window_class.hIcon;
    if (RegisterClassExW(&window_class) == 0) return 1;

    const float scale = static_cast<float>(system_dpi()) / 96.0f;
    const int width = static_cast<int>(1200.0f * scale);
    const int height = static_cast<int>(760.0f * scale);

    HWND window = CreateWindowExW(WS_EX_APPWINDOW, window_class.lpszClassName, L"Vesper",
                                  WS_POPUP | WS_THICKFRAME | WS_MINIMIZEBOX | WS_MAXIMIZEBOX | WS_CLIPCHILDREN,
                                  CW_USEDEFAULT, CW_USEDEFAULT, width, height, nullptr, nullptr, instance,
                                  nullptr);
    if (window == nullptr) return 1;

    // Rounded corners on Windows 11. Attribute 33 is DWMWA_WINDOW_CORNER_PREFERENCE;
    // 2 is DWMWCP_ROUND. Pre-11 builds reject it and keep square corners.
    const DWORD corner_preference = 2;
    DwmSetWindowAttribute(window, 33, &corner_preference, sizeof(corner_preference));

    ShowWindow(window, show_command == 0 ? SW_SHOWNORMAL : show_command);
    UpdateWindow(window);

    MSG message{};
    while (GetMessageW(&message, nullptr, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    return 0;
}
