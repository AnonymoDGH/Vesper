// Bisection switch for a freeze that no single component explains.
//
// %LOCALAPPDATA%\Vesper\stage holds one digit, optionally followed by skip letters;
// absent or unreadable means 4 with nothing skipped, the full engine.
//   1  load only: log, exception ring, nothing else runs
//   2  + attach: profile, scheduler walk, state resolution (no bridge)
//   3  + bridge: the HTTP listener and the client record, but no periodic tick
//   4  + tick: the timer that refreshes state every 250 ms
// Skip letters, for the load step itself:
//   u  do not register the image's unwind table (RtlAddFunctionTable)
//   v  do not install the vectored exception handler
// Read once per process, with kernel32 calls only.
#pragma once

#include <windows.h>

namespace vesper {

namespace stage_detail {
inline const char* text() {
    static char buffer[8] = {};
    static bool read = false;
    if (read) return buffer;
    read = true;

    wchar_t path[MAX_PATH] = {};
    const DWORD n = GetEnvironmentVariableW(L"LOCALAPPDATA", path, MAX_PATH - 16);
    if (n > 0 && n < MAX_PATH - 16) {
        lstrcatW(path, L"\\Vesper\\stage");
        const HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file != INVALID_HANDLE_VALUE) {
            DWORD got = 0;
            ReadFile(file, buffer, 7, &got, nullptr);
            CloseHandle(file);
        }
    }
    return buffer;
}
}  // namespace stage_detail

inline int engine_stage() {
    const char* t = stage_detail::text();
    // Default 2: attach, no server, no tick, no thread -- the APC command channel.
    return (t[0] >= '1' && t[0] <= '4') ? t[0] - '0' : 2;
}

inline bool stage_skips(char letter) {
    const char* t = stage_detail::text();
    for (int i = 1; i < 7 && t[i] != '\0'; ++i) {
        if (t[i] == letter) return true;
    }
    return false;
}

}  // namespace vesper
