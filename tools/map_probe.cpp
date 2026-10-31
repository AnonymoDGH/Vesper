// Vesper -- mapping probe payload.
//
// The smallest payload that can answer a hard question: does a module mapped as a
// file-backed image section, finished by hand and entered from a thread whose start
// address the client already trusts, actually run? It uses nothing but kernel32 and
// writes one file naming the base it was handed, the address of an API reached
// through its own import table, and whether it was given a thread context to hand
// back.
//
// Two entry shapes:
//   MapProbeEntry(void* image_base, void* saved_context)
//       entered by a thread that was redirected into this image; hands the thread
//       back through `NtContinue` when given a context.
//   MapProbeThunk(void)
//       entered through a jump from a module the client trusts; finds its own image
//       base and leaves nothing to restore.
//
// Both announce themselves on `Local\vesper_probe_entry_<pid>` before anything else,
// which is proof of execution that depends on no other API working.
//
// Built as `out/map_probe.dll`, deliberately unsigned.
#include <windows.h>

namespace {

// Walks back from a known address inside this image to its header. This is how a
// payload entered without arguments finds out where it was mapped.
void* own_image_base() {
    UINT_PTR page = reinterpret_cast<UINT_PTR>(&own_image_base) & ~static_cast<UINT_PTR>(0xFFF);
    for (int steps = 0; steps < 0x2000; ++steps, page -= 0x1000) {
        if (page < 0x10000) break;
        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(page);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) continue;
        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(page + dos->e_lfanew);
        if (nt->Signature == IMAGE_NT_SIGNATURE) return reinterpret_cast<void*>(page);
    }
    return nullptr;
}

unsigned long probe_body(void* image_base, void* saved_context) {
    // First thing: announce that this code is running. The launcher waits on this
    // event, which is proof of execution that does not depend on the filesystem or
    // on anything else in this function working.
    wchar_t event_name[96] = {};
    wsprintfW(event_name, L"Local\\vesper_probe_entry_%lu", GetCurrentProcessId());
    const HANDLE announced = CreateEventW(nullptr, TRUE, FALSE, event_name);
    if (announced != nullptr) SetEvent(announced);

    constexpr DWORD kBuffer = 512;
    wchar_t directory[kBuffer] = {};
    const DWORD length = GetTempPathW(kBuffer, directory);
    if (length == 0 || length >= kBuffer) return 1;

    wchar_t path[kBuffer] = {};
    wchar_t number[32] = {};

    // %TEMP%\vesper-map-probe-<pid>.txt, assembled without the C runtime.
    wsprintfW(number, L"%lu", GetCurrentProcessId());
    lstrcpyW(path, directory);
    lstrcatW(path, L"vesper-map-probe-");
    lstrcatW(path, number);
    lstrcatW(path, L".txt");

    char text[400] = {};
    // `&GetTickCount64` goes through the import table, which only holds the right
    // address if the mapper resolved this image's imports.
    wsprintfA(text,
              "pid=%lu\r\nbase=0x%p\r\ngettickcount64=0x%p\r\ncontext=0x%p\r\n"
              "thread=%lu\r\nimports=resolved\r\n",
              GetCurrentProcessId(), image_base, reinterpret_cast<void*>(&GetTickCount64),
              saved_context, GetCurrentThreadId());

    const HANDLE file = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS,
                                    FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return 2;

    DWORD written = 0;
    const BOOL ok = WriteFile(file, text, static_cast<DWORD>(lstrlenA(text)), &written, nullptr);
    FlushFileBuffers(file);
    CloseHandle(file);

    // The launcher may free this image the moment it sees the first event, and this
    // function is still running inside the image when it does. A second event, raised
    // as the very last thing here, says the image is finished with, so it is not
    // pulled out from under a live thread.
    wchar_t done_name[96] = {};
    wsprintfW(done_name, L"Local\\vesper_probe_done_%lu", GetCurrentProcessId());
    const HANDLE finished = CreateEventW(nullptr, TRUE, FALSE, done_name);
    if (finished != nullptr) SetEvent(finished);

    // Hand a borrowed thread back to where it was. This never returns, which is the
    // point: the thread's own code continues from its saved context.
    if (saved_context != nullptr) {
        const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (ntdll != nullptr) {
            using NtContinueFn = long (*)(void*, unsigned char);
            const auto nt_continue =
                reinterpret_cast<NtContinueFn>(GetProcAddress(ntdll, "NtContinue"));
            if (nt_continue != nullptr) nt_continue(saved_context, 0);
        }
    }

    return ok ? 0 : 3;
}

}  // namespace

extern "C" __declspec(dllexport) unsigned long WINAPI MapProbeEntry(void* image_base,
                                                                   void* saved_context) {
    return probe_body(image_base, saved_context);
}

extern "C" __declspec(dllexport) unsigned long WINAPI MapProbeThunk() {
    return probe_body(own_image_base(), nullptr);
}
