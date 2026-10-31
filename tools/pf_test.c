/* pf_test.c - which protection changes a pagefile-backed section view allows.
 *
 * Built to answer one question the mapper ran into: a SEC_COMMIT section with no
 * file, mapped into a process, refused VirtualProtectEx to PAGE_EXECUTE_READWRITE
 * with error 87. This runs the combinations locally and prints the raw status, so
 * the mapper can be written against the rule the kernel actually enforces instead
 * of against an assumption.
 *
 *   build: gcc -O1 -o pf_test.exe pf_test.c
 */
#include <windows.h>
#include <stdio.h>

typedef long(NTAPI* pNtCreateSection)(HANDLE*, unsigned long, void*, long long*, unsigned long,
                                      unsigned long, HANDLE);
typedef long(NTAPI* pNtMapViewOfSection)(HANDLE, HANDLE, void**, unsigned long long, SIZE_T,
                                         long long*, SIZE_T*, unsigned long, unsigned long,
                                         unsigned long);

static const unsigned long kSecCommit = 0x08000000;
static const unsigned long kSecImage = 0x01000000;
static const unsigned long kSectionAllAccess = 0x000F001F;

static pNtCreateSection g_create;
static pNtMapViewOfSection g_map;

static void try_case(const char* label, unsigned long section_prot, unsigned long view_prot,
                     unsigned long new_prot) {
    HANDLE section = NULL;
    long long maximum = 0x10000;
    long status = g_create(&section, kSectionAllAccess, NULL, &maximum, section_prot, kSecCommit,
                           NULL);
    printf("%-46s create(%s) -> %08lX\n", label,
           section_prot == PAGE_READWRITE ? "RW" : "RWX", status & 0xFFFFFFFFu);
    if (status < 0) return;

    void* at = NULL;
    SIZE_T view_size = 0;
    status = g_map(section, GetCurrentProcess(), &at, 0, 0, NULL, &view_size, 2 /*ViewShare*/, 0,
                   view_prot);
    printf("%-46s map(%s)      -> %08lX at %p\n", label,
           view_prot == PAGE_READWRITE ? "RW" : "RWX", status & 0xFFFFFFFFu, at);
    if (status < 0) {
        CloseHandle(section);
        return;
    }

    DWORD old = 0;
    BOOL ok = VirtualProtect(at, 0x1000, new_prot, &old);
    printf("%-46s protect(%s)%s -> %s (err %lu, was %lX)\n", label,
           new_prot == PAGE_EXECUTE_READWRITE ? "RWX"
                                              : new_prot == PAGE_EXECUTE_READ ? "RX" : "R",
           "     ", ok ? "ok" : "FAILED", ok ? 0ul : GetLastError(), old);

    VirtualFree(at, 0, MEM_RELEASE);
    CloseHandle(section);
    printf("\n");
}

int main(void) {
    HMODULE ntdll = LoadLibraryA("ntdll.dll");
    g_create = (pNtCreateSection)GetProcAddress(ntdll, "NtCreateSection");
    g_map = (pNtMapViewOfSection)GetProcAddress(ntdll, "NtMapViewOfSection");

    try_case("A: RW section, RW view, ask for RWX", PAGE_READWRITE, PAGE_READWRITE,
             PAGE_EXECUTE_READWRITE);
    try_case("B: RWX section, RW view, ask for RWX", PAGE_EXECUTE_READWRITE, PAGE_READWRITE,
             PAGE_EXECUTE_READWRITE);
    try_case("C: RWX section, RWX view, ask for RX", PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_READWRITE,
             PAGE_EXECUTE_READ);
    try_case("D: RWX section, RWX view, ask for RW", PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_READWRITE,
             PAGE_READWRITE);
    return 0;
}
