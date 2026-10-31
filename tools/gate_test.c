/* gate_test.c - where inside a mapped image can a stub actually run?
 *
 * The mapper puts a few instructions into the unused tail of a signed image's last
 * code page and has an APC call it. In Notepad that kills the process instantly, and
 * Notepad has no anti-tamper, so the refusal is a property of the address, not of the
 * process. This tool reproduces it locally -- it maps the same image into its own
 * process, writes the same kind of stub in a few different places, and has an APC
 * call each one -- so the rule can be read off instead of guessed at.
 *
 * Every stub ends in a jump to GetTickCount64: it takes no arguments, it is a genuine
 * function entry, and a call to it returns, which is what an APC routine has to do.
 *
 *   build: gcc -O1 -o gate_test.exe gate_test.c
 *   run:   gate_test.exe <mode> [path]
 *     1  stub in the tail of the last code section's page, page left executable
 *     2  same place, page left read-write-execute
 *     3  stub written over the first bytes of the code section itself
 *     4  stub in a pagefile-backed section (the shape the payload usually lives in)
 *     5  stub in a private allocation (the plain VirtualAlloc case)
 */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

typedef long(NTAPI* pNtCreateSection)(HANDLE*, unsigned long, void*, long long*, unsigned long,
                                      unsigned long, HANDLE);
typedef long(NTAPI* pNtMapViewOfSection)(HANDLE, HANDLE, void**, unsigned long long, SIZE_T,
                                         long long*, SIZE_T*, unsigned long, unsigned long,
                                         unsigned long);

static const unsigned long kSecCommit = 0x08000000;
static const unsigned long kSecImage = 0x01000000;

static void* g_stub = NULL;
static volatile LONG g_calls = 0;
static HANDLE g_seen = NULL;

static void NTAPI on_apc(unsigned long long param) {
    (void)param;
    InterlockedIncrement(&g_calls);
    if (g_seen) SetEvent(g_seen);
}

/* mov rax, imm64; jmp rax */
static void build_stub(void* at, void* destination) {
    unsigned char bytes[12];
    bytes[0] = 0x48;
    bytes[1] = 0xB8;
    for (int i = 0; i < 8; ++i) bytes[2 + i] = (unsigned char)(((unsigned long long)destination >> (i * 8)) & 0xFF);
    bytes[10] = 0xFF;
    bytes[11] = 0xE0;

    DWORD old = 0;
    if (!VirtualProtect(at, sizeof(bytes), PAGE_EXECUTE_READWRITE, &old)) {
        printf("  protect(rwx) failed: %lu\n", GetLastError());
        return;
    }
    memcpy(at, bytes, sizeof(bytes));
    printf("  wrote 12 bytes at %p, protection was %08lX\n", at, old);
}

static void describe(const void* at) {
    MEMORY_BASIC_INFORMATION info;
    memset(&info, 0, sizeof(info));
    if (VirtualQuery(at, &info, sizeof(info)) != sizeof(info)) {
        printf("  VirtualQuery failed\n");
        return;
    }
    static const char* names[] = {"free", "reserved", "committed"};
    printf("  region: %s type=%s protect=%08lX size=%llu KB base=%p\n",
           names[info.State <= 2 ? info.State : 0],
           info.Type == MEM_IMAGE ? "image  " : info.Type == MEM_MAPPED ? "mapped " : "private",
           info.Protect, (unsigned long long)(info.RegionSize / 1024), info.BaseAddress);
}

static void fire(const char* what) {
    g_seen = CreateEventW(NULL, TRUE, FALSE, NULL);
    printf("  firing an APC at %s (%p)...\n", what, g_stub);
    QueueUserAPC((PAPCFUNC)g_stub, GetCurrentThread(), 0);
    const DWORD waited = SleepEx(1500, TRUE);
    printf("  SleepEx returned %lu, apc calls so far: %ld\n", waited, g_calls);
    if (g_seen) CloseHandle(g_seen);
    g_seen = NULL;
}

int main(int argc, char** argv) {
    const int mode = argc > 1 ? atoi(argv[1]) : 1;
    const char* path = argc > 2 ? argv[2] : "C:\\Windows\\System32\\fltlib.dll";
    printf("mode %d, image %s\n", mode, path);

    /* The same code the mapper jumps to in the end: a real function entry, called
       from the stub. */
    void* destination = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetTickCount64");
    printf("jump destination: GetTickCount64 at %p\n", destination);

    HMODULE ntdll = LoadLibraryA("ntdll.dll");
    const pNtCreateSection create_section =
        (pNtCreateSection)GetProcAddress(ntdll, "NtCreateSection");
    const pNtMapViewOfSection map_view =
        (pNtMapViewOfSection)GetProcAddress(ntdll, "NtMapViewOfSection");

    if (mode >= 1 && mode <= 3) {
        /* Read the file, walk to the section headers, choose the last executable
           section -- the same walk the mapper does. */
        const HANDLE file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                                        FILE_ATTRIBUTE_NORMAL, NULL);
        if (file == INVALID_HANDLE_VALUE) {
            printf("cannot open the image\n");
            return 2;
        }
        const DWORD size = GetFileSize(file, NULL);
        unsigned char* bytes = (unsigned char*)malloc(size);
        DWORD got = 0;
        ReadFile(file, bytes, size, &got, NULL);
        CloseHandle(file);

        const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*)bytes;
        const IMAGE_NT_HEADERS64* nt = (const IMAGE_NT_HEADERS64*)(bytes + dos->e_lfanew);
        const IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);
        const unsigned count = nt->FileHeader.NumberOfSections;
        printf("sections: %u, image size 0x%lX, preferred base 0x%llX\n", count,
               nt->OptionalHeader.SizeOfImage,
               (unsigned long long)nt->OptionalHeader.ImageBase);

        HANDLE section = NULL;
        const HANDLE image_file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        long status = create_section(&section, 0x000F001F, NULL, NULL, PAGE_READONLY, kSecImage,
                                     image_file);
        CloseHandle(image_file);
        printf("create_section(image) -> %08lX\n", status & 0xFFFFFFFFu);
        if (status < 0) return 2;

        void* at = (void*)(unsigned long long)nt->OptionalHeader.ImageBase;
        SIZE_T view_size = 0;
        status = map_view(section, GetCurrentProcess(), &at, 0, 0, NULL, &view_size, 2, 0,
                          PAGE_READONLY);
        printf("map_view -> %08lX at %p (%llu KB)\n", status & 0xFFFFFFFFu, at,
               (unsigned long long)(view_size / 1024));
        CloseHandle(section);
        if (status < 0) return 2;

        /* The last executable section, and its declared end. */
        const IMAGE_SECTION_HEADER* code = NULL;
        for (unsigned i = 0; i < count; ++i) {
            if (sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) code = &sections[i];
        }
        if (code == NULL) {
            printf("no executable section\n");
            return 2;
        }
        const unsigned long end = code->VirtualAddress +
                                  (code->Misc.VirtualSize > code->SizeOfRawData
                                       ? code->Misc.VirtualSize
                                       : code->SizeOfRawData);
        printf("code section \"%.8s\" va 0x%lX vsize 0x%lX raw 0x%lX -> declared end 0x%lX\n",
               code->Name, code->VirtualAddress, code->Misc.VirtualSize, code->SizeOfRawData, end);

        if (mode == 1 || mode == 2) {
            g_stub = (unsigned char*)at + end;
            printf("stub goes at %p (tail of the code section's last page)\n", g_stub);
            describe(g_stub);
            build_stub(g_stub, destination);
            if (mode == 1) {
                DWORD old = 0;
                VirtualProtect(g_stub, 12, PAGE_EXECUTE_READ, &old);
                printf("  page restored to execute-read\n");
            } else {
                printf("  page left read-write-execute\n");
            }
        } else {
            g_stub = (unsigned char*)at + code->VirtualAddress + 0x40;
            printf("stub goes at %p (inside the code section, over its own bytes)\n", g_stub);
            describe(g_stub);
            build_stub(g_stub, destination);
            DWORD old = 0;
            VirtualProtect(g_stub, 12, PAGE_EXECUTE_READ, &old);
        }
        describe(g_stub);
    } else if (mode == 4) {
        HANDLE section = NULL;
        long long maximum = 0x10000;
        const long status =
            create_section(&section, 0x000F001F, NULL, &maximum, PAGE_EXECUTE_READWRITE,
                           kSecCommit, NULL);
        printf("create_section(pagefile) -> %08lX\n", status & 0xFFFFFFFFu);
        void* at = NULL;
        SIZE_T view_size = 0;
        map_view(section, GetCurrentProcess(), &at, 0, 0, NULL, &view_size, 2, 0,
                 PAGE_EXECUTE_READWRITE);
        CloseHandle(section);
        printf("pagefile view at %p\n", at);
        g_stub = at;
        describe(g_stub);
        build_stub(g_stub, destination);
        DWORD old = 0;
        VirtualProtect(g_stub, 12, PAGE_EXECUTE_READ, &old);
    } else {
        g_stub = VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        printf("private page at %p\n", g_stub);
        build_stub(g_stub, destination);
        DWORD old = 0;
        VirtualProtect(g_stub, 12, PAGE_EXECUTE_READ, &old);
    }

    fire("the stub");
    printf("done, the process lived: apc ran %ld time(s)\n", g_calls);
    return 0;
}
