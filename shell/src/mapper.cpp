// Vesper -- loader-free module mapping, implemented in the shell.
//
// Everything here runs in the shell's own process and only *writes* into the
// target, so nothing about the payload needs the target's cooperation until the
// last step, when one of the payload's own exported functions is entered from
// inside the image it was mapped into.
#include "mapper.hpp"
#include "net.hpp"
#include "util.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>

namespace vesper::shell {
namespace {

constexpr std::size_t kNowhere = static_cast<std::size_t>(-1);

// ---------------------------------------------------------------- ntdll api --

// These two calls are the whole mapper: a section created from the payload file
// with the image flag set, mapped into the target. That is what makes the pages
// `MEM_IMAGE` rather than private memory, and the page type is the property the
// client's checks care about. Resolved by name so the shell does not carry a
// link-time dependency on ntdll for two functions.
using CreateSectionFn = long (*)(HANDLE* section, unsigned long access, void* attributes,
                                 long long* maximum_size, unsigned long page_protection,
                                 unsigned long section_attributes, HANDLE file);
using MapViewFn = long (*)(HANDLE section, HANDLE process, void** base, unsigned long long zero_bits,
                           unsigned long long commit_size, long long* section_offset,
                           unsigned long long* view_size, unsigned long inherit,
                           unsigned long allocation_type, unsigned long protection);
using UnmapViewFn = long (*)(HANDLE process, void* base);

struct NtApi {
    CreateSectionFn create_section = nullptr;
    MapViewFn map_view = nullptr;
    UnmapViewFn unmap_view = nullptr;
};

const NtApi& nt_api() {
    static NtApi api = [] {
        NtApi loaded;
        const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (ntdll == nullptr) return loaded;
        loaded.create_section =
            reinterpret_cast<CreateSectionFn>(GetProcAddress(ntdll, "NtCreateSection"));
        loaded.map_view =
            reinterpret_cast<MapViewFn>(GetProcAddress(ntdll, "NtMapViewOfSection"));
        loaded.unmap_view =
            reinterpret_cast<UnmapViewFn>(GetProcAddress(ntdll, "NtUnmapViewOfSection"));
        return loaded;
    }();
    return api;
}

// Section and view constants, spelled out because the shell does not include the
// native headers they come from.
constexpr unsigned long kSectionAllAccess = 0x000F001Fu;
constexpr unsigned long kSectionMapAll = 0x0000000Fu;  // read | write | execute | query
constexpr unsigned long kSecImage = 0x01000000u;
constexpr unsigned long kSecCommit = 0x08000000u;       // pages, file or pagefile
constexpr unsigned long kViewShare = 1u;

std::string hex32(long value) {
    char buffer[16] = {};
    std::snprintf(buffer, sizeof(buffer), "0x%08lX", static_cast<unsigned long>(value));
    return buffer;
}

std::string hex64(std::uint64_t value) {
    char buffer[24] = {};
    std::snprintf(buffer, sizeof(buffer), "0x%llX", static_cast<unsigned long long>(value));
    return buffer;
}

// --------------------------------------------------------------- pe reading --

struct PeImage {
    std::vector<std::uint8_t> bytes;
    std::uint64_t image_base = 0;
    std::uint32_t size_of_image = 0;
    std::uint32_t size_of_headers = 0;
    std::uint32_t entry_rva = 0;
    std::uint32_t section_count = 0;
    const IMAGE_SECTION_HEADER* sections = nullptr;
    std::uint32_t import_rva = 0;
    std::uint32_t import_size = 0;
    std::uint32_t reloc_rva = 0;
    std::uint32_t reloc_size = 0;
    std::uint32_t export_rva = 0;
    std::uint32_t export_size = 0;
};

bool parse_pe(std::vector<std::uint8_t>&& bytes, PeImage& out, std::string& error) {
    if (bytes.size() < sizeof(IMAGE_DOS_HEADER)) {
        error = "file is too small to be an image";
        return false;
    }
    out.bytes = std::move(bytes);

    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(out.bytes.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        error = "missing MZ signature";
        return false;
    }
    const std::size_t nt_offset = static_cast<std::size_t>(dos->e_lfanew);
    if (nt_offset + sizeof(IMAGE_NT_HEADERS64) > out.bytes.size()) {
        error = "truncated headers";
        return false;
    }
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(out.bytes.data() + nt_offset);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        error = "missing PE signature";
        return false;
    }
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        error = "not a 64-bit image";
        return false;
    }

    out.image_base = nt->OptionalHeader.ImageBase;
    out.size_of_image = nt->OptionalHeader.SizeOfImage;
    out.size_of_headers = nt->OptionalHeader.SizeOfHeaders;
    out.entry_rva = nt->OptionalHeader.AddressOfEntryPoint;
    out.section_count = nt->FileHeader.NumberOfSections;
    out.sections = IMAGE_FIRST_SECTION(nt);
    out.import_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    out.import_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    out.reloc_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    out.reloc_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    out.export_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    out.export_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

    if (out.size_of_image == 0) {
        error = "image reports no size";
        return false;
    }
    const std::size_t section_bytes =
        static_cast<std::size_t>(out.section_count) * sizeof(IMAGE_SECTION_HEADER);
    if (nt_offset + sizeof(IMAGE_NT_HEADERS64) + section_bytes > out.bytes.size()) {
        error = "truncated section table";
        return false;
    }
    return true;
}

std::size_t rva_to_offset(const PeImage& pe, std::uint32_t rva) {
    if (rva == 0) return kNowhere;
    if (rva < pe.size_of_headers) {
        return rva < pe.bytes.size() ? rva : kNowhere;
    }
    for (std::uint32_t i = 0; i < pe.section_count; ++i) {
        const IMAGE_SECTION_HEADER& section = pe.sections[i];
        const std::uint32_t size = std::max(section.Misc.VirtualSize, section.SizeOfRawData);
        if (rva < section.VirtualAddress || rva >= section.VirtualAddress + size) continue;
        const std::size_t offset = section.PointerToRawData + (rva - section.VirtualAddress);
        return offset < pe.bytes.size() ? offset : kNowhere;
    }
    return kNowhere;
}

const char* string_at(const PeImage& pe, std::uint32_t rva) {
    const std::size_t offset = rva_to_offset(pe, rva);
    if (offset == kNowhere) return nullptr;
    const char* text = reinterpret_cast<const char*>(pe.bytes.data() + offset);
    const std::size_t remaining = pe.bytes.size() - offset;
    if (std::memchr(text, '\0', remaining) == nullptr) return nullptr;
    return text;
}

// The payload's own export table, read from the file rather than from a loaded
// copy: the shell must never load the payload to find an address inside it.
std::uint32_t export_lookup(const PeImage& pe, const std::string& name) {
    if (pe.export_rva == 0 || pe.export_size < sizeof(IMAGE_EXPORT_DIRECTORY)) return 0;
    const std::size_t base = rva_to_offset(pe, pe.export_rva);
    if (base == kNowhere || base + sizeof(IMAGE_EXPORT_DIRECTORY) > pe.bytes.size()) return 0;

    const auto* directory =
        reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(pe.bytes.data() + base);
    const std::size_t names = rva_to_offset(pe, directory->AddressOfNames);
    const std::size_t ordinals = rva_to_offset(pe, directory->AddressOfNameOrdinals);
    const std::size_t functions = rva_to_offset(pe, directory->AddressOfFunctions);
    if (names == kNowhere || ordinals == kNowhere || functions == kNowhere) return 0;

    for (std::uint32_t i = 0; i < directory->NumberOfNames; ++i) {
        const std::size_t name_slot = names + static_cast<std::size_t>(i) * 4;
        const std::size_t ordinal_slot = ordinals + static_cast<std::size_t>(i) * 2;
        if (name_slot + 4 > pe.bytes.size() || ordinal_slot + 2 > pe.bytes.size()) break;

        std::uint32_t name_rva = 0;
        std::uint16_t ordinal = 0;
        std::memcpy(&name_rva, pe.bytes.data() + name_slot, 4);
        std::memcpy(&ordinal, pe.bytes.data() + ordinal_slot, 2);

        const char* text = string_at(pe, name_rva);
        if (text == nullptr || name != text) continue;

        const std::size_t address_slot = functions + static_cast<std::size_t>(ordinal) * 4;
        if (address_slot + 4 > pe.bytes.size()) return 0;
        std::uint32_t address_rva = 0;
        std::memcpy(&address_rva, pe.bytes.data() + address_slot, 4);
        return address_rva;
    }
    return 0;
}

unsigned long protect_of(const IMAGE_SECTION_HEADER& section) {
    const unsigned long flags = section.Characteristics;
    const bool readable = (flags & IMAGE_SCN_MEM_READ) != 0;
    const bool writable = (flags & IMAGE_SCN_MEM_WRITE) != 0;
    if ((flags & IMAGE_SCN_MEM_EXECUTE) != 0) {
        if (!readable) return PAGE_EXECUTE;
        return writable ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
    }
    return writable ? PAGE_READWRITE : PAGE_READONLY;
}

// ---------------------------------------------------------------- target io --

bool read_remote(HANDLE process, std::uintptr_t address, void* data, std::size_t size) {
    SIZE_T got = 0;
    return ReadProcessMemory(process, reinterpret_cast<const void*>(address), data, size, &got) ==
               TRUE &&
           got == size;
}

bool write_remote(HANDLE process, std::uintptr_t address, const void* data, std::size_t size) {
    SIZE_T written = 0;
    return WriteProcessMemory(process, reinterpret_cast<void*>(address), data, size, &written) ==
               TRUE &&
           written == size;
}

// Lays an image out at `base` the way a loader would: the headers first, then every
// section's raw bytes at its virtual address. What the file does not cover reads back
// as the zeroes the pages start as.
bool write_image(HANDLE process, const PeImage& pe, std::uintptr_t base) {
    const std::size_t headers = std::min<std::size_t>(pe.size_of_headers, pe.bytes.size());
    if (headers != 0 && !write_remote(process, base, pe.bytes.data(), headers)) return false;

    for (std::uint32_t i = 0; i < pe.section_count; ++i) {
        const IMAGE_SECTION_HEADER& section = pe.sections[i];
        if (section.SizeOfRawData == 0) continue;
        const std::size_t start = section.PointerToRawData;
        if (start >= pe.bytes.size()) continue;
        const std::size_t size =
            std::min<std::size_t>(section.SizeOfRawData, pe.bytes.size() - start);
        if (size == 0) continue;
        if (!write_remote(process, base + section.VirtualAddress, pe.bytes.data() + start, size)) {
            return false;
        }
    }
    return true;
}

std::uintptr_t remote_module_base(HANDLE process, const std::wstring& module_name) {
    HMODULE modules[1024];
    DWORD needed = 0;
    if (!EnumProcessModulesEx(process, modules, sizeof(modules), &needed, LIST_MODULES_ALL)) return 0;
    const DWORD count = needed / sizeof(HMODULE);
    for (DWORD i = 0; i < count && i < std::size(modules); ++i) {
        wchar_t path[MAX_PATH * 2] = {};
        if (GetModuleFileNameExW(process, modules[i], path, static_cast<DWORD>(std::size(path))) == 0) {
            continue;
        }
        if (_wcsicmp(file_name(path).c_str(), module_name.c_str()) == 0) {
            return reinterpret_cast<std::uintptr_t>(modules[i]);
        }
    }
    return 0;
}

// A marker path may name itself with the pid of the process it is expected to come
// from, which the caller cannot know before that process exists.
std::wstring resolve_pid_placeholder(const std::wstring& path, int pid) {
    std::wstring resolved = path;
    const std::wstring placeholder = L"%pid%";
    for (std::size_t at = resolved.find(placeholder); at != std::wstring::npos;
         at = resolved.find(placeholder)) {
        resolved.replace(at, placeholder.size(), std::to_wstring(pid));
    }
    return resolved;
}

// Asks the target to load a module by name. The mapper can only resolve imports
// against modules the target already has; a dependency that is missing is one the
// target's own loader has to provide, and it will do so for a signed system module
// in exactly the window where it refuses everything else.
bool request_module(HANDLE process, const std::string& name) {
    const HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    if (kernel32 == nullptr) return false;
    const auto load =
        reinterpret_cast<LPTHREAD_START_ROUTINE>(GetProcAddress(kernel32, "LoadLibraryA"));
    if (load == nullptr) return false;

    void* remote_name = VirtualAllocEx(process, nullptr, name.size() + 1, MEM_COMMIT | MEM_RESERVE,
                                       PAGE_READWRITE);
    if (remote_name == nullptr) return false;
    if (!write_remote(process, reinterpret_cast<std::uintptr_t>(remote_name), name.c_str(),
                      name.size() + 1)) {
        VirtualFreeEx(process, remote_name, 0, MEM_RELEASE);
        return false;
    }

    const HANDLE thread = CreateRemoteThread(process, nullptr, 0, load, remote_name, 0, nullptr);
    if (thread == nullptr) {
        VirtualFreeEx(process, remote_name, 0, MEM_RELEASE);
        return false;
    }
    WaitForSingleObject(thread, 5000);
    DWORD loaded = 0;
    GetExitCodeThread(thread, &loaded);
    CloseHandle(thread);
    VirtualFreeEx(process, remote_name, 0, MEM_RELEASE);
    return loaded != 0;
}

// Every module the payload imports by name, in the order the payload lists them.
std::vector<std::string> imported_modules(const PeImage& pe) {
    std::vector<std::string> names;
    if (pe.import_rva == 0) return names;
    const std::size_t offset = rva_to_offset(pe, pe.import_rva);
    if (offset == kNowhere) return names;

    for (std::size_t index = 0;; ++index) {
        const std::size_t descriptor_offset =
            offset + index * sizeof(IMAGE_IMPORT_DESCRIPTOR);
        if (descriptor_offset + sizeof(IMAGE_IMPORT_DESCRIPTOR) > pe.bytes.size()) break;
        IMAGE_IMPORT_DESCRIPTOR descriptor{};
        std::memcpy(&descriptor, pe.bytes.data() + descriptor_offset, sizeof(descriptor));
        if (descriptor.Name == 0 && descriptor.FirstThunk == 0) break;

        const char* name = string_at(pe, descriptor.Name);
        if (name == nullptr || name[0] == '\0') continue;
        names.push_back(name);
    }
    return names;
}

// The probe payloads announce themselves by signalling this event. It is the only
// way to tell "this code ran" from "this code never ran" when the payload may have
// no chance to leave anything else behind.
std::wstring probe_entry_event(int pid) {
    return L"Local\\vesper_probe_entry_" + std::to_wstring(pid);
}

// The same payload raises this one when it has finished with its image. The first
// event means "this code is running", and a launcher that frees the image on that
// alone is freeing it while a thread is still inside: the thread dies with it. This
// one means the image is no longer needed.
std::wstring probe_done_event(int pid) {
    return L"Local\\vesper_probe_done_" + std::to_wstring(pid);
}

// Waits, briefly, for a payload that promises a done event to raise it. Returns true
// if it was raised, false if the payload never got that far -- either way the caller
// decides what to do next, it just no longer has to guess.
bool wait_for_payload_done(int pid, int budget_ms) {
    HANDLE done = nullptr;
    for (int waited = 0; waited < budget_ms && done == nullptr; waited += 100) {
        done = OpenEventW(SYNCHRONIZE, FALSE, probe_done_event(pid).c_str());
        if (done == nullptr) Sleep(100);
    }
    if (done == nullptr) return false;
    const DWORD signalled = WaitForSingleObject(done, static_cast<DWORD>(budget_ms));
    CloseHandle(done);
    if (signalled == WAIT_OBJECT_0) {
        // The last instructions of the payload are its epilogue and its return to
        // ntdll; give them a moment to run before the memory goes away.
        Sleep(250);
        return true;
    }
    return false;
}

// A two-byte `jmp rcx`, inside a module the target already trusts. A thread whose
// start address lies in such a module looks ordinary to anything that judges thread
// start addresses, and the first thing it executes is a jump into the mapped image.
// `ntdll` and `kernel32` have been mapped since boot, so an address found here is
// the same address in the target.
std::uintptr_t find_jump_gadget(const wchar_t* module_name) {
    const HMODULE module = GetModuleHandleW(module_name);
    if (module == nullptr) return 0;
    const auto base = reinterpret_cast<std::uintptr_t>(module);

    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    const IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
        if ((section->Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) continue;
        const std::size_t size = std::max(section->Misc.VirtualSize, section->SizeOfRawData);
        const auto* bytes = reinterpret_cast<const unsigned char*>(base + section->VirtualAddress);
        for (std::size_t at = 0; at + 2 <= size; ++at) {
            if (bytes[at] == 0xFF && bytes[at + 1] == 0xE1) {  // jmp rcx
                return base + section->VirtualAddress + at;
            }
        }
    }
    return 0;
}

// Queue an APC to every thread of the target. The dispatcher in ntdll calls the
// routine on the thread the next time that thread is alertable: nothing in the
// process is created, no context is touched, and the call into the payload is an
// ordinary `call` from ntdll's own dispatch code. `data` arrives in `rcx`, which is
// where an entry expecting the image base wants it.
int queue_apc_to_threads(int pid, std::uintptr_t routine, std::uintptr_t data, int limit = 0) {
    const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    int queued = 0;
    THREADENTRY32 entry{};
    entry.dwSize = sizeof(entry);
    if (Thread32First(snapshot, &entry)) {
        do {
            if (entry.th32OwnerProcessID != static_cast<DWORD>(pid)) continue;
            const HANDLE thread =
                OpenThread(THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, entry.th32ThreadID);
            if (thread == nullptr) continue;
            if (QueueUserAPC(reinterpret_cast<PAPCFUNC>(routine), thread, data)) ++queued;
            CloseHandle(thread);
            // A command only needs one thread to become alertable; queueing to every thread
            // of a 200-thread client on every retry is thousands of APCs for one command.
            if (limit > 0 && queued >= limit) break;
        } while (Thread32Next(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return queued;
}

int count_threads(int pid) {
    const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;
    int count = 0;
    THREADENTRY32 entry{};
    entry.dwSize = sizeof(entry);
    if (Thread32First(snapshot, &entry)) {
        do {
            if (entry.th32OwnerProcessID == static_cast<DWORD>(pid)) ++count;
        } while (Thread32Next(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return count;
}

std::wstring temporary_directory() {    wchar_t buffer[MAX_PATH * 2] = {};
    const DWORD length = GetTempPathW(static_cast<DWORD>(std::size(buffer)), buffer);
    if (length == 0 || length >= std::size(buffer)) return L".";
    return std::wstring(buffer, length);
}

std::wstring copy_beside_temp(const std::wstring& source, int pid) {
    std::wstring target = temporary_directory();
    target += L"vesper_loaded_" + std::to_wstring(pid) + L"_" +
              std::to_wstring(static_cast<unsigned long long>(GetTickCount64())) + L".dll";
    if (!CopyFileW(source.c_str(), target.c_str(), FALSE)) return std::wstring();
    return target;
}

}  // namespace

void print_remote_modules(int pid) {
    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (process == nullptr) {
        std::printf("cannot open pid %d (error %lu)\n", pid, GetLastError());
        return;
    }

    HMODULE modules[1024] = {};
    DWORD needed = 0;
    if (!EnumProcessModulesEx(process, modules, sizeof(modules), &needed, LIST_MODULES_ALL)) {
        std::printf("module enumeration failed (error %lu)\n", GetLastError());
        CloseHandle(process);
        return;
    }

    const DWORD count = needed / sizeof(HMODULE);
    std::printf("process     : %d\n", pid);
    std::printf("modules     : %lu\n", count);
    for (DWORD i = 0; i < count && i < std::size(modules); ++i) {
        wchar_t name[MAX_PATH] = {};
        if (GetModuleFileNameExW(process, modules[i], name, static_cast<DWORD>(std::size(name))) ==
            0) {
            continue;
        }
        std::printf("  0x%016llX  %s\n",
                    static_cast<unsigned long long>(
                        reinterpret_cast<std::uintptr_t>(modules[i])),
                    narrow(name).c_str());
    }
    CloseHandle(process);
}

// Copies a byte range of a target's address space into a file exactly as it is
// mapped there. Pages that cannot be read are zero-filled, so a module dump
// keeps the module's original layout even across guard pages.
void dump_remote_image(int pid, std::uintptr_t base, std::size_t size, const std::wstring& path) {
    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (process == nullptr) {
        std::printf("cannot open pid %d (error %lu)\n", pid, GetLastError());
        return;
    }

    FILE* out = _wfopen(path.c_str(), L"wb");
    if (out == nullptr) {
        std::printf("cannot write %s\n", narrow(path).c_str());
        CloseHandle(process);
        return;
    }

    const std::size_t chunk = 1 << 20;
    std::vector<std::uint8_t> buffer;
    std::size_t read_ok = 0;
    std::size_t read_fail = 0;
    for (std::size_t offset = 0; offset < size; offset += chunk) {
        const std::size_t want = (std::min)(chunk, size - offset);
        buffer.assign(want, 0);

        SIZE_T got = 0;
        if (ReadProcessMemory(process, reinterpret_cast<const void*>(base + offset), buffer.data(),
                              want, &got)) {
            read_ok += got;
        } else {
            for (std::size_t page = 0; page < want; page += 0x1000) {
                const std::size_t page_want = (std::min)(std::size_t{0x1000}, want - page);
                SIZE_T page_got = 0;
                if (ReadProcessMemory(process, reinterpret_cast<const void*>(base + offset + page),
                                      buffer.data() + page, page_want, &page_got)) {
                    read_ok += page_got;
                } else {
                    read_fail += page_want;
                }
            }
        }

        if (std::fwrite(buffer.data(), 1, want, out) != want) {
            std::printf("short write at offset %llu\n",
                        static_cast<unsigned long long>(offset));
            break;
        }
    }

    std::fclose(out);
    std::printf("dumped      : %llu bytes readable, %llu bytes zero-filled\n",
                static_cast<unsigned long long>(read_ok),
                static_cast<unsigned long long>(read_fail));
    std::printf("file        : %s\n", narrow(path).c_str());
    CloseHandle(process);
}

void print_remote_regions(int pid) {
    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (process == nullptr) {
        std::printf("cannot open pid %d (error %lu)\n", pid, GetLastError());
        return;
    }

    const char* type_name[3] = {"private", "mapped ", "image  "};
    int counts[3] = {0, 0, 0};
    std::printf("process     : %d\n", pid);
    std::printf("executable regions (committed, executable):\n");

    std::uintptr_t address = 0;
    const std::uintptr_t limit = 0x00007FFFFFFF0000ull;
    int printed = 0;
    while (address < limit) {
        MEMORY_BASIC_INFORMATION info{};
        if (VirtualQueryEx(process, reinterpret_cast<void*>(address), &info, sizeof(info)) !=
            sizeof(info)) {
            break;
        }
        const auto base = reinterpret_cast<std::uintptr_t>(info.BaseAddress);
        const std::size_t region = static_cast<std::size_t>(info.RegionSize);
        const DWORD prot = info.Protect & 0xFF;
        const bool executable = info.State == MEM_COMMIT &&
                                (prot == PAGE_EXECUTE || prot == PAGE_EXECUTE_READ ||
                                 prot == PAGE_EXECUTE_READWRITE || prot == PAGE_EXECUTE_WRITECOPY);
        if (executable) {
            const int kind = info.Type == MEM_IMAGE ? 2 : (info.Type == MEM_MAPPED ? 1 : 0);
            ++counts[kind];
            wchar_t name[MAX_PATH * 2] = {};
            const DWORD length =
                GetMappedFileNameW(process, reinterpret_cast<void*>(base), name,
                                   static_cast<DWORD>(std::size(name)));
            std::printf("  %s  0x%012llX  %8llu KB  prot %s  %s\n", type_name[kind],
                        static_cast<unsigned long long>(base),
                        static_cast<unsigned long long>(region / 1024),
                        prot == PAGE_EXECUTE ? "X "
                                             : prot == PAGE_EXECUTE_READ
                                                   ? "RX"
                                                   : prot == PAGE_EXECUTE_READWRITE ? "RWX" : "RCX",
                        length != 0 ? narrow(std::wstring(name, length)).c_str() : "");
            ++printed;
        }
        if (region == 0) break;
        address = base + region;
    }

    std::printf("totals      : %d private, %d mapped, %d image\n", counts[0], counts[1], counts[2]);
    CloseHandle(process);
}

const char* map_status_name(std::uint32_t status) {
    switch (status) {
        case 0x00000000u:
            return "returned cleanly";
        case 0x00000102u:
            return "still running when the wait expired";
        case 0xC000071Cu:
            return "terminated by the client's runtime (code from outside an image)";
        case 0xC00006AAu:
            return "terminated by the client's runtime (refused at entry)";
        case 0xC0000135u:
            return "STATUS_DLL_NOT_FOUND: a dependency was not resolvable";
        case 0xC0000142u:
            return "STATUS_DLL_INIT_FAILED: DllMain returned failure";
        case 0xC0000005u:
            return "access violation";
        case 0xC0000409u:
            return "fail-fast exception";
        default:
            return "see the status code";
    }
}

// ---------------------------------------------------------------- the gate --

struct GateInfo {
    bool ok = false;
    bool registered = false;
    std::wstring file;
    std::uintptr_t base = 0;
    std::uintptr_t stub = 0;
    // A second routine in the same page: `mov rax, <target>; call rax; ret`. The engine
    // writes the target into the immediate and calls through it, so the call into the
    // client is made *from inside an image* -- the return address the client sees is this
    // page, not the mapped payload. MEASURED: calling the client's `luau_load` straight
    // from the payload ends the session with no dump, which is the shape of a check on
    // where the call comes from.
    std::uintptr_t call_stub = 0;
    std::string detail;
};

// Control Flow Guard checks an indirect call -- and the call an APC dispatcher makes
// is one -- against a bitmap of valid targets, and an image that never went through
// the loader has no bitmap: every address inside it reads as invalid, and a call to
// one is a fail-fast (0xC0000409). The bitmap can be filled in from outside, page by
// page, which is the mechanism the system offers to anything that generates code.
//
// The region handed in is rounded to the page and only that page is marked, with the
// offset of the one instruction the gate needs marked valid inside it.
struct CfgCallTarget {
    unsigned long long offset;
    unsigned long long flags;
};
using SetValidTargetsFn = int (*)(HANDLE, void*, unsigned long long, unsigned long,
                                  CfgCallTarget*);

bool register_call_target(HANDLE process, std::uintptr_t address) {
    static const SetValidTargetsFn set_valid_targets = []() -> SetValidTargetsFn {
        const HMODULE kernelbase = GetModuleHandleA("kernelbase.dll");
        if (kernelbase == nullptr) return nullptr;
        return reinterpret_cast<SetValidTargetsFn>(
            GetProcAddress(kernelbase, "SetProcessValidCallTargets"));
    }();
    if (set_valid_targets == nullptr) return false;

    constexpr unsigned long long kCfgCallTargetValid = 0x1;
    const std::uintptr_t page = address & ~static_cast<std::uintptr_t>(0xFFF);
    CfgCallTarget target{};
    target.offset = address - page;
    target.flags = kCfgCallTargetValid;
    return set_valid_targets(process, reinterpret_cast<void*>(page), 0x1000, 1, &target) != 0;
}

// The instructions the gate page carries: put the payload's base where its entry
// expects it, put the entry in a register, jump. A tail jump, not a call, so the
// entry's own return goes straight back to whoever delivered the gate -- ntdll, for
// an APC -- with the call stack exactly as balanced as the delivery made it.
std::vector<std::uint8_t> gate_stub(std::uintptr_t payload_base, std::uintptr_t payload_entry) {
    std::vector<std::uint8_t> bytes;
    const auto mov_reg_imm64 = [&](std::uint8_t low_byte_of_opcode, std::uint64_t value) {
        bytes.push_back(0x48);
        bytes.push_back(low_byte_of_opcode);
        for (int i = 0; i < 8; ++i) {
            bytes.push_back(static_cast<std::uint8_t>((value >> (i * 8)) & 0xFF));
        }
    };
    mov_reg_imm64(0xB9, payload_base);    // mov rcx, base
    mov_reg_imm64(0xB8, payload_entry);   // mov rax, entry
    bytes.push_back(0xFF);                // jmp rax
    bytes.push_back(0xE0);
    return bytes;
}

// `mov rax, <imm64 target>; call rax; ret`. The immediate starts at zero and the engine
// rewrites it before each call, which is why the page is left writable.
std::vector<std::uint8_t> call_stub_bytes() {
    std::vector<std::uint8_t> bytes;
    bytes.push_back(0x48);  // mov rax, imm64
    bytes.push_back(0xB8);
    for (int i = 0; i < 8; ++i) bytes.push_back(0);
    bytes.push_back(0xFF);  // call rax
    bytes.push_back(0xD0);
    bytes.push_back(0xC3);  // ret
    return bytes;
}

// Opens the gate: maps a signed image from a file this process has never loaded, and
// writes the stub above into a page of it that belongs to no section.
//
// Why a separate image at all: an address is allowed to be the start of an APC (or of
// a thread) only if it lies inside an image. A payload mapped by hand -- private
// pages, or a pagefile section -- is not inside an image, and delivery to it is
// dropped silently. A page *inside* an image is, and it makes no difference to that
// check that the file the image came from never reached the loader.
//
// Why this file: it is signed, it lives where system modules live, and the process
// has no other copy of it, so the view looks like a module and duplicates nothing.
// The page the stub goes into is the padding between two of its sections: inside the
// image's committed range, inside no section, so no section's bytes are altered and
// no file is ever written.
GateInfo open_gate(HANDLE process, const std::wstring& path, std::uintptr_t payload_base,
                   std::uintptr_t payload_entry) {
    GateInfo gate;
    gate.file = path;

    std::vector<std::uint8_t> bytes = read_file(path);
    if (bytes.empty()) {
        gate.detail = "cannot read " + narrow(path);
        return gate;
    }
    PeImage pe;
    std::string error;
    if (!parse_pe(std::move(bytes), pe, error)) {
        gate.detail = "not an image: " + error;
        return gate;
    }

    const NtApi& nt = nt_api();
    if (nt.create_section == nullptr || nt.map_view == nullptr) {
        gate.detail = "ntdll does not expose the section calls";
        return gate;
    }

    const HANDLE file = CreateFileW(path.c_str(), GENERIC_READ,
                                    FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                                    FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        gate.detail = "cannot open " + narrow(path);
        return gate;
    }
    HANDLE section = nullptr;
    long status = nt.create_section(&section, kSectionAllAccess, nullptr, nullptr, PAGE_READONLY,
                                    kSecImage, file);
    if (status < 0) {
        status = nt.create_section(&section, kSectionMapAll, nullptr, nullptr, PAGE_READONLY,
                                   kSecImage, file);
    }
    CloseHandle(file);
    if (status < 0 || section == nullptr) {
        gate.detail = "NtCreateSection(SEC_IMAGE) failed (" + hex32(status) + ")";
        return gate;
    }

    // Its own preferred base first, anywhere if that is taken. An image view lands
    // with the image's own per-section protections either way.
    void* at = reinterpret_cast<void*>(static_cast<std::uintptr_t>(pe.image_base));
    SIZE_T view_size = 0;
    status = nt.map_view(section, process, &at, 0, 0, nullptr, &view_size, kViewShare, 0,
                         PAGE_READONLY);
    if (status < 0) {
        at = nullptr;
        view_size = 0;
        status = nt.map_view(section, process, &at, 0, 0, nullptr, &view_size, kViewShare, 0,
                             PAGE_READONLY);
    }
    CloseHandle(section);
    if (status < 0 || at == nullptr) {
        gate.detail = "NtMapViewOfSection(image) failed (" + hex32(status) + ")";
        return gate;
    }
    gate.base = reinterpret_cast<std::uintptr_t>(at);

    // Where the stub goes: inside the image, inside no section, and in a page that is
    // already code. The widest of those places is used.
    //
    // Two kinds exist. The gap between two sections is the cleanest, but most images
    // have none. Every image has the second kind: the last page of a section carries
    // the section's declared content and then zeroes to the page boundary -- bytes no
    // section's size still describes, in a page the section still owns. The address
    // is an address inside the image, which is the property the entrance needs, and
    // nothing the image itself declares has been altered.
    const std::size_t stub_size = gate_stub(0, 0).size();
    std::uintptr_t page = 0;
    std::uint32_t widest = 0;
    for (std::uint32_t i = 0; i + 1 < pe.section_count; ++i) {
        const IMAGE_SECTION_HEADER& left = pe.sections[i];
        const IMAGE_SECTION_HEADER& right = pe.sections[i + 1];
        const std::uint32_t end = left.VirtualAddress +
                                  std::max(left.Misc.VirtualSize, left.SizeOfRawData);
        const std::uint32_t start = (end + 0xFFFu) & ~0xFFFu;
        if (right.VirtualAddress <= start) continue;
        const std::uint32_t room = right.VirtualAddress - start;
        if (room >= stub_size && (page == 0 || room > widest)) {
            page = gate.base + start;
            widest = room;
        }
    }
    if (page == 0) {
        for (std::uint32_t i = 0; i < pe.section_count; ++i) {
            const IMAGE_SECTION_HEADER& section = pe.sections[i];
            if ((section.Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) continue;
            const std::uint32_t end = section.VirtualAddress +
                                      std::max(section.Misc.VirtualSize, section.SizeOfRawData);
            const std::uint32_t boundary = (end + 0xFFFu) & ~0xFFFu;
            if (boundary <= end) continue;
            const std::uint32_t room = boundary - end;
            if (room >= stub_size && (page == 0 || room > widest)) {
                page = gate.base + end;
                widest = room;
            }
        }
    }
    if (page == 0) {
        const NtApi& nt2 = nt_api();
        if (nt2.unmap_view != nullptr) nt2.unmap_view(process, at);
        gate.base = 0;
        gate.detail = "no room for the stub inside the image";
        return gate;
    }

    DWORD previous = 0;
    if (!VirtualProtectEx(process, reinterpret_cast<void*>(page), stub_size,
                          PAGE_EXECUTE_READWRITE, &previous)) {
        const NtApi& nt2 = nt_api();
        if (nt2.unmap_view != nullptr) nt2.unmap_view(process, at);
        gate.base = 0;
        gate.detail = "cannot open the free page (error " + std::to_string(GetLastError()) + ")";
        return gate;
    }

    const std::vector<std::uint8_t> stub = gate_stub(payload_base, payload_entry);
    if (!write_remote(process, page, stub.data(), stub.size())) {
        const NtApi& nt2 = nt_api();
        if (nt2.unmap_view != nullptr) nt2.unmap_view(process, at);
        gate.base = 0;
        gate.detail = "cannot write the stub into the free page";
        return gate;
    }

    // The call gate, if the free page is wide enough to hold both routines.
    const std::vector<std::uint8_t> call_stub = call_stub_bytes();
    const std::uintptr_t call_stub_at = page + 0x40;
    bool call_stub_ok = false;
    if (widest >= 0x40 + call_stub.size()) {
        call_stub_ok = write_remote(process, call_stub_at, call_stub.data(), call_stub.size());
    }

    // Left writable on purpose: the engine rewrites the target immediate before every
    // call, and a page inside an image view cannot be re-protected from inside the
    // client (VirtualProtect on image memory fails with error 5 on this build).
    VirtualProtectEx(process, reinterpret_cast<void*>(page), stub_size, PAGE_EXECUTE_READWRITE,
                     &previous);

    std::vector<std::uint8_t> read_back(stub.size(), 0);
    if (!read_remote(process, page, read_back.data(), read_back.size()) || read_back != stub) {
        const NtApi& nt2 = nt_api();
        if (nt2.unmap_view != nullptr) nt2.unmap_view(process, at);
        gate.base = 0;
        gate.detail = "the stub does not read back the way it was written";
        return gate;
    }

    // The page the stub lives on is part of no image the loader knows, so its
    // addresses are not in any CFG bitmap yet: say where the valid targets are.
    gate.registered = register_call_target(process, page);
    if (call_stub_ok) {
        register_call_target(process, call_stub_at);
        gate.call_stub = call_stub_at;
    }

    gate.stub = page;
    gate.ok = true;
    gate.detail = "stub at " + hex64(page) + " inside the image at " + hex64(gate.base) +
                  (gate.registered ? ", registered as a call target"
                                   : ", left unregistered (no CFG to satisfy)");
    return gate;
}

void remember_call_gate(int pid, std::uintptr_t stub);

MapOutcome map_module(const MapOptions& options) {
    MapOutcome out;
    out.pid = options.pid;

    // One engine per client: the engine claims `Local\VesperCrt_<pid>` when it starts, and a
    // second mapping into the same process would re-run the client's CRT initialisation (which
    // the client refuses with a modal R6031 dialog that freezes the game). Refuse before
    // anything is written into the target.
    const std::wstring claim = L"Local\\VesperCrt_" + std::to_wstring(options.pid);
    if (HANDLE existing = OpenMutexW(SYNCHRONIZE, FALSE, claim.c_str())) {
        CloseHandle(existing);
        out.detail = "this client already has a Vesper engine: one injection per client. "
                     "Close the client and open it again to inject a new one.";
        return out;
    }

    // 1. Read and understand the payload. Parsing locally keeps the file format
    //    work in one place; only finished values are written into the target.
    std::vector<std::uint8_t> bytes = read_file(options.dll_path);
    if (bytes.empty()) {
        out.detail = "cannot read " + narrow(options.dll_path);
        return out;
    }
    PeImage pe;
    std::string error;
    if (!parse_pe(std::move(bytes), pe, error)) {
        out.detail = "payload is not a 64-bit image: " + error;
        return out;
    }
    out.preferred_base = static_cast<std::uintptr_t>(pe.image_base);
    out.image_size = pe.size_of_image;

    std::uint32_t entry_rva = pe.entry_rva;
    if (!options.entry_export.empty()) {
        entry_rva = export_lookup(pe, options.entry_export);
        if (entry_rva == 0) {
            out.detail = "payload has no export named `" + options.entry_export + "`";
            return out;
        }
    }
    if (entry_rva == 0) {
        out.detail = "payload has no entry point to call";
        return out;
    }

    // 2. Open the target with exactly the rights the mapping needs.
    const DWORD access = PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE |
                         PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION;
    const HANDLE process = OpenProcess(access, FALSE, options.pid);
    if (process == nullptr) {
        out.detail = "cannot open pid " + std::to_string(options.pid) + " (error " +
                     std::to_string(GetLastError()) + ")";
        return out;
    }

    // Dependencies first. Every module the payload imports has to exist in the
    // target before the image can be finished, and each one has to exist here too:
    // an import is resolved by looking the name up in both and checking that the
    // loader put it in the same place. A dependency missing here is not a failure --
    // the shell loads it -- and one missing there is worth a single attempt through
    // the target's own loader, which accepts a signed system module even in the
    // window where it refuses everything else.
    for (const std::string& name : imported_modules(pe)) {
        if (GetModuleHandleA(name.c_str()) == nullptr) LoadLibraryA(name.c_str());
        if (remote_module_base(process, widen(name)) != 0) continue;
        if (request_module(process, name)) out.preloaded.push_back(name);
    }

    // 3. Two ways to give the payload its memory, and the choice matters to what the
    //    target can see. A file-backed image section is what the OS itself would
    //    create, and it needs a copy of the file on disk: the pages answer a
    //    "which file are you from" query with that path. A private copy -- committed
    //    pages, backed by the pagefile -- answers nothing: there is no file behind
    //    it, and nothing in the target can name one.
    std::uintptr_t mapped_at = 0;
    out.image_path = options.dll_path;

    if (options.private_image || options.pagefile_section) {
        const SIZE_T size = pe.size_of_image;
        void* at = nullptr;
        if (options.pagefile_section) {
            // A section with no file behind it. The pages are still "mapped" rather
            // than "private", and they answer no file name, which is what a payload
            // wants when the process it lives in goes looking at what its pages are.
            const NtApi& nt = nt_api();
            if (nt.create_section == nullptr || nt.map_view == nullptr) {
                CloseHandle(process);
                out.detail = "ntdll does not expose the section calls";
                return out;
            }
            HANDLE section = nullptr;
            // A section with no file behind it has to be told its size; the fileless
            // form is the pagefile, and the kernel rejects the call without it. Its
            // own protection is the ceiling for every view of it, so it is created
            // executable-capable even though the view starts read-write.
            long long maximum = static_cast<long long>(size);
            long status = nt.create_section(&section, kSectionAllAccess, nullptr, &maximum,
                                            PAGE_EXECUTE_READWRITE, kSecCommit, nullptr);
            if (status < 0) {
                status = nt.create_section(&section, kSectionMapAll, nullptr, &maximum,
                                           PAGE_EXECUTE_READWRITE, kSecCommit, nullptr);
            }
            if (status < 0 || section == nullptr) {
                CloseHandle(process);
                out.detail = "NtCreateSection(SEC_COMMIT) failed (" + hex32(status) + ")";
                return out;
            }
            at = reinterpret_cast<void*>(out.preferred_base);
            SIZE_T view_size = 0;
            // Executable at map time, because that is the only time a data-section
            // view can be given execute: the kernel refuses to promote one afterwards
            // (measured in tools/pf_test.c). It is reduced to the image's own
            // per-section protections once the image has been written and finished.
            status = nt.map_view(section, process, &at, 0, 0, nullptr, &view_size, kViewShare, 0,
                                 PAGE_EXECUTE_READWRITE);
            if (status < 0) {
                at = nullptr;
                view_size = 0;
                status = nt.map_view(section, process, &at, 0, 0, nullptr, &view_size, kViewShare, 0,
                                     PAGE_EXECUTE_READWRITE);
            }
            CloseHandle(section);
            if (status < 0 || at == nullptr) {
                CloseHandle(process);
                out.detail = "NtMapViewOfSection(pagefile) failed (" + hex32(status) + ")";
                return out;
            }
        } else {
            at = VirtualAllocEx(process, reinterpret_cast<void*>(out.preferred_base), size,
                                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (at == nullptr) {
                at = VirtualAllocEx(process, nullptr, size, MEM_COMMIT | MEM_RESERVE,
                                    PAGE_READWRITE);
            }
            if (at == nullptr) {
                CloseHandle(process);
                out.detail = "cannot reserve " + std::to_string(size) +
                             " bytes in the target (error " + std::to_string(GetLastError()) + ")";
                return out;
            }
        }
        mapped_at = reinterpret_cast<std::uintptr_t>(at);
        if (!write_image(process, pe, mapped_at)) {
            CloseHandle(process);
            out.detail = "cannot write the image into the target";
            return out;
        }
    } else {
        // The section is created from a file, so work from a copy: the payload stays
        // free to be rebuilt while a mapped copy is live in another process.
        if (options.copy_first) {
            const std::wstring copy = copy_beside_temp(options.dll_path, options.pid);
            if (copy.empty()) {
                CloseHandle(process);
                out.detail = "cannot copy the payload into " + narrow(temporary_directory());
                return out;
            }
            out.image_path = copy;
        }

        const NtApi& nt = nt_api();
        if (nt.create_section == nullptr || nt.map_view == nullptr) {
            CloseHandle(process);
            out.detail = "ntdll does not expose the section calls";
            return out;
        }

        // 4. A file-backed image section. `SEC_IMAGE` is the point of the exercise:
        //    the pages belong to an image, which is what the client's runtime expects
        //    of code it is willing to run.
        HANDLE file = CreateFileW(out.image_path.c_str(), GENERIC_READ,
                                  FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                                  FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE) {
            CloseHandle(process);
            out.detail = "cannot open " + narrow(out.image_path);
            return out;
        }

        HANDLE section = nullptr;
        long status = nt.create_section(&section, kSectionAllAccess, nullptr, nullptr, PAGE_READONLY,
                                        kSecImage, file);
        if (status < 0) {
            status = nt.create_section(&section, kSectionMapAll, nullptr, nullptr, PAGE_READONLY,
                                       kSecImage, file);
        }
        CloseHandle(file);
        if (status < 0 || section == nullptr) {
            CloseHandle(process);
            out.detail = "NtCreateSection(SEC_IMAGE) failed (" + hex32(status) + ")";
            return out;
        }

        // 5. Map it, preferring the address the image was linked for. An image mapped
        //    elsewhere needs its own base relocations applied by hand, so ask for the
        //    preferred base first and only fall back when it is occupied.
        void* base = reinterpret_cast<void*>(out.preferred_base);
        SIZE_T view_size = 0;
        status = nt.map_view(section, process, &base, 0, 0, nullptr, &view_size, kViewShare, 0,
                             PAGE_READONLY);
        if (status < 0) {
            base = nullptr;
            view_size = 0;
            status = nt.map_view(section, process, &base, 0, 0, nullptr, &view_size, kViewShare, 0,
                                 PAGE_READONLY);
        }
        CloseHandle(section);
        if (status < 0 || base == nullptr) {
            CloseHandle(process);
            out.detail = "NtMapViewOfSection failed (" + hex32(status) + ")";
            return out;
        }
        mapped_at = reinterpret_cast<std::uintptr_t>(base);
    }

    out.base = mapped_at;
    out.entry = out.base + entry_rva;
    out.mapped = true;

    // From here on the target holds memory that is ours. Anything that fails from
    // this point gives it back first: memory left behind in a process is memory
    // something else can find later.
    const auto abandon = [&](const std::string& why) {
        if (options.private_image) {
            VirtualFreeEx(process, reinterpret_cast<void*>(out.base), 0, MEM_RELEASE);
        } else {
            const NtApi& nt = nt_api();
            if (nt.unmap_view != nullptr) {
                nt.unmap_view(process, reinterpret_cast<void*>(out.base));
            }
        }
        out.mapped = false;
        CloseHandle(process);
        out.detail = why + " (the mapping was given back)";
        return out;
    };

    // 6. Prove the view is really there before writing into it.
    char magic[2] = {};
    if (!read_remote(process, out.base, magic, sizeof(magic)) || magic[0] != 'M' ||
        magic[1] != 'Z') {
        return abandon("the mapped view does not read back as an image");
    }

    // 7. Open the whole image for writing once, then finish the image: relocations
    //    first (they can touch any address), imports second. Protections are put
    //    back from the section headers afterwards.
    //
    //    A pagefile-section view was mapped executable already: a data-section view
    //    can never be promoted to execute after the fact, the kernel answers with
    //    STATUS_INVALID_PARAMETER (measured in tools/pf_test.c). Only the other
    //    modes need the call here.
    DWORD previous = 0;
    if (!options.pagefile_section &&
        !VirtualProtectEx(process, reinterpret_cast<void*>(out.base), pe.size_of_image,
                          PAGE_EXECUTE_READWRITE, &previous)) {
        return abandon("cannot open the mapped image for finishing (error " +
                       std::to_string(GetLastError()) + ")");
    }

    const std::int64_t delta = static_cast<std::int64_t>(out.base) -
                               static_cast<std::int64_t>(pe.image_base);
    if (delta != 0) {
        if (pe.reloc_rva == 0 || pe.reloc_size == 0) {
            return abandon("image has no relocation table and cannot live at " + hex64(out.base));
        }
        const std::size_t start = rva_to_offset(pe, pe.reloc_rva);
        const std::size_t end = start == kNowhere
                                    ? kNowhere
                                    : std::min(pe.bytes.size(), start + pe.reloc_size);
        std::size_t cursor = start;
        int applied = 0;
        while (cursor != kNowhere && cursor + sizeof(IMAGE_BASE_RELOCATION) <= end) {
            IMAGE_BASE_RELOCATION block{};
            std::memcpy(&block, pe.bytes.data() + cursor, sizeof(block));
            if (block.SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION)) break;

            const std::size_t count =
                (block.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(std::uint16_t);
            for (std::size_t i = 0; i < count; ++i) {
                const std::size_t entry_offset = cursor + sizeof(IMAGE_BASE_RELOCATION) + i * 2;
                if (entry_offset + 2 > pe.bytes.size()) break;
                std::uint16_t entry = 0;
                std::memcpy(&entry, pe.bytes.data() + entry_offset, 2);
                if ((entry >> 12) != IMAGE_REL_BASED_DIR64) continue;

                const std::uintptr_t address = out.base + block.VirtualAddress + (entry & 0x0FFF);
                std::uint64_t value = 0;
                if (!read_remote(process, address, &value, sizeof(value))) continue;
                value += static_cast<std::uint64_t>(delta);
                if (write_remote(process, address, &value, sizeof(value))) ++applied;
            }
            cursor += block.SizeOfBlock;
        }
        out.relocations_applied = applied;
    }

    // 8. Imports. Every dependency has to be a module the target already has:
    //    there is no loader here to bring in a missing one, and a module is looked
    //    up by name and by address, so a mismatch is reported rather than guessed.
    std::vector<std::string> missing;
    if (pe.import_rva != 0) {
        const std::size_t import_offset = rva_to_offset(pe, pe.import_rva);
        if (import_offset == kNowhere) {
            return abandon("import directory is not in the payload");
        }
        for (std::size_t index = 0;; ++index) {
            const std::size_t descriptor_offset = import_offset + index * sizeof(IMAGE_IMPORT_DESCRIPTOR);
            if (descriptor_offset + sizeof(IMAGE_IMPORT_DESCRIPTOR) > pe.bytes.size()) break;
            IMAGE_IMPORT_DESCRIPTOR descriptor{};
            std::memcpy(&descriptor, pe.bytes.data() + descriptor_offset, sizeof(descriptor));
            if (descriptor.Name == 0 && descriptor.FirstThunk == 0) break;

            const char* module_name = string_at(pe, descriptor.Name);
            if (module_name == nullptr || module_name[0] == '\0') continue;

            const std::uintptr_t remote_base = remote_module_base(process, widen(module_name));
            if (remote_base == 0) {
                missing.push_back(module_name);
                continue;
            }
            const HMODULE local = GetModuleHandleA(module_name);
            if (local == nullptr) {
                missing.push_back(std::string(module_name) + " (absent here too)");
                continue;
            }
            if (reinterpret_cast<std::uintptr_t>(local) != remote_base) {
                missing.push_back(std::string(module_name) + " (loaded at a different address)");
                continue;
            }

            const std::uint32_t thunk_rva =
                descriptor.OriginalFirstThunk != 0 ? descriptor.OriginalFirstThunk
                                                   : descriptor.FirstThunk;
            const std::size_t thunk_offset = rva_to_offset(pe, thunk_rva);
            if (thunk_offset == kNowhere) continue;

            for (std::size_t slot = 0;; ++slot) {
                const std::size_t entry_offset = thunk_offset + slot * sizeof(std::uint64_t);
                if (entry_offset + sizeof(std::uint64_t) > pe.bytes.size()) break;
                std::uint64_t entry = 0;
                std::memcpy(&entry, pe.bytes.data() + entry_offset, sizeof(entry));
                if (entry == 0) break;

                ++out.imports_total;
                std::uintptr_t address = 0;
                if ((entry & IMAGE_ORDINAL_FLAG64) != 0) {
                    const auto ordinal = static_cast<WORD>(entry & 0xFFFF);
                    address = reinterpret_cast<std::uintptr_t>(
                        GetProcAddress(local, reinterpret_cast<const char*>(ordinal)));
                } else {
                    const std::size_t hint_offset = rva_to_offset(pe, static_cast<std::uint32_t>(entry));
                    if (hint_offset == kNowhere || hint_offset + 2 >= pe.bytes.size()) {
                        missing.push_back(std::string(module_name) + " (unreadable import name)");
                        continue;
                    }
                    // The name follows a two-byte hint and is already checked to be
                    // terminated inside the file.
                    const char* symbol =
                        reinterpret_cast<const char*>(pe.bytes.data() + hint_offset + 2);
                    address = reinterpret_cast<std::uintptr_t>(GetProcAddress(local, symbol));
                    if (address == 0) {
                        missing.push_back(std::string(module_name) + "!" + symbol);
                    }
                }
                if (address == 0) continue;

                const std::uintptr_t target = out.base + descriptor.FirstThunk +
                                              slot * sizeof(std::uint64_t);
                if (write_remote(process, target, &address, sizeof(address))) ++out.imports_resolved;
            }
        }
    }

    if (!missing.empty()) {
        std::string list;
        for (const std::string& name : missing) {
            if (!list.empty()) list += ", ";
            list += name;
            if (list.size() > 240) {
                list += ", ...";
                break;
            }
        }
        return abandon("unresolved imports in the target: " + list);
    }

    // 9. Put the protections back the way the image asks for them, and the headers
    //    back to read-only.
    for (std::uint32_t i = 0; i < pe.section_count; ++i) {
        const IMAGE_SECTION_HEADER& section = pe.sections[i];
        const std::uint32_t size = std::max(section.Misc.VirtualSize, section.SizeOfRawData);
        if (size == 0) continue;
        VirtualProtectEx(process, reinterpret_cast<void*>(out.base + section.VirtualAddress), size,
                         protect_of(section), &previous);
    }
    VirtualProtectEx(process, reinterpret_cast<void*>(out.base), pe.size_of_headers, PAGE_READONLY,
                     &previous);

    const std::wstring report_file = resolve_pid_placeholder(options.wait_file, options.pid);

    // 10. Enter the image through its own code. The thread's start address is a
    //     page of this image, and the first thing it runs is the payload's own
    //     loader-less entry, which hands control to the C runtime and `DllMain`.
    //
    //     A caller that wants the payload entered from a thread the target already
    //     has passes `enter = false` and does the entry itself; everything up to
    //     this point is the same either way.
    if (!options.enter) {
        CloseHandle(process);
        out.detail = "mapped at " + hex64(out.base) + ", " +
                     std::to_string(out.imports_resolved) +
                     " imports resolved, entry left to the caller";
        return out;
    }

    // A probe payload announces itself through a named event, so the launcher can
    // tell whether its first instruction ran at all.
    const HANDLE entry_event =
        options.probe_event
            ? CreateEventW(nullptr, TRUE, FALSE, probe_entry_event(options.pid).c_str())
            : nullptr;

    // Where the entry thread starts. Starting it inside the mapped image is the
    // direct route; starting it at a genuine function entry in a module the target
    // trusts, and letting that function set the thread's context, is the indirect
    // one.
    //
    // `NtContinue` is the function of choice: it is a real entry point in ntdll, so
    // anything that validates call targets -- including Control Flow Guard, which
    // rejects a *mid-function* address in a protected module with a fail-fast --
    // accepts it, and the first thing it does is give the thread the context stored
    // in the structure passed to it.
    std::uintptr_t start_address = out.entry;
    void* parameter = reinterpret_cast<void*>(out.base);
    // Kept out here so the gate below can move the context's entry point without the
    // whole trampoline setup being duplicated.
    std::uintptr_t parked_context = 0;
    CONTEXT trampoline_context{};
    if (options.trampoline) {
        const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        const auto nt_continue =
            ntdll != nullptr ? GetProcAddress(ntdll, "NtContinue") : nullptr;
        if (nt_continue == nullptr) {
            CloseHandle(process);
            out.detail = "ntdll does not expose NtContinue";
            return out;
        }

        // The stack the payload's entry runs on, with its return address in place.
        void* stack = VirtualAllocEx(process, nullptr, 0x10000, MEM_COMMIT | MEM_RESERVE,
                                     PAGE_READWRITE);
        if (stack == nullptr) {
            CloseHandle(process);
            out.detail = "could not allocate a stack in the target";
            return out;
        }
        std::uintptr_t top = reinterpret_cast<std::uintptr_t>(stack) + 0x10000 - 0x100;
        top &= ~static_cast<std::uintptr_t>(0xF);
        top |= 8;

        const HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
        const std::uintptr_t return_to =
            kernel32 != nullptr
                ? reinterpret_cast<std::uintptr_t>(GetProcAddress(kernel32, "ExitThread"))
                : 0;
        if (return_to != 0 && !write_remote(process, top, &return_to, sizeof(return_to))) {
            CloseHandle(process);
            out.detail = "could not write the return address";
            return out;
        }

        // A user-mode context for the new thread. Segment selectors and flags are the
        // values an ordinary 64-bit thread runs with.
        CONTEXT context{};
        context.ContextFlags = CONTEXT_FULL;
        context.Rip = out.entry;
        context.Rsp = top;
        context.Rcx = out.base;
        context.EFlags = 0x202;
        context.SegCs = 0x33;
        context.SegSs = 0x2B;
        context.SegDs = 0x2B;
        context.SegEs = 0x2B;
        context.SegFs = 0x53;
        context.SegGs = 0x2B;
        context.MxCsr = 0x1F80;

        void* parked = VirtualAllocEx(process, nullptr, sizeof(CONTEXT), MEM_COMMIT | MEM_RESERVE,
                                      PAGE_READWRITE);
        if (parked == nullptr ||
            !write_remote(process, reinterpret_cast<std::uintptr_t>(parked), &context,
                          sizeof(context))) {
            CloseHandle(process);
            out.detail = "could not park the context for the entry thread";
            return out;
        }

        start_address = reinterpret_cast<std::uintptr_t>(nt_continue);
        parameter = parked;
        parked_context = reinterpret_cast<std::uintptr_t>(parked);
        trampoline_context = context;
        out.trampoline_address = start_address;
    }

    // 10b. The gate, when one was asked for: a few instructions inside a signed image
    //      that call the payload's entry. The address the entrance uses is then an
    //      address inside an image, which is the only kind a delivery is allowed to
    //      land on.
    if (!options.gate_path.empty()) {
        const GateInfo gate = open_gate(process, options.gate_path, out.base, out.entry);
        out.gate_open = gate.ok;
        out.gate_registered = gate.registered;
        out.gate_file = gate.file;
        out.gate_base = gate.base;
        out.gate_stub = gate.stub;
        out.gate_call_stub = gate.call_stub;
        if (!gate.ok) {
            return abandon("the gate could not be opened: " + gate.detail);
        }
        out.gate_detail = gate.detail;
        // Later commands reuse this stub; it stays valid as long as the view does.
        if (options.apc) remember_gate(options.pid, out.gate_stub);
        remember_call_gate(options.pid, out.gate_call_stub);
    }

    // MEASURED (9ac8), twice: a thread created from outside the client and started at our
    // entry dies with 0xC000071C, and starting it instead at the gate stub -- an address
    // inside the mapped view of fltlib, i.e. inside an image -- dies with exactly the same
    // code. So the check is not on the start address: creating the thread is what is
    // refused. Only the APC route survives, because it creates nothing and reuses a thread
    // the client started itself.
    //
    // The redirection is kept because it is the right shape if a start-address check ever
    // appears, but it does not by itself make a remote thread acceptable on this build.
    if (options.trampoline && out.gate_open && parked_context != 0) {
        CONTEXT redirected = trampoline_context;
        redirected.Rip = out.gate_stub;
        redirected.Rcx = 0;  // the stub supplies the image base
        if (!write_remote(process, parked_context, &redirected, sizeof(redirected))) {
            return abandon("could not point the trampoline at the gate stub");
        }
        out.trampoline_address = out.gate_stub;
        out.detail += "; trampoline starts at the gate stub";
    }

    if (options.apc) {
        // The APC route: nothing new appears in the process. The address the APC
        // carries is the entrance -- the gate's stub when there is one, which is an
        // address inside an image, and the payload's own entry otherwise -- and it is
        // handed to threads the target started for itself. ntdll's dispatcher makes
        // the call the next time one of them is alertable.
        const std::uintptr_t entrance = out.gate_open ? out.gate_stub : out.entry;
        const std::uintptr_t argument = out.gate_open ? 0 : out.base;
        out.apc_queued = queue_apc_to_threads(options.pid, entrance, argument);
        out.entry_called = out.apc_queued > 0;
        if (entry_event != nullptr) {
            out.entry_event_seen = WaitForSingleObject(entry_event, 3000) == WAIT_OBJECT_0;
        }
        if (entry_event != nullptr) CloseHandle(entry_event);
        // There is no thread handle to join; whether the entry ran is what the event
        // answers, and what it left behind is what the report file answers.
        out.entry_finished = out.entry_event_seen;
    } else {
        const HANDLE thread = CreateRemoteThread(
            process, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(start_address),
            parameter, 0, nullptr);
        if (thread == nullptr) {
            CloseHandle(process);
            out.detail = "CreateRemoteThread failed (error " + std::to_string(GetLastError()) + ")";
            return out;
        }
        out.entry_called = true;

        if (entry_event != nullptr) {
            out.entry_event_seen = WaitForSingleObject(entry_event, 3000) == WAIT_OBJECT_0;
        }

        if (WaitForSingleObject(thread, static_cast<DWORD>(options.wait_ms)) == WAIT_OBJECT_0) {
            DWORD exit_code = 0;
            if (GetExitCodeThread(thread, &exit_code)) out.thread_exit = exit_code;
            out.entry_finished = true;
        }
        CloseHandle(thread);
        if (entry_event != nullptr) CloseHandle(entry_event);
    }
    // 11. A payload that keeps working after its entry returns is observed through
    //     a file it is expected to leave behind.
    if (!report_file.empty()) {
        const int deadline = options.wait_ms;
        int since_delivery = 0;
        for (int waited = 0; waited < deadline; waited += 100) {
            if (file_exists(report_file)) {
                out.wait_file_seen = true;
                break;
            }
            if (!pid_alive(options.pid)) break;
            // A startup thread the client terminates half-way leaves no record, so the
            // entry is delivered again: the engine sees its own claim is stale and runs
            // the startup once more. Without this a single killed thread loses the client.
            if (options.apc && out.gate_open && ++since_delivery >= 30) {
                since_delivery = 0;
                queue_apc_to_threads(options.pid, out.gate_stub, 0, 16);
            }
            Sleep(100);
        }
    }

    if (options.apc) {
        // Nothing was created to wait on. The entry either announced itself, or the
        // payload it started left the file it was expected to leave.
        out.ok = !report_file.empty() ? out.wait_file_seen : out.entry_event_seen;
        if (out.ok) {
            out.detail = "mapped at " + hex64(out.base) + ", " +
                         std::to_string(out.imports_resolved) +
                         " imports resolved, entry ran on one of the target's threads";
        } else {
            out.detail = "entry queued to " + std::to_string(out.apc_queued) +
                         " thread(s) as an APC, not observed running";
        }
    } else if (out.ok) {
        out.detail = "mapped at " + hex64(out.base) + ", " +
                     std::to_string(out.imports_resolved) + " imports resolved, entry returned 0";
    } else if (!out.entry_finished) {
        out.detail = "entry did not return within " + std::to_string(options.wait_ms) + " ms";
    } else {
        out.detail = std::string(map_status_name(out.thread_exit)) + " (" +
                     hex32(static_cast<long>(out.thread_exit)) + ")";
    }

    // 12. A probe hands its memory back when the observation is over: memory left
    //     behind in a process is memory something else can find later. The image is
    //     not freed on the first event alone -- that event fires at the start of the
    //     payload's own code, and the payload is still running when it does. It is
    //     freed after the payload's done event, or, for payloads that never raise
    //     one, at the end of a short grace period.
    if (options.cleanup && out.mapped) {
        if (options.probe_event) {
            const bool finished = wait_for_payload_done(options.pid, 5000);
            out.payload_finished = finished;
        }
        if (options.pagefile_section || !options.private_image) {
            const NtApi& nt = nt_api();
            if (nt.unmap_view != nullptr) {
                nt.unmap_view(process, reinterpret_cast<void*>(out.base));
                out.unmapped = true;
            }
        } else {
            out.unmapped = VirtualFreeEx(process, reinterpret_cast<void*>(out.base), 0,
                                         MEM_RELEASE) != FALSE;
        }
        // The copy exists only to back the section; with the view gone it is nothing
        // but a file with our name on it.
        if (out.unmapped && options.copy_first && !options.private_image &&
            !options.pagefile_section && !out.image_path.empty()) {
            DeleteFileW(out.image_path.c_str());
        }
        if (out.gate_open && out.gate_base != 0) {
            const NtApi& nt = nt_api();
            if (nt.unmap_view != nullptr) {
                nt.unmap_view(process, reinterpret_cast<void*>(out.gate_base));
                out.gate_open = false;
            }
        }
    }

    CloseHandle(process);
    return out;
}

LaunchMapOutcome launch_and_map(const LaunchMapOptions& options) {
    LaunchMapOutcome out;

    if (!file_exists(options.dll_path)) {
        out.detail = "payload not found: " + narrow(options.dll_path);
        return out;
    }

    std::wstring exe = preferred_client_path(options.build);
    // An explicitly named build must not silently fall back to the newest install.
    if (!options.build.empty() && exe.find(options.build) == std::wstring::npos) exe.clear();
    if (exe.empty()) {
        out.detail = options.build.empty()
                         ? std::string("no RobloxPlayerBeta.exe under %LOCALAPPDATA%\\Roblox\\Versions")
                         : "no installed client matches " + narrow(options.build);
        return out;
    }
    out.exe = exe;

    std::wstring command = L"\"" + exe + L"\"";
    if (!options.argument.empty()) command += L" " + options.argument;
    out.command_line = command;

    std::vector<wchar_t> mutable_command(command.begin(), command.end());
    mutable_command.push_back(L'\0');

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION info{};

    // The process exists, its loader has finished, and not one instruction of the
    // game's own code has run yet.
    if (!CreateProcessW(exe.c_str(), mutable_command.data(), nullptr, nullptr, FALSE,
                        CREATE_SUSPENDED, nullptr, directory_of(exe).c_str(), &startup, &info)) {
        out.detail = "CreateProcess failed (" + std::to_string(GetLastError()) + ")";
        return out;
    }
    out.pid = static_cast<int>(info.dwProcessId);

    const std::wstring report_file = resolve_pid_placeholder(options.wait_file, out.pid);

    const HANDLE entry_event =
        options.probe_event
            ? CreateEventW(nullptr, TRUE, FALSE, probe_entry_event(out.pid).c_str())
            : nullptr;

    MapOptions map;
    map.pid = out.pid;
    map.dll_path = options.dll_path;
    map.entry_export = options.entry_export;
    map.wait_ms = options.map_wait_ms;
    map.wait_file = report_file;
    map.enter = !options.hijack;
    map.probe_event = options.probe_event;
    map.trampoline = options.trampoline;
    map.apc = options.apc;
    map.private_image = options.private_image;
    map.pagefile_section = options.pagefile_section;
    map.cleanup = options.cleanup;
    out.map = map_module(map);

    if (!out.map.mapped) {
        TerminateProcess(info.hProcess, 0);
        CloseHandle(info.hThread);
        CloseHandle(info.hProcess);
        out.detail = "mapping failed before the client was resumed: " + out.map.detail;
        return out;
    }

    const auto abandon = [&](const std::string& why) {
        TerminateProcess(info.hProcess, 0);
        CloseHandle(info.hThread);
        CloseHandle(info.hProcess);
        out.detail = why;
        return out;
    };

    // Entering the payload from the client's own main thread. That thread is
    // already suspended at its entry point, so its context can be pointed at the
    // mapped image: the first instruction of the payload is then run by a thread
    // the client created itself, and no new thread appears anywhere.
    if (options.hijack) {
        std::uintptr_t return_to = options.hijack_return;
        if (return_to == 0) {
            const HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
            if (kernel32 != nullptr) {
                return_to = reinterpret_cast<std::uintptr_t>(GetProcAddress(kernel32, "ExitThread"));
            }
        }
        if (return_to == 0) return abandon("no address to return the hijacked thread to");

        // A stack for the entry to run on, with its return address already in
        // place. x64 enters a function by jump with `rsp % 16 == 8`.
        void* scratch = VirtualAllocEx(info.hProcess, nullptr, 0x10000,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (scratch == nullptr) return abandon("could not allocate a stack in the client");

        std::uintptr_t top = reinterpret_cast<std::uintptr_t>(scratch) + 0x10000 - 0x100;
        top &= ~static_cast<std::uintptr_t>(0xF);
        top |= 8;
        if (!write_remote(info.hProcess, top, &return_to, sizeof(return_to))) {
            return abandon("could not write the return address");
        }

        CONTEXT context{};
        context.ContextFlags = CONTEXT_FULL;
        if (!GetThreadContext(info.hThread, &context)) {
            return abandon("GetThreadContext failed (" + std::to_string(GetLastError()) + ")");
        }

        // The thread's own state is parked inside the client so the payload can
        // hand the thread back with `NtContinue` when it is done with it.
        void* parking = VirtualAllocEx(info.hProcess, nullptr, 0x1000,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (parking == nullptr) return abandon("could not park the thread's context");
        if (!write_remote(info.hProcess, reinterpret_cast<std::uintptr_t>(parking), &context,
                          sizeof(context))) {
            return abandon("could not write the parked context");
        }

        context.Rip = out.map.entry;
        context.Rcx = out.map.base;
        context.Rdx = reinterpret_cast<std::uintptr_t>(parking);
        context.Rsp = top;
        if (!SetThreadContext(info.hThread, &context)) {
            return abandon("SetThreadContext failed (" + std::to_string(GetLastError()) + ")");
        }
        out.hijacked = true;
    }

    // Only now does the client get to run. A payload entered before this point is
    // already part of the process when the first of the game's instructions runs.
    out.resumed = ResumeThread(info.hThread) != static_cast<DWORD>(-1);
    CloseHandle(info.hThread);

    if (entry_event != nullptr) {
        out.entry_event_seen = WaitForSingleObject(entry_event, 5000) == WAIT_OBJECT_0;
        CloseHandle(entry_event);
    }

    const std::int64_t deadline = now_ms() + std::max(5000, options.wait_ms);
    while (now_ms() < deadline) {
        if (!report_file.empty() && file_exists(report_file)) {
            out.ok = true;
            out.detail = "payload entered before the client ran, and it reported";
            break;
        }
        if (!pid_alive(out.pid)) {
            out.detail = "the client exited during startup";
            break;
        }
        Sleep(200);
    }

    const DWORD after = WaitForSingleObject(info.hProcess, 0);
    out.process_alive = after == WAIT_TIMEOUT;
    if (out.process_alive) out.threads_after = count_threads(out.pid);
    CloseHandle(info.hProcess);

    if (!out.ok && out.detail.empty()) {
        out.detail = report_file.empty()
                         ? "the client is running; no report was requested"
                         : "the payload entry ran but never reported";
    }
    return out;
}

void remember_gate(int pid, std::uintptr_t stub) {
    const std::wstring directory = clients_directory();
    ensure_directory(directory);
    char text[40] = {};
    std::snprintf(text, sizeof(text), "0x%llX", static_cast<unsigned long long>(stub));
    write_file(directory + L"\\" + std::to_wstring(pid) + L".gate", text, std::strlen(text));
}

// The call gate address, in its own file: the engine reads it at startup and calls the
// client's functions through it so the return address lies inside an image.
void remember_call_gate(int pid, std::uintptr_t stub) {
    if (stub == 0) return;
    const std::wstring directory = clients_directory();
    ensure_directory(directory);
    char text[40] = {};
    std::snprintf(text, sizeof(text), "0x%llX", static_cast<unsigned long long>(stub));
    write_file(directory + L"\\" + std::to_wstring(pid) + L".tramp", text, std::strlen(text));
}

int deliver_command_apc(int pid) {
    const auto data = read_file(clients_directory() + L"\\" + std::to_wstring(pid) + L".gate");
    if (data.empty()) return -1;
    const std::string text(data.begin(), data.end());
    const std::uintptr_t stub = static_cast<std::uintptr_t>(std::strtoull(text.c_str(), nullptr, 16));
    if (stub == 0) return -1;
    return queue_apc_to_threads(pid, stub, 0, 16);
}

}  // namespace vesper::shell
