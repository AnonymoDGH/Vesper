// Vesper -- loader-free module mapping.
//
// The client's loader refuses foreign modules, and its runtime kills threads whose
// code comes from a private page, so neither `LoadLibrary` nor a code cave is
// available. What is left is to do the loader's job from the outside: create a
// file-backed *image* section, map it into the target, finish the image by hand
// (base relocations, import table) and enter it through one of its own exported
// functions. The result is real image-backed memory that no loader call ever
// touched and that appears in no module list.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace vesper::shell {

struct MapOptions {
    int pid = 0;
    std::wstring dll_path;

    // Export called with the mapped base as its only argument. Empty means the
    // image's own entry point is used instead, which only works for payloads that
    // need no runtime initialisation.
    std::string entry_export = "VesperAttach";

    // How long to wait for the entry thread, and then for `wait_file`.
    int wait_ms = 8000;

    // Optional file the payload is expected to produce; polling for it is the only
    // way to observe an engine that keeps running after its entry returns.
    std::wstring wait_file;

    // The section is created from a file, so the payload is copied first. This
    // keeps a long-lived file handle out of the build directory and leaves the
    // trace a mapper is expected to leave: one `vesper_loaded_*` file in %TEMP%.
    bool copy_first = true;

    // When false, the image is mapped and finished but nothing is entered: the
    // caller takes over the entry, which is what entering it from a thread that
    // already exists requires.
    bool enter = true;

    // Diagnostics for probe payloads: it signals `Local\vesper_probe_entry_<pid>`
    // as its first instruction, which tells "ran" from "never ran" independently of
    // anything else the payload does.
    bool probe_event = false;

    // Start the entry thread at a two-byte `jmp rcx` inside a module the target
    // trusts, with `rcx` pointing at the payload's entry. The thread's start address
    // is then ordinary, and the first thing it runs is a jump into the mapped image.
    bool trampoline = false;

    // Deliver the entry as an APC to the target's own threads: ntdll's dispatcher
    // calls the routine on a thread that already exists, with a normal call, and
    // nothing new ever appears in the process.
    bool apc = false;

    // Give the payload private committed pages -- backed by the pagefile -- instead
    // of a file-backed image section. Nothing on disk stands behind the result, so a
    // query for the file a page came from has no answer to give.
    bool private_image = false;

    // The same idea through a pagefile-backed *section*: no file behind the pages
    // either, but their type is "mapped" rather than "private", which is the shape of
    // an ordinary data mapping rather than of a fresh allocation.
    bool pagefile_section = false;

    // Hand the memory back when the observation is over, so a probe leaves nothing
    // in the target for anything else to find.
    bool cleanup = false;

    // The entrance. When set, the address handed to the APC or the new thread is not
    // the payload's entry but a few instructions inside a signed image mapped from
    // this file -- an image this process has no other copy of -- which then call the
    // payload's entry. An address outside an image is refused as an entrance; one
    // inside an image is not, and the call that follows is indistinguishable from the
    // target's own loader calling into mapped code.
    std::wstring gate_path;
};

struct MapOutcome {
    bool ok = false;
    bool mapped = false;
    bool entry_called = false;
    bool entry_finished = false;
    bool wait_file_seen = false;
    bool entry_event_seen = false;
    int pid = 0;
    std::uintptr_t base = 0;
    std::uintptr_t preferred_base = 0;
    std::uintptr_t entry = 0;
    std::size_t image_size = 0;
    std::uint32_t thread_exit = 0;
    int imports_resolved = 0;
    int imports_total = 0;
    int relocations_applied = 0;
    std::uintptr_t trampoline_address = 0;
    int apc_queued = 0;
    bool unmapped = false;
    bool payload_finished = false;
    bool gate_open = false;
    bool gate_registered = false;
    std::uintptr_t gate_base = 0;
    std::uintptr_t gate_stub = 0;
    std::uintptr_t gate_call_stub = 0;
    std::wstring gate_file;
    std::string gate_detail;
    std::vector<std::string> preloaded;
    std::wstring image_path;
    std::string detail;
};

// Maps `options.dll_path` into `options.pid` without calling any loader routine,
// then enters `options.entry_export` from inside the mapped image.
// Prints the module list of a target, one per line with its base: which of a
// payload's dependencies actually exist in there, and what the loader had at the
// moment it was asked.
void print_remote_modules(int pid);

// Prints every committed, executable region of a target with its type, protection
// and, when a file stands behind it, the file's name. This is the picture a
// scanner inside that process gets to see, so it is the picture worth choosing a
// place for a payload against.
void print_remote_regions(int pid);

// Copies a byte range out of a target into a file (unreadable pages are
// zero-filled). Used to lift decrypted images and live tables for offline
// analysis -- the on-disk files are encrypted, the mapped ones are not.
void dump_remote_image(int pid, std::uintptr_t base, std::size_t size, const std::wstring& path);

MapOutcome map_module(const MapOptions& options);

// APC command channel. Nothing of the engine stays resident in the client except the
// mapped image: each command is delivered as an APC through the gate stub that `--map`
// opened, the engine runs it and answers through a file. `remember_gate` records the
// stub for a pid; `deliver_command_apc` queues one APC through it to every thread of
// that pid and returns how many accepted it (negative: no stub is known for the pid).
void remember_gate(int pid, std::uintptr_t stub);
int deliver_command_apc(int pid);

struct LaunchMapOptions {
    std::wstring dll_path;
    std::string entry_export = "VesperAttach";
    std::wstring argument;  // passed to the client verbatim
    std::wstring wait_file;
    std::wstring build;  // empty selects the newest installed client
    int map_wait_ms = 8000;
    int wait_ms = 90000;

    // Enter the payload from the client's own main thread instead of from a new
    // thread. The thread that starts the payload is then one the client made
    // itself, which is the only kind a process that judges thread start addresses
    // will have.
    bool hijack = false;

    // Where the hijacked thread goes once the payload's entry returns, as an
    // absolute address in the client. Zero means the thread is ended cleanly with
    // `kernel32!ExitThread`, which is right for a payload that has nothing to
    // restore.
    std::uintptr_t hijack_return = 0;

    // The payload signals a named event as its first instruction; see MapOptions.
    bool probe_event = false;

    // Start the entry thread at a `jmp rcx` trampoline inside a trusted module; see
    // MapOptions. Only meaningful without `hijack`.
    bool trampoline = false;

    // Deliver the entry as an APC to the target's own threads; see MapOptions.
    bool apc = false;

    // Private pages instead of a file-backed section; see MapOptions.
    bool private_image = false;

    // A pagefile-backed section instead of private pages; see MapOptions.
    bool pagefile_section = false;

    // Hand the memory back once the observation is over; see MapOptions.
    bool cleanup = false;
};

struct LaunchMapOutcome {
    bool ok = false;
    int pid = 0;
    bool resumed = false;
    bool hijacked = false;
    bool entry_event_seen = false;
    bool process_alive = false;
    int threads_after = 0;
    std::wstring exe;
    std::wstring command_line;
    MapOutcome map;
    std::string detail;
};

// Starts the client suspended, maps the payload into it before any of the game's
// own code has run, enters it, and only then resumes the client. The suspended
// window is the one state in which nothing of the game has executed yet, so it is
// the earliest point a payload can be made a part of the process.
LaunchMapOutcome launch_and_map(const LaunchMapOptions& options);

// Human-readable meaning of a thread exit status, for the codes a mapped entry
// actually comes back with.
const char* map_status_name(std::uint32_t status);

}  // namespace vesper::shell
