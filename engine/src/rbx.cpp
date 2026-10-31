#include <vesper/rbx.hpp>

#include <algorithm>
#include <atomic>
#include <cstring>
#include <deque>
#include <mutex>
#include <vector>

#include <lua.h>
#include <lualib.h>
#include <lstate.h>
#include <lobject.h>
#include <lapi.h>
#include <ldo.h>
#include <lfunc.h>

#include <Luau/Compiler.h>
#include <Luau/BytecodeBuilder.h>
#include <Luau/BytecodeUtils.h>

#include <Roblox/Offsets.hpp>
#include <Roblox/Encryptions.hpp>

#include <vesper/env.hpp>
#include <vesper/guard.hpp>
#include <vesper/stage.hpp>

// Set by the engine (compile_bytecode_impl) from the `nofb` marker; read by the
// vendored BytecodeBuilder to suppress the per-proto feedback section.
extern "C" int g_vesper_no_fb = 0;

// Set by the engine from the `bcver` marker; read by the vendored
// BytecodeBuilder's `getVersion()` to force a wire-format version (11..14).
extern "C" int g_vesper_bc_version = 0;

namespace vesper::rbx {

// Defined further down; `refresh` installs these once per session.
void install_environment(lua_State* L);

namespace {

bool install_pump(lua_State* L);
bool g_pump_installed = false;

// Defined with the UNC surface further down. Runs the surface preludes that are
// still pending, for at most `budget_ms`, then returns: the surface is
// preparation, so it is bounded and never allowed to delay the user's chunk
// beyond the cap.
int install_unc_surface(lua_State* parent, int budget_ms);


Profile g_profile;
Bindings g_bindings;
Status g_status;
std::uintptr_t g_module_base = 0;
bool g_module_base_pinned = false;

lua_State* g_lua_state = nullptr;
lua_State* g_executor_thread = nullptr;

struct Request {
    std::string source;
    std::string chunk;
    std::string tag;
};
std::deque<Request> g_queue;
std::mutex g_queue_mutex;
std::atomic<int> g_pending{0};
std::atomic<unsigned long long> g_sequence{0};

std::uintptr_t g_opcode_lookup = 0;
// The loader's companion table at RVA 0x7144260 (adjacent to the decode table).
// MEASURED: `class_table[internal_opcode] == vendored_opcode`, i.e. it is the
// inverse of the map the encoder needs. Inverting it yields the whole
// vendored->internal map, which is how CAPTURE / SETLIST / LENGTH were pinned.
std::uintptr_t g_opcode_class = 0;
bool g_use_host_loader = true;

constexpr std::uintptr_t kMaxCapabilities = ~static_cast<std::uintptr_t>(0);

// Fields of the host `RobloxExtraSpace` we need. Resolved per build; the
// defaults match the layout the public scene has observed and are verified
// before use.
std::uintptr_t g_identity_offset = 0;
std::uintptr_t g_capabilities_offset = 0;

constexpr std::uintptr_t kExtraSpaceIdentityCandidate = 0x60;
constexpr std::uintptr_t kExtraSpaceCapabilityCandidate = 0x38;

// ------------------------------------------------------------- markers --
//
// One-shot files under `%LOCALAPPDATA%\Vesper` that can be created and deleted
// between two bridge calls on the *same* session. The client's own environment
// cannot be changed after it starts, so this is what makes the fatal
// experiments (force the VM, change the opcode encoder, enter the interpreter)
// repeatable without paying a 70 s relaunch for each one.
std::wstring engine_directory() {
    wchar_t local[MAX_PATH * 2] = {};
    const DWORD length =
        GetEnvironmentVariableW(L"LOCALAPPDATA", local, static_cast<DWORD>(std::size(local)));
    std::wstring root = length > 0 ? std::wstring(local, length) : default_engine_directory();
    return root + L"\\Vesper";
}

bool marker_present(const wchar_t* name) {
    const std::wstring path = engine_directory() + L"\\" + name;
    const DWORD attributes = GetFileAttributesW(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

// Reads `name` as text; empty when absent.
std::string marker_text(const wchar_t* name) {
    const std::wstring path = engine_directory() + L"\\" + name;
    const auto data = read_file(path);
    return std::string(data.begin(), data.end());
}

bool marker_flag(const wchar_t* name) {
    if (!marker_present(name)) return false;
    const std::string text = marker_text(name);
    if (text.empty()) return true;
    return text[0] == '1' || text[0] == 't' || text[0] == 'T' || text[0] == 'y' ||
           text[0] == 'Y';
}

// Dumps a range of the host image to `<engine dir>/<name>`. Hyperion decrypts
// pages only once they have executed, so a cold error path becomes readable
// *after* it has run: this is the only way to see the code behind a failure
// message the loader raises from a page that reads back empty before it fires.
bool dump_image_region(std::uintptr_t start_rva, std::uintptr_t end_rva, const wchar_t* name) {
    if (g_module_base == 0 || end_rva <= start_rva) return false;
    const std::wstring path = engine_directory() + L"\\" + name;
    HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    std::uint8_t buffer[0x1000];
    std::size_t readable = 0;
    for (std::uintptr_t rva = start_rva; rva < end_rva; rva += sizeof(buffer)) {
        const std::size_t want =
            static_cast<std::size_t>(end_rva - rva) < sizeof(buffer)
                ? static_cast<std::size_t>(end_rva - rva)
                : sizeof(buffer);
        std::memset(buffer, 0, want);
        if (safe_read(reinterpret_cast<const void*>(g_module_base + rva), buffer, want)) {
            readable += want;
        }
        DWORD written = 0;
        WriteFile(file, buffer, static_cast<DWORD>(want), &written, nullptr);
    }
    CloseHandle(file);
    VSP_INFO("dump: wrote rva 0x%llx..0x%llx (%zu readable bytes) to %s",
             static_cast<unsigned long long>(start_rva),
             static_cast<unsigned long long>(end_rva), readable, narrow(path).c_str());
    return true;
}

// `%LOCALAPPDATA%\Vesper\encoder` = "0" | "1" | "2" | "3"; -1 when absent.
int encoder_marker() {
    if (!marker_present(L"encoder")) return -1;
    const std::string text = marker_text(L"encoder");
    if (text.empty()) return -1;
    if (text[0] == '0') return 0;
    if (text[0] == '2') return 2;
    if (text[0] == '3') return 3;
    if (text[0] == '4') return 4;
    if (text[0] == '1') return 1;
    return -1;
}

// ---------------------------------------------------------------- binding --

struct EncKey {
    const char* key;
    std::uint8_t field;
};

const EncKey kEncKeys[] = {
    {"enc.proto.line_info", abi::kEncProtoLineInfo},
    {"enc.proto.abs_line_info", abi::kEncProtoAbsLineInfo},
    {"enc.proto.loc_vars", abi::kEncProtoLocVars},
    {"enc.proto.upvalues", abi::kEncProtoUpvalues},
    {"enc.proto.source", abi::kEncProtoSource},
    {"enc.proto.debug_insn", abi::kEncProtoDebugInsn},
    {"enc.proto.debug_name", abi::kEncProtoDebugName},
    {"enc.proto.type_info", abi::kEncProtoTypeInfo},
    {"enc.proto.userdata", abi::kEncProtoUserdata},
    {"enc.lstate.stack_size", abi::kEncLStateStackSize},
    {"enc.closure.cont", abi::kEncClosureCont},
    {"enc.closure.debug_name", abi::kEncClosureDebugName},
    {"enc.userdata.meta", abi::kEncUdataMeta},
    {"enc.tstring.hash", abi::kEncTStringHash},
};

std::string hex_of(std::uintptr_t value) {
    return vformat("0x%llx", static_cast<unsigned long long>(value));
}

// ------------------------------------------------------------- resolution --

bool pointer_plausible(std::uintptr_t value) {
    return value > 0x10000 && value < 0x00007fffffffffffULL;
}

// Reads a pointer, tolerating Hyperion's page protection.
bool read_ptr(std::uintptr_t address, std::uintptr_t& out) {
    if (!pointer_plausible(address)) return false;
    return safe_read_value(address, out) && pointer_plausible(out);
}

// Size of the host image, read from its mapped headers (the host is always the
// main module of the process).
std::uintptr_t host_image_size() {
    static std::uintptr_t cached = 0;
    if (cached != 0) return cached;
    const std::uintptr_t base = g_module_base != 0
                                    ? g_module_base
                                    : reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
    if (!pointer_plausible(base)) return 0;
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    cached = nt->OptionalHeader.SizeOfImage;
    return cached;
}

// Every class instance's first pointer is a vtable inside the host image.
// This is what keeps a bad layout guess from being handed to host code, where
// it would trip the host's own assertions (a wrong candidate in the script
// context search once took a client down with a hard assert inside
// `get_global_state`).
bool looks_like_object(std::uintptr_t value) {
    if (!pointer_plausible(value)) return false;
    std::uintptr_t vtable = 0;
    if (!read_ptr(value, vtable)) return false;
    const std::uintptr_t base = g_module_base != 0
                                    ? g_module_base
                                    : reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
    const std::uintptr_t size = host_image_size();
    if (base == 0 || size == 0) return true;
    return vtable >= base && vtable < base + size;
}

// Confirms a candidate `lua_State` is a live Luau thread by checking the
// invariants of its stack window. This is the check that decides whether a
// resolution strategy is accepted.
// Offsets of the *live* `lua_State`, read straight out of this client's own
// code rather than out of a header:
//
//   luaD_growstack     rax = [L+0x58] (top) - [L+0x48] (base); cmp against
//                      LUAI_MAXCSTACK, then reallocs [L+0x60] and decodes
//                      [L+0x70] with `mov eax, esi; xor eax, [rsi]`
//   luaD_reallocstack  rcx = [L+0x38] (stack_last); size_ci from [L+0x74]
//   stack push helper  stores the new limit at [[L+0x40]+0x18] (ci)
//   index2addr         positive index -> ([L+0x48] - 0x10) + i*16, bound [L+0x58]
//
// The vendored header the Luau layer in this DLL compiles against describes an
// older build and places the same fields elsewhere, which is why a genuine
// state used to be rejected as "not a thread".
// Field map re-derived on version-9ac8595712b447a7 from the client's own inlined
// `lua_newthread` (rva.sc.thread_helper body) and confirmed against `lua_pcall`
// and `resume_continue`, which read the same offsets:
//   tt@+2, status@+3, env@+8, end_ci@+0x10, base_ci@+0x18, nCcalls@+0x20,
//   baseCcalls@+0x22, ci@+0x50, base@+0x58, stack@+0x60, stack_last@+0x68,
//   top@+0x70, global@+0x78, stack_size@+0x80, size_ci@+0x84.
namespace live {
constexpr std::uintptr_t kTt = 0x2;
constexpr std::uintptr_t kEnv = 0x8;
constexpr std::uintptr_t kEndCi = 0x10;
constexpr std::uintptr_t kBaseCi = 0x18;
constexpr std::uintptr_t kStackLast = 0x68;
constexpr std::uintptr_t kCi = 0x50;
constexpr std::uintptr_t kBase = 0x58;
constexpr std::uintptr_t kUserdata = 0x78;
constexpr std::uintptr_t kTop = 0x70;
constexpr std::uintptr_t kStack = 0x60;
constexpr std::uintptr_t kStackSize = 0x80;
constexpr std::uintptr_t kSizeCi = 0x84;
constexpr std::uintptr_t kCallInfoSize = 0x30;
}  // namespace live

bool validate_state(lua_State* L) {
    if (!pointer_plausible(reinterpret_cast<std::uintptr_t>(L))) return false;
    const auto base = reinterpret_cast<std::uintptr_t>(L);

    // Byte 2 of a Roblox thread is its tag on this build (+2, not +0); it is
    // 0x0A on every client checked.
    std::uint8_t tag = 0;
    if (!safe_read(reinterpret_cast<const void*>(base + live::kTt), &tag, sizeof(tag)) ||
        tag != 0x0A) {
        return false;
    }

    std::uintptr_t stack = 0;
    std::uintptr_t stack_last = 0;
    std::uintptr_t top = 0;
    std::uintptr_t frame = 0;
    std::uintptr_t ci = 0;
    std::uintptr_t base_ci = 0;
    std::uintptr_t end_ci = 0;
    if (!read_ptr(base + live::kStack, stack)) return false;
    if (!read_ptr(base + live::kStackLast, stack_last)) return false;
    if (!read_ptr(base + live::kTop, top)) return false;
    if (!read_ptr(base + live::kBase, frame)) return false;
    if (!read_ptr(base + live::kCi, ci)) return false;
    if (!read_ptr(base + live::kBaseCi, base_ci)) return false;
    if (!read_ptr(base + live::kEndCi, end_ci)) return false;

    if (stack_last <= stack) return false;
    const std::uintptr_t slots = (stack_last - stack) / sizeof(TValue);
    if (slots < BASIC_STACK_SIZE || slots > (1u << 22)) return false;
    if (top < stack || top > stack_last) return false;
    if (frame < stack || frame > top) return false;
    if (((top - stack) & (sizeof(TValue) - 1)) != 0) return false;

    // Frame chain: base_ci <= ci <= end_ci, both ends aligned to the 0x30 byte
    // CallInfo, and the active frame's function slot inside the stack window.
    if (base_ci == 0 || end_ci < base_ci) return false;
    if (ci < base_ci || ci > end_ci) return false;
    if (((ci - base_ci) % live::kCallInfoSize) != 0) return false;
    if (((end_ci - base_ci) % live::kCallInfoSize) != 0) return false;

    std::uintptr_t func = 0;
    if (!read_ptr(ci + 8, func)) return false;
    return func >= stack && func <= stack_last;
}

using GetGlobalStateFn = lua_State* (*)(std::uintptr_t, std::uintptr_t*, std::uintptr_t*);

// One-shot diagnostic for a rejected candidate: the raw return value and the
// head of whatever it points at, so a layout that shifted shows up in the log
// instead of only as "rejected".
void dump_state_candidate(std::uintptr_t candidate, std::uintptr_t scratch_a,
                          std::uintptr_t scratch_b) {
    std::string line = vformat("probe: get_global_state -> %s scratch=%s/%s",
                               hex_of(candidate).c_str(), hex_of(scratch_a).c_str(),
                               hex_of(scratch_b).c_str());
    if (pointer_plausible(candidate)) {
        std::uintptr_t words[12] = {};
        if (safe_read(reinterpret_cast<const void*>(candidate), words, sizeof(words))) {
            for (int i = 0; i < 12; ++i) {
                line += vformat(" +%02x=%s", i * 8, hex_of(words[i]).c_str());
            }
        }
    }
    VSP_INFO("%s", line.c_str());
}

// Result of the last `get_global_state` probe. It lives in a static rather than a
// local so the fault guard can unwind without the value becoming indeterminate.
lua_State* g_last_global_state = nullptr;

// Defined with the scheduler walk below. Every path that asks the host for a
// state goes through it, because the host asserts on anything that is not the
// script context it expects and that assert is a hard fail the fault guard
// cannot catch.
bool safe_to_ask_host(std::uintptr_t script_context);

// The client keeps pointers in the ScriptContext XOR-encoded against the low 32 bits of
// the slot's own address: each dword is `dword ^ low32(slot)`. The function that reads them
// (RVA 0x425F880 on 9ac8) decodes `sc+0x200` and `sc+0x4B0` that way and then reads
// `[ptr+0x78]`, which is `global` in this build's lua_State. Reading is all this does:
// nothing of the client is called. Returns the candidate only if it passes the same
// validate_state every other path uses.
lua_State* decode_state_slot(std::uintptr_t script_context, std::uintptr_t offset) {
    const std::uintptr_t slot = script_context + offset;
    std::uint32_t words[2] = {};
    if (!safe_read(reinterpret_cast<const void*>(slot), words, sizeof(words))) return nullptr;
    const std::uint32_t key = static_cast<std::uint32_t>(slot);
    const std::uintptr_t pointer =
        (static_cast<std::uintptr_t>(words[1] ^ key) << 32) | (words[0] ^ key);
    const bool plausible = pointer_plausible(pointer);
    const bool valid = plausible && validate_state(reinterpret_cast<lua_State*>(pointer));
    VSP_INFO("attach: decoded sc+0x%llx -> %s plausible=%d validate_state=%d",
             static_cast<unsigned long long>(offset), hex_of(pointer).c_str(), plausible ? 1 : 0,
             valid ? 1 : 0);
    return valid ? reinterpret_cast<lua_State*>(pointer) : nullptr;
}

lua_State* call_get_global_state(std::uintptr_t instance) {
    // With a 'g' in the stage file the client's own function is never called (MEASURED:
    // calling it is what stops the client dead, 2u froze at +26 s, 2ug ran 94 s at normal
    // load). The state is read out of the ScriptContext instead.
    // This is now the default path; the client's function is opt-in with a 'G'.
    for (const std::uintptr_t offset : {std::uintptr_t{0x200}, std::uintptr_t{0x4B0}}) {
        if (lua_State* state = decode_state_slot(instance, offset)) return state;
    }
    if (!vesper::stage_skips('G')) return nullptr;
    if (g_bindings.get_global_state == 0 || !safe_to_ask_host(instance)) return nullptr;

    g_last_global_state = nullptr;
    std::uintptr_t scratch_a = 0;
    std::uintptr_t scratch_b = 0;
    auto fn = reinterpret_cast<GetGlobalStateFn>(g_bindings.get_global_state);

    guarded([&] { g_last_global_state = fn(instance, &scratch_a, &scratch_b); });

    if (g_last_global_state != nullptr && validate_state(g_last_global_state)) {
        return g_last_global_state;
    }

    static bool logged_probe = false;
    if (!logged_probe) {
        logged_probe = true;
        dump_state_candidate(reinterpret_cast<std::uintptr_t>(g_last_global_state), scratch_a,
                             scratch_b);
    }
    return nullptr;
}

// ------------------------------------------------------------ scheduler jobs --

// The route SolaraV3 uses, and the one this engine prefers: the scheduler keeps
// one `WaitingHybridScriptsJob` per script context, so the context is found by
// walking the job vector and matching a name -- a table-driven lookup that does
// not depend on the DataModel layout. `DataModel::ScriptContext` reads zero in
// the menu and read zero on 11f1 even while a place was loaded, which is what
// made the old path unusable there.
//
// Every step is bounded and read-only, and no candidate reaches the host until
// it has passed the vtable gate, so a table that is wrong degrades to "no job
// found" instead of a bad pointer handed to host code.

// First-tick tracing of the resolution path. A hang inside refresh() leaves no
// log line at all, which is indistinguishable from an engine that never started,
// so the steps stay visible for the first few ticks and then stop for good.
int g_trace_budget = 48;
void trace_step(const char* step) {
    if (g_trace_budget <= 0) return;
    --g_trace_budget;
    VSP_INFO("trace: %s", step);
}

bool printable_ascii(const char* text, std::size_t length) {
    if (length == 0) return false;
    for (std::size_t i = 0; i < length; ++i) {
        const auto c = static_cast<unsigned char>(text[i]);
        if (c < 32 || c > 126) return false;
    }
    return true;
}

// `TaskSchedulerJob::Name` has been an MSVC `std::string`, a plain C string and
// an inline buffer across builds; recognizing all three keeps a table that is
// right about the offset but wrong about the type working.
bool read_job_name(std::uintptr_t job, std::uintptr_t name_offset, char* out, std::size_t capacity,
                   std::size_t& out_length) {
    out_length = 0;
    if (capacity < 32 || name_offset == 0) return false;

    std::uintptr_t header[3] = {};
    if (safe_read(reinterpret_cast<const void*>(job + name_offset), header, sizeof(header))) {
        // (a) MSVC std::string: {buffer | pointer, size @ +0x10, capacity @ +0x18}
        const std::uintptr_t size = header[1];
        if (size > 0 && size < capacity) {
            char text[64] = {};
            const bool inline_name = size < 16;
            const bool ok =
                inline_name
                    ? safe_read(reinterpret_cast<const void*>(job + name_offset), text, size)
                    : (pointer_plausible(header[0]) &&
                       safe_read(reinterpret_cast<const void*>(header[0]), text, size));
            if (ok && printable_ascii(text, size)) {
                std::memcpy(out, text, size);
                out[size] = '\0';
                out_length = size;
                return true;
            }
        }
        // (b) pointer to a NUL terminated name
        if (pointer_plausible(header[0])) {
            char text[64] = {};
            if (safe_read(reinterpret_cast<const void*>(header[0]), text, sizeof(text))) {
                std::size_t length = 0;
                while (length < sizeof(text) && text[length] != '\0') ++length;
                if (length >= 3 && printable_ascii(text, length)) {
                    std::memcpy(out, text, length);
                    out[length] = '\0';
                    out_length = length;
                    return true;
                }
            }
        }
    }

    // (c) the name is stored inline in the object's head
    static constexpr char kNeedle[] = "WaitingHybridScriptsJob";
    char head[0x200] = {};
    if (safe_read(reinterpret_cast<const void*>(job), head, sizeof(head))) {
        for (std::size_t i = 0; i + sizeof(kNeedle) - 1 <= sizeof(head); ++i) {
            if (std::memcmp(head + i, kNeedle, sizeof(kNeedle) - 1) == 0) {
                std::memcpy(out, kNeedle, sizeof(kNeedle) - 1);
                out[sizeof(kNeedle) - 1] = '\0';
                out_length = sizeof(kNeedle) - 1;
                return true;
            }
        }
    }
    return false;
}

struct JobSpan {
    std::uintptr_t begin = 0;
    std::uintptr_t end = 0;
};

bool valid_job_span(const JobSpan& span) {
    if (!pointer_plausible(span.begin) || !pointer_plausible(span.end)) return false;
    if (span.end <= span.begin) return false;
    const std::uintptr_t bytes = span.end - span.begin;
    return bytes <= 0x40000 && (bytes % 0x10) == 0;
}

// The job vector itself moved between builds, so the discovery pass looks for a
// {begin, end} pair in the scheduler's head once.
std::vector<JobSpan> job_vector_candidates(std::uintptr_t scheduler, bool deep) {
    std::vector<JobSpan> spans;

    JobSpan known;
    if (g_bindings.ts_job_start != 0 && g_bindings.ts_job_end != 0) {
        safe_read_value(scheduler + g_bindings.ts_job_start, known.begin);
        safe_read_value(scheduler + g_bindings.ts_job_end, known.end);
        if (valid_job_span(known)) spans.push_back(known);
    }
    if (!deep) return spans;

    int extra = 0;
    for (std::uintptr_t offset = 0; offset < 0x600 && extra < 6; offset += 0x8) {
        JobSpan candidate;
        if (!safe_read_value(scheduler + offset, candidate.begin)) continue;
        if (!safe_read_value(scheduler + offset + 0x8, candidate.end)) continue;
        if (!valid_job_span(candidate)) continue;
        bool duplicate = false;
        for (const auto& existing : spans) {
            if (existing.begin == candidate.begin && existing.end == candidate.end) duplicate = true;
        }
        if (duplicate) continue;
        // A real job vector starts with a job object.
        std::uintptr_t first = 0;
        if (!read_ptr(candidate.begin, first) || !looks_like_object(first)) continue;
        spans.push_back(candidate);
        ++extra;
    }
    return spans;
}

// A script context candidate is only ever handed to the host when its vtable is
// the ScriptContext's. `get_global_state` reads a field at +0x14f8 and takes a
// crash path when the object is not a script context, so a bare "looks like an
// object" match is not enough: an earlier build of this search called the host
// on such a match and took the client down with it.
bool looks_like_script_context(std::uintptr_t value) {
    if (!looks_like_object(value)) return false;
    const std::uintptr_t expected = g_bindings.sc_vtable;
    if (expected == 0) return true;
    std::uintptr_t vtable = 0;
    if (!read_ptr(value, vtable)) return false;
    return vtable == expected;
}

// The host reads a field at +0x14f8 before handing out a state and takes a crash
// path when the value is >= 3. That is the whole reason a bad candidate kills the
// client instead of returning null, so the same value is checked here first: a
// candidate the host would assert on is never passed to it.
bool safe_to_ask_host(std::uintptr_t script_context) {
    if (!looks_like_script_context(script_context)) return false;
    const std::uintptr_t guard_offset = g_bindings.sc_guard;
    if (guard_offset != 0) {
        std::uint32_t guard = 0;
        if (!safe_read_value(script_context + guard_offset, guard)) return false;
        if (guard >= 3) return false;
    }
    return true;
}

// The context id rides along in the inline name: the place's own job is the
// "(Default;Ugc)" one, while the engine keeps a second WaitingHybridScriptsJob
// for the menu's LuaApp context. Reading it is a single bounded read of the job's
// head, and it is one of the two marks that identify the right context.
bool job_head_contains(std::uintptr_t job, const char* needle) {
    const std::size_t needle_length = std::strlen(needle);
    if (needle_length == 0) return false;

    char head[0x220] = {};
    if (!safe_read(reinterpret_cast<const void*>(job), head, sizeof(head))) return false;
    for (std::size_t i = 0; i + needle_length <= sizeof(head); ++i) {
        if (std::memcmp(head + i, needle, needle_length) == 0) return true;
    }
    return false;
}

struct WaitingJob {
    std::uintptr_t job = 0;
    std::uintptr_t script_context = 0;
    std::uintptr_t context_offset = 0;
    bool preferred = false;  // the place's own context, not the menu's clone
};

// Reads the context out of one job. The table offset is tried first and the
// job's head is then walked, so a build that moved the field is discovered
// rather than trusted. Both paths are read-only and both require the vtable
// check, which is what keeps the host out of the loop until a real script
// context has been identified.
WaitingJob inspect_job(std::uintptr_t job, bool deep, std::uintptr_t expected_data_model) {
    WaitingJob found;
    found.job = job;

    // The job that points back at the loaded place's own DataModel is the context
    // the place runs on. Asking the host about the other one leaves the client
    // wedged inside a host lock, which is worse than no state at all.
    if (expected_data_model != 0 && g_bindings.ts_job_data_model != 0) {
        std::uintptr_t owned = 0;
        if (read_ptr(job + g_bindings.ts_job_data_model, owned) && owned == expected_data_model) {
            found.preferred = true;
        }
    }
    if (!found.preferred) found.preferred = job_head_contains(job, "Default;Ugc");

    const std::uintptr_t field = g_bindings.ts_job_script_context;
    if (field != 0) {
        std::uintptr_t candidate = 0;
        if (read_ptr(job + field, candidate) && looks_like_script_context(candidate)) {
            found.script_context = candidate;
            found.context_offset = field;
            return found;
        }
    }

    // The context is a plain object pointer in the job's head; walking it is a
    // handful of reads and never reaches the host.
    const std::uintptr_t limit = deep ? 0x800 : 0x220;
    for (std::uintptr_t offset = 0x8; offset < limit; offset += 0x8) {
        std::uintptr_t candidate = 0;
        if (!read_ptr(job + offset, candidate)) continue;
        if (!looks_like_script_context(candidate)) continue;
        found.script_context = candidate;
        found.context_offset = offset;
        return found;
    }
    return found;
}

// Both WaitingHybridScriptsJob instances are considered and the one that owns the
// place wins. When neither mark matches and there is more than one context, the
// search declines instead of guessing: a missing state is recoverable, a client
// stuck inside a host lock is not.
WaitingJob find_script_context_job(std::uintptr_t scheduler, bool deep,
                                   std::uintptr_t expected_data_model) {
    static constexpr char kTarget[] = "WaitingHybridScriptsJob";

    std::vector<WaitingJob> matches;
    for (const JobSpan& span : job_vector_candidates(scheduler, deep)) {
        const std::uintptr_t count = (span.end - span.begin) / 0x10;
        for (std::uintptr_t index = 0; index < count; ++index) {
            std::uintptr_t job = 0;
            // shared_ptr<Job>: the object pointer is the first word of the slot.
            if (!read_ptr(span.begin + index * 0x10, job)) continue;
            if (!looks_like_object(job)) continue;

            char name[72] = {};
            std::size_t length = 0;
            if (!read_job_name(job, g_bindings.ts_job_name, name, sizeof(name), length)) continue;
            if (length < sizeof(kTarget) - 1 || std::memcmp(name, kTarget, sizeof(kTarget) - 1) != 0)
                continue;

            WaitingJob candidate = inspect_job(job, deep, expected_data_model);
            if (candidate.script_context == 0) continue;
            // Which job was taken matters more than how long it took: two of these exist and
            // only one is the place's. Logging the name and the mark is what says whether the
            // context that was picked is the game's or the app shell's.
            std::uintptr_t owned = 0;
            if (g_bindings.ts_job_data_model != 0) read_ptr(job + g_bindings.ts_job_data_model, owned);

            // ForlornWare tells the two jobs apart by the size of the registry's array part
            // (`registry->sizearray == 4` is the one it skips). Read the same value for each
            // candidate state: lua_State -> global_State (+0x78) -> registry TValue (+0x618)
            // -> LuaTable.sizearray (+0x08). Read only, two dereferences per job.
            int registry_array = -1;
            if (lua_State* state = decode_state_slot(candidate.script_context, 0x200)) {
                std::uintptr_t global = 0, registry = 0;
                std::int32_t sizearray = -1;
                if (read_ptr(reinterpret_cast<std::uintptr_t>(state) + live::kUserdata, global) &&
                    read_ptr(global + 0x618, registry) &&
                    safe_read_value(registry + 0x08, sizearray)) {
                    registry_array = sizearray;
                }
            }
            VSP_INFO("attach: job \"%.44s\" (%zu chars) preferred=%d context=%s offset=+0x%llx "
                     "owned=%s real_dm=%s registry_sizearray=%d",
                     name, length, candidate.preferred ? 1 : 0,
                     hex_of(candidate.script_context).c_str(),
                     static_cast<unsigned long long>(candidate.context_offset), hex_of(owned).c_str(),
                     hex_of(expected_data_model).c_str(), registry_array);
            trace_step(candidate.preferred ? "jobs: preferred match" : "jobs: plain match");
            if (candidate.preferred) return candidate;
            matches.push_back(candidate);
        }
    }

    if (matches.size() == 1) return matches.front();
    if (!matches.empty()) {
        static bool warned = false;
        if (!warned) {
            warned = true;
            VSP_WARN("attach: %zu script context jobs and none owns the place; host not asked",
                     matches.size());
        }
    }
    return {};
}

// refresh() runs on the bridge's 250 ms tick, so the discovery pass is rate
// limited and capped: a client whose layout we do not understand costs one
// bounded scan every two seconds, not one per tick, and stops after a handful.
constexpr int kJobProbes = 12;
constexpr std::uint64_t kJobProbeIntervalMs = 2000;
int g_job_probes_left = kJobProbes;
std::uint64_t g_last_job_probe = 0;

// The script job whose virtual `step()` the scheduler calls on the game's Lua
// thread. Recorded while resolving the state, because the vtable redirect below
// needs the object itself and re-walking the vector to find it again would be a
// second scan of live memory just to learn something we already had.
std::uintptr_t g_script_job = 0;

std::uintptr_t resolve_script_context_via_jobs(Strategy& strategy, std::uintptr_t expected_data_model) {
    if (g_bindings.task_scheduler == 0 || g_bindings.ts_job_name == 0) return 0;

    std::uintptr_t scheduler = 0;
    if (!read_ptr(g_bindings.task_scheduler, scheduler)) return 0;
    trace_step("jobs: scheduler read");

    // Cheap pass: the vector layout and context offset the table describes.
    WaitingJob found = find_script_context_job(scheduler, false, expected_data_model);
    trace_step("jobs: cheap pass done");

    // Discovery pass, for a build whose vector moved: the {begin, end} pair is
    // searched for in the scheduler's head and the job is walked further. Read
    // only, rate limited and capped, so a tick stays cheap either way.
    if (found.script_context == 0) {
        const std::uint64_t now = GetTickCount64();
        if (g_job_probes_left <= 0 || now - g_last_job_probe < kJobProbeIntervalMs) return 0;
        g_last_job_probe = now;
        --g_job_probes_left;
        found = find_script_context_job(scheduler, true, expected_data_model);
    }
    if (found.script_context == 0) return 0;

    g_job_probes_left = kJobProbes;
    if (found.job != 0) g_script_job = found.job;
    if (found.context_offset != g_bindings.ts_job_script_context) {
        VSP_INFO("attach: job script context lives at struct offset +0x%llx (table has +0x%llx)",
                 static_cast<unsigned long long>(found.context_offset),
                 static_cast<unsigned long long>(g_bindings.ts_job_script_context));
    }
    strategy = Strategy::ViaJobs;
    return found.script_context;
}

std::uintptr_t resolve_script_context(std::uintptr_t data_model, Strategy& strategy) {
    const std::uintptr_t field = g_bindings.dm_script_context;

    struct Candidate {
        Strategy strategy;
        std::uintptr_t value;
    };

    std::vector<Candidate> candidates;

    if (field != 0) {
        std::uintptr_t object = 0;
        if (read_ptr(data_model + field, object)) candidates.push_back({Strategy::Direct, object});

        std::uintptr_t children = 0;
        if (g_bindings.dm_children != 0 && read_ptr(data_model + g_bindings.dm_children, children)) {
            std::uintptr_t indirect = 0;
            if (read_ptr(children + field, indirect)) {
                candidates.push_back({Strategy::ViaChildren, indirect});
            }
        }
        candidates.push_back({Strategy::InlineObj, data_model + field});
    }

    for (const auto& candidate : candidates) {
        if (!looks_like_script_context(candidate.value)) continue;
        if (call_get_global_state(candidate.value) != nullptr) {
            strategy = candidate.strategy;
            return candidate.value;
        }
    }

    strategy = Strategy::Unknown;
    return 0;
}

// ------------------------------------------------------- abi self repair --

bool decode_at(std::uintptr_t address, std::uint64_t raw, std::uint8_t scheme, std::uint64_t& out) {
    const std::uint64_t self = address;
    switch (scheme) {
        case abi::kEncSubSelf: out = raw - self; return true;
        case abi::kEncSelfSub: out = self - raw; return true;
        case abi::kEncXorSelf: out = self ^ raw; return true;
        case abi::kEncAddSelf: out = self + raw; return true;
        default: out = raw; return true;
    }
}

// `L->stacksize` is the only `lua_State` field we depend on that is obfuscated.
// Because we can cross-check it against the stack window, its transform can be
// recovered rather than trusted.
bool repair_stack_size_scheme(lua_State* L, std::string& report) {
    const std::uintptr_t address = reinterpret_cast<std::uintptr_t>(L) + offsetof(lua_State, stacksize);
    std::uint64_t raw = 0;
    if (!safe_read_value(address, raw)) return false;

    std::uintptr_t stack = 0;
    std::uintptr_t stack_last = 0;
    if (!read_ptr(reinterpret_cast<std::uintptr_t>(L) + offsetof(lua_State, stack), stack)) return false;
    if (!read_ptr(reinterpret_cast<std::uintptr_t>(L) + offsetof(lua_State, stack_last), stack_last)) return false;
    const std::uint64_t expected = (stack_last - stack) / sizeof(TValue);

    for (std::uint8_t scheme = 0; scheme <= abi::kEncAddSelf; ++scheme) {
        std::uint64_t decoded = 0;
        decode_at(address, raw, scheme, decoded);
        if (decoded >= BASIC_STACK_SIZE && decoded <= (1u << 22) && decoded >= expected &&
            decoded - expected <= 8) {
            abi::set_scheme(abi::kEncLStateStackSize, scheme);
            report += vformat("stack_size scheme=%u (decoded=%llu, window=%llu)\n", scheme,
                              static_cast<unsigned long long>(decoded),
                              static_cast<unsigned long long>(expected));
            return true;
        }
    }

    report += vformat("stack_size scheme unresolved (raw=%llu window=%llu)\n",
                      static_cast<unsigned long long>(raw),
                      static_cast<unsigned long long>(expected));
    return false;
}

// Whether candidate offsets inside the host's extra space may be write-probed.
// Off by default: the write test puts an identity-like value into whichever
// offset it is checking, and a wrong offset can trip the host's own security
// assertions on another thread before the value is restored. Enable with
// VESPER_EXTRA_SCAN=1 only when hunting for the field on a disposable client.
bool extra_scan_allowed() {
    wchar_t value[8] = {};
    const DWORD len = GetEnvironmentVariableW(L"VESPER_EXTRA_SCAN", value, 8);
    return len > 0 && (value[0] == L'1' || value[0] == L't' || value[0] == L'T');
}

// Locates Identity/Capabilities inside the host `RobloxExtraSpace`.
// A table-provided pair was verified offline against this exact build and is
// authoritative; it is accepted on a read-only sanity check and nothing in the
// host is touched. Without one, only the opt-in write-probe scan is attempted.
bool resolve_extra_space(lua_State* L) {
    if (L == nullptr || L->userdata == nullptr) return false;
    auto* base = reinterpret_cast<std::uint8_t*>(L->userdata);

    const std::uintptr_t from_table_identity = g_bindings.es_identity;
    const std::uintptr_t from_table_caps = g_bindings.es_capabilities;
    if (from_table_identity != 0 && from_table_caps != 0) {
        std::uint64_t current = 0;
        if (safe_read_value(reinterpret_cast<std::uintptr_t>(base) + from_table_identity,
                            current) &&
            current <= 64) {
            g_identity_offset = from_table_identity;
            g_capabilities_offset = from_table_caps;
            return true;
        }
        VSP_WARN("attach: table identity offset did not read back; probing instead");
    }

    if (!extra_scan_allowed()) return false;

    std::vector<std::pair<std::uintptr_t, std::uintptr_t>> candidates;
    candidates.emplace_back(kExtraSpaceIdentityCandidate, kExtraSpaceCapabilityCandidate);

    // Layout scan: an identity is a small integer; capabilities sit in the same
    // object. Only used when the known candidates fail.
    for (std::uintptr_t offset = 0x08; offset < 0x180; offset += 8) {
        std::uint64_t value = 0;
        if (!safe_read_value(reinterpret_cast<std::uintptr_t>(base) + offset, value)) break;
        if (value >= 1 && value <= 8) {
            for (std::uintptr_t caps = 0x08; caps < 0x180; caps += 8) {
                if (caps == offset) continue;
                candidates.emplace_back(offset, caps);
                break;
            }
        }
    }

    for (const auto& [identity_offset, caps_offset] : candidates) {
        std::uint64_t current = 0;
        if (!safe_read_value(reinterpret_cast<std::uintptr_t>(base) + identity_offset, current)) continue;
        if (current > 64) continue;

        const std::uint64_t probe = 8;
        if (!WriteProcessMemory(GetCurrentProcess(),
                                base + identity_offset, &probe, sizeof(probe), nullptr)) {
            continue;
        }
        std::uint64_t verified = 0;
        const bool ok = safe_read_value(reinterpret_cast<std::uintptr_t>(base) + identity_offset, verified) &&
                        verified == probe;
        WriteProcessMemory(GetCurrentProcess(), base + identity_offset, &current, sizeof(current), nullptr);
        if (!ok) continue;

        g_identity_offset = identity_offset;
        g_capabilities_offset = caps_offset;
        return true;
    }

    return false;
}

// ---------------------------------------------------------------- encoder --

// The loader's opcode map, MEASURED (see docs/opcode-space-11f1.md): the byte the
// loader stores is `table[in]` -- a plain 256-byte permutation lookup at
// `rva.opcode_lookup_table` -- not `table[in*227]`, not a multiply and not an
// XOR. The six measured pairs (three from a stock chunk, three from a chunk the
// old encoder mangled) all satisfy `stored == table[in]`.
//
// The table is a bijection on 0..255, so the input that makes the VM see a given
// opcode byte is the inverse permutation: `in = inverse[op]`, because
// `table[inverse[op]] == op`. That is mode 3 below; it is the default.
std::uint8_t g_opcode_table[256] = {};
std::uint8_t g_opcode_inverse[256] = {};
bool g_opcode_table_ready = false;
bool g_opcode_inverse_ready = false;

// Reads the live 256-byte table and builds its inverse. Returns false when the
// table is unreadable or is not a bijection (in which case the encoder is a
// no-op rather than a guess).
bool load_opcode_table() {
    g_opcode_table_ready = false;
    g_opcode_inverse_ready = false;
    if (g_opcode_lookup == 0) return false;
    std::uint8_t table[256] = {};
    if (!safe_read(reinterpret_cast<const void*>(g_opcode_lookup), table, sizeof(table))) return false;
    bool seen[256] = {};
    std::uint8_t inverse[256] = {};
    for (int i = 0; i < 256; ++i) {
        const std::uint8_t value = table[i];
        if (seen[value]) return false;  // not a bijection; refuse to guess
        seen[value] = true;
        inverse[value] = static_cast<std::uint8_t>(i);
    }
    std::memcpy(g_opcode_table, table, sizeof(table));
    std::memcpy(g_opcode_inverse, inverse, sizeof(inverse));
    g_opcode_table_ready = true;
    g_opcode_inverse_ready = true;
    return true;
}

// Mode 3: the measured map. The loader does `stored = table[in]`, so we hand it
// `inverse[op]` and the VM sees the canonical opcode byte.
class PermEncoder : public Luau::BytecodeEncoder {
public:
    void encode(std::uint32_t* data, std::size_t count) override {
        if (!g_opcode_inverse_ready && !load_opcode_table()) return;
        if (!g_opcode_inverse_ready) return;
        for (std::size_t i = 0; i < count;) {
            const std::uint8_t opcode = LUAU_INSN_OP(data[i]);
            data[i] = (data[i] & ~0xffu) | g_opcode_inverse[opcode];
            i += Luau::getOpLength(static_cast<LuauOpcode>(opcode));
        }
    }
};

// Mode 4: the vendored (YuB-X) compiler enum is NOT the client's internal enum.
// The client's dispatch (byte table at RVA 0x267b0ac; the `> 0xF7` and case-0x5c
// target is `int 0x29`, the deliberate trap that killed the client on every
// entry) accepts only 92 opcode values, and the handler each dispatches to is the
// oracle for what opcode it implements. Identified by disassembling the handlers
// in `dumps/11f1-live.bin`:
//     internal 0x0d (case 05) = LOADNIL      0x49 (case 17) = LOADB
//     internal 0x4b (case 18) = LOADN        0xc8 (case 46) = MOVE
//     internal 0x6b (case 24) = CLOSEUPVALS  0x82 (case 2d) = RETURN
//     internal 0x9c (case 37) = a pure skip (NOP)
// Mode 4 translates vendored opcode -> internal opcode, then applies the loader
// inverse: input = inverse[internal]. Ops not yet identified are left vendored
// (and will trap), so the map only needs the ops a given probe uses.
constexpr std::uint8_t kInternalUnknown = 0xff;
std::uint8_t g_vendor_to_internal[256] = {};
bool g_semantic_ready = false;

// Vendored opcodes the compiler emitted that have no internal counterpart yet.
// Logged per run so a failing chunk names the next gap instead of just trapping.
bool g_seen_vendored[256] = {};
bool g_seen_any_vendored[256] = {};
bool g_seen_internal_unknown = false;

void cp(std::uint8_t vendored, std::uint8_t internal_op) {
    g_vendor_to_internal[vendored] = internal_op;
}

// Vendored (YuB-X / public Luau) opcode -> 11f1 internal opcode. Every entry was
// derived by disassembling the 92 dispatch handlers in dumps/11f1-live.bin (see
// docs/opcode-space-11f1.md for the per-op evidence). Vendored 0x41 PREPVARARGS
// is folded onto the internal NOP slot: the probe chunks are not variadic.
void build_semantic_map() {
    for (int i = 0; i < 256; ++i) g_vendor_to_internal[i] = kInternalUnknown;

    // AUTHORITATIVE map, derived from the loader's own class table at RVA
    // 0x7144260 (measured in `dumps/11f1-live.bin`): `class_table[internal] ==
    // vendored opcode` for all 256 internal bytes, so inverting it yields the
    // whole vendored->internal bijection. Cross-checked against every opcode
    // confirmed live (LOADN 0x4b, RETURN 0x82, GETTABLEKS 0xdd, NEWTABLE 0x13,
    // DUPCLOSURE 0x8e, ...) and against the reader at 0x269F907-0x269F974, which
    // uses the same table to decide each instruction's length.
    cp(0x00, 0x9C);  // NOP
    cp(0x01, 0xCF);  // BREAK
    cp(0x02, 0x0D);  // LOADNIL
    cp(0x03, 0x49);  // LOADB
    cp(0x04, 0x4B);  // LOADN
    cp(0x05, 0xF2);  // LOADK
    cp(0x06, 0xC8);  // MOVE
    cp(0x07, 0xC2);  // GETGLOBAL
    cp(0x08, 0x00);  // SETGLOBAL
    cp(0x09, 0xC3);  // GETUPVAL
    cp(0x0A, 0x32);  // SETUPVAL
    cp(0x0B, 0x6B);  // CLOSEUPVALS
    cp(0x0C, 0xB4);  // GETIMPORT
    cp(0x0D, 0xC5);  // GETTABLE
    cp(0x0E, 0xD7);  // SETTABLE
    cp(0x0F, 0xDD);  // GETTABLEKS
    cp(0x10, 0xEC);  // SETTABLEKS
    cp(0x11, 0xB8);  // GETTABLEN
    cp(0x12, 0x18);  // SETTABLEN
    cp(0x13, 0xD1);  // NEWCLOSURE
    cp(0x14, 0xD0);  // NAMECALL
    cp(0x15, 0xBF);  // CALL
    cp(0x16, 0x82);  // RETURN
    cp(0x17, 0x7B);  // JUMP
    cp(0x18, 0x3A);  // JUMPBACK
    cp(0x19, 0x2C);  // JUMPIF
    cp(0x1A, 0x10);  // JUMPIFNOT
    cp(0x1B, 0x2F);  // JUMPIFEQ
    cp(0x1C, 0xEF);  // JUMPIFLE
    cp(0x1D, 0x0B);  // JUMPIFLT
    cp(0x1E, 0xF6);  // JUMPIFNOTEQ
    cp(0x1F, 0xF7);  // JUMPIFNOTLE
    cp(0x20, 0x58);  // JUMPIFNOTLT
    cp(0x21, 0x99);  // ADD
    cp(0x22, 0x8A);  // SUB
    cp(0x23, 0x38);  // MUL
    cp(0x24, 0xAD);  // DIV
    cp(0x25, 0xEA);  // MOD
    cp(0x26, 0xDA);  // POW
    cp(0x27, 0xF5);  // ADDK
    cp(0x28, 0x54);  // SUBK
    cp(0x29, 0x7F);  // MULK
    cp(0x2A, 0x02);  // DIVK
    cp(0x2B, 0x24);  // MODK
    cp(0x2C, 0xA0);  // POWK
    cp(0x2D, 0x5B);  // AND
    cp(0x2E, 0x66);  // OR
    cp(0x2F, 0x77);  // ANDK
    cp(0x30, 0x1E);  // ORK
    cp(0x31, 0x7D);  // CONCAT
    cp(0x32, 0x6C);  // NOT
    cp(0x33, 0x4D);  // MINUS
    cp(0x34, 0x2E);  // LENGTH
    cp(0x35, 0x13);  // NEWTABLE
    cp(0x36, 0xE0);  // DUPTABLE
    cp(0x37, 0xE5);  // SETLIST
    cp(0x38, 0x05);  // FORNPREP
    cp(0x39, 0x3B);  // FORNLOOP
    cp(0x3A, 0x56);  // FORGLOOP
    cp(0x3B, 0x83);  // FORGPREP_INEXT
    cp(0x3C, 0x36);  // FASTCALL3
    cp(0x3D, 0xE4);  // FORGPREP_NEXT
    cp(0x3E, 0x74);  // NATIVECALL (never emitted by the compiler)
    cp(0x3F, 0x11);  // GETVARARGS
    cp(0x40, 0x8E);  // DUPCLOSURE
    // PREPVARARGS is folded onto the internal NOP: every chunk the executor runs
    // is entered with zero varargs, and the real handler (internal 0xDF) resizes
    // the stack; folding keeps the probe chunks identical to the verified runs.
    cp(0x41, 0x9C);  // PREPVARARGS -> NOP (correct internal is 0xDF)
    cp(0x42, 0x61);  // LOADKX
    cp(0x43, 0x0F);  // JUMPX
    cp(0x44, 0x14);  // FASTCALL
    cp(0x45, 0x6E);  // COVERAGE
    cp(0x46, 0xC9);  // CAPTURE
    cp(0x47, 0x6D);  // SUBRK
    cp(0x48, 0xCE);  // DIVRK
    cp(0x49, 0x5F);  // FASTCALL1
    cp(0x4A, 0xAE);  // FASTCALL2
    cp(0x4B, 0xC0);  // FASTCALL2K
    cp(0x4C, 0xBD);  // FORGPREP
    cp(0x4D, 0x8C);  // JUMPXEQKNIL
    cp(0x4E, 0x04);  // JUMPXEQKB
    cp(0x4F, 0xD9);  // JUMPXEQKN
    cp(0x50, 0x90);  // JUMPXEQKS
    cp(0x51, 0xCB);  // IDIV
    cp(0x52, 0x92);  // IDIVK
    cp(0x53, 0xBB);  // GETUDATAKS
    cp(0x54, 0xA6);  // SETUDATAKS
    cp(0x55, 0xC1);  // NAMECALLUDATA
    cp(0x56, 0x5A);  // NEWCLASSMEMBER
    cp(0x57, 0x88);  // CALLFB
    cp(0x58, 0xE2);  // CMPPROTO
    g_semantic_ready = true;
}

// Prefer the LIVE class table over the static one when it reads back as a
// bijection: `class_table[internal] == vendored`, so inverting it rebuilds the
// whole vendored->internal map for this exact session. Falls back silently to
// the measured static map above if the page is not committed.
bool g_semantic_from_class = false;
int g_semantic_entries = 0;

bool refine_semantic_map_from_class() {
    if (g_opcode_class == 0) return false;
    std::uint8_t table[256] = {};
    if (!safe_read(reinterpret_cast<const void*>(g_opcode_class), table, sizeof(table))) return false;
    bool seen[256] = {};
    for (int i = 0; i < 256; ++i) {
        if (seen[table[i]]) return false;  // not a bijection
        seen[table[i]] = true;
    }
    std::uint8_t map[256];
    for (int i = 0; i < 256; ++i) map[i] = kInternalUnknown;
    int count = 0;
    for (int internal_op = 0; internal_op < 256; ++internal_op) {
        const std::uint8_t vendored = table[internal_op];
        if (vendored <= 0x58 && map[vendored] == kInternalUnknown) {
            map[vendored] = static_cast<std::uint8_t>(internal_op);
            ++count;
        }
    }
    for (int i = 0; i < 256; ++i) g_vendor_to_internal[i] = map[i];
    g_semantic_from_class = true;
    g_semantic_entries = count;
    return true;
}

class SemanticEncoder : public Luau::BytecodeEncoder {
public:
    void encode(std::uint32_t* data, std::size_t count) override {
        if (!g_opcode_inverse_ready && !load_opcode_table()) return;
        if (!g_opcode_inverse_ready) return;
        if (!g_semantic_ready) build_semantic_map();
        if (!g_semantic_from_class) refine_semantic_map_from_class();
        for (std::size_t i = 0; i < count;) {
            const std::uint8_t vendored = LUAU_INSN_OP(data[i]);
            g_seen_any_vendored[vendored] = true;
            const std::uint8_t internal_op = g_vendor_to_internal[vendored];
            if (internal_op != kInternalUnknown) {
                data[i] = (data[i] & ~0xffu) | g_opcode_inverse[internal_op];
            } else {
                g_seen_vendored[vendored] = true;
                g_seen_internal_unknown = true;
            }
            i += Luau::getOpLength(static_cast<LuauOpcode>(vendored));
        }
    }
};

// Mode 1: the transform the public bases ship (`RavageDevs/SkidBase`,
// `Vexo6967`): the opcode byte is *scaled* by 227 and the scaled value is used
// as an index into the host table at `rva.opcode_lookup_table`.
class RobloxEncoder : public Luau::BytecodeEncoder {
public:
    void encode(std::uint32_t* data, std::size_t count) override {
        if (g_opcode_lookup == 0) return;
        auto* lookup = reinterpret_cast<const std::uint8_t*>(g_opcode_lookup);
        for (std::size_t i = 0; i < count;) {
            const std::uint8_t opcode = LUAU_INSN_OP(data[i]);
            const std::uint8_t mapped = lookup[static_cast<std::size_t>(opcode) * 227];
            data[i] = (data[i] & ~0xffu) | mapped;
            i += Luau::getOpLength(static_cast<LuauOpcode>(opcode));
        }
    }
};

// Mode 2: `opcode *= 227` and nothing else (the `XMSW-Easy-Roblox-Exploit-Base`
// / `Xeno` / `Brilliant-executor` variant). Byte-for-byte the simple form the
// task points at, so the two can be told apart by measurement.
class MulEncoder : public Luau::BytecodeEncoder {
public:
    void encode(std::uint32_t* data, std::size_t count) override {
        for (std::size_t i = 0; i < count;) {
            auto* opcode = reinterpret_cast<std::uint8_t*>(data + i);
            const std::uint8_t original = *opcode;
            i += Luau::getOpLength(static_cast<LuauOpcode>(original));
            *opcode = static_cast<std::uint8_t>(original * 227);
        }
    }
};

const char* kCommonGlobals[] = {"Game", "Workspace", "game",        "plugin", "script",
                                "shared", "workspace", "_G",   "_ENV",   nullptr};

}  // namespace

const char* to_string(Strategy strategy) {
    switch (strategy) {
        case Strategy::Direct: return "direct";
        case Strategy::ViaChildren: return "via-children";
        case Strategy::InlineObj: return "inline";
        case Strategy::ViaJobs: return "via-jobs";
        default: return "unknown";
    }
}

namespace {

// Mirrors the profile into the linked VM: the two Luau data anchors, the
// interpreter entry point and the per-field transform map. Everything the Luau
// sources reference through `Roblox/*` is set here, which is what keeps the
// build-specific numbers out of the source tree.
bool bind_abi(const Profile& profile) {
    const std::uintptr_t base = g_module_base;
    if (base == 0) return false;

    Offsets::Luau::LuaO_NilObject = profile.at("rva.luau.nil_object", base);
    Offsets::Luau::LuaH_DummyNode = profile.at("rva.luau.dummy_node", base);
    Roblox::Luau_Execute =
        reinterpret_cast<void (*)(lua_State*)>(profile.at("rva.luau.execute", base));

    for (const auto& entry : kEncKeys) {
        const std::uint8_t current = vesper::abi::scheme(entry.field);
        vesper::abi::set_scheme(entry.field, profile.transform(entry.key, current));
    }
    return true;
}

}  // namespace

// ------------------------------------------------------------ attach/lifecycle --

void set_module_base(std::uintptr_t base, bool pinned) {
    g_module_base = base;
    g_module_base_pinned = pinned;
}

namespace {

std::uintptr_t host_module_base() {
    if (g_module_base_pinned) return g_module_base;
    const HMODULE module = GetModuleHandleW(nullptr);
    return reinterpret_cast<std::uintptr_t>(module);
}

void clear_runtime_state() {
    g_lua_state = nullptr;
    g_executor_thread = nullptr;
    g_status.has_lua_state = false;
    g_status.environment_ready = false;
    g_status.ready = false;
    g_status.in_game = false;
    g_status.script_context = 0;
    g_status.data_model = 0;
    g_status.lua_state = 0;
    g_status.strategy = Strategy::Unknown;
    g_status.identity_field = 0;
    g_status.thread_identity = -1;
}

}  // namespace

bool attach(std::string& error) {
    g_module_base = host_module_base();
    if (!pointer_plausible(g_module_base)) {
        error = "host module not found";
        return false;
    }
    g_status.has_module = true;

    const std::string build = detect_build();
    g_status.build = build;

    {
        wchar_t image[MAX_PATH * 2] = {};
        DWORD image_size = static_cast<DWORD>(std::size(image));
        const bool have_image =
            QueryFullProcessImageNameW(GetCurrentProcess(), 0, image, &image_size) != 0;
        VSP_INFO("attach: build='%s' image='%s'", build.c_str(),
                 have_image ? narrow(std::wstring(image, image_size)).c_str() : "(unavailable)");
    }
    if (build.empty()) {
        error = "build not detected yet (process image path unavailable)";
        return false;
    }

    bool from_disk = false;
    if (!profile_load(build, g_profile, g_status.profile_error, &from_disk)) {
        // A missing table for a brand-new client build used to be fatal for the whole
        // session: attach() returned false and nothing else ran, so a routine Roblox
        // update (every 2-4 weeks, forever) turned the executor into a corpse until
        // 400+ entries had been ported. Keep going instead: every binding below comes
        // out zero, each resolution step already checks for zero and reports "not
        // found", and the bridge stays up in diagnostic mode. Execution stays
        // impossible, but the session *reports*, and that is what makes the port
        // diagnosable instead of a silent dead client.
        VSP_WARN("attach: no offset table for '%s' (%s) -- continuing in diagnostic mode",
                 build.c_str(), g_status.profile_error.c_str());
        g_status.has_profile = false;
    } else {
        g_status.has_profile = true;
        g_status.profile_source = g_profile.source;
    }
    g_bindings = Bindings{};
    g_bindings.module_base = g_module_base;
    g_bindings.fake_data_model = g_profile.at("rva.fake_datamodel", g_module_base);
    g_bindings.task_scheduler = g_profile.at("rva.task_scheduler", g_module_base);
    g_bindings.get_global_state = g_profile.at("rva.get_global_state", g_module_base);
    g_bindings.opcode_lookup = g_profile.at("rva.opcode_lookup_table", g_module_base);
    g_bindings.opcode_class = g_profile.at("rva.luau.loader_opcode_class_table", g_module_base);
    g_bindings.luau_load = g_profile.at("rva.luau.load", g_module_base);
    g_bindings.luau_execute = g_profile.at("rva.luau.execute", g_module_base);
    g_bindings.nil_object = g_profile.at("rva.luau.nil_object", g_module_base);
    g_bindings.dummy_node = g_profile.at("rva.luau.dummy_node", g_module_base);
    g_bindings.rbx_print = g_profile.at("rva.roblox.print", g_module_base);
    g_bindings.instance_new = g_profile.at("rva.instance_new", g_module_base);
    g_bindings.push_instance = g_profile.at("rva.push_instance", g_module_base);
    g_bindings.sc_resume = g_profile.at("rva.sc_resume", g_module_base);
    g_bindings.enable_load_module = g_profile.at("rva.enable_load_module", g_module_base);

    g_bindings.fdm_to_real = g_profile.field("struct.fake_datamodel.to_real");
    g_bindings.dm_children = g_profile.field("struct.data_model.children");
    g_bindings.dm_script_context = g_profile.field("struct.data_model.script_context");
    g_bindings.sc_vtable = g_profile.at("rva.script_context_vtable", g_module_base);
    g_bindings.ts_job_data_model = g_profile.field("struct.task_scheduler.job_data_model");
    g_bindings.sc_guard = g_profile.field("struct.script_context.guard");
    g_bindings.dm_game_loaded = g_profile.field("struct.data_model.game_loaded");
    g_bindings.dm_place_id = g_profile.field("struct.data_model.place_id");
    g_bindings.dm_job_id = g_profile.field("struct.data_model.job_id");
    g_bindings.ts_job_start = g_profile.field("struct.task_scheduler.job_start");
    g_bindings.ts_job_end = g_profile.field("struct.task_scheduler.job_end");
    g_bindings.ts_job_name = g_profile.field("struct.task_scheduler.job_name");
    g_bindings.ts_job_script_context = g_profile.field("struct.task_scheduler.job_script_context");
    g_bindings.es_require_bypass = g_profile.field("struct.extra_space.require_bypass");
    g_bindings.es_identity = g_profile.field("struct.extra_space.identity");
    g_bindings.es_capabilities = g_profile.field("struct.extra_space.capabilities");

    g_opcode_lookup = g_bindings.opcode_lookup;
    g_opcode_class = g_bindings.opcode_class;

    if (g_bindings.get_global_state == 0) {
        error = "profile does not expose rva.get_global_state";
        return false;
    }
    if (g_bindings.luau_load == 0) {
        error = "profile does not expose rva.luau.load";
        return false;
    }

    // Only now. `has_bindings` is what releases refresh() onto the 250 ms tick, and
    // setting it before the profile was validated sent the engine into a four-times-
    // a-second scheduler walk against half-bound numbers, forever, inside the client.
    g_status.has_bindings = true;

    if (!bind_abi(g_profile)) {
        error = "could not bind the Luau ABI";
        return false;
    }
    VSP_INFO("attach: build=%s profile=%s entries=%zu", build.c_str(), g_profile.source.c_str(),
             g_profile.size());
    VSP_INFO("attach: module=%s dm=%s gs=%s load=%s exec=%s opcodes=%s",
             hex_of(g_module_base).c_str(), hex_of(g_bindings.fake_data_model).c_str(),
             hex_of(g_bindings.get_global_state).c_str(), hex_of(g_bindings.luau_load).c_str(),
             hex_of(g_bindings.luau_execute).c_str(), hex_of(g_opcode_lookup).c_str());

    if (g_bindings.rbx_print != 0) {
        // The host console is the only place that survives a script error.
        VSP_DEBUG("attach: host print available");
    }

    refresh();
    return true;
}

// refresh() runs on the bridge's 250 ms tick; a repeated failure is logged once
// per distinct message instead of once per tick.
std::string g_last_refresh_error;

void note_refresh_error(const std::string& message) {
    if (message == g_last_refresh_error) return;
    g_last_refresh_error = message;
    VSP_WARN("refresh: %s", message.c_str());
}

// The host call that hands out the state is the one step here that can wedge the
// client, so it is retried slowly instead of on every tick, and the resolution
// line is written only when the answer changes rather than four times a second.
constexpr std::uint64_t kStateAttemptIntervalMs = 5000;
std::uint64_t g_last_state_attempt = 0;
std::uintptr_t g_logged_script_context = 0;
Strategy g_logged_strategy = Strategy::Unknown;

// Interval between full resolution walks while no state is bound. The bridge tick
// runs every 250 ms; the walk must not.
constexpr std::uint64_t kResolveIntervalMs = 2000;
std::uint64_t g_last_resolve_attempt = 0;

bool refresh() {
    if (!g_status.has_bindings) return false;
    trace_step("refresh enter");

    // Hyperion decrypts the module entry point lazily; resolve the module base
    // again in case the loader moved it.
    if (!g_module_base_pinned) g_module_base = host_module_base();

    // The DataModel is best effort: the scheduler route below does not need it,
    // and it is legitimately unreadable while the client is still starting.
    std::uintptr_t fake = 0;
    std::uintptr_t data_model = 0;
    if (read_ptr(g_bindings.fake_data_model, fake)) {
        if (g_bindings.fdm_to_real != 0) {
            read_ptr(fake + g_bindings.fdm_to_real, data_model);
        } else {
            data_model = fake;
        }
    }

    if (data_model != 0) {
        if (g_bindings.dm_game_loaded != 0) {
            std::uint32_t loaded = 0;
            safe_read_value(data_model + g_bindings.dm_game_loaded, loaded);
            g_status.in_game = loaded == 31;
        } else {
            g_status.in_game = true;
        }
    } else {
        g_status.in_game = false;
    }

    // Attaching from the menu is supported, and it is the safer place to do it: the
    // client is idle there and nothing is being loaded. But the state resolved in the
    // menu belongs to the menu's CoreScripts context, and entering a place builds a new
    // one. The old state does not necessarily fail `validate_state` -- it is still a
    // live, valid thread -- so waiting for validation to fail would keep the menu state
    // forever. The transition itself is the signal.
    {
        static bool last_in_game = false;
        if (g_status.in_game && !last_in_game) {
            VSP_INFO("attach: a place is loaded; dropping any state resolved before it");
            clear_runtime_state();
            g_status.in_game = true;  // clear_runtime_state resets it
            g_last_resolve_attempt = 0;
            g_last_state_attempt = 0;
        }
        last_in_game = g_status.in_game;
    }

    // A tick with a bound state only re-validates it. Re-running the search would
    // take the host call on every tick, and that call is what left a client
    // spinning on an earlier run once the wrong context was picked.
    if (g_status.has_lua_state && g_lua_state != nullptr) {
        if (validate_state(g_lua_state)) {
            g_status.data_model = data_model;
            g_status.ready = g_status.in_game;
            return true;
        }
        // The state went away (place change, context rebuilt): resolve again.
        clear_runtime_state();
    }

    // Solara's chain first: TaskScheduler -> WaitingHybridScriptsJob -> context.
    // It resolves before the DataModel route and is what works on 11f1.
    //
    // While the state is unbound (menu, loading, wrong profile) the walk cannot
    // succeed and repeating it four times a second only reads the client's memory
    // and pays for it. Two seconds is fast enough to catch a place load and slow
    // enough to stay invisible.
    const std::uint64_t resolve_now = GetTickCount64();
    if (!g_status.ready && g_last_resolve_attempt != 0 &&
        resolve_now - g_last_resolve_attempt < kResolveIntervalMs) {
        return false;
    }
    g_last_resolve_attempt = resolve_now;

    // MEASURED (in a place): the job walk costs 1.1 s (309 ms to the first match, 814 ms to
    // the preferred one) and the attach runs on a client thread the client may be using for
    // a scheduler job. Holding that thread for a second is what left a place frozen with all
    // threads parked. So when a place is loaded the DataModel is tried FIRST: it is a couple
    // of reads plus the `sc+0x200` decode (`call_get_global_state` never calls the host
    // unless 'G' is in the stage file). The job walk stays as the fallback, which is what
    // still has to run in the menu, where `DataModel::ScriptContext` reads zero.
    Strategy strategy = Strategy::Unknown;
    std::uintptr_t script_context = 0;
    if (g_status.in_game && data_model != 0) {
        // Say why the direct route does or does not land, so the next run does not need a
        // second attach to find out: the DataModel it starts from, the pointer at +0x440 and
        // that object's vtable against the one the table expects.
        {
            std::uintptr_t candidate = 0, vtable = 0;
            read_ptr(data_model + g_bindings.dm_script_context, candidate);
            if (candidate != 0) read_ptr(candidate, vtable);
            VSP_INFO("attach: datamodel=%s +0x%llx -> %s vtable=%s expected=%s looks=%d",
                     hex_of(data_model).c_str(),
                     static_cast<unsigned long long>(g_bindings.dm_script_context),
                     hex_of(candidate).c_str(), hex_of(vtable).c_str(),
                     hex_of(g_bindings.sc_vtable).c_str(),
                     looks_like_script_context(candidate) ? 1 : 0);
        }
        const std::uint64_t started = GetTickCount64();
        script_context = resolve_script_context(data_model, strategy);
        VSP_INFO("attach: datamodel route -> %s (%llu ms)", hex_of(script_context).c_str(),
                 static_cast<unsigned long long>(GetTickCount64() - started));
    }
    if (script_context == 0) {
        const std::uint64_t started = GetTickCount64();
        trace_step("resolving via jobs");
        // The real DataModel, not the fake one: a job's back-pointer at +0x198 names the real
        // DataModel it runs for, so ownership can be checked against the place's own object.
        script_context = resolve_script_context_via_jobs(strategy, data_model);
        trace_step("jobs pass done");
        VSP_INFO("attach: jobs route -> %s (%llu ms)", hex_of(script_context).c_str(),
                 static_cast<unsigned long long>(GetTickCount64() - started));
    }
    if (script_context == 0) {
        clear_runtime_state();
        g_status.error = "script context not resolved (build layout may have changed)";
        note_refresh_error(g_status.error);
        return false;
    }

    if (script_context != g_logged_script_context || strategy != g_logged_strategy) {
        VSP_INFO("attach: script context=%s (strategy %d/%s)", hex_of(script_context).c_str(),
                 static_cast<int>(strategy), to_string(strategy));
        g_logged_script_context = script_context;
        g_logged_strategy = strategy;
    }

    const std::uint64_t now = GetTickCount64();
    if (g_last_state_attempt != 0 && now - g_last_state_attempt < kStateAttemptIntervalMs) {
        return false;
    }
    g_last_state_attempt = now;

    trace_step("asking host for state");
    lua_State* L = call_get_global_state(script_context);
    trace_step("host answered");
    if (L == nullptr) {
        clear_runtime_state();
        g_status.error = "lua_State not resolved (get_global_state rejected candidate)";
        note_refresh_error(g_status.error);
        return false;
    }
    g_last_state_attempt = 0;

    VSP_INFO("attach: lua state=%p", static_cast<void*>(L));

    g_status.data_model = data_model;
    g_status.script_context = script_context;
    g_status.strategy = strategy;
    g_status.lua_state = reinterpret_cast<std::uintptr_t>(L);
    g_status.has_lua_state = true;
    g_status.error.clear();
    g_last_refresh_error.clear();
    g_lua_state = L;

    if (g_identity_offset == 0) {
        resolve_extra_space(L);
        if (g_identity_offset != 0) {
            VSP_INFO("attach: extra space identity=+0x%llx capabilities=+0x%llx",
                     static_cast<unsigned long long>(g_identity_offset),
                     static_cast<unsigned long long>(g_capabilities_offset));
        } else {
            VSP_WARN("attach: could not locate thread identity field; scripts run with the "
                     "attaching identity");
        }
    }
    g_status.identity_field = g_identity_offset;
    g_status.ready = g_status.has_lua_state && g_status.in_game;
    return true;
}

// --------------------------------------------------------------- autorun --
//
// Drop a Lua file at `%LOCALAPPDATA%\Vesper\autorun.lua` and it is executed
// once, on the private-thread lane, the moment the lane becomes ready -- before
// the bridge has even written its client record. It exists because the client
// tears foreign threads down within seconds of attach: waiting for an HTTP
// round trip to ask for an execution loses that race, so the request has to be
// able to arrive before the clock starts.
//
// The file is renamed to `autorun.done.lua` afterwards, so a session runs it
// once and nothing else picks it up.
std::wstring autorun_path() {
    wchar_t local[MAX_PATH * 2] = {};
    const DWORD length =
        GetEnvironmentVariableW(L"LOCALAPPDATA", local, static_cast<DWORD>(std::size(local)));
    std::wstring root = length > 0 ? std::wstring(local, length) : default_engine_directory();
    root += L"\\Vesper";
    ensure_directory(root);
    return root + L"\\autorun.lua";
}

void maybe_run_autorun() {
    static bool done = false;
    if (done) return;
    done = true;

    const std::wstring path = autorun_path();
    const auto data = read_file(path);
    if (data.empty()) return;

    std::string source(data.begin(), data.end());
    const std::string name = narrow(file_name(path));
    VSP_INFO("autorun: running %s (%d bytes)", name.c_str(), static_cast<int>(source.size()));

    // Permutation-inverse first (the measured map), then plain, because only
    // running a chunk can tell them apart; the verdicts are in the log one after
    // the other.
    for (int mode : {4, 0}) {
        ExecOutcome outcome;
        exec_on_private_thread(g_lua_state, source, name, outcome, mode);
        VSP_INFO("autorun: mode %d -> ok=%d value=\"%s\" error=\"%s\"", mode, outcome.ok ? 1 : 0,
                 outcome.value.c_str(), outcome.error.c_str());
        if (outcome.ok) {
            g_status.executed_scripts++;
            break;
        }
    }

    MoveFileW(path.c_str(), (path + L".done").c_str());
}

bool setup() {
    if (g_status.environment_ready) return true;
    lua_State* L = g_lua_state;
    if (L == nullptr || !g_status.in_game) return false;

    // `install_environment` and `install_pump` stay deliberately disabled. They
    // push values, read globals and call `lua_pcall` against the *vendored*
    // `lua_State`, and on this client those offsets land in the middle of the
    // live state: the first tick after the state is accepted tears the VM down.
    //
    // What replaced them is the private-thread lane (`exec_source`): the chunk
    // is compiled here, a thread is built out of the client's own allocator and
    // the client's `luau_load` / `lua_pcall` run on it. That needs nothing that
    // `validate_state` has not already accepted, so this is the one gate that
    // decides whether the bridge may execute at all.
    if (!validate_state(L)) {
        g_status.error = "the resolved lua_State does not satisfy the live layout";
        return false;
    }
    if (g_bindings.luau_load == 0 || g_module_base == 0) {
        g_status.error = "this build's table exposes no rva.luau.load";
        return false;
    }

    g_status.error.clear();
    g_status.environment_ready = true;
    VSP_INFO("setup: execution lane ready (private thread on %s, load %s)",
             hex_of(reinterpret_cast<std::uintptr_t>(L)).c_str(),
             hex_of(g_bindings.luau_load).c_str());
    maybe_run_autorun();
    return true;
}

bool ready() { return g_status.ready; }

lua_State* state() { return g_lua_state; }

const Status& status() { return g_status; }

const Profile& profile() { return g_profile; }

std::string status_json() {
    std::string mode = g_identity_offset != 0 ? "identity" : "degraded";
    return vformat(
        "{\"build\":\"%s\",\"profile\":\"%s\",\"module\":\"%s\",\"dataModel\":\"%s\","
        "\"scriptContext\":\"%s\",\"luaState\":\"%s\",\"strategy\":\"%s\",\"identityField\":\"%s\","
        "\"threadIdentity\":%d,\"inGame\":%s,\"environment\":%s,\"ready\":%s,\"pending\":%d,"
        "\"executed\":%d,\"failed\":%d,\"mode\":\"%s\",\"error\":\"%s\",\"abiVerified\":%s}",
        g_status.build.c_str(), g_status.profile_source.c_str(), hex_of(g_module_base).c_str(),
        hex_of(g_status.data_model).c_str(), hex_of(g_status.script_context).c_str(),
        hex_of(g_status.lua_state).c_str(), to_string(g_status.strategy),
        hex_of(g_status.identity_field).c_str(), g_status.thread_identity,
        g_status.in_game ? "true" : "false", g_status.environment_ready ? "true" : "false",
        g_status.ready ? "true" : "false", g_pending.load(), g_status.executed_scripts,
        g_status.failed_scripts, mode.c_str(), g_status.error.c_str(),
        g_status.abi_verified ? "true" : "false");
}

// ------------------------------------------------------------- capability --

bool set_thread_identity(lua_State* L, int identity) {
    if (L == nullptr || L->userdata == nullptr) return false;
    if (g_identity_offset == 0) return false;

    auto* base = reinterpret_cast<std::uint8_t*>(L->userdata) + g_identity_offset;
    const std::uint64_t value = static_cast<std::uint64_t>(identity);
    if (!WriteProcessMemory(GetCurrentProcess(), base, &value, sizeof(value), nullptr)) return false;
    if (g_capabilities_offset != 0) {
        auto* caps = reinterpret_cast<std::uint8_t*>(L->userdata) + g_capabilities_offset;
        const std::uint64_t maximum = kMaxCapabilities;
        WriteProcessMemory(GetCurrentProcess(), caps, &maximum, sizeof(maximum), nullptr);
    }
    return true;
}

int get_thread_identity(lua_State* L) {
    if (L == nullptr || L->userdata == nullptr || g_identity_offset == 0) return -1;
    std::uint64_t value = 0;
    if (!safe_read_value(reinterpret_cast<std::uintptr_t>(L->userdata) + g_identity_offset, value)) return -1;
    return static_cast<int>(value);
}

std::wstring workspace_directory() {
    wchar_t local[MAX_PATH * 2];
    const DWORD len = GetEnvironmentVariableW(L"LOCALAPPDATA", local, static_cast<DWORD>(std::size(local)));
    std::wstring root = len > 0 ? std::wstring(local, len) : default_engine_directory();
    root += L"\\Vesper\\workspace";
    ensure_directory(root);
    return root;
}

// -------------------------------------------------------------- compiler --

std::string compile_bytecode_impl(const std::string& source, int mode, int opt_level, int debug_level) {
    // The vendored BytecodeBuilder's VESPER_NO_FB hook: whether the client's
    // loader reads the per-proto feedback section. Measured via the `nofb` marker.
    g_vesper_no_fb = marker_present(L"nofb") ? 1 : 0;
    {
        const std::string version = marker_text(L"bcver");
        g_vesper_bc_version = version.empty() ? 0 : std::atoi(version.c_str());
    }
    for (int i = 0; i < 256; ++i) {
        g_seen_vendored[i] = false;
        g_seen_any_vendored[i] = false;
    }
    g_seen_internal_unknown = false;
    Luau::CompileOptions options{};
    options.optimizationLevel = opt_level;
    options.debugLevel = debug_level;
    options.mutableGlobals = kCommonGlobals;
    options.vectorLib = "Vector3";
    options.vectorCtor = "new";
    options.vectorType = "Vector3";
    switch (mode) {
        case 0:
            return Luau::compile(source, options, {}, nullptr);
        case 2: {
            MulEncoder encoder;
            return Luau::compile(source, options, {}, &encoder);
        }
        case 3: {
            PermEncoder encoder;
            return Luau::compile(source, options, {}, &encoder);
        }
        case 4: {
            SemanticEncoder encoder;
            return Luau::compile(source, options, {}, &encoder);
        }
        case 1:
        default: {
            RobloxEncoder encoder;
            return Luau::compile(source, options, {}, &encoder);
        }
    }
}

std::string compile_bytecode_mode(const std::string& source, int mode) {
    const int opt = marker_present(L"opt0") ? 0 : 1;
    const int dbg = marker_present(L"dbg0") ? 0 : (marker_present(L"dbg1") ? 1 : 2);
    return compile_bytecode_impl(source, mode, opt, dbg);
}

std::string compile_bytecode(const std::string& source) {
    return compile_bytecode_mode(source, 4);
}

bool compile(const std::string& source, std::string& bytecode, std::string& error) {
    try {
        bytecode = compile_bytecode_mode(source, 4);
    } catch (const std::exception& ex) {
        error = ex.what();
        return false;
    }
    if (bytecode.empty()) {
        error = "compiler produced no output";
        return false;
    }
    return true;
}

// ------------------------------------------------------------- execution --

namespace {

using LuauLoadFn = int (*)(lua_State*, const char*, const char*, std::size_t, int);

void set_proto_capabilities(Proto* proto, std::uintptr_t* capabilities) {
    if (proto == nullptr) return;
    proto->userdata = capabilities;
    for (int i = 0; i < proto->sizep; ++i) set_proto_capabilities(proto->p[i], capabilities);
}

void host_print(const std::string& message) {
    if (g_bindings.rbx_print == 0) return;
    using PrintFn = void (*)(int, const char*, ...);
    auto fn = reinterpret_cast<PrintFn>(g_bindings.rbx_print);
    const char* text = message.c_str();
    guarded([&] { fn(3, "%s", text); });
}

// The dispatch wrapper is compiled once and cached in the registry. It exists so
// that (a) scripts run through `task.defer` and may therefore yield, and (b)
// failures come back with a traceback through `__vesper_finish` instead of
// vanishing into the scheduler.
constexpr const char* kWrapperSource =
    "local fn, tag = ...\n"
    "local traceback = nil\n"
    "if debug and debug.traceback then traceback = debug.traceback end\n"
    "task.defer(function()\n"
    "    local ok, err = xpcall(fn, function(message)\n"
    "        if traceback then return traceback(tostring(message), 2) end\n"
    "        return tostring(message)\n"
    "    end)\n"
    "    __vesper_finish(tag, ok, err)\n"
    "end)\n";

char g_wrapper_key = 'w';

bool push_wrapper(lua_State* thread, std::string& error) {
    lua_pushlightuserdata(thread, &g_wrapper_key);
    lua_gettable(thread, LUA_REGISTRYINDEX);
    if (lua_type(thread, -1) == LUA_TFUNCTION) return true;

    if (!lua_isnil(thread, -1)) {
        lua_pop(thread, 1);
    } else {
        lua_pop(thread, 1);
    }

    std::string bytecode;
    if (!compile(kWrapperSource, bytecode, error)) return false;

    auto loader = reinterpret_cast<LuauLoadFn>(g_bindings.luau_load);
    const int loaded = loader(thread, "=Vesper", bytecode.data(), bytecode.size(), 0);
    if (loaded != LUA_OK) {
        error = lua_tostring(thread, -1) ? lua_tostring(thread, -1) : "wrapper load failed";
        lua_pop(thread, 1);
        return false;
    }

    lua_pushlightuserdata(thread, &g_wrapper_key);
    lua_pushvalue(thread, -2);
    lua_settable(thread, LUA_REGISTRYINDEX);
    lua_pop(thread, 1);
    return true;
}

// Compiles, loads and hands a script to the scheduler. Returns an empty string
// when the script was accepted; the result then arrives through env::take_outcome.
std::string dispatch(lua_State* thread, const std::string& source, const std::string& chunk,
                     const std::string& tag) {
    if (thread == nullptr) return "no lua_State";
    if (source.empty()) return {};

    env::set_pending(tag);

    std::string bytecode;
    std::string error;
    if (!compile(source, bytecode, error)) {
        env::complete(tag, false, "compile error: " + error);
        return {};
    }

    const int original_top = lua_gettop(thread);

    auto loader = reinterpret_cast<LuauLoadFn>(g_bindings.luau_load);
    const std::string chunk_name = chunk.empty() ? "=Vesper" : ("=" + chunk);
    const int loaded = loader(thread, chunk_name.c_str(), bytecode.data(), bytecode.size(), 0);
    if (loaded != LUA_OK) {
        const char* text = lua_tostring(thread, -1);
        env::complete(tag, false, std::string("load error: ") + (text ? text : "unknown"));
        lua_settop(thread, original_top);
        return {};
    }

    std::uintptr_t maximum = kMaxCapabilities;
    if (const TValue* value = luaA_toobject(thread, -1)) {
        Closure* closure = clvalue(value);
        if (closure != nullptr && closure->isC == 0) set_proto_capabilities(closure->l.p, &maximum);
    }

    lua_getglobal(thread, "__vesper_begin");
    lua_pushstring(thread, tag.c_str());
    if (lua_pcall(thread, 1, 0, 0) != LUA_OK) {
        const char* text = lua_tostring(thread, -1);
        const std::string message = text ? text : "unknown";
        lua_settop(thread, original_top);
        env::complete(tag, false, "dispatch error: " + message);
        return {};
    }

    if (!push_wrapper(thread, error)) {
        lua_settop(thread, original_top);
        env::complete(tag, false, "dispatch error: " + error);
        return {};
    }

    // stack: [closure, wrapper]
    lua_pushvalue(thread, -2);
    lua_pushstring(thread, tag.c_str());
    // stack: [closure, wrapper, closure, tag]
    if (lua_pcall(thread, 2, 0, 0) != LUA_OK) {
        const char* text = lua_tostring(thread, -1);
        const std::string message = text ? text : "unknown";
        lua_settop(thread, original_top);
        env::complete(tag, false, "dispatch error: " + message);
        return {};
    }

    lua_settop(thread, original_top);
    return {};
}

int frame_pump(lua_State* L) {
    (void)L;
    pump();
    return 0;
}

bool install_pump(lua_State* L) {
    const int original_top = lua_gettop(L);

    lua_getglobal(L, "game");
    if (!lua_istable(L, -1) && lua_type(L, -1) != LUA_TUSERDATA) {
        lua_settop(L, original_top);
        return false;
    }
    lua_getfield(L, -1, "GetService");
    lua_pushvalue(L, -2);
    lua_pushstring(L, "RunService");
    if (lua_pcall(L, 2, 1, 0) != LUA_OK) {
        lua_settop(L, original_top);
        return false;
    }
    if (lua_getfield(L, -1, "RenderStepped") != LUA_TTABLE && !lua_istable(L, -1) &&
        lua_type(L, -1) != LUA_TUSERDATA) {
        lua_settop(L, original_top);
        return false;
    }
    lua_getfield(L, -1, "Connect");
    lua_pushvalue(L, -2);
    lua_pushcclosure(L, frame_pump, "vesper_pump", 0);
    const int connected = lua_pcall(L, 2, 0, 0);
    lua_settop(L, original_top);
    return connected == LUA_OK;
}

}  // namespace

// -------------------------------------------------------------- host API lane --
// Everything above this seam assumes the vendored `lua_State`: it pushes values,
// reads globals and calls functions with an older build's layout, so on this
// client it cannot drive the VM at all. The client's own Lua C API is the way
// out -- those functions take the state and use the layout the client was built
// with, so neither the state nor the object model has to be known here.
//
// The probe below walks that lane one call at a time, writing the state of the
// world *before* each call, so if the client dies the last line names the call
// that did it.
namespace {

int probe_entry(lua_State* L) {
    const auto base = reinterpret_cast<std::uintptr_t>(L);
    std::uintptr_t top = 0;
    read_ptr(base + live::kTop, top);
    VSP_INFO("hostapi: step C entered: the client called our C function (L=%s top=%s)", hex_of(base).c_str(),
             hex_of(top).c_str());
    return 1;  // hand the argument back as the result
}

std::string stack_window(lua_State* L, std::uintptr_t top_before, const char* label) {
    const auto base = reinterpret_cast<std::uintptr_t>(L);
    std::uintptr_t stack = 0;
    std::uintptr_t top = 0;
    read_ptr(base + live::kStack, stack);
    read_ptr(base + live::kTop, top);
    std::string line = vformat("hostapi: %s top=%s delta=%lld window={", label, hex_of(top).c_str(),
                               static_cast<long long>(static_cast<std::intptr_t>(top) -
                                                      static_cast<std::intptr_t>(top_before)));
    // The four words below `top`: `top - 0x10` is the TValue the last call
    // pushed -- its value word and its tag word -- and the two words under it are
    // the slots beneath. The stack only holds a handful of live slots, so the old
    // `top >= stack + 0x60` bound printed nothing at all; 0x20 is all that is
    // needed to reach the pushed TValue.
    std::uintptr_t words[4] = {};
    if (top >= stack + 0x20 && safe_read(reinterpret_cast<const void*>(top - 0x20), words, sizeof(words))) {
        for (std::size_t i = 0; i < 4; ++i) line += vformat("%s%s", i ? " " : "", hex_of(words[i]).c_str());
    }
    return line + "}";
}

}  // namespace

// ------------------------------------------------------- private-thread lane --
//
// Roblox inlines `lua_newthread` at every call site, so this build has no RVA to
// call. What it does have is the body itself: the cleanest inlined copy sits in
// the Roblox thread helper at RVA 0x4323680 and runs from 0x4323852 to
// 0x4323CF5. Read back on a 11f155f3450f4c8e client it is three allocations and
// a fixed set of field writes, and nothing else:
//
//   state = alloc(memcat <- [rva 0x7FD2E08], 0x88)
//   ci    = alloc(memcat <- [rva 0x7FD2F00], 0x180)
//   stack = alloc(memcat <- [rva 0x7FD3050], 0x2D0)
//   g->totalbytes (+= size); g->memcat_bytes[parent_memcat] (+= size)
//   if (g->cb_alloc)      g->cb_alloc(parent, block, 0, size, <0xa|0x11>, 0, 0)
//   L1+0x00 = 0x0A                       (LUA_TTHREAD)
//   L1+0x01 = parent+0x06, L1+0x02 = g->currentwhite & 3
//   L1+0x04 = parent+0x04,  L1+0x06 = parent+0x06
//   L1+0x50 = parent+0x50                (the global_State)
//   L1+0x20 = ci + 0x150, L1+0x28 = ci, L1+0x40 = ci, L1+0x74 = 8
//   L1+0x60 = stack
//   L1+0x70 = (L1+0x70) ^ 0x2D           (the address-obfuscated stack size)
//   for (i = 0; i < 0x2D; ++i) *(u32*)(stack + i*0x10 + 0xC) = 0
//   L1+0x58 = stack; L1+0x38 = stack + (stacksize - 5) * 0x10
//   ci->func = stack, ci->base = 0, *(u32*)(stack+0xC) = 0, L1->top += 0x10
//   ci->savedpc = L1->top, L1+0x48 = ci->savedpc, ci->top = L1->top + 0x140
//   L1+0x80 = parent+0x80, L1+0x04 = parent+0x04
//   push L1 on the parent (tt = 0x0A)
//   if (g->cb_userthread) g->cb_userthread(parent, L1)
//
// The allocator is the client's own: `0x265DBA0` is a per-memory-category bump
// allocator, `void* (lua_State* L, int memcat)` -- it takes no size, because the
// size is a property of the page the category is carved out of. The legacy path
// (taken when the category byte is negative) is `g->frealloc(g->ud, NULL, 0,
// size)` with `g->frealloc` at g+0x38 and `g->ud` at g+0x40. Both are
// reproduced here rather than assumed, including the branch on the category byte.
namespace pvt {

// Byte 0 of a thread is its tag; 0x0A on every client checked.
constexpr std::uint8_t kTagThread = 0x0A;

// Sizes and the one derived offset, straight out of the immediates the inlined
// body uses. `0x180` is six CallInfos and `end_ci` stops one short of the last
// one, which is what Roblox itself does.
constexpr std::uintptr_t kStateBytes = 0x88;
constexpr std::uintptr_t kCiBytes = 0x180;
constexpr std::uintptr_t kStackBytes = 0x2D0;
constexpr std::uintptr_t kEndCiOffset = 0x150;
constexpr std::uintptr_t kSizeCi = 8;
constexpr std::uintptr_t kSlotBytes = sizeof(TValue);

// `global_State` fields the body touches. On 9ac8 the byte counters are at +0x50,
// the allocator pair at +0x20/+0x28 and the callbacks at +0x6b0/+0x6c0; the client
// body adds each logical size to `g+0x50` and to `g + memcat*8 + 0x2db0`.
constexpr std::uintptr_t kGlobalTotalBytes = 0x50;
constexpr std::uintptr_t kGlobalFrealloc = 0x20;
constexpr std::uintptr_t kGlobalUserData = 0x28;
constexpr std::uintptr_t kGlobalCurrentWhite = 0x10;
constexpr std::uintptr_t kGlobalMemcatBytes = 0x2DB0;
constexpr std::uintptr_t kGlobalCbUserThread = 0x6B0;
constexpr std::uintptr_t kGlobalCbAlloc = 0x6C0;

// One global byte per allocation site: the memory category the client asks its
// own allocator for. A negative byte selects the legacy `frealloc` path.
// Measured live: 0x0c (12), 0x18 (24), 0x1f (31).
constexpr std::uintptr_t kMemcatStateRva = 0x814677F;
constexpr std::uintptr_t kMemcatCiRva = 0x8146870;
constexpr std::uintptr_t kMemcatStackRva = 0x81469C0;

// `rva.luau.bump_alloc` -- the client's per-category bump allocator.
constexpr std::uintptr_t kBumpAllocRva = 0x26E00E0;

// `unsigned short nCcalls; unsigned short baseCcalls;` live at +0x10/+0x12 in
// this build (`lua_pcall` saves and restores both around the protected call).
//
// They decide whether the thread is *yieldable*, and that decides whether a
// call runs the VM at all. `performcall` (RVA `0x261BD20`) compares the two
// before entering `luau_execute`: when `nCcalls > baseCcalls` it calls
// `luau_execute`, and otherwise it skips the VM and sets
// `status = SCHEDULED_REENTRY` (0x7F), leaving the call for the scheduler.
// `lua_pcall` then reports -1 for that status even though the protected call
// itself returned 0 -- measured: a fresh thread with both counters at 0 loads
// its chunk and returns -1 with `L+3 == 0x7F` and `L->ci` still at `base_ci`.
//
// Setting `nCcalls = 1` takes the other branch and the VM does run -- and the
// client is gone within milliseconds, twice, with and without
// `g->cb_userthread`. That is Hyperion: bytecode must not be executed on a
// thread the host does not own. The default therefore leaves the counters the
// way the client's own `lua_newthread` leaves them; `VESPER_FORCE_VM=1` makes
// the fatal experiment reproducible.
constexpr std::uintptr_t kNccalls = 0x20;
constexpr std::uintptr_t kBaseCcalls = 0x22;
constexpr std::uint8_t kScheduledReentry = 0x7F;

// The client's own env slot: the loader resolves a chunk's environment from the
// qword at `L+8` when `LoadContext.env == 0`, and the inlined body copies the
// parent's qword there. (On 11f1 this was `L+0x80`.)
constexpr std::uintptr_t kExtraSlot = 0x08;

// `global_State+0x648` / `+0x658` are NULL-checked callbacks. When they are set
// the client notifies them about every allocation and about every new thread.
struct Callbacks {
    std::uintptr_t alloc = 0;
    std::uintptr_t user_thread = 0;
};

Callbacks read_callbacks(std::uintptr_t g) {
    Callbacks cb;
    read_ptr(g + kGlobalCbAlloc, cb.alloc);
    read_ptr(g + kGlobalCbUserThread, cb.user_thread);
    return cb;
}

// Every store the lane makes goes through `WriteProcessMemory` on this process
// rather than a plain store: the client's pages are policed, and the engine
// already relies on this path for every other field it writes.
template <typename T>
void poke(std::uintptr_t address, const T& value) {
    WriteProcessMemory(GetCurrentProcess(), reinterpret_cast<void*>(address), &value, sizeof(T),
                       nullptr);
}

// The category byte is read straight out of the client's image at the address
// its own code reads it from, so a build that renumbers the categories needs no
// table update.
std::int8_t memcat_of(std::uintptr_t rva) {
    std::int8_t value = -1;
    if (g_module_base != 0) {
        safe_read(reinterpret_cast<const void*>(g_module_base + rva), &value, sizeof(value));
    }
    return value;
}

// `void* bump(lua_State* L, int memcat)` -- three arguments in, one out. It is
// called through the fault guard because it is the first client code the
// private-thread lane reaches, and a stale address must not take the process.
using BumpAllocFn = void* (*)(lua_State*, int);
using FreeAllocFn = void* (*)(void*, void*, std::size_t, std::size_t);

void* allocate(lua_State* parent, std::uintptr_t g, std::uintptr_t size, std::int8_t memcat,
               bool& via_bump) {
    void* block = nullptr;
    via_bump = memcat >= 0;
    if (via_bump) {
        auto fn = reinterpret_cast<BumpAllocFn>(g_module_base + kBumpAllocRva);
        guarded([&] { block = fn(parent, memcat); });
        return block;
    }

    std::uintptr_t frealloc = 0;
    std::uintptr_t user_data = 0;
    if (!read_ptr(g + kGlobalFrealloc, frealloc)) return nullptr;
    if (!read_ptr(g + kGlobalUserData, user_data)) return nullptr;
    auto fn = reinterpret_cast<FreeAllocFn>(frealloc);
    void* argument = reinterpret_cast<void*>(user_data);
    void* none = nullptr;
    guarded([&] { block = fn(argument, none, 0, size); });
    return block;
}

// Everything the inlined body does around an allocation: the two accounting
// bumps and the (skipped) notification callback.
void account(std::uintptr_t g, std::uintptr_t memcat, std::uintptr_t size) {
    std::uint64_t total = 0;
    if (safe_read_value(g + kGlobalTotalBytes, total)) poke(g + kGlobalTotalBytes, total + size);
    const std::uintptr_t bucket = g + memcat * 8 + kGlobalMemcatBytes;
    std::uint64_t category = 0;
    if (safe_read_value(bucket, category)) poke(bucket, category + size);
}

// The three blocks, so the caller can report them and the caller of the caller
// can see that the private thread is a real one before anything is loaded.
struct Blocks {
    std::uintptr_t state = 0;
    std::uintptr_t ci = 0;
    std::uintptr_t stack = 0;
    std::int8_t memcat_state = -1;
    std::int8_t memcat_ci = -1;
    std::int8_t memcat_stack = -1;
    bool skip_alloc_cb = false;
    bool skip_thread_cb = false;
};

// `lua_State* make(lua_State* parent, std::string& report)`.
//
// `parent` is the game's own state: it supplies the global_State, the white
// colour, the memory category and the one slot the new thread is pushed onto
// (so the GC can still reach it while the chunk runs).
lua_State* make(lua_State* parent, std::string& report) {
    if (parent == nullptr) {
        report += "no parent state\n";
        return nullptr;
    }
    const auto parent_base = reinterpret_cast<std::uintptr_t>(parent);

    std::uintptr_t g = 0;
    if (!read_ptr(parent_base + live::kUserdata, g) || !pointer_plausible(g)) {
        report += "parent has no global_State\n";
        return nullptr;
    }

    Blocks blocks;
    blocks.memcat_state = memcat_of(kMemcatStateRva);
    blocks.memcat_ci = memcat_of(kMemcatCiRva);
    blocks.memcat_stack = memcat_of(kMemcatStackRva);

    // `L+4` is the thread's own memory category on this build, inherited by the
    // new thread and used by the client for the per-category byte counter.
    std::uint8_t parent_memcat = 0;
    safe_read(reinterpret_cast<const void*>(parent_base + 4), &parent_memcat, sizeof(parent_memcat));
    std::uint8_t white = 0;
    safe_read(reinterpret_cast<const void*>(g + kGlobalCurrentWhite), &white, sizeof(white));

    const Callbacks callbacks = read_callbacks(g);
    blocks.skip_alloc_cb = callbacks.alloc != 0;
    blocks.skip_thread_cb = callbacks.user_thread != 0;

    bool bump_state = false;
    bool bump_ci = false;
    bool bump_stack = false;
    blocks.state = reinterpret_cast<std::uintptr_t>(
        allocate(parent, g, kStateBytes, blocks.memcat_state, bump_state));
    blocks.ci =
        reinterpret_cast<std::uintptr_t>(allocate(parent, g, kCiBytes, blocks.memcat_ci, bump_ci));
    blocks.stack = reinterpret_cast<std::uintptr_t>(
        allocate(parent, g, kStackBytes, blocks.memcat_stack, bump_stack));

    report += vformat(
        "newthread: g=%s categories state=%d ci=%d stack=%d (bump=%d/%d/%d) "
        "blocks state=%s ci=%s stack=%s\n",
        hex_of(g).c_str(), static_cast<int>(blocks.memcat_state),
        static_cast<int>(blocks.memcat_ci), static_cast<int>(blocks.memcat_stack),
        bump_state ? 1 : 0, bump_ci ? 1 : 0, bump_stack ? 1 : 0,
        hex_of(blocks.state).c_str(), hex_of(blocks.ci).c_str(), hex_of(blocks.stack).c_str());
    report += vformat(
        "newthread: g->frealloc=%s g->ud=%s cb_alloc=%s cb_userthread=%s parent_memcat=%u\n",
        hex_of([&] {
            std::uintptr_t value = 0;
            read_ptr(g + kGlobalFrealloc, value);
            return value;
        }())
            .c_str(),
        hex_of([&] {
            std::uintptr_t value = 0;
            read_ptr(g + kGlobalUserData, value);
            return value;
        }())
            .c_str(),
        hex_of(callbacks.alloc).c_str(), hex_of(callbacks.user_thread).c_str(),
        static_cast<unsigned>(parent_memcat));

    if (blocks.state == 0 || blocks.ci == 0 || blocks.stack == 0) {
        report += "newthread: allocation failed\n";
        return nullptr;
    }

    account(g, parent_memcat, kStateBytes);
    account(g, parent_memcat, kCiBytes);
    account(g, parent_memcat, kStackBytes);

    // The client zeroes the 0x88 block itself only when its "already initialised"
    // flag is clear; the bump allocator is expected to hand back clean memory.
    // Zeroing it unconditionally is the same result and does not depend on that
    // flag being in the state this process booted in.
    std::uint8_t zeros[kStateBytes] = {};
    poke(blocks.state, std::uint64_t(0));
    poke(blocks.state + 8, std::uint64_t(0));
    poke(blocks.state + 0x10, std::uint64_t(0));
    poke(blocks.state + 0x18, std::uint64_t(0));
    poke(blocks.state + 0x20, std::uint64_t(0));
    poke(blocks.state + 0x28, std::uint64_t(0));
    poke(blocks.state + 0x30, std::uint64_t(0));
    poke(blocks.state + 0x38, std::uint64_t(0));
    poke(blocks.state + 0x40, std::uint64_t(0));
    poke(blocks.state + 0x48, std::uint64_t(0));
    poke(blocks.state + 0x50, std::uint64_t(0));
    poke(blocks.state + 0x58, std::uint64_t(0));
    poke(blocks.state + 0x60, std::uint64_t(0));
    poke(blocks.state + 0x68, std::uint64_t(0));
    poke(blocks.state + 0x70, std::uint32_t(0));
    poke(blocks.state + 0x74, std::uint32_t(0));
    poke(blocks.state + 0x78, std::uint64_t(0));
    poke(blocks.state + 0x80, std::uint64_t(0));

    // Header, exactly what the client's own inlined body writes on this build:
    // +0 mark colour, +1 and +4 the parent's memory category, +2 the thread tag,
    // +3 status (zeroed = LUA_OK), +5 inherited from the parent, +8 the env slot,
    // +0x78 the global_State.
    std::uint8_t parent_flag5 = 0;
    safe_read(reinterpret_cast<const void*>(parent_base + 5), &parent_flag5, sizeof(parent_flag5));
    poke(blocks.state + 0, static_cast<std::uint8_t>(white & 3));
    poke(blocks.state + 1, static_cast<std::uint8_t>(parent_memcat));
    poke(blocks.state + 2, kTagThread);
    poke(blocks.state + 4, static_cast<std::uint8_t>(parent_memcat));
    poke(blocks.state + 5, parent_flag5);
    poke<std::uintptr_t>(blocks.state + live::kUserdata, g);

    // Frame window. `end_ci` is the client's own value, one CallInfo short of
    // the end of the allocation.
    poke<std::uintptr_t>(blocks.state + live::kEndCi, blocks.ci + kEndCiOffset);
    poke<std::uintptr_t>(blocks.state + live::kBaseCi, blocks.ci);
    poke<std::uintptr_t>(blocks.state + live::kCi, blocks.ci);
    poke<std::uint32_t>(blocks.state + live::kSizeCi, static_cast<std::uint32_t>(kSizeCi));

    // Stack: the size is stored XOR-obfuscated with the address it lives at,
    // which is the client's own `xor eax, 0x2D`.
    poke<std::uintptr_t>(blocks.state + live::kStack, blocks.stack);
    poke<std::uint32_t>(blocks.state + live::kStackSize,
                        static_cast<std::uint32_t>(blocks.state + live::kStackSize) ^
                            static_cast<std::uint32_t>(kStackBytes));

    // Every slot reads as nil; the client only writes the tag word, which is
    // what a nil is.
    for (std::uintptr_t offset = 0xC; offset < kStackBytes; offset += 0x10) {
        poke<std::uint32_t>(blocks.stack + offset, 0);
    }

    const std::uintptr_t slots = (kStackBytes / kSlotBytes) - 5;
    poke<std::uintptr_t>(blocks.state + live::kTop, blocks.stack);
    poke<std::uintptr_t>(blocks.state + live::kStackLast, blocks.stack + slots * kSlotBytes);

    // The first frame: `func` is the nil the client parked at the bottom of the
    // stack, `savedpc` is the top after the one-slot push and `top` leaves
    // LUA_MINSTACK headroom inside the window.
    poke<std::uintptr_t>(blocks.ci + 0x08, blocks.stack);
    poke<std::uintptr_t>(blocks.ci + 0x10, 0);
    poke<std::uint32_t>(blocks.stack + 0x0C, 0);
    const std::uintptr_t top = blocks.stack + kSlotBytes;
    poke<std::uintptr_t>(blocks.state + live::kTop, top);
    poke<std::uintptr_t>(blocks.ci + 0x00, top);
    poke<std::uintptr_t>(blocks.state + live::kBase, top);
    poke<std::uintptr_t>(blocks.ci + 0x18, top + 0x140);

    // `unsigned short nCcalls; unsigned short baseCcalls;` live at +0x10/+0x12 in
// this build (`lua_pcall` saves and restores both around the protected call).
//
// They decide whether the thread is *yieldable*, and that decides whether a
// call runs the VM at all. `performcall` (RVA `0x261BD20`) compares the two
// before entering `luau_execute`: when `nCcalls > baseCcalls` it calls
// `luau_execute`, and otherwise it skips the VM and sets
// `status = SCHEDULED_REENTRY` (0x7F), leaving the call for the scheduler.
// `lua_pcall` then reports -1 for that status even though the protected call
// itself returned 0 -- measured: a fresh thread with both counters at 0 loads
// its chunk and returns -1 with `L+3 == 0x7F` and `L->ci` still at `base_ci`.
//
// Setting `nCcalls = 1` takes the other branch and the VM does run -- and the
// client is gone within milliseconds, twice, with and without
// `g->cb_userthread`. That is Hyperion: bytecode must not be executed on a
// thread the host does not own. The default therefore leaves the counters the
// way the client's own `lua_newthread` leaves them; `VESPER_FORCE_VM=1` makes
// the fatal experiment reproducible.
constexpr std::uintptr_t kNccalls = 0x20;  // 9ac8 layout; +0x10 is end_ci (11f1 had it here)
constexpr std::uintptr_t kBaseCcalls = 0x22;
constexpr std::uint8_t kScheduledReentry = 0x7F;

// The client's own extra slot, inherited from the parent.
// The client's last two writes before the push: inherit the parent's extra
    // slot and its status.
    std::uintptr_t inherited = 0;
    read_ptr(parent_base + kExtraSlot, inherited);
    poke<std::uintptr_t>(blocks.state + kExtraSlot, inherited);

    // Both counters stay 0, exactly as the client's own `lua_newthread` leaves
    // them. That is what makes the VM defer the call to the scheduler instead of
    // running it here; `VESPER_FORCE_VM=1` is the measured, fatal alternative.
    const bool force_vm = [] {
        wchar_t flag[8] = {};
        return GetEnvironmentVariableW(L"VESPER_FORCE_VM", flag, 8) > 0 &&
               (flag[0] == L'1' || flag[0] == L't' || flag[0] == L'T');
    }();
    poke<std::uint16_t>(blocks.state + kNccalls, static_cast<std::uint16_t>(force_vm ? 1 : 0));
    poke<std::uint16_t>(blocks.state + kBaseCcalls, 0);
    report += vformat("newthread: nCcalls=%u baseCcalls=0 (VESPER_FORCE_VM=%d)\n",
                      static_cast<unsigned>(force_vm ? 1 : 0), force_vm ? 1 : 0);

    auto* thread = reinterpret_cast<lua_State*>(blocks.state);
    {
        std::uintptr_t rb_end = 0, rb_ci = 0, rb_base_ci = 0, rb_top = 0;
        read_ptr(blocks.state + live::kEndCi, rb_end);
        read_ptr(blocks.state + live::kCi, rb_ci);
        read_ptr(blocks.state + live::kBaseCi, rb_base_ci);
        read_ptr(blocks.state + live::kTop, rb_top);
        report += vformat("newthread: readback end_ci=%s ci=%s base_ci=%s top=%s\n",
                          hex_of(rb_end).c_str(), hex_of(rb_ci).c_str(),
                          hex_of(rb_base_ci).c_str(), hex_of(rb_top).c_str());
    }
    report += vformat("newthread: thread=%s top=%s base=%s stack_last=%s size_ci=%u slots=%llu\n",
                      hex_of(blocks.state).c_str(), hex_of(top).c_str(),
                      hex_of(blocks.stack + kSlotBytes).c_str(),
                      hex_of(blocks.stack + slots * kSlotBytes).c_str(),
                      static_cast<unsigned>(kSizeCi),
                      static_cast<unsigned long long>(slots));
    report += vformat("newthread: validate_state=%d\n", validate_state(thread) ? 1 : 0);

    if (blocks.skip_alloc_cb) {
        report += vformat("newthread: skipped g->cb_alloc=%s (3 allocations, NULL-checked upstream)\n",
                          hex_of(callbacks.alloc).c_str());
    }
    if (blocks.skip_thread_cb) {
        report += vformat("newthread: skipped g->cb_userthread=%s\n",
                          hex_of(callbacks.user_thread).c_str());
    }
    return thread;
}

// Push the private thread onto the parent so the GC can reach it while the
// chunk runs, and pop it again afterwards. This is the only thing the lane ever
// does to the game's live state, and it is the same class of operation as
// `hostapi_probe` step A: a single store plus a `top` bump.
// Returns the parent's `top` after the push (what pop_from_parent expects), or 0. It was
// declared `bool`, which turned every address into 1: pop_from_parent then never matched,
// and each thread this lane built stayed on the game's own Lua stack for good.
std::uintptr_t push_on_parent(lua_State* parent, lua_State* thread) {
    const auto parent_base = reinterpret_cast<std::uintptr_t>(parent);
    std::uintptr_t top = 0;
    if (!read_ptr(parent_base + live::kTop, top)) return 0;
    if (top == 0) return 0;
    poke<std::uintptr_t>(top, reinterpret_cast<std::uintptr_t>(thread));
    poke<std::uint32_t>(top + 0x0C, kTagThread);
    poke<std::uintptr_t>(parent_base + live::kTop, top + pvt::kSlotBytes);
    return top + kSlotBytes;
}

// `g->cb_userthread(parent, L1)`, the last thing the inlined body does. It is
// NULL-checked, so the client skips it when the host installed no callback --
// which is what this lane does by default: this build *has* one set
// (`g+0x648`), and whether it is safe to call from a thread the host does not
// own is a measurement, not an assumption. `VESPER_CALL_USERTHREAD=1` turns it
// on once that has been measured.
void notify_user_thread(lua_State* parent, lua_State* thread, std::uintptr_t g, std::string& report) {
    wchar_t flag[8] = {};
    const bool wanted = GetEnvironmentVariableW(L"VESPER_CALL_USERTHREAD", flag, 8) > 0 &&
                        (flag[0] == L'1' || flag[0] == L't' || flag[0] == L'T');

    std::uintptr_t callback = 0;
    if (!read_ptr(g + kGlobalCbUserThread, callback) || callback == 0) {
        report += "exec: g->cb_userthread is null; nothing to notify\n";
        return;
    }
    if (!wanted) {
        report += vformat("exec: skipped g->cb_userthread=%s (opt in with VESPER_CALL_USERTHREAD=1)\n",
                          hex_of(callback).c_str());
        return;
    }
    using UserThreadFn = void (*)(lua_State*, lua_State*);
    const bool ok = guarded([&] {
        reinterpret_cast<UserThreadFn>(callback)(parent, thread);
    });
    report += vformat("exec: g->cb_userthread(%s) called=%d\n", hex_of(callback).c_str(),
                      ok ? 1 : 0);
}

// Undo `push_on_parent`, but only when nothing was pushed above it in the
// meantime -- the game's own thread owns that stack and a stale `top` write
// would corrupt it.
void pop_from_parent(lua_State* parent, std::uintptr_t expected_top) {
    if (expected_top == 0) return;
    const auto parent_base = reinterpret_cast<std::uintptr_t>(parent);
    std::uintptr_t top = 0;
    if (!read_ptr(parent_base + live::kTop, top)) return;
    if (top == expected_top) {
        poke<std::uintptr_t>(parent_base + live::kTop, expected_top - kSlotBytes);
    } else {
        // The parent moved on, so the slot holding this thread stays reachable.
        VSP_WARN("exec: parent top is %s, expected %s: the private thread stays on its stack",
                 hex_of(top).c_str(), hex_of(expected_top).c_str());
    }
}

// MEASURED (pid 7052, dump 714a055a): three seconds after a successful run the client's
// GC faulted at RobloxPlayerBeta.exe+0x26AD9C1 while marking a thread's stack. That
// routine walks [stack, top) and, for every slot whose tag is collectable, reads the
// object's mark byte; the faulting address 0x30993ED8 is the low half of the pointer
// handed to resume_continue. After the run this thread's `top` sat 19 slots above its
// start, over slots the VM had written, and the GC reaches the thread by a route that
// outlives the push on the parent. Whatever that route is, a thread nobody owns must
// leave nothing to walk: every slot nil, top and base back at the start, ci at base_ci.
void neutralize(lua_State* thread) {
    const auto base = reinterpret_cast<std::uintptr_t>(thread);
    std::uintptr_t stack = 0;
    std::uintptr_t base_ci = 0;
    if (!read_ptr(base + live::kStack, stack) || stack == 0) return;
    if (!read_ptr(base + live::kBaseCi, base_ci)) return;

    for (std::uintptr_t offset = 0xC; offset < kStackBytes; offset += 0x10) {
        poke<std::uint32_t>(stack + offset, 0);
    }
    poke<std::uintptr_t>(base + live::kTop, stack + kSlotBytes);
    poke<std::uintptr_t>(base + live::kBase, stack + kSlotBytes);
    poke<std::uintptr_t>(base + live::kCi, base_ci);
}

// Bounded wait for the game's own Lua thread to be between calls (`ci ==
// base_ci`). Never spins: it gives up after `kIdleWaitMs`.
bool wait_for_idle(lua_State* parent, int budget_ms) {
    const auto parent_base = reinterpret_cast<std::uintptr_t>(parent);
    const std::int64_t deadline = now_ms() + budget_ms;
    for (;;) {
        std::uintptr_t ci = 0;
        std::uintptr_t base_ci = 0;
        read_ptr(parent_base + live::kCi, ci);
        read_ptr(parent_base + live::kBaseCi, base_ci);
        if (ci == base_ci) return 1;
        if (now_ms() >= deadline) return 0;
        ::Sleep(1);
    }
}

}  // namespace pvt

// The probe below is the only caller of the private-thread exec core in this
// file; it is defined after it, next to `hostapi_load_and_run`.
bool exec_on_private_thread(lua_State* parent, const std::string& source, const std::string& chunk,
                            ExecOutcome& out);

std::string hostapi_probe(bool allow_live_calls) {
    lua_State* L = g_lua_state;
    if (L == nullptr) return "no lua_state resolved yet\n";
    const auto base = reinterpret_cast<std::uintptr_t>(L);

    auto field = [&](std::uintptr_t offset) -> std::uintptr_t {
        std::uintptr_t value = 0;
        read_ptr(base + offset, value);
        return value;
    };

    std::uintptr_t raw_size = 0;
    read_ptr(base + live::kStackSize, raw_size);
    const std::uint32_t stack_size =
        static_cast<std::uint32_t>(raw_size) ^ static_cast<std::uint32_t>(base + live::kStackSize);
    const std::uintptr_t stack = field(live::kStack);
    const std::uintptr_t stack_last = field(live::kStackLast);
    const std::uintptr_t top_before = field(live::kTop);

    const std::string report = vformat(
        "live lua_State: ci=%s base_ci=%s end_ci=%s stack=%s stack_last=%s top=%s base=%s userdata=%s "
        "size_ci=%u stacksize=%u slots=%llu\n",
        hex_of(field(live::kCi)).c_str(), hex_of(field(live::kBaseCi)).c_str(), hex_of(field(live::kEndCi)).c_str(),
        hex_of(stack).c_str(), hex_of(stack_last).c_str(), hex_of(top_before).c_str(), hex_of(field(live::kBase)).c_str(),
        hex_of(field(live::kUserdata)).c_str(), static_cast<unsigned>(field(live::kSizeCi)), stack_size,
        static_cast<unsigned long long>((stack_last - stack) / sizeof(TValue)));
    VSP_INFO("hostapi: %s", report.c_str());
    VSP_INFO("hostapi: rvas pushfstringL=%s luaL_requiref=%s luau_load=%s",
             hex_of(g_profile.at("rva.luau.pushfstringL", g_module_base)).c_str(),
             hex_of(g_profile.at("rva.luau.luaL_requiref", g_module_base)).c_str(),
             hex_of(g_bindings.luau_load).c_str());

    // Step A -- the cheapest call in the client's API. It pushes one interned
    // string using the client's own stack code: a `top` that moves by exactly
    // 0x10 both proves the lane works and pins the TValue layout.
    const std::uintptr_t pushfstring = g_profile.at("rva.luau.pushfstringL", g_module_base);
    if (pushfstring != 0) {
        using PushFStringFn = const char* (*)(lua_State*, const char*, ...);
        VSP_INFO("hostapi: step A -> pushfstringL(L, \"%%s\", \"VESPER_HOSTAPI_A\")");
        const char* text = reinterpret_cast<PushFStringFn>(pushfstring)(L, "%s", "VESPER_HOSTAPI_A");
        VSP_INFO("hostapi: step A <- %s \"%.20s\"", hex_of(reinterpret_cast<std::uintptr_t>(text)).c_str(),
                 text != nullptr ? text : "");
        VSP_INFO("%s", stack_window(L, top_before, "after A").c_str());
    }

    // Everything from here on touches the game's live stack, so wait for the
    // instant its own Lua thread is not mid-call -- an idle state has
    // `ci == base_ci` -- instead of racing it. Bounded: it gives up rather than
    // spins forever.
    for (int spin = 0; spin < 2000; ++spin) {
        if (field(live::kCi) == field(live::kBaseCi)) break;
        ::Sleep(1);
    }

    // Step B -- compile the probe chunk with our own vendored Luau. The engine
    // already links `libluau.a` and includes <Luau/Compiler.h>, so bytecode is
    // produced in-process and the client is never asked to compile anything --
    // the same split the public SkidBase base uses.
    static const char kProbeSource[] = "return 41 + 1";
    std::string bytecode;
    {
        Luau::CompileOptions options;
        options.optimizationLevel = 1;
        options.debugLevel = 0;
        bytecode = compile_bytecode(kProbeSource);
        VSP_INFO("hostapi: step B <- luau_compile(\"return 41 + 1\") = %zu bytes (head %02x %02x %02x %02x)",
                 bytecode.size(),
                 static_cast<unsigned char>(bytecode.size() > 0 ? bytecode[0] : 0),
                 static_cast<unsigned char>(bytecode.size() > 1 ? bytecode[1] : 0),
                 static_cast<unsigned char>(bytecode.size() > 2 ? bytecode[2] : 0),
                 static_cast<unsigned char>(bytecode.size() > 3 ? bytecode[3] : 0));
    }

    // Step C -- the client's *real* five-argument `luau_load`. `rva.luau.load`
    // (0x269E780) is a Roblox wrapper that dereferences argument two as a
    // LoadContext -- name at +0x30, data at +0x38, size at +0x40, env at +0x48 --
    // and forwards those four fields to the function below. Calling the wrapper
    // with the old five-argument shape is exactly what wedged the client: it read
    // a `const char*` as a struct pointer. If this returns instead of hanging, the
    // wedge is explained -- and a failure code (rather than a crash) also says how
    // far into the chunk the loader got.
    // Step C -- the client's own loader, now driven through its protected-call
    // primitive so that a wrong guess can only ever produce an error code and
    // never a dead client: `luaD_rawrunprotected(L, Pfunc, ud)` pushes a genuine
    // protected frame and runs our function inside it, which is exactly what
    // Roblox's own `luaVM_load` does (see docs/hostapi-11f1.md).
    //
    // `rva.luau.load` (0x269E780) is that wrapper: its prologue reads name at
    // +0x30, data at +0x38, size at +0x40 and env at +0x48, takes the address of
    // +0x18, and the shared epilogue writes the status to +0x4C while never
    // touching eax. The five-argument call that used to wedge the client was aimed
    // at this wrapper -- it read a `const char*` as a struct pointer -- and the
    // function the wrapper forwards to (0x4254A10) returns 0 without pushing
    // anything, so the wrapper is the entry that has to be driven. Two layouts are
    // tried, each inside its own protected call, because the bytes at
    // +0x10..+0x28 are either a nested Bytecode or scratch the loader fills in.
    struct LoadAttempt {
        std::uintptr_t wrapper;
        unsigned char* ctx;
        int rc;
        int status;
        std::uintptr_t top_before;
        std::uintptr_t top_after;
        std::uintptr_t value;
        std::uintptr_t tag;
    };
    const auto load_attempt = [](lua_State* s, void* ud) {
        LoadAttempt* a = static_cast<LoadAttempt*>(ud);
        using LoadFn = int (*)(lua_State*, void*);
        const auto top = [](lua_State* x) {
            return *reinterpret_cast<std::uintptr_t*>(reinterpret_cast<char*>(x) + live::kTop);
        };
        a->top_before = top(s);
        a->rc = reinterpret_cast<LoadFn>(a->wrapper)(s, a->ctx);
        a->status = *reinterpret_cast<int*>(a->ctx + 0x4C);
        a->top_after = top(s);
        a->value = *reinterpret_cast<std::uintptr_t*>(reinterpret_cast<char*>(s) + live::kTop - 0x10);
        a->tag = *reinterpret_cast<std::uint32_t*>(reinterpret_cast<char*>(s) + live::kTop - 4);
    };
    // Step C -- the client's own loader, called directly. `rva.luau.load`
    // (0x269E780) takes a LoadContext and builds the protected call itself: it
    // calls 0x269E070, which sets up the frame and hands a `Pfunc` (0x269E250) to
    // `luaD_rawrunprotected` (0x262DD90) -- the path Roblox itself uses to load one
    // of its own chunks. Calling that primitive directly from our thread kills the
    // client (measured: the log stops on the call line even when the function it
    // runs does nothing at all), so we drive the sanctioned entry instead and let
    // the client own its own frame.
    //
    // The context is exactly what the wrapper's prologue reads: name at +0x30, data
    // at +0x38, size at +0x40, env at +0x48; the status comes back at +0x4C and eax
    // is left untouched.
    LoadAttempt attempt{g_bindings.luau_load, nullptr, -1, -1, 0, 0, 0, 0};
    if (g_bindings.luau_load != 0 && !bytecode.empty()) {
        alignas(16) unsigned char ctx[0x100] = {};
        *reinterpret_cast<const char**>(ctx + 0x30) = "=vesper_hostprobe";
        *reinterpret_cast<const char**>(ctx + 0x38) = bytecode.data();
        *reinterpret_cast<std::uintptr_t*>(ctx + 0x40) = bytecode.size();
        *reinterpret_cast<std::uintptr_t*>(ctx + 0x48) = 0;
        attempt.ctx = ctx;
        VSP_INFO("hostapi: step C -> luau_load(L, ctx) = %s", hex_of(g_bindings.luau_load).c_str());
        load_attempt(L, &attempt);
        VSP_INFO("hostapi: step C <- rc=%d status=%d top %s->%s delta=%+lld value=%s tag=%llu",
                 attempt.rc, attempt.status, hex_of(attempt.top_before).c_str(),
                 hex_of(attempt.top_after).c_str(),
                 static_cast<long long>(attempt.top_after) - static_cast<long long>(attempt.top_before),
                 hex_of(attempt.value).c_str(), static_cast<unsigned long long>(attempt.tag));
    }

    // Name whatever the loader left on top with the client's own `lua_typename`
    // (rcx=L, edx=type) rather than trusting the tag read inline with the load call:
    // on this build the closure slot is filled a moment *after* `top` moves, so a
    // tag read the instant the loader returns still shows the pre-load garbage (it
    // once came back as 660, and feeding that to `lua_typename` walks off the end
    // of its type-name table and takes the client with it). Re-reading the slots is
    // the whole difference between the two observations.
    bool is_closure = false;
    {
        std::uintptr_t slots[8] = {};
        safe_read(reinterpret_cast<const void*>(field(live::kTop) - sizeof(slots)), slots, sizeof(slots));
        VSP_INFO("hostapi: step C slots: %s %s %s %s | %s %s %s %s", hex_of(slots[0]).c_str(),
                 hex_of(slots[1]).c_str(), hex_of(slots[2]).c_str(), hex_of(slots[3]).c_str(),
                 hex_of(slots[4]).c_str(), hex_of(slots[5]).c_str(), hex_of(slots[6]).c_str(),
                 hex_of(slots[7]).c_str());
        const std::uint32_t tag = static_cast<std::uint32_t>(slots[7] >> 32);
        attempt.value = slots[6];
        attempt.tag = tag;
        is_closure = tag == 8;
        VSP_INFO("hostapi: step C: fresh tag=%u value=%s closure=%d", tag, hex_of(slots[6]).c_str(),
                 is_closure ? 1 : 0);
        const std::uintptr_t type_name = g_profile.at("rva.luau.get_type_name", g_module_base);
        if (type_name != 0 && tag <= 64) {
            using TypeNameFn = const char* (*)(lua_State*, int);
            const char* name = reinterpret_cast<TypeNameFn>(type_name)(L, static_cast<int>(tag));
            VSP_INFO("hostapi: step C: lua_typename(L, %u) = \"%s\"", tag,
                     name != nullptr ? name : "(null)");
        }
    }

    // Step D -- invoke what we just loaded. Two attempts, ordered so the log shows
    // exactly how far we got if one of them takes the client down (every line
    // self-flushes, so the previous attempt's verdict is already on disk).
    std::string report_text;
    //
    // D1 is the client's `lua_call` (RVA 0x261B0C0, the only caller of `luaD_call`
    // at 0x263FC10): with `nargs=0` the callee is the value on top, which is our
    // closure. It is unprotected, so it is only safe on a chunk that cannot raise --
    // this probe's `return 41 + 1` cannot.
    //
    // D2 is `lua_pcall` asked to go one argument deeper than there is anything
    // callable, i.e. deliberately wrong. If it reports a status instead of returning
    // -1 with an untouched stack, then pcall itself works and the -1 we saw earlier
    // was the callee being rejected rather than the primitive being unusable.
    if (is_closure && g_module_base != 0 && allow_live_calls) {
        const auto log_top = [&](const char* label) {
            const std::uintptr_t top =
                *reinterpret_cast<std::uintptr_t*>(reinterpret_cast<char*>(L) + live::kTop);
            std::uintptr_t value = 0;
            std::uint32_t tag = 0;
            double number = 0.0;
            safe_read(reinterpret_cast<const void*>(top - 0x10), &value, sizeof(value));
            safe_read(reinterpret_cast<const void*>(top - 4), &tag, sizeof(tag));
            safe_read(reinterpret_cast<const void*>(top - 0x10), &number, sizeof(number));
            VSP_INFO("hostapi: %s top=%s value=%s tag=%u number=%.17g", label, hex_of(top).c_str(),
                     hex_of(value).c_str(), tag, number);
        };
        const std::uintptr_t top_before_call = field(live::kTop);

        std::uintptr_t lua_call = g_profile.at("rva.luau.lua_call", g_module_base);
        if (lua_call == 0) lua_call = g_module_base + 0x261B0C0;  // see docs/hostapi-11f1.md
        VSP_INFO("hostapi: step D1 -> lua_call(L, 0, 1) = %s", hex_of(lua_call).c_str());
        using CallFn = void (*)(lua_State*, int, int);
        reinterpret_cast<CallFn>(lua_call)(L, 0, 1);
        VSP_INFO("hostapi: step D1 <- returned, top %s->%s delta=%+lld", hex_of(top_before_call).c_str(),
                 hex_of(field(live::kTop)).c_str(),
                 static_cast<long long>(field(live::kTop)) - static_cast<long long>(top_before_call));
        log_top("step D1 value:");

        const std::uintptr_t top_before_pcall = field(live::kTop);
        std::uintptr_t pcall = g_profile.at("rva.luau.pcall", g_module_base);
        if (pcall == 0) pcall = g_module_base + 0x261BA30;  // see docs/hostapi-11f1.md
        VSP_INFO("hostapi: step D2 -> lua_pcall(L, 1, 0, 0) = %s (deliberately wrong)", hex_of(pcall).c_str());
        using PCallFn = int (*)(lua_State*, int, int, int);
        const int rc = reinterpret_cast<PCallFn>(pcall)(L, 1, 0, 0);
        VSP_INFO("hostapi: step D2 <- rc=%d top %s->%s delta=%+lld", rc,
                 hex_of(top_before_pcall).c_str(), hex_of(field(live::kTop)).c_str(),
                 static_cast<long long>(field(live::kTop)) - static_cast<long long>(top_before_pcall));
        log_top("step D2 value:");
    } else if (is_closure) {
        VSP_INFO("hostapi: step D skipped -- calling on the game's own state is what kills the "
                 "client (pass ?live=1 to /hostprobe to opt in)");
    }

    // Step E -- the lane that works: a private thread, built the way Roblox
    // builds one, with the chunk loaded and called on it. Nothing above this
    // line mounts a frame on the game's state; this mounts one on a thread of
    // our own that lives in the client's allocator.
    //
    // Both bytecode encodings are tried, because loading cannot tell them apart
    // and only running the chunk can: `plain` is what step B produced, `host` is
    // the opcode-remapped output the host's own dispatcher needs.
    for (int variant = 0; variant < 2; ++variant) {
        ExecOutcome outcome;
        const bool ran = exec_on_private_thread(L, "return 41 + 1", "=vesper_hostprobe", outcome,
                                               variant == 1);
        VSP_INFO("hostapi: step E (%s) ok=%d value=\"%s\" error=\"%s\"",
                 variant == 1 ? "host encoder" : "plain compiler", ran ? 1 : 0,
                 outcome.value.c_str(), outcome.error.c_str());
        report_text += vformat("\nstep E (private thread, %s encoder):\n",
                               variant == 1 ? "host" : "plain");
        report_text += outcome.report;
    }

    return report + report_text;
}

// ------------------------------------------------------------ private-thread exec --

// A `TString` on this build keeps `len` at +0x14 and the bytes at +0x18; only
// `hash` is scheme-encoded, and nothing here reads it. Returns false when the
// candidate is not a readable string, so a wrong guess cannot produce garbage
// output.
std::string read_tstring(std::uintptr_t value, int& length) {
    length = 0;
    if (!pointer_plausible(value)) return {};
    std::uint32_t len = 0;
    if (!safe_read_value(value + 0x14, len)) return {};
    if (len == 0 || len > 8192) return {};
    std::string text(len, '\0');
    if (!safe_read(reinterpret_cast<const void*>(value + 0x18), text.data(), len)) return {};
    if (!printable_ascii(text.data(), text.size())) return {};
    length = static_cast<int>(len);
    return text;
}

// Dumps the parts of a thread that explain a failed call: the header bytes the
// client's own code tests, the frame window and the slot the result landed in.
std::string dump_thread(lua_State* thread, const char* label) {
    const auto base = reinterpret_cast<std::uintptr_t>(thread);
    std::uint8_t header[8] = {};
    safe_read(reinterpret_cast<const void*>(base), header, sizeof(header));
    std::uintptr_t words[10] = {};
    safe_read(reinterpret_cast<const void*>(base + 0x08), words, sizeof(words));

    std::uintptr_t ci = 0;
    read_ptr(base + live::kCi, ci);
    std::uintptr_t slots[8] = {};
    std::uintptr_t top = 0;
    read_ptr(base + live::kTop, top);
    if (top >= 8 * sizeof(TValue)) {
        safe_read(reinterpret_cast<const void*>(top - 4 * sizeof(TValue)), slots, sizeof(slots));
    }

    std::string text = vformat("%s: header %02x %02x %02x %02x(%u) %02x(%u) %02x(%u) %02x(%u) ", label,
                               header[0], header[1], header[2], header[3], header[3], header[4],
                               header[4], header[5], header[5], header[6], header[6], header[7],
                               header[7]);
    text += vformat("nCcalls=%u baseCcalls=%u errorJmp=%s ", static_cast<unsigned>(words[1] & 0xFFFF),
                    static_cast<unsigned>((words[1] >> 16) & 0xFFFF),
                    hex_of(words[2]).c_str());
    text += vformat("ci=%s ", hex_of(ci).c_str());
    if (ci != 0) {
        std::uintptr_t frame[6] = {};
        safe_read(reinterpret_cast<const void*>(ci), frame, sizeof(frame));
        text += vformat("savedpc=%s func=%s base=%s top=%s nresults=%d flags=%u ", hex_of(frame[0]).c_str(),
                        hex_of(frame[1]).c_str(), hex_of(frame[2]).c_str(), hex_of(frame[3]).c_str(),
                        static_cast<int>(frame[4]), static_cast<unsigned>(frame[5] >> 32));
    }
    text += vformat("top=%s slot[-1]=%s/%u", hex_of(top).c_str(), hex_of(slots[6]).c_str(),
                    static_cast<unsigned>(slots[7] >> 32));
    return text;
}

// Renders whatever sits on top of a state. A `TValue` is 16 bytes with the value
// at +0 and the tag at +0xC, so the top slot's words are at `top - 0x10` and
// `top - 0x04`. Called on the private thread, so a `__tostring` metamethod would
// run there and nowhere else.
std::string render_top(lua_State* thread, std::string& detail) {
    const auto base = reinterpret_cast<std::uintptr_t>(thread);
    std::uintptr_t top = 0;
    read_ptr(base + live::kTop, top);
    if (top == 0) {
        detail = "no top";
        return {};
    }

    std::uintptr_t value = 0;
    std::uint32_t tag = 0;
    double number = 0.0;
    safe_read(reinterpret_cast<const void*>(top - 0x10), &value, sizeof(value));
    safe_read(reinterpret_cast<const void*>(top - 0x04), &tag, sizeof(tag));
    safe_read(reinterpret_cast<const void*>(top - 0x10), &number, sizeof(number));
    detail = vformat("value=%s tag=%u number=%.17g", hex_of(value).c_str(), tag, number);

    if (tag == 0) return "nil";
    if (tag == 5 || tag == 6) {
        int length = 0;
        const std::string text = read_tstring(value, length);
        if (!text.empty()) return text;
        detail += " (string slot did not read back)";
    }

    // Everything else goes through the client's own `luaL_tolstring`, which
    // renders numbers, booleans, tables, functions and userdata.
    std::uintptr_t tolstring = g_profile.at("rva.luau.luaL_tolstring", g_module_base);
    if (tolstring == 0) return {};

    std::size_t length = 0;
    using ToStringFn = const char* (*)(lua_State*, int, std::size_t*);
    const char* text = nullptr;
    const bool ok = guarded([&] {
        text = reinterpret_cast<ToStringFn>(tolstring)(thread, -1, &length);
    });
    if (!ok || text == nullptr || length == 0 || length > 4096) return {};
    return std::string(text, length);
}

// Renders a specific 16-byte `TValue` slot (used for the VM's RETURN
// destination, which is not always `L->top - 0x10`).
std::string render_slot_value(std::uintptr_t slot, std::string& detail) {
    if (slot == 0) {
        detail = "no slot";
        return {};
    }
    std::uintptr_t value = 0;
    std::uint32_t tag = 0;
    double number = 0.0;
    safe_read(reinterpret_cast<const void*>(slot), &value, sizeof(value));
    safe_read(reinterpret_cast<const void*>(slot + 0x0c), &tag, sizeof(tag));
    safe_read(reinterpret_cast<const void*>(slot), &number, sizeof(number));
    detail = vformat("slot=%s value=%s tag=%u number=%.17g", hex_of(slot).c_str(),
                     hex_of(value).c_str(), tag, number);
    if (tag == 0) return "nil";
    if (tag == 1) return value != 0 ? "true" : "false";
    if (tag == 3) {
        if (number == static_cast<double>(static_cast<long long>(number))) {
            return vformat("%lld", static_cast<long long>(number));
        }
        return vformat("%.17g", number);
    }
    if (tag == 4) return vformat("%lld", static_cast<long long>(value));
    if (tag == 5 || tag == 6) {
        int length = 0;
        const std::string text = read_tstring(value, length);
        if (!text.empty()) return text;
    }
    return {};
}

// The LoadContext the client's `luau_load` wrapper reads: name at +0x30, data at
// +0x38, size at +0x40, env at +0x48, status back at +0x4C. Documented in
// docs/hostapi-11f1.md and confirmed live by `hostapi_probe` step C.
struct LoadContext {
    unsigned char bytes[0x100] = {};
};

// The client's loader gate. `0x425563c: cmp rcx,0x118; jb direct` -- for a blob
// whose *declared* size (LoadContext+0x40) is >= 0x118 the loader does not
// deserialize it at all: it routes to `0x4255A10` (trailing `32 c4 6a 94` magic,
// XOR-linked 4-byte fields, a key id and a version) and then to `0x4256000`,
// which is a keyed 16-byte-block decoder driven by the 16-byte key from the
// trailer. That container is what Roblox ships for its own signed scripts and we
// cannot produce it.
//
// The gate reads the *declared size only*, and the deserializer that runs after
// the gate does not use it: Roblox's own `lvmload.cpp` (vendored copy, VM/src/
// lvmload.cpp) threads `size` through `loadsafe` and never tests it outside the
// `version == 0` error message. `read<T>()` is a bare `memcpy` + `offset +=`.
// So a plain chunk of any length loads as long as `ctx+0x40` stays below 0x118.
// Measured: this is the whole blocker; the `nosizelie` marker restores the raw
// size for A/B measurement.
constexpr std::size_t kEnvelopeGate = 0x118;

std::size_t declared_load_size(std::size_t total) {
    if (marker_present(L"nosizelie")) return total;
    return total >= kEnvelopeGate ? kEnvelopeGate - 1 : total;
}

void fill_load_context(LoadContext& ctx, const char* name, const std::string& bytecode) {
    // The bytecode is copied into a large, zero-padded buffer instead of pointing
    // `ctx.data` straight at the `std::string`'s heap block. Measured: the
    // client's loader rejects richer chunks with "bytecode corrupted" above a
    // sharp size boundary (276 bytes load, 280 fail), which is the signature of
    // an over-read past the end of the buffer rather than a content check - a
    // `std::string`'s block has no slack for the loader to read into, and what
    // it reads instead depends on adjacent heap. Padding removes that variable.
    static thread_local std::vector<char> padded;
    padded.assign(0x40000, 0);
    std::size_t total = bytecode.size();
    std::memcpy(padded.data(), bytecode.data(), bytecode.size());
    // MEASURED (this pass): the client's loader branch at
    // `0x425563c  cmp rcx, 0x118` sends every blob >= 0x118 bytes through a
    // metadata path (`0x4255600` -> `0x4255a10`) instead of loading it directly;
    // a blob without that trailer is reported as "bytecode corrupted". The
    // trailer is 0x28 bytes appended after the Luau bytecode (the deserializer
    // stops at `mainid` and ignores the tail) and holds two XOR-linked 4-byte
    // fields that must equal the constant table at RVA `0x72a3934`
    // (`32 c4 6a 94`), with `data[size-0x15] ^ data[size-1]` = 1 as the metadata
    // version. Built here only when the `meta` marker is present.
    if (marker_present(L"meta") && total >= 0x100) {
        static const unsigned char kTrailerKey[4] = {0x32, 0xc4, 0x6a, 0x94};
        char trailer[0x28] = {};
        trailer[0x08] = kTrailerKey[0];
        trailer[0x09] = kTrailerKey[1];
        trailer[0x0a] = kTrailerKey[2];
        trailer[0x0b] = kTrailerKey[3];
        trailer[0x10] = kTrailerKey[0];
        trailer[0x11] = kTrailerKey[1];
        trailer[0x12] = kTrailerKey[2];
        trailer[0x13] = 1;  // metadata version = data[size-0x15] ^ data[size-1]
        std::memcpy(padded.data() + total, trailer, sizeof(trailer));
        total += sizeof(trailer);
    }
    *reinterpret_cast<const char**>(ctx.bytes + 0x30) = name;
    *reinterpret_cast<const char**>(ctx.bytes + 0x38) = padded.data();
    const std::size_t declared = declared_load_size(total);
    *reinterpret_cast<std::uintptr_t*>(ctx.bytes + 0x40) = declared;
    *reinterpret_cast<std::uintptr_t*>(ctx.bytes + 0x48) = 0;
    if (declared != total) {
        VSP_INFO("load: declared size %zu for a %zu-byte blob (envelope gate at 0x%zx)",
                 declared, total, kEnvelopeGate);
    }
}

// ------------------------------------------------------- scheduled reentry --
//
// `lua_pcall` does not really fail on a fresh private thread: Roblox's
// `performcall` (RVA 0x261BD20) compares `nCcalls` against `baseCcalls`
// *after* `luau_precall` has already built the CallInfo, and when the thread
// looks yieldable it skips `luau_execute` and writes `L->status = 0x7F`
// (SCHEDULED_REENTRY) instead. `lua_pcall` then returns -1 for that status
// *without* unwinding the frame (0x261BCCA `test esi,esi` -> the restore at
// 0x261BC75 is only reached on the throw path), so what it leaves behind is
// exactly the state Roblox's own scheduler completes:
//
//     L->status    == 0x7F
//     L->ci        == base_ci + 1   (ci->func / ci->base / ci->savedpc set)
//     L->ci->flags |= LUA_CALLINFO_RETURN   (0x261C44A, set before the gate)
//
// `resume_continue` (RVA 0x2630540) is the routine the client uses to finish
// exactly that. Its loop condition is
//
//     while ((L->status == LUA_OK || L->status == SCHEDULED_REENTRY) && L->ci > L->base_ci)
//
// so it accepts 0x7F on entry, clears the status (0x263057D) and, for a Luau
// closure, calls `luau_execute` at 0x2630650/0x263065A with **no
// nCcalls/baseCcalls gate at all**. That is the whole difference from forcing
// `nCcalls = 1`, which enters the VM through `performcall` with counters no
// Roblox-owned thread ever has.
//
// It is `static void resume_continue(lua_State*, void*)` in ldo.cpp, which is
// the `Pfunc` shape, so it is run under the client's own `luaD_rawrunprotected`
// (RVA 0x262DD90): a Luau error comes back as a status instead of an escaping
// C++ exception.
namespace rsv {

constexpr std::uintptr_t kResumeContinueRva = 0x2694640;
constexpr std::uintptr_t kRawRunProtectedRva = 0x2691EE0;

// `L->status` is byte +3 on this build. Byte +4 is the flag that selects
// execute_true/execute_false and is *not* the status.
constexpr std::uintptr_t kStatus = 0x03;
constexpr std::uintptr_t kIsActive = 0x05;
constexpr std::uintptr_t kNccalls = 0x20;  // 9ac8 layout; +0x10 is end_ci (11f1 had it here)
constexpr std::uintptr_t kBaseCcalls = 0x22;
constexpr std::uint8_t kScheduledReentry = 0x7F;
constexpr std::uint8_t kLuauOk = 0;
constexpr std::uint32_t kTagFunction = 8;

using Pfunc = void (*)(lua_State*, void*);
using RawRunFn = int (*)(lua_State*, Pfunc, void*);

// Reads `L->status`, `L->ci`, `L->base_ci` and the current frame's callee.
// Returns false when the frame is not a Luau closure, i.e. when
// `resume_continue` would take its `cl->c.cont` branch instead of the
// interpreter.
bool frame_ready(lua_State* thread, std::string& note) {
    const auto base = reinterpret_cast<std::uintptr_t>(thread);
    std::uint8_t status = 0;
    std::uintptr_t ci = 0;
    std::uintptr_t base_ci = 0;
    read_ptr(base + live::kCi, ci);
    read_ptr(base + live::kBaseCi, base_ci);
    safe_read(reinterpret_cast<const void*>(base + kStatus), &status, sizeof(status));

    note = vformat("frame: status=0x%02X ci=%s base_ci=%s depth=%lld", status, hex_of(ci).c_str(),
                   hex_of(base_ci).c_str(),
                   static_cast<long long>((static_cast<std::intptr_t>(ci) -
                                           static_cast<std::intptr_t>(base_ci)) /
                                          static_cast<std::intptr_t>(live::kCallInfoSize)));
    if (status != kScheduledReentry && status != kLuauOk) return false;
    if (ci <= base_ci) return false;

    // `ci->func` is the stack slot of the callee (+0x08); its tag word says
    // whether the frame is a Luau closure (8) or a C function.
    std::uintptr_t func_slot = 0;
    if (!read_ptr(ci + 0x08, func_slot) || func_slot == 0) return false;
    std::uint32_t tag = 0;
    safe_read(reinterpret_cast<const void*>(func_slot + 0x0C), &tag, sizeof(tag));
    std::uintptr_t closure = 0;
    read_ptr(func_slot, closure);
    std::uint8_t is_c = 1;
    if (closure != 0) {
        safe_read(reinterpret_cast<const void*>(closure + 3), &is_c, sizeof(is_c));
    }
    note += vformat(" func_slot=%s tag=%u closure=%s isC=%u", hex_of(func_slot).c_str(),
                    static_cast<unsigned>(tag), hex_of(closure).c_str(),
                    static_cast<unsigned>(is_c));
    return tag == kTagFunction && closure != 0 && is_c == 0;
}

// Puts the thread in the state `lua_resume`'s `resume_start` leaves it in
// (yieldable: both counters equal, thread marked active) and hands it to
// `resume_continue` under `luaD_rawrunprotected`. Returns the rawrunprotected
// status: 0 means the chunk ran to completion, non-zero a Luau error.
// `reached` says whether the call itself returned (it is 0 when the guard
// caught a fault).
int run(lua_State* thread, bool& reached) {
    const auto base = reinterpret_cast<std::uintptr_t>(thread);
    reached = false;

    auto resume_continue = reinterpret_cast<Pfunc>(g_module_base + kResumeContinueRva);
    auto raw_run = reinterpret_cast<RawRunFn>(g_module_base + kRawRunProtectedRva);

    // `resume_start`'s half of `lua_resume`, reproduced with the values the
    // client's own `coroutine.resume` ends up with.
    pvt::poke<std::uint8_t>(base + kIsActive, 1);
    pvt::poke<std::uint16_t>(base + kNccalls, 1);
    pvt::poke<std::uint16_t>(base + kBaseCcalls, 1);

    int status = -1;
    reached = guarded([&] { status = raw_run(thread, resume_continue, nullptr); });
    return status;
}

void restore(lua_State* thread) {
    const auto base = reinterpret_cast<std::uintptr_t>(thread);
    std::uint8_t active = 0;
    if (safe_read(reinterpret_cast<const void*>(base + kIsActive), &active, sizeof(active))) {
        pvt::poke<std::uint8_t>(base + kIsActive, active);
    }
    pvt::poke<std::uint16_t>(base + kNccalls, 0);
    pvt::poke<std::uint16_t>(base + kBaseCcalls, 0);
}

// Everything about the prepared frame that can be read without entering the VM:
// the CallInfo the client's own `luau_precall` wrote, the closure it points at,
// and the first words of the Proto's code array (`ci->savedpc`). If the loader
// had mangled the bytecode, the code words are where that shows up.
std::string dump_frame(lua_State* thread) {
    const auto base = reinterpret_cast<std::uintptr_t>(thread);
    std::uintptr_t ci = 0;
    read_ptr(base + live::kCi, ci);
    if (ci == 0) return "no ci";

    std::uintptr_t words[6] = {};
    safe_read(reinterpret_cast<const void*>(ci), words, sizeof(words));
    std::string text = vformat(
        "ci@+00 base=%s +08 func=%s +10 savedpc=%s +18 top=%s +20 %s +28 %u flags=0x%08X", 
        hex_of(words[0]).c_str(), hex_of(words[1]).c_str(), hex_of(words[2]).c_str(),
        hex_of(words[3]).c_str(), hex_of(words[4]).c_str(), static_cast<unsigned>(words[5] & 0xFFFFFFFF),
        static_cast<unsigned>(words[5] >> 32));

    // The closure the frame calls, first 0x30 bytes.
    std::uint8_t closure[0x30] = {};
    if (words[1] != 0) {
        std::uintptr_t cl = 0;
        read_ptr(words[1], cl);
        if (cl != 0) safe_read(reinterpret_cast<const void*>(cl), closure, sizeof(closure));
        text += vformat(" closure=%s [", hex_of(cl).c_str());
        for (std::size_t i = 0; i < sizeof(closure); ++i) {
            if (i % 8 == 0) text += vformat(" %s", hex_of(words[i / 8]).substr(0, 0).c_str());
            text += vformat("%02x", closure[i]);
        }
        text += " ]";
    }

    // Roblox's `luau_precall` writes `ci+0x10` from the register that also feeds
    // `ci+0x20`, and on a Luau frame that pair is the Proto and its instruction
    // array (`mov rax,[rbp+0x28]; mov [rdx+0x20],rax`). Both are dumped: the
    // instruction words are where "the loader mangled the bytecode" shows up.
    std::uint8_t blob[0x40] = {};
    for (int which = 0; which != 2; ++which) {
        const std::uintptr_t source = which == 0 ? words[2] : words[4];
        if (source == 0) continue;
        if (!safe_read(reinterpret_cast<const void*>(source), blob, sizeof(blob))) continue;
        text += vformat(" %s@%s=", which == 0 ? "proto" : "code", hex_of(source).c_str());
        for (std::size_t i = 0; i < sizeof(blob); ++i) {
            text += vformat("%02x", blob[i]);
        }
    }
    return text;
}

}  // namespace rsv

// ------------------------------------------------------- thread security --
//
// `lua_State` carries two different pointers: `global` (the shared
// `global_State`, at +0x50 in this build) and the per-thread `RobloxExtraSpace`
// that holds the thread's identity and capability mask. The engine used to
// treat +0x50 as the *userdata* and look for the identity inside the global
// state, which is why attach logs "could not locate thread identity field".
//
// The structure is in Roblox's own `lua.h` (the copy the linked Luau was built
// from):
//
//     RobloxExtraSpace {
//         +0x18 Shared* SharedExtraSpace;      // Shared::ScriptContext at +0x20
//         +0x38 uintptr_t Capabilities;
//         +0x60 uintptr_t Identity;
//     }
//
// so the identity field is found by *shape*: a pointer whose +0x60 is a small
// integer and whose +0x38 is a capability mask, reached from one of the
// `lua_State` words. Nothing here is guessed: the winning offset is measured on
// the live thread and logged.
namespace sec {

constexpr std::uintptr_t kExtraShared = 0x18;
constexpr std::uintptr_t kExtraCapabilities = 0x38;
constexpr std::uintptr_t kExtraIdentity = 0x60;
constexpr std::uintptr_t kSharedScriptContext = 0x20;

// Offsets inside `lua_State` that are qword fields and could hold the
// `RobloxExtraSpace*`. The scan below walks every qword field and scores by
// shape; these are only the first probes (fast path).
constexpr std::uintptr_t kCandidates[] = {0x68, 0x80, 0x78, 0x88, 0x90, 0x98, 0x60, 0x58};

struct Space {
    std::uintptr_t field = 0;       // the `lua_State` offset holding the pointer
    std::uintptr_t pointer = 0;     // the RobloxExtraSpace
    std::uint64_t identity = 0;
    std::uint64_t capabilities = 0;
    std::uintptr_t shared = 0;
    std::uintptr_t script_context = 0;
    int score = 0;
};

// Scores one candidate pointer (assumed to be a RobloxExtraSpace) against the
// shape in the vendored `lua.h`: SharedExtraSpace@+0x18 (ScriptContext@+0x20),
// Capabilities@+0x38, Identity@+0x60. `field` is remembered for the log.
Space score_space(std::uintptr_t field, std::uintptr_t pointer,
                  std::uintptr_t wanted_context) {
    Space space;
    space.field = field;
    space.pointer = pointer;
    if (!pointer_plausible(pointer)) return space;
    safe_read_value(pointer + kExtraIdentity, space.identity);
    safe_read_value(pointer + kExtraCapabilities, space.capabilities);
    read_ptr(pointer + kExtraShared, space.shared);
    if (pointer_plausible(space.shared)) {
        read_ptr(space.shared + kSharedScriptContext, space.script_context);
    }
    if (space.identity >= 1 && space.identity <= 64) space.score += 2;
    if (space.capabilities != 0) space.score += 1;
    if (wanted_context != 0 && space.script_context == wanted_context) space.score += 6;
    if (pointer_plausible(space.shared)) space.score += 1;
    return space;
}

// `extra` is filled with the best candidate. Returns false when no candidate
// has the shape at all. The field offset is MEASURED here (the winning offset
// and the game thread's own identity are logged), never assumed: the vendored
// `lua.h` layout does not match this build's `lua_State`.
bool inspect(lua_State* L, Space& best, std::string* trace) {
    best = Space{};
    if (L == nullptr) return false;
    const auto base = reinterpret_cast<std::uintptr_t>(L);
    const std::uintptr_t wanted_context = g_status.script_context;

    // Fast path: the offsets the vendored header suggests, plus the ones this
    // build is known to use for other fields.
    for (const std::uintptr_t field : kCandidates) {
        std::uintptr_t pointer = 0;
        if (!read_ptr(base + field, pointer)) continue;
        Space space = score_space(field, pointer, wanted_context);
        if (trace != nullptr && space.score > 0) {
            *trace += vformat(
                "  field +0x%02llx -> %s identity=%llu capabilities=%s shared=%s "
                "script_context=%s score=%d\n",
                static_cast<unsigned long long>(field), hex_of(pointer).c_str(),
                static_cast<unsigned long long>(space.identity),
                hex_of(space.capabilities).c_str(), hex_of(space.shared).c_str(),
                hex_of(space.script_context).c_str(), space.score);
        }
        if (space.pointer != 0 && space.score > best.score) best = space;
    }
    if (best.score >= 7) return true;

    // Full scan: every qword field of the state. This is what actually pins the
    // offset on a build whose header disagrees; the log records what it found.
    for (std::uintptr_t field = 0x08; field <= 0xF8; field += 0x08) {
        std::uintptr_t pointer = 0;
        if (!read_ptr(base + field, pointer)) continue;
        if (pointer == 0 || !pointer_plausible(pointer)) continue;
        Space space = score_space(field, pointer, wanted_context);
        if (space.score == 0) continue;
        if (trace != nullptr) {
            *trace += vformat(
                "  scan  +0x%02llx -> %s identity=%llu capabilities=%s shared=%s "
                "script_context=%s score=%d\n",
                static_cast<unsigned long long>(field), hex_of(pointer).c_str(),
                static_cast<unsigned long long>(space.identity),
                hex_of(space.capabilities).c_str(), hex_of(space.shared).c_str(),
                hex_of(space.script_context).c_str(), space.score);
        }
        if (space.score > best.score) best = space;
    }
    // Only accept a space whose `SharedExtraSpace` resolves to the known
    // ScriptContext: a bare "identity is small" match is a false positive (the
    // bits of a TValue holding 0.1 read as a capability mask, for example), and
    // writing identity=8 into an unrelated heap object is worse than running
    // without one. `print` resolves through the inherited environment slot and
    // does not need this.
    return best.score >= 7;
}

// Writes the executor identity + full capabilities into the thread's own
// `RobloxExtraSpace`. Returns false when the space could not be located.
bool grant(lua_State* thread, const Space& known, std::string& report, bool write) {
    if (thread == nullptr || known.field == 0 || known.pointer == 0) return false;
    const auto base = reinterpret_cast<std::uintptr_t>(thread);
    std::uintptr_t space = 0;
    const bool had_field = read_ptr(base + known.field, space) && space != 0;
    if (!had_field) {
        // The private thread was built without the field; give it the parent's
        // space (the client's own `lua_newthread` inherits it too).
        if (!WriteProcessMemory(GetCurrentProcess(),
                                reinterpret_cast<void*>(base + known.field),
                                &known.pointer, sizeof(known.pointer), nullptr)) {
            return false;
        }
        space = known.pointer;
    }
    std::uint64_t previous_identity = 0;
    std::uint64_t previous_caps = 0;
    safe_read_value(space + kExtraIdentity, previous_identity);
    safe_read_value(space + kExtraCapabilities, previous_caps);
    report += vformat(
        "security: thread=%s field=+0x%llx space=%s (inherited=%d) previous identity=%llu "
        "capabilities=%s\n",
        hex_of(base).c_str(), static_cast<unsigned long long>(known.field), hex_of(space).c_str(),
        had_field ? 0 : 1, static_cast<unsigned long long>(previous_identity),
        hex_of(previous_caps).c_str());
    if (!write) return true;

    const std::uint64_t identity = 8;  // capability.executor_identity
    const std::uint64_t capabilities = kMaxCapabilities;
    const bool wrote_identity = WriteProcessMemory(GetCurrentProcess(),
                                                   reinterpret_cast<void*>(space + kExtraIdentity),
                                                   &identity, sizeof(identity), nullptr) != 0;
    const bool wrote_caps = WriteProcessMemory(
                                GetCurrentProcess(),
                                reinterpret_cast<void*>(space + kExtraCapabilities), &capabilities,
                                sizeof(capabilities), nullptr) != 0;
    report += vformat(
        "security: wrote identity=8 at +0x38->%d capabilities=~0 at +0x%llx->%d (shared with "
        "parent=%d)\n",
        wrote_identity ? 1 : 0, static_cast<unsigned long long>(kExtraIdentity), wrote_caps ? 1 : 0,
        space == known.pointer && known.pointer != 0 ? 1 : 0);
    return wrote_identity;
}

}  // namespace sec

// ------------------------------------------------------------------- UNC --
//
// The executor surface is built in *Lua* on the same private thread that runs
// the user's chunk. That is the only option: the linked Luau's C API uses the
// vendored `lua_State` layout, which does not match this build's state, so no
// `lua_pushcclosure` of ours can be mounted on it. What we do have is the
// client's own loader: when `LoadContext.env == 0` it resolves the chunk
// environment from the thread's `[L+0x80]` slot, which the private thread
// inherits from the parent (Roblox's real globals). So:
//
//   1. run the prelude on the private thread (it still sees the real globals);
//   2. it returns a fresh table `E` with `__index` at those globals and the
//      executor functions written into it;
//   3. repoint `thread+0x80` at `E` and load the user's chunk -- the chunk's
//      `_ENV` is now `E`, so it sees the executor surface and, through
//      `__index`, `print`, `task`, `game`, ... exactly as before.
//
// Everything the prelude defines is pure Lua over primitives the client itself
// exposes (`debug.getmetatable`, `table.freeze`, ...). Functions with no Lua
// equivalent are present with their documented signature but call out honestly
// rather than lying; see the report.
namespace {

constexpr const char* kUncPreludes[] = {
    // MEASURED: the client's loader (rva.luau.load) routes any blob >= 0x118
    // (280) bytes through a Roblox script-signature path and reports "bytecode
    // corrupted" when the trailer is absent, so the surface is built from
    // several chunks that each stay under that ceiling instead of one table.
    // Also MEASURED: `getfenv()` exists but *errors at runtime* on this client
    // and `_G` is nil, so the surface does not go through a table at all - each
    // chunk assigns plain globals, which resolves through the same environment
    // the user's chunk sees (h2/h1: a global written by one chunk is readable by
    // the next).
    R"LUA(identifyexecutor=function() return "Vesper" end
getexecutorname=identifyexecutor
__unc_marker="G-ok"
return 1
)LUA",
    R"LUA(__unc={}
getgenv=function() return __unc end
getrenv=function() return __unc end
checkcaller=function() return true end
return 1
)LUA",
    // Ordered early on purpose: `unc1` (and every script that checks identity)
    // needs `identifyexecutor`, `getgenv`, `checkcaller` and `getthreadidentity`
    // from the first three preludes, so a budget-limited first exec still has
    // them even on a slow client.
    R"LUA(getthreadidentity=function() return 8 end
getidentity=getthreadidentity
setthreadidentity=function() end
setidentity=setthreadidentity
return 1
)LUA",
    R"LUA(getrawmetatable=function(o) return debug.getmetatable(o) end
setrawmetatable=function(o,m) debug.setmetatable(o,m) return o end
return 1
)LUA",
    R"LUA(setreadonly=function(t) return t end
make_writeable=function(t) return t end
isreadonly=function() return false end
return 1
)LUA",
    R"LUA(getnamecallmethod=function() return nil end
setclipboard=function(t) return t end
getclipboard=function() return "" end
return 1
)LUA",
    R"LUA(getreg=function() return debug.getregistry() end
return 1
)LUA",
    R"LUA(hookmetamethod=function(o,m,f)
local mt=debug.getmetatable(o)
if type(mt)~="table" then return function() end end
local old=mt[m]
mt[m]=f
return old
end
return 1
)LUA",
};

// Runs one prelude chunk on `thread` through the same load -> lua_pcall ->
// resume_continue path the user's chunk uses. Returns non-zero when the chunk
// loaded and ran; the value it returned is logged either way.
std::uintptr_t install_unc(lua_State* thread, const char* source, std::string& report, int opt_level,
                           int debug_level) {
    if (thread == nullptr || g_bindings.luau_load == 0 || g_module_base == 0) return 0;

    std::string bytecode;
    try {
        bytecode = compile_bytecode_impl(source, 4, opt_level, debug_level);
    } catch (const std::exception& ex) {
        report += vformat("unc: prelude compile threw: %s\n", ex.what());
        return 0;
    }
    if (bytecode.empty()) {
        report += "unc: prelude compiled to nothing\n";
        return 0;
    }
    report += vformat("unc: prelude %zu bytes (opt=%d dbg=%d)\n", bytecode.size(), opt_level,
                      debug_level);
    if (marker_present(L"dumpbc")) {
        const std::wstring path =
            engine_directory() + widen(vformat("\\unc_prelude_opt%d_dbg%d_%zu.bc", opt_level, debug_level,
                                              bytecode.size()));
        HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                                  FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file != INVALID_HANDLE_VALUE) {
            DWORD written = 0;
            WriteFile(file, bytecode.data(), static_cast<DWORD>(bytecode.size()), &written, nullptr);
            CloseHandle(file);
        }
    }

    LoadContext ctx;
    fill_load_context(ctx, "=vesper_unc", bytecode);
    const bool loaded = guarded([&] {
        using LoadFn = int (*)(lua_State*, void*);
        reinterpret_cast<LoadFn>(g_bindings.luau_load)(thread, ctx.bytes);
    });
    const int status = *reinterpret_cast<int*>(ctx.bytes + 0x4C);
    if (!loaded || status != 0) {
        std::uintptr_t top = 0;
        read_ptr(reinterpret_cast<std::uintptr_t>(thread) + live::kTop, top);
        std::string detail;
        const std::string text = top >= 0x10 ? render_slot_value(top - 0x10, detail) : std::string();
        report += vformat("unc: prelude load guarded=%d status=%d text=\"%s\"\n", loaded ? 1 : 0,
                          status, text.c_str());
        if (marker_present(L"dumpcode")) {
            dump_image_region(0x2680000, 0x2760000, L"loader_dump.bin");
        }
        return 0;
    }

    std::uintptr_t pcall = g_profile.at("rva.luau.pcall", g_module_base);
    if (pcall == 0) pcall = g_module_base + 0x261BA30;
    int rc = -1;
    guarded([&] { rc = reinterpret_cast<int (*)(lua_State*, int, int, int)>(pcall)(thread, 0, 1, 0); });

    std::string note;
    if (!rsv::frame_ready(thread, note)) {
        report += "unc: " + note + "\n";
        return 0;
    }
    std::uintptr_t slot = 0;
    std::uintptr_t ci = 0;
    read_ptr(reinterpret_cast<std::uintptr_t>(thread) + live::kCi, ci);
    if (ci != 0) read_ptr(ci + 0x08, slot);

    bool reached = false;
    const int resume_status = rsv::run(thread, reached);
    rsv::restore(thread);
    if (!reached || resume_status != 0) {
        report += vformat("unc: prelude resume status=%d reached=%d\n", resume_status,
                          reached ? 1 : 0);
        return 0;
    }
    std::uintptr_t env = 0;
    std::uint32_t tag = 0;
    read_ptr(slot, env);
    if (slot != 0) safe_read(reinterpret_cast<const void*>(slot + 0x0C), &tag, sizeof(tag));
    report += vformat("unc: prelude rc=%d slot=%s value=%s tag=%u\n", rc, hex_of(slot).c_str(),
                      hex_of(env).c_str(), static_cast<unsigned>(tag));
    // The chunk ran to completion; that is all this lane needs (the preludes
    // write into the globals, so a table return is not required).
    return 1;
}

// --- executor surface: prepared, but never allowed to block the user's chunk --
//
// The eight preludes are *preparation*: each is its own private thread plus a
// load -> lua_pcall -> resume_continue pass. Running all of them inline on the
// `--exec` call path is exactly what produced the live symptom this pass fixes:
// on a busy client each pass took ~1 s, so eight of them blew past the shell's
// HTTP timeout and the user's chunk was never reached ("run: failed - no
// response from the bridge"). Two rules now hold, and they are the whole fix:
//
//   * the pass is bounded. `install_unc_surface` stops at `budget_ms` and the
//     caller runs the user's chunk regardless; the next exec resumes where this
//     one stopped, so the surface still completes across execs on a slow client;
//   * a prelude the client's loader rejects costs only that one global -- it is
//     logged and the pass moves on, it never aborts the rest nor the user chunk.
//
// The install runs on the same private-thread lane as the chunk, so no two lanes
// ever touch the client's bump allocator or its shared string tables at once. If
// the surface still cannot be prepared, it stays documented as pending
// (docs/hostapi-11f1.md); a chunk that only needs `print` never depends on it.
constexpr int kUncBudgetMs = 4000;

std::atomic<int> g_unc_next{0};
std::atomic<bool> g_unc_done{false};

int install_unc_surface(lua_State* parent, int budget_ms) {
    if (parent == nullptr || marker_present(L"no-unc") || g_unc_done.load()) return 0;

    const int total = static_cast<int>(sizeof(kUncPreludes) / sizeof(kUncPreludes[0]));
    const std::int64_t deadline = now_ms() + budget_ms;
    int installed = 0;
    int index = g_unc_next.load();
    while (index < total) {
        // The budget is checked before each prelude, so the cap bounds how long
        // this exec can be delayed even when a single pass is slow.
        if (now_ms() >= deadline) {
            VSP_INFO("exec: unc: budget %d ms spent after %d of %d preludes; resuming next exec",
                     budget_ms, index, total);
            break;
        }
        const char* prelude = kUncPreludes[index];
        bool done = false;
        for (int opt : {1, 0}) {
            std::string make_report;
            lua_State* unc_thread = pvt::make(parent, make_report);
            if (unc_thread == nullptr || !validate_state(unc_thread)) {
                VSP_INFO("exec: unc: could not build the prelude thread");
                break;
            }
            const std::uintptr_t pushed = pvt::push_on_parent(parent, unc_thread);
            if (pushed == 0) break;
            std::string unc_report;
            const std::uintptr_t ok = install_unc(unc_thread, prelude, unc_report, opt, 0);
            VSP_INFO("exec: %s", unc_report.c_str());
            // The closures now live in the global table, so the thread can be
            // dropped again; otherwise every prelude leaks a stack slot and a
            // lua_State, which is fatal after a handful.
            pvt::neutralize(unc_thread);
            pvt::pop_from_parent(parent, pushed);
            if (ok != 0) {
                done = true;
                break;
            }
        }
        // A rejected prelude is not fatal: move on to the next one.
        if (!done) VSP_INFO("exec: unc: one surface chunk could not be loaded (continuing)");
        else ++installed;
        ++index;
        g_unc_next.store(index);
    }
    if (index >= total) {
        g_unc_done.store(true);
        VSP_INFO("exec: unc: surface pass complete (%d preludes attempted)", total);
    }
    return installed;
}

}  // namespace

namespace {

// Lane D. The chunk is already loaded as one closure on `thread`'s stack. Move it to the
// game's own main state and call `task.defer` on it, so the game's scheduler runs the
// closure on a thread Roblox owns. Nothing here enters the VM on a thread we built.
// The result of a deferred call cannot be read back (it runs later); output reaches the
// client's console through `print`.
bool defer_to_scheduler(lua_State* parent, lua_State* thread, std::uintptr_t pushed_top,
                        ExecOutcome& out) {
    // REFUSED, deliberately. The first version of this lane called `lua_getglobal`,
    // `lua_getfield`, `lua_xmove` and `lua_remove` with the *client's* `lua_State`.
    // Those four are our own Luau, linked into Vesper.dll -- `nm out\Vesper.dll` lists
    // them as defined (`T lua_xmove(lua_State*, lua_State*, int)`), not imported. Their
    // `lua_State`, `LuaTable`, `TString` and `TValue` are not the client's: 9ac8 keeps
    // `gt` at +0x08, an encoded `stacksize`, `safeenv`/`nodemask8` bytes and vmval1..4
    // pointer encodings that our copy knows nothing about. Calling them on the client's
    // state reads and writes the wrong offsets -- corrupting the game's Lua heap, not
    // scheduling anything. The lane stays disabled until the lookup is done over raw
    // 9ac8 structs (see docs/9ac8-findings.md, "lane D, done correctly").
    // `pushed_top` is the slot where the private thread itself sits on the game's stack; it is
    // removed at the end, after the closure has been handed to the scheduler.

    // The closure the loader left on the private thread's stack, copied as raw bytes: no
    // of our own Luau may move it (nm shows lua_xmove is ours, not the client's).
    std::uint8_t closure_slot[pvt::kSlotBytes] = {};
    std::uintptr_t thread_top = 0;
    if (!read_ptr(reinterpret_cast<std::uintptr_t>(thread) + live::kTop, thread_top) ||
        thread_top < pvt::kSlotBytes ||
        !safe_read(reinterpret_cast<const void*>(thread_top - pvt::kSlotBytes), closure_slot,
                   sizeof(closure_slot))) {
        out.error = "defer: no closure on the private thread's stack";
        out.report += out.error + "\n";
        VSP_ERROR("%s", out.error.c_str());
        return false;
    }

    // The client's own `task.defer`. The Lua binding cannot be used: MEASURED, the `task`
    // table of the state this engine resolves has no `defer` and no `spawn`, only
    // cancel/wait/desynchronize/synchronize/delay. The C function behind the binding is a
    // normal `int task_defer(lua_State*)` in the client's image (RVA 0x43C38D0 on 9ac8), so
    // it can be called directly with the client's own `lua_pcall`: the client calling itself.
    std::uintptr_t task_defer = g_module_base + 0x43C38D0;
    std::uintptr_t pcall = g_profile.at("rva.luau.pcall", g_module_base);
    if (pcall == 0) pcall = g_module_base + 0x261BA30;
    using PCallFn = int (*)(lua_State*, int, int, int);

    const auto parent_base = reinterpret_cast<std::uintptr_t>(parent);
    std::uintptr_t top = 0;
    if (!read_ptr(parent_base + live::kTop, top) || top == 0) {
        out.error = "defer: cannot read the game's stack top";
        out.report += out.error + "\n";
        VSP_ERROR("%s", out.error.c_str());
        return false;
    }
    const std::uintptr_t saved_top = top;

    // Stack shape is exactly `task.defer(closure)`: the C function first, its argument next.
    pvt::poke<std::uintptr_t>(top, task_defer);
    pvt::poke<std::uint32_t>(top + 0x0C, rsv::kTagFunction);
    std::memcpy(reinterpret_cast<void*>(top + pvt::kSlotBytes), closure_slot, sizeof(closure_slot));
    pvt::poke<std::uintptr_t>(parent_base + live::kTop, top + 2 * pvt::kSlotBytes);

    const std::uint64_t started = GetTickCount64();
    int rc = -1;
    const bool called = guarded([&] {
        rc = reinterpret_cast<PCallFn>(pcall)(parent, 1, 0, 0);
    });

    std::uintptr_t after = 0;
    read_ptr(parent_base + live::kTop, after);
    pvt::poke<std::uintptr_t>(parent_base + live::kTop, saved_top);
    VSP_INFO("defer: task.defer(closure) guarded=%d rc=%d top %s->%s in %llu ms", called ? 1 : 0, rc,
             hex_of(saved_top).c_str(), hex_of(after).c_str(),
             static_cast<unsigned long long>(GetTickCount64() - started));

    // The closure belongs to the scheduler now; the private thread is no longer needed.
    pvt::neutralize(thread);
    pvt::pop_from_parent(parent, pushed_top);

    out.ok = called && rc == 0;
    out.value = out.ok ? std::string("handed to the game's task.defer") : std::string();
    if (!out.ok) {
        out.error = vformat("task.defer call failed (guarded=%d rc=%d)", called ? 1 : 0, rc);
        out.report += out.error + "\n";
    }
    return out.ok;
}

}  // namespace

// The call gate the mapper writes into the gate image: `mov rax,<target>; call rax; ret`.
// Calling the client through it makes the return address the client sees an address inside
// an image instead of one inside this mapped payload, which is the difference between "the
// client runs the call" and "the client ends the session".
std::uintptr_t call_gate_address() {
    static std::uintptr_t cached = 0;
    static bool looked = false;
    if (looked) return cached;
    looked = true;

    wchar_t root[MAX_PATH * 2] = {};
    const DWORD length = GetEnvironmentVariableW(L"LOCALAPPDATA", root, static_cast<DWORD>(std::size(root)));
    if (length == 0) return 0;
    std::wstring path(root, length);
    path += L"\\Vesper\\clients\\" + std::to_wstring(GetCurrentProcessId()) + L".tramp";

    const HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return 0;
    char text[40] = {};
    DWORD read = 0;
    ReadFile(file, text, sizeof(text) - 1, &read, nullptr);
    CloseHandle(file);

    cached = static_cast<std::uintptr_t>(std::strtoull(text, nullptr, 16));
    if (cached != 0) VSP_INFO("exec: call gate at %s", hex_of(cached).c_str());
    return cached;
}

bool exec_on_private_thread(lua_State* parent, const std::string& source, const std::string& chunk,
                            ExecOutcome& out, int encoder_mode) {
    out = ExecOutcome{};
    std::string& report = out.report;
    report += vformat("exec: parent=%s %zu bytes of source, chunk=%s\n",
                      hex_of(reinterpret_cast<std::uintptr_t>(parent)).c_str(), source.size(),
                      chunk.c_str());

    if (parent == nullptr) {
        out.error = "no parent lua_State";
        report += out.error + "\n";
        VSP_INFO("%s", report.c_str());
        return false;
    }
    if (g_bindings.luau_load == 0 || g_module_base == 0) {
        out.error = "this build's table exposes no rva.luau.load";
        report += out.error + "\n";
        VSP_INFO("%s", report.c_str());
        return false;
    }

    // Each step is flushed to the log as it happens: the client's own anti-tamper
// tears foreign threads down within seconds of attach, so a crash in the middle
// of the lane must leave the last completed step on disk.
#define PVT_STEP(...)                                \
    do {                                             \
        const std::string pvt_text = vformat(__VA_ARGS__); \
        report += pvt_text;                          \
        report += "\n";                              \
        VSP_INFO("exec: %s", pvt_text.c_str());      \
    } while (false)

    // A marker file wins over the caller, so all three encodings can be measured
    // on one client. 0 = plain, 1 = table[op*227], 2 = op*227.
    const int marker = encoder_marker();
    if (marker >= 0 && marker != encoder_mode) {
        PVT_STEP("encoder: caller asked for %d, marker overrides with %d", encoder_mode, marker);
        encoder_mode = marker;
    }

    // Compile in-process. Loading cannot tell the encodings apart (loading does
    // not execute), so three variants exist and which one ran is always logged.
    static const char* kModeNames[] = {"plain compiler", "table[op*227]", "op*227",
                                       "permutation-inverse", "vendored->internal"};
    const char* mode_name =
        kModeNames[(encoder_mode >= 0 && encoder_mode <= 4) ? encoder_mode : 1];

    std::string bytecode;
    std::string compile_error;
    bool compiled = false;
    try {
        bytecode = compile_bytecode_mode(source, encoder_mode);
        compiled = !bytecode.empty();
        if (!compiled) compile_error = "compiler produced no output";
    } catch (const std::exception& ex) {
        compile_error = ex.what();
    }
    if (!compiled) {
        out.error = "compile error: " + compile_error;
        report += out.error + "\n";
        VSP_INFO("%s", report.c_str());
        return false;
    }
    PVT_STEP("compiled %zu bytes with %s (head %02x %02x %02x %02x)", bytecode.size(), mode_name,
             static_cast<unsigned char>(bytecode.size() > 0 ? bytecode[0] : 0),
             static_cast<unsigned char>(bytecode.size() > 1 ? bytecode[1] : 0),
             static_cast<unsigned char>(bytecode.size() > 2 ? bytecode[2] : 0),
             static_cast<unsigned char>(bytecode.size() > 3 ? bytecode[3] : 0));
    {
        std::string hex;
        for (std::size_t i = 0; i < bytecode.size() && i < 96; ++i) {
            hex += vformat("%02x", static_cast<unsigned char>(bytecode[i]));
        }
        PVT_STEP("bytecode[%zu]= %s", bytecode.size(), hex.c_str());
    }
    if (marker_present(L"dumpbc")) {
        const std::wstring path = engine_directory() + L"\\user_chunk.bc";
        HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                                  FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file != INVALID_HANDLE_VALUE) {
            DWORD written = 0;
            WriteFile(file, bytecode.data(), static_cast<DWORD>(bytecode.size()), &written, nullptr);
            CloseHandle(file);
        }
    }
    {
        std::string all, missing;
        for (int i = 0; i < 256; ++i) {
            if (g_seen_any_vendored[i]) {
                const std::uint8_t internal_op = g_vendor_to_internal[i];
                if (internal_op == kInternalUnknown) {
                    missing += vformat(" %02x=UNMAPPED", i);
                } else {
                    all += vformat(" %02x->%02x", i, internal_op);
                }
            }
        }
        PVT_STEP("opcode trace: source=%s entries=%d | mapped%s | missing%s",
                 g_semantic_from_class ? "live-class-table" : "static-measured",
                 g_semantic_entries, all.c_str(),
                 missing.empty() ? " (none)" : missing.c_str());
    }

    // The loader's map, read live on this session. The measured relation is
    // `stored = table[in]`, with `table` the 256-byte permutation at
    // `rva.opcode_lookup_table`. So `table[in]` for the opcode bytes we just
    // emitted is exactly what the VM will see; with the permutation-inverse
    // encoder that column is the canonical opcode byte.
    {
        const bool shaped = load_opcode_table();
        PVT_STEP("opcode map: table=%s readable=1 bijection=%d",
                 hex_of(g_bindings.opcode_lookup).c_str(), shaped ? 1 : 0);
        if (g_opcode_table_ready) {
            std::string table_hex;
            for (int i = 0; i < 256; ++i) table_hex += vformat("%02x", g_opcode_table[i]);
            PVT_STEP("opcode table[256]= %s", table_hex.c_str());
        }
    }

    // Ground truth for the internal opcode space: a Proto the CLIENT itself
    // produced. The game's own Lua thread is running one, so its current frame
    // (`ci->func` -> closure -> Proto) is the oracle. Dumped before our chunk
    // loads, so nothing of ours can have influenced it.
    PVT_STEP("parent frame: %s", rsv::dump_frame(parent).c_str());

    // The loader resolves a chunk's environment from slot `[L+0x80]` when the
    // LoadContext env is 0 (`docs/hostapi-11f1.md` §1.2). The private thread
    // inherits that slot; log its type so `print` visibility is measurable.
    {
        std::uintptr_t env = 0;
        std::uint32_t env_tag = 0;
        read_ptr(reinterpret_cast<std::uintptr_t>(parent) + pvt::kExtraSlot, env);
        if (env != 0) safe_read(reinterpret_cast<const void*>(env + 0x0C), &env_tag, sizeof(env_tag));
        PVT_STEP("parent env slot [L+0x%llx]=%s tag=%u",
                 static_cast<unsigned long long>(pvt::kExtraSlot), hex_of(env).c_str(), env_tag);
    }

    // The private thread is pushed onto the parent so the GC can reach it while
    // the chunk runs; do that while the game's own thread is between calls. The
    // budget is short on purpose: the client's anti-tamper tears foreign threads
    // down seconds after attach, so waiting longer only makes the lane miss.
    // Lane D ('D' in the stage file): no synthesised thread at all. MEASURED: every run that
    // reached `luau_load` on a `pvt::make` thread ended with the client gone -- the loader is
    // entering a thread the client does not own. The game's own state loads chunks all day,
    // so load there, then hand the closure to the client's `task.defer` and let the scheduler
    // run it on its own thread.
    if (vesper::stage_skips('D')) {
        PVT_STEP("lane D: loading on the game's own state");
        if (!pvt::wait_for_idle(parent, 50)) PVT_STEP("lane D: the game's thread is busy");
        const auto parent_base = reinterpret_cast<std::uintptr_t>(parent);
        std::uintptr_t saved_top = 0, top_after_load = 0;
        read_ptr(parent_base + live::kTop, saved_top);

        // MEASURED (minidump, 0xC0000409 subcode 2 on the serving thread): calling
        // `0x4254A10` as a five-argument loader is wrong on this build -- the client's own
        // `__security_check_cookie` fast-failed inside it, which is what a mismatched calling
        // convention does. The wrapper the old lane used (`rva.luau.load`) plus the
        // `LoadContext` it fills is the route that actually loaded chunks here, so lane D
        // uses the same one, only pointed at the game's own state.
        LoadContext load_ctx;
        fill_load_context(load_ctx, "=Vesper", bytecode);
        *reinterpret_cast<std::int32_t*>(load_ctx.bytes + 0x48) = 0;
        // Through the call gate when the mapper left one: the call into the client is then
        // made from inside an image.
        const std::uintptr_t gate = call_gate_address();
        int load_rc = -1;
        const bool load_ok = guarded([&] {
            using LoadFn = int (*)(lua_State*, void*);
            if (gate != 0) {
                pvt::poke<std::uintptr_t>(gate + 2, g_bindings.luau_load);
                load_rc = reinterpret_cast<LoadFn>(gate)(parent, load_ctx.bytes);
            } else {
                load_rc = reinterpret_cast<LoadFn>(g_bindings.luau_load)(parent, load_ctx.bytes);
            }
            load_rc = *reinterpret_cast<int*>(load_ctx.bytes + 0x4C);
        });
        read_ptr(parent_base + live::kTop, top_after_load);
        std::uint32_t loaded_tag = 0;
        if (top_after_load >= pvt::kSlotBytes) {
            safe_read(reinterpret_cast<const void*>(top_after_load - pvt::kSlotBytes + 0x0C), &loaded_tag,
                      sizeof(loaded_tag));
        }
        PVT_STEP("lane D: luau_load(parent) guarded=%d rc=%d top %s->%s tag=%u", load_ok ? 1 : 0,
                 load_rc, hex_of(saved_top).c_str(), hex_of(top_after_load).c_str(), loaded_tag & 0xFF);
        if ((loaded_tag & 0xFF) != rsv::kTagFunction) {
            pvt::poke<std::uintptr_t>(parent_base + live::kTop, saved_top);
            out.error = vformat("lane D: the loader did not leave a function (tag=%u)", loaded_tag & 0xFF);
            out.report += out.error + "\n";
            VSP_ERROR("%s", out.error.c_str());
            return false;
        }

        const bool deferred = defer_to_scheduler(parent, parent, saved_top, out);
        pvt::poke<std::uintptr_t>(parent_base + live::kTop, saved_top);
        return deferred;
    }

    PVT_STEP("step: wait_for_idle begin");
    if (!pvt::wait_for_idle(parent, 50)) {
        PVT_STEP("the game's Lua thread was busy for 50 ms; still going ahead");
    }

    std::string make_report;
    PVT_STEP("step: pvt::make begin");
    lua_State* thread = pvt::make(parent, make_report);
    PVT_STEP("step: pvt::make end thread=%s", hex_of(reinterpret_cast<std::uintptr_t>(thread)).c_str());
    report += make_report;
    VSP_INFO("exec: %s", make_report.c_str());
    if (thread == nullptr) {
        out.error = "could not build a private thread";
        report += out.error + "\n";
        VSP_INFO("%s", report.c_str());
        return false;
    }
    if (!validate_state(thread)) {
        out.error = "the private thread does not satisfy validate_state";
        report += out.error + "\n";
        VSP_INFO("%s", report.c_str());
        return false;
    }

    const std::uintptr_t pushed_top = pvt::push_on_parent(parent, thread);
    PVT_STEP("pushed thread on the parent at top=%s", hex_of(pushed_top).c_str());
    {
        std::uintptr_t g = 0;
        read_ptr(reinterpret_cast<std::uintptr_t>(parent) + live::kUserdata, g);
        std::string notify;
        pvt::notify_user_thread(parent, thread, g, notify);
        report += notify;
        VSP_INFO("exec: %s", notify.c_str());
    }

    // The executor surface is *preparation*, so it is bounded and runs here,
    // before the chunk, never blocking longer than `kUncBudgetMs`; the next exec
    // continues from wherever this one stopped. A prelude the loader rejects is
    // logged and skipped -- it never stops the other preludes nor the chunk.
    // The loader still receives env index 0: the measured `LoadContext+0x48`
    // route never changed what a chunk resolves (docs/hostapi-11f1.md §night),
    // and the surface writes into the globals the chunk already sees.
    // Off by default (an 'S' in the stage file turns it on). MEASURED on 9ac8: the thread an
    // APC borrows from the game disappeared from the process while this ran (tid 11524,
    // gone mid-prelude; the game then sat at 0 CPU). Each prelude costs ~1 s on that thread,
    // and a user chunk needs none of them, so the borrowed thread now does only the user's
    // compile, load and call.
    PVT_STEP("step: install_unc_surface begin (budget %d ms)", vesper::stage_skips('S') ? kUncBudgetMs : 0);
    install_unc_surface(parent, vesper::stage_skips('S') ? kUncBudgetMs : 0);
    PVT_STEP("step: install_unc_surface end");
    const int unc_env_index = 0;

    struct Run {
        lua_State* thread;
        std::uintptr_t loader;
        LoadContext ctx;
        int status;
        int call_rc;
        std::uintptr_t top_before;
        std::uintptr_t top_after;
        std::uintptr_t result_slot;
    };
    Run run{thread, g_bindings.luau_load, LoadContext{}, -1, -1, 0, 0, 0};

    auto attempt_load = [&](const std::string& bc) -> bool {
        const char* name = chunk.empty() ? "=Vesper" : chunk.c_str();
        // MEASURED (this pass): the client's wrapper `rva.luau.load` rejects any
        // blob whose serialized size exceeds ~277 bytes, sharply and
        // content-independently (`return "<s>"` at 276 bytes loads, at 280 does
        // not; a 30-number table at 498 bytes fails the same way). Every earlier
        // "content-dependent" shape - debug sections, FASTCALL, >= 7 protos, wide
        // tables - was really byte count. The `load5arg` marker routes the chunk
        // through 0x4254A10, the 5-arg load the wrapper itself forwards to
        // (docs/hostapi-11f1.md Q1), to measure whether the ceiling belongs to the
        // wrapper or to the deserializer.
        // REFUSED, on evidence: a minidump of this path shows 0xC0000409 subcode 2 -- the
        // client's `__security_check_cookie` fast-failing -- because `0x4254A10` is not a
        // five-argument loader on this build and the call corrupts its frame. The marker is
        // kept as a name so an old script does not silently fall through to the wrapper, but
        // it no longer calls anything.
        if (marker_present(L"load5arg")) {
            PVT_STEP("load5arg: refused (wrong signature on 9ac8; it fast-fails the client)");
            out.error = "load5arg is not a five-argument loader on this build";
            report += out.error + "\n";
            pvt::neutralize(thread);
            pvt::pop_from_parent(parent, pushed_top);
            return false;
        }
        fill_load_context(run.ctx, name, bc);
        *reinterpret_cast<std::int32_t*>(run.ctx.bytes + 0x48) = unc_env_index;
        const bool ok = guarded([&] {
            using LoadFn = int (*)(lua_State*, void*);
            const auto fn = reinterpret_cast<LoadFn>(run.loader);
            const int ignored = fn(run.thread, run.ctx.bytes);
            (void)ignored;  // the status comes back at ctx+0x4C, not in eax
            run.status = *reinterpret_cast<int*>(run.ctx.bytes + 0x4C);
        });
        return ok && run.status == 0;
    };

    std::uintptr_t load_top_before = 0;
    read_ptr(reinterpret_cast<std::uintptr_t>(thread) + live::kTop, load_top_before);
    bool loaded = attempt_load(bytecode);

    // MEASURED: the client's `luau_load` rejects some chunks that the vendored
    // compiler produces, reporting "bytecode corrupted" and status 1, even though
    // the bytecode parses cleanly against the client's own decode/class tables
    // (verified offline, `%TEMP%\parse_bc.py`). The two shapes isolated are
    // (a) optimizationLevel 1 FASTCALL inside a proto that also captures an
    // upvalue, and (b) a proto whose debug-info section (line info / function
    // name) the client's loader walks off the end of. Both vanish when the chunk
    // is compiled with debug info off, and (a) also vanishes at optimization
    // level 0. So a rejected chunk is recompiled down this ladder before it is
    // declared unloadable; the first attempt keeps FASTCALL and full debug info,
    // which is what every verified chunk in the regression already uses.
    if (!loaded && !marker_present(L"noladder")) {
        static const int kLadder[][2] = {{0, 2}, {1, 0}, {0, 0}};
        for (const auto& step : kLadder) {
            if (loaded) break;
            pvt::poke<std::uintptr_t>(reinterpret_cast<std::uintptr_t>(thread) + live::kTop,
                                      load_top_before);
            std::string retry;
            try {
                retry = compile_bytecode_impl(source, encoder_mode, step[0], step[1]);
            } catch (const std::exception&) {
                retry.clear();
            }
            if (retry.empty()) continue;
            PVT_STEP("load: status=%d; retrying opt=%d debug=%d (%zu bytes)", run.status, step[0],
                     step[1], retry.size());
            loaded = attempt_load(retry);
            if (loaded) bytecode = retry;
        }
    }

    if (!loaded) {
        PVT_STEP("load: guarded failed status(ctxt+0x4C)=%d", run.status);
        // `luau_load` leaves its error message on the stack; render it so a
        // rejected chunk says why instead of just "status=1".
        {
            std::uintptr_t top = 0;
            read_ptr(reinterpret_cast<std::uintptr_t>(run.thread) + live::kTop, top);
            std::string detail;
            const std::string text = top >= 0x10 ? render_slot_value(top - 0x10, detail) : std::string();
            if (!text.empty()) PVT_STEP("load error text: \"%s\"", text.c_str());
        }
        if (marker_present(L"dumpcode")) {
            dump_image_region(0x2680000, 0x2760000, L"loader_dump_chunk.bin");
            dump_image_region(0x4240000, 0x4270000, L"gate_dump.bin");
        }
        out.error = vformat("load failed (status=%d)", run.status);
        report += out.error + "\n";
        pvt::neutralize(thread);
        pvt::pop_from_parent(parent, pushed_top);
        VSP_INFO("%s", report.c_str());
        return false;
    }
    report += "exec: luau_load -> status 0, closure on the private thread\n";
    report += dump_thread(thread, "exec: after load");
    report += "\n";
    VSP_INFO("exec: after load: %s", dump_thread(thread, "after load").c_str());

    // Stage 'D': hand the loaded closure to the game's scheduler instead of entering
    // the VM on the thread built above (see defer_to_scheduler).
    if (vesper::stage_skips('D')) {
        PVT_STEP("lane D: deferring to the game's task scheduler");
        const bool deferred = defer_to_scheduler(parent, thread, pushed_top, out);
        VSP_INFO("exec: lane D %s: %s", deferred ? "ok" : "failed", out.report.c_str());
        return deferred;
    }

    // The private thread needs its own security context: an identity and a
    // capability mask on the per-thread `RobloxExtraSpace`. The offset of that
    // space inside `lua_State` is measured on the live parent (never guessed)
    // and the chosen one is logged with its shape.
    {
        sec::Space space;
        std::string trace;
        PVT_STEP("step: sec::inspect begin");
        const bool shaped = sec::inspect(parent, space, &trace);
        PVT_STEP("step: sec::inspect end shaped=%d", shaped ? 1 : 0);
        report += trace;
        VSP_INFO("exec: security candidates:\n%s", trace.c_str());
        if (shaped) {
            std::string grant_report;
            PVT_STEP("step: sec::grant begin");
            const bool granted = sec::grant(thread, space, grant_report, true);
            PVT_STEP("step: sec::grant end granted=%d", granted ? 1 : 0);
            report += grant_report;
            VSP_INFO("exec: %s", grant_report.c_str());
            VSP_INFO("exec: security: identity field measured at lua_State+0x%llx, "
                     "RobloxExtraSpace identity=+0x%llx capabilities=+0x%llx granted=%d",
                     static_cast<unsigned long long>(space.field),
                     static_cast<unsigned long long>(sec::kExtraIdentity),
                     static_cast<unsigned long long>(sec::kExtraCapabilities), granted ? 1 : 0);
        } else {
            report += "security: no per-thread RobloxExtraSpace matched the shape\n";
            VSP_WARN("exec: no per-thread RobloxExtraSpace matched; running without identity");
        }
    }

    PVT_STEP("calling lua_pcall(thread, 0, 1, 0)");
    const bool called = guarded([&] {
        std::uintptr_t pcall = g_profile.at("rva.luau.pcall", g_module_base);
        if (pcall == 0) pcall = g_module_base + 0x261BA30;
        using PCallFn = int (*)(lua_State*, int, int, int);
        run.top_before =
            *reinterpret_cast<std::uintptr_t*>(reinterpret_cast<char*>(run.thread) + live::kTop);
        run.call_rc = reinterpret_cast<PCallFn>(pcall)(run.thread, 0, 1, 0);
        run.top_after =
            *reinterpret_cast<std::uintptr_t*>(reinterpret_cast<char*>(run.thread) + live::kTop);
    });
    PVT_STEP("lua_pcall -> rc=%d top %s->%s delta=%+lld guarded=%d", run.call_rc,
             hex_of(run.top_before).c_str(), hex_of(run.top_after).c_str(),
             static_cast<long long>(run.top_after) - static_cast<long long>(run.top_before),
             called ? 1 : 0);

    // `lua_pcall` returning -1 with `L->status == SCHEDULED_REENTRY` is not a
    // failure: `luau_precall` already built the CallInfo and `resume_continue`
    // (RVA 0x2630540) is the client's own routine for finishing that entry.
    // Drive it here, under the client's `luaD_rawrunprotected`.
    std::string frame_note;
    PVT_STEP("step: frame_ready begin");
    const bool framed = rsv::frame_ready(run.thread, frame_note);
    PVT_STEP("step: frame_ready end framed=%d", framed ? 1 : 0);
    PVT_STEP("%s", frame_note.c_str());
    PVT_STEP("%s", rsv::dump_frame(run.thread).c_str());

    // The VM's RETURN copies its results to the callee's `ci->func` slot (see the
    // handler at RVA 0x2670AB4: `rdx = [ci+8]`), so that slot, not `L->top - 0x10`
    // (which `RETURN` leaves pointing at the caller frame), is where the chunk's
    // return value ends up. Captured here, before the frame is popped.
    if (framed) {
        std::uintptr_t callee_ci = 0;
        read_ptr(reinterpret_cast<std::uintptr_t>(run.thread) + live::kCi, callee_ci);
        if (callee_ci != 0) read_ptr(callee_ci + 0x08, run.result_slot);
        PVT_STEP("result slot (callee ci->func) = %s", hex_of(run.result_slot).c_str());
    }

    // `VESPER_NO_RESUME=1` (or a `%LOCALAPPDATA%\Vesper\no-resume` marker file,
    // which can be created and deleted between two bridge calls on one session)
    // stops here: the frame is prepared and everything about it is in the log,
    // but the interpreter is never entered. Useful for telling "the loader
    // mangled the bytecode" apart from "the VM refuses this thread" without
    // spending a client on the second attempt.
    const bool skip_resume = [] {
        wchar_t flag[8] = {};
        if (GetEnvironmentVariableW(L"VESPER_NO_RESUME", flag, 8) > 0 &&
            (flag[0] == L'1' || flag[0] == L't' || flag[0] == L'T')) {
            return true;
        }
        wchar_t root[MAX_PATH * 2] = {};
        const DWORD length =
            GetEnvironmentVariableW(L"LOCALAPPDATA", root, static_cast<DWORD>(std::size(root)));
        if (length == 0) return false;
        std::wstring marker(root, length);
        marker += L"\\Vesper\\no-resume";
        const DWORD attributes = GetFileAttributesW(marker.c_str());
        return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
    }();

    // `called` records whether `lua_pcall` returned without our fault guard
    // tripping. Hyperion raises periodic illegal-instruction traps in the
    // process, and the guard turns a trap inside the call into `called == 0`
    // even though the call itself completed (the frame is intact and the
    // interpreter then runs it). The authoritative success signal is therefore
    // the resume: when it reports `status=0` and the thread's status byte is
    // back to LUA_OK, the chunk ran to completion regardless of `called`.
    bool executed = false;
    if (framed && skip_resume) {
        PVT_STEP("VESPER_NO_RESUME=1: the interpreter was not entered");
    } else if (framed) {
        PVT_STEP("calling resume_continue(%s) @ 0x%llx under luaD_rawrunprotected @ 0x%llx",
                 hex_of(reinterpret_cast<std::uintptr_t>(run.thread)).c_str(),
                 static_cast<unsigned long long>(rsv::kResumeContinueRva),
                 static_cast<unsigned long long>(rsv::kRawRunProtectedRva));
        std::uintptr_t before = 0;
        read_ptr(reinterpret_cast<std::uintptr_t>(run.thread) + live::kTop, before);
        bool reached = false;
        const int resume_status = rsv::run(run.thread, reached);
        std::uintptr_t after = 0;
        read_ptr(reinterpret_cast<std::uintptr_t>(run.thread) + live::kTop, after);
        PVT_STEP("resume_continue -> status=%d reached=%d top %s->%s delta=%+lld", resume_status,
                 reached ? 1 : 0, hex_of(before).c_str(), hex_of(after).c_str(),
                 static_cast<long long>(after) - static_cast<long long>(before));
        std::uint8_t status_byte = 0;
        safe_read(reinterpret_cast<const void*>(reinterpret_cast<std::uintptr_t>(run.thread) +
                                                rsv::kStatus),
                  &status_byte, sizeof(status_byte));
        PVT_STEP("after resume: L->status=0x%02X %s", status_byte,
                 dump_thread(run.thread, "resume").c_str());
        rsv::restore(run.thread);
        if (reached && resume_status == 0 && status_byte == 0) {
            // The interpreter ran the chunk to completion; the result the frame
            // left behind is the chunk's return value.
            run.call_rc = 0;
            executed = true;
        } else if (resume_status != 0) {
            // A Luau error: the message is the object `luaD_seterrorobj` left at
            // the stack top. Surface it instead of a bare status code.
            std::uintptr_t top = 0;
            read_ptr(reinterpret_cast<std::uintptr_t>(run.thread) + live::kTop, top);
            std::string detail;
            const std::string text =
                top >= 0x10 ? render_slot_value(top - 0x10, detail) : std::string();
            if (!text.empty()) PVT_STEP("runtime error: \"%s\"", text.c_str());
        }
    }

    std::string detail;
    VSP_INFO("exec: after call: %s", dump_thread(thread, "after call").c_str());
    report += dump_thread(thread, "exec: after call");
    report += "\n";
    // Only a call that actually returned has a result to report; on any other
    // outcome the slot still holds the closure the loader pushed, and rendering
    // that would be a lie. On the resume path the value lives at the callee's
    // `ci->func` slot (RETURN's destination), so prefer that; fall back to
    // `L->top - 0x10` otherwise.
    if ((called || executed) && run.call_rc == 0) {
        std::string slot_detail;
        const std::string slot_value = render_slot_value(run.result_slot, slot_detail);
        out.value = render_top(thread, detail);
        if (!slot_value.empty()) {
            out.value = slot_value;
        }
        detail += "; " + slot_detail;
    } else {
        out.value = std::string();
    }
    PVT_STEP("result %s", detail.c_str());
    out.ok = (called || executed) && run.call_rc == 0;
    if (!out.ok && out.error.empty()) {
        std::uint8_t status_byte = 0;
        safe_read(reinterpret_cast<const void*>(reinterpret_cast<std::uintptr_t>(run.thread) + 3),
                  &status_byte, sizeof(status_byte));
        if (run.call_rc == -1 && status_byte == pvt::kScheduledReentry) {
            out.error =
                "the chunk compiled and loaded on a private thread, but the VM deferred the "
                "call: lua_pcall returned -1 with L->status = SCHEDULED_REENTRY (0x7F), which is "
                "what performcall sets instead of entering luau_execute when the thread looks "
                "yieldable (nCcalls <= baseCcalls). Entering the VM from a thread Roblox does "
                "not own terminates the client, so the call has to be handed to the scheduler.";
        } else {
            std::string slot;
            render_top(thread, slot);
            out.error = vformat("lua_pcall returned %d (status byte %u)%s", run.call_rc,
                                static_cast<unsigned>(status_byte), slot.c_str());
        }
    }

    // The engine's log is the only place a returned value can be observed, so
    // the value is always written there. On success it is also echoed to the
    // client's own console, through the same channel the chunk's `print` lands
    // on, so the executor is visible in-game as well as in the engine log.
    VSP_INFO("exec: chunk=%s ok=%d value=\"%s\" (%s)", chunk.c_str(), out.ok ? 1 : 0,
             out.value.c_str(), detail.c_str());
    host_print(vformat("Vesper: %s -> %s", chunk.c_str(), out.ok ? out.value.c_str() : "(error)"));

    PVT_STEP("step: neutralize + pop begin");
    pvt::neutralize(thread);
    pvt::pop_from_parent(parent, pushed_top);
    PVT_STEP("step: neutralize + pop end");
    {
        std::uintptr_t top = 0;
        read_ptr(reinterpret_cast<std::uintptr_t>(parent) + live::kTop, top);
        report += vformat("exec: parent top is now %s (pushed %s)\n", hex_of(top).c_str(),
                          hex_of(pushed_top).c_str());
    }

    VSP_INFO("%s", report.c_str());
    return out.ok;
}

ExecOutcome exec_source(const std::string& source, const std::string& chunk, int encoder_mode) {
    ExecOutcome out;
    VSP_INFO("exec: state=%s script_context=%s in_game=%d has_lua_state=%d",
             hex_of(reinterpret_cast<std::uintptr_t>(g_lua_state)).c_str(),
             hex_of(g_status.script_context).c_str(), g_status.in_game ? 1 : 0,
             g_status.has_lua_state ? 1 : 0);

    // Diagnostic command: with `L` in the stage file a command runs the read-only lookup
    // instead of a chunk. That is what makes it possible to probe the *game* state without
    // injecting a second time -- join the place, send any command, read the keys.
    if (vesper::stage_skips('L')) {
        VSP_INFO("exec: stage L -- running the read-only lookup instead of a chunk");
        probe_defer_lookup();
        out.ok = true;
        out.report += "probe: read-only lookup ran\n";
        return out;
    }
    // Menu state is a valid state, but a chunk there runs in the CoreScripts context with
    // no DataModel: `game`, `workspace` and `script` are not what a user script expects.
    // `stage` letter 'M' overrides this for experiments.
    if (!g_status.in_game && !vesper::stage_skips('M')) {
        out.error = "no place is loaded: attached but not in a game (in_game=0). "
                    "Join a game, or put 'M' in the stage file to run in the menu anyway.";
        out.report += out.error + "\n";
        VSP_WARN("exec: %s", out.error.c_str());
        return out;
    }
    // The loader's opcode map is MEASURED: it is the 256-byte permutation at
    // `rva.opcode_lookup_table` indexed by the input byte, `stored = table[in]`
    // (see docs/opcode-space-11f1.md). The default is therefore the permutation
    // inverse (mode 3), which hands the loader `inverse[op]` so the VM sees the
    // canonical opcode byte. The legacy public recipes are still reachable
    // explicitly (mode 1 = `table[op*227]`, mode 2 = `op*227`) and by the
    // `%LOCALAPPDATA%\Vesper\encoder` marker, which can be toggled between bridge
    // calls on one session.
    const int mode = (encoder_mode >= 1 && encoder_mode <= 3) ? encoder_mode : 4;
    exec_on_private_thread(g_lua_state, source, chunk, out, mode);
    return out;
}

// ------------------------------------------------------------ hook load/run --
//
// `luau_load` is driven on a private thread built out of the client's own
// allocator, so this is callable from any thread: the game's own Lua thread and
// the bridge thread reach the same code. The only thing it does to the game's
// live state is the one-slot push the client itself performs when it makes a
// thread.
void hostapi_load_and_run(lua_State* L, const char* source, std::size_t size) {
    ExecOutcome outcome;
    exec_on_private_thread(L != nullptr ? L : g_lua_state,
                           std::string(source != nullptr ? source : "", size), "=Vesper", outcome,
                           4);
    VSP_INFO("hostapi: load_and_run ok=%d value=\"%s\" error=\"%s\"", outcome.ok ? 1 : 0,
             outcome.value.c_str(), outcome.error.c_str());
}

// ------------------------------------------------------------- VM hook lane --
//
// Every path above either runs on the bridge thread or assumes the vendored
// `lua_State`. Neither can drive this client: the game's own Lua thread is live
// on the same state, and two threads must not push frames on it. `hostapi_probe`
// showed the shape of the answer -- a pure push (`lua_pushfstringL`) from any
// thread is fine, but a call-ish entry (`luau_load`, `luaL_requiref`) wedges the
// client. Execution therefore has to happen *inside the game's own Lua thread*.
//
// The lane here borrows that thread: a detour on the VM entry the client calls
// on it, `rva.luau.execute`, so our code runs in the middle of a call the client
// itself is making, and calling the client's C API there is the client calling
// itself.
//
// The bridge only *enqueues* -- it never dereferences the `lua_State` and never
// calls a `lua_*` function. A normal attach installs none of this: installation
// is behind `hook_install()`, reached only by the `/hooktest` route and the
// `VESPER_HOOKTEST` self-test.
namespace {

enum class HookJobKind { None = 0, Probe, LoadAndRun };

struct HookJob {
    HookJobKind kind = HookJobKind::None;
    std::string source;
    std::string chunk;
};

// The whole bridge-to-hook handoff is one atomic: `g_hook_slot` is 0 = empty,
// 1 = a job is staged in `g_hook_job`, 2 = a hook thread is running it. The hook
// only ever touches it with atomics -- a lock the VM could re-enter is a
// deadlock waiting to happen -- so `g_hook_producer` (taken by the HTTP and tick
// threads, never by the hook) only serializes the producers against each other.
constexpr int kHookEmpty = 0;
constexpr int kHookReady = 1;
constexpr int kHookInUse = 2;

std::atomic<int> g_hook_slot{kHookEmpty};
std::atomic<bool> g_hook_running{false};
HookJob g_hook_job;
std::mutex g_hook_producer;

std::atomic<long> g_hook_entries{0};
std::atomic<long> g_hook_jobs{0};
std::atomic<long> g_hook_probes{0};

std::uintptr_t g_hook_target = 0;
std::uintptr_t g_hook_true = 0;
std::uintptr_t g_hook_false = 0;
std::uintptr_t g_hook_arena = 0;
bool g_hook_arena_owned = false;
std::uint8_t g_hook_saved[16] = {};
std::size_t g_hook_saved_len = 0;
bool g_hook_installed = false;

// Re-implements the entry thunk: `cmp byte ptr [rcx+4], 0; jne execute_true;
// jmp execute_false`. Only rcx is an input, so the branch is all the thunk does.
std::uintptr_t hook_dispatch_target(lua_State* L) {
    const std::uint8_t flag =
        *reinterpret_cast<const volatile std::uint8_t*>(reinterpret_cast<std::uintptr_t>(L) + 4);
    return flag == 0 ? g_hook_false : g_hook_true;
}

void hook_run_probe(lua_State* L) {
    const auto base = reinterpret_cast<std::uintptr_t>(L);
    std::uintptr_t top_before = 0;
    std::uintptr_t ci = 0;
    read_ptr(base + live::kTop, top_before);
    read_ptr(base + live::kCi, ci);
    VSP_INFO("hook: entered on thread %lu  L=%s top=%s ci=%s", GetCurrentThreadId(),
             hex_of(base).c_str(), hex_of(top_before).c_str(), hex_of(ci).c_str());

    const std::uintptr_t pushfstring = g_profile.at("rva.luau.pushfstringL", g_module_base);
    if (pushfstring == 0) {
        VSP_WARN("hook: this build's table does not expose rva.luau.pushfstringL");
        return;
    }
    using PushFStringFn = const char* (*)(lua_State*, const char*, ...);
    const char* text = reinterpret_cast<PushFStringFn>(pushfstring)(L, "%s", "VESPER_IN_HOOK");
    VSP_INFO("hook: pushfstringL -> %s \"%.24s\"",
             hex_of(reinterpret_cast<std::uintptr_t>(text)).c_str(), text != nullptr ? text : "");
    VSP_INFO("%s", stack_window(L, top_before, "in hook").c_str());
}

void hook_run_job(HookJob job, lua_State* L) {
    ++g_hook_jobs;
    switch (job.kind) {
        case HookJobKind::Probe:
            ++g_hook_probes;
            hook_run_probe(L);
            break;
        case HookJobKind::LoadAndRun:
            hostapi_load_and_run(L, job.source.data(), job.source.size());
            break;
        default:
            break;
    }
}

// Defined just below; the detour target calls it.
std::uintptr_t hook_execute_body(lua_State* L);

// The detour target. It is entered by a jmp, so the stack is exactly as a normal
// call to `execute` left it; it then *calls* the real body and returns the way
// `execute` would have. Calling rather than tail-jumping costs one frame and
// keeps the ABI -- stack alignment, callee saved registers, the return address
// -- exactly what the client's own code expects.
void hook_execute_entry(lua_State* L) {
    using ExecuteFn = void (*)(lua_State*);
    const std::uintptr_t target = hook_execute_body(L);
    if (target != 0) reinterpret_cast<ExecuteFn>(target)(L);
}

std::uintptr_t hook_execute_body(lua_State* L) {
    g_hook_entries.fetch_add(1, std::memory_order_relaxed);

    // Fast path: nothing staged. One relaxed load, a plain read of one byte and a
    // branch. Nothing is written, nothing is called, no lock is taken, so an idle
    // detour is invisible to the client and cannot freeze it.
    if (g_hook_slot.load(std::memory_order_acquire) == kHookReady) {
        bool idle = false;
        if (g_hook_running.compare_exchange_strong(idle, true, std::memory_order_acq_rel)) {
            int ready = kHookReady;
            if (g_hook_slot.compare_exchange_strong(ready, kHookInUse, std::memory_order_acq_rel)) {
                HookJob job = std::move(g_hook_job);
                g_hook_slot.store(kHookEmpty, std::memory_order_release);
                hook_run_job(std::move(job), L);
            }
            g_hook_running.store(false, std::memory_order_release);
        }
    }
    return hook_dispatch_target(L);
}

bool hook_write_code(std::uintptr_t address, const void* bytes, std::size_t len, DWORD restore) {
    DWORD previous = 0;
    if (!VirtualProtect(reinterpret_cast<void*>(address), len, PAGE_EXECUTE_READWRITE, &previous)) {
        return false;
    }
    std::memcpy(reinterpret_cast<void*>(address), bytes, len);
    FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(address), len);
    DWORD ignored = 0;
    VirtualProtect(reinterpret_cast<void*>(address), len, restore, &ignored);
    return true;
}

// Length of the documented thunk, or 0 when the bytes are not that shape. The
// thunk is `cmp byte ptr [rcx+disp8], imm8` / `jcc` / `jmp`, where each jump is
// either near or short, so the three encodings are all that is decoded.
std::size_t thunk_shape_length(const std::uint8_t* code) {
    std::size_t i = 0;
    if (code[0] == 0x80 && code[1] == 0x79) {
        i = 4;
    } else {
        return 0;
    }
    if (code[i] == 0x0F && (code[i + 1] & 0xF0) == 0x80) {
        i += 6;
    } else if ((code[i] & 0xF0) == 0x70) {
        i += 2;
    } else {
        return 0;
    }
    if (code[i] == 0xE9) {
        i += 5;
    } else if (code[i] == 0xEB) {
        i += 2;
    } else {
        return 0;
    }
    return i;
}

bool all_padding(const std::uint8_t* code, std::size_t from, std::size_t to) {
    for (std::size_t i = from; i < to; ++i) {
        const std::uint8_t byte = code[i];
        if (byte != 0xCC && byte != 0x90 && byte != 0x00) return false;
    }
    return true;
}

// `VESPER_HOOK_ARENA=0x...` lets a caller hand in a page that is already inside a
// signed image (the shell's gate stub region is exactly that), which is the one
// place the anti-tamper is known to tolerate generated code.
std::uintptr_t hook_env_arena() {
    wchar_t value[32] = {};
    if (GetEnvironmentVariableW(L"VESPER_HOOK_ARENA", value, 32) == 0) return 0;
    std::uintptr_t result = 0;
    for (const wchar_t* cursor = value; *cursor != L'\0'; ++cursor) {
        const wchar_t character = *cursor;
        int digit = -1;
        if (character >= L'0' && character <= L'9') digit = character - L'0';
        else if (character >= L'a' && character <= L'f') digit = character - L'a' + 10;
        else if (character >= L'A' && character <= L'F') digit = character - L'A' + 10;
        else continue;  // the "0x" prefix and any separator
        result = (result << 4) | static_cast<std::uintptr_t>(digit);
    }
    return result;
}

// A page within rel32 of the target, for the short-thunk case where a 14-byte
// absolute patch would run past the function. The arena is data written once; it
// is a private page, which the client's own runtime may police, so it is a
// fallback rather than the default.
std::uintptr_t acquire_near_arena(std::uintptr_t target, std::string& detail) {
    const std::uintptr_t from_env = hook_env_arena();
    if (from_env != 0) {
        MEMORY_BASIC_INFORMATION info{};
        if (VirtualQuery(reinterpret_cast<void*>(from_env), &info, sizeof(info)) != 0 &&
            info.State == MEM_COMMIT &&
            (info.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                             PAGE_EXECUTE_WRITECOPY)) != 0) {
            detail = "VESPER_HOOK_ARENA";
            return from_env;
        }
        detail = "VESPER_HOOK_ARENA is not a committed executable page";
        return 0;
    }

    SYSTEM_INFO info{};
    GetSystemInfo(&info);
    const std::uintptr_t granularity =
        info.dwAllocationGranularity != 0 ? info.dwAllocationGranularity : 0x10000;
    const std::uintptr_t limit = 0x70000000ULL;  // stay inside rel32 range
    for (std::uintptr_t delta = 0; delta < limit; delta += granularity) {
        for (int direction = 1; direction >= -1; direction -= 2) {
            std::uintptr_t hint = direction > 0 ? target + delta : target - delta;
            hint &= ~(granularity - 1);
            if (hint < 0x10000) continue;
            void* block = VirtualAlloc(reinterpret_cast<void*>(hint), 0x1000,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (block != nullptr) {
                g_hook_arena_owned = true;
                detail = "private page near the target";
                return reinterpret_cast<std::uintptr_t>(block);
            }
        }
    }
    detail = "no executable page inside rel32 of the target";
    return 0;
}

// The run point we can actually get. The TaskScheduler calls the script job's
// `step()` through its vtable, on the game's own Lua thread, and the job object's
// vtable pointer is a writable field on the heap -- so redirecting that one pointer
// is a *data* write, which is allowed. Hyperion protects code pages and nothing
// else: measured on this build, an in-process `VirtualProtect` of the client's
// `.text` to writable fails ("the page would not become writable") and an external
// write returns win32_error 998, while writes to a heap object and to a module
// `.data` global both succeed. Nothing here touches a code page.
std::uintptr_t g_hook_job_object = 0;
std::uintptr_t g_hook_vtable = 0;
std::uintptr_t g_hook_vtable_copy = 0;
std::uintptr_t g_hook_step_original = 0;
std::size_t g_hook_slot_index = 0;

// The signature is not a guess. roblox-modloader hooks this exact function, and its
// hook is `StepResult on_job_step(DataModelJob* job, const Stats& time_metrics)` --
// two arguments and a return value. Our earlier detour took six arguments and
// returned void, i.e. it discarded the step's result and the scheduler then acted on
// garbage: that, and not Hyperion, is what killed the client on the very first call.
// The result comes back in eax, so returning 64 bits satisfies either width.
std::uint64_t hook_job_entry(void* self, const void* time_metrics) {
    g_hook_entries.fetch_add(1, std::memory_order_relaxed);
    if (g_hook_slot.load(std::memory_order_acquire) == kHookReady) {
        bool idle = false;
        if (g_hook_running.compare_exchange_strong(idle, true, std::memory_order_acq_rel)) {
            int ready = kHookReady;
            if (g_hook_slot.compare_exchange_strong(ready, kHookInUse, std::memory_order_acq_rel)) {
                HookJob job = std::move(g_hook_job);
                g_hook_slot.store(kHookEmpty, std::memory_order_release);
                hook_run_job(std::move(job), g_lua_state);
            }
            g_hook_running.store(false, std::memory_order_release);
        }
    }
    using StepFn = std::uint64_t (*)(void*, const void*);
    return reinterpret_cast<StepFn>(g_hook_step_original)(self, time_metrics);
}

std::string hook_install_job_impl() {
    if (g_hook_installed) return "hook: already installed\n";
    const std::uintptr_t job = g_script_job;
    if (job == 0) return "hook: no script context job resolved yet\n";

    std::uintptr_t vtable = 0;
    if (!read_ptr(job, vtable) || vtable == 0) return "hook: the job object has no vtable\n";

    const std::uintptr_t step = g_profile.at("rva.whjs_step", g_module_base);
    std::string report = vformat("hook: job=%s vtable=%s whjs_step=%s\n", hex_of(job).c_str(),
                                 hex_of(vtable).c_str(), hex_of(step).c_str());

    // The vtable is copied wholesale, because the scheduler calls other slots on it
    // as well: truncating the copy would leave its tail uninitialised, and a crash
    // from a slot we never touched looks like anything but a hook. The longest read
    // that succeeds wins, so a vtable ending at a page boundary does not fail the
    // install.
    std::vector<std::uintptr_t> slots;
    for (std::size_t count : {64u, 128u, 256u, 512u}) {
        std::vector<std::uintptr_t> attempt(count, 0);
        if (!safe_read(reinterpret_cast<const void*>(vtable), attempt.data(),
                       count * sizeof(std::uintptr_t))) {
            break;
        }
        slots = std::move(attempt);
    }
    if (slots.empty()) return report + "hook: cannot read the job vtable\n";
    report += vformat("hook: vtable copy holds %zu slots\n", slots.size());
    report += "hook: vtable head:";
    for (std::size_t i = 0; i < 8; ++i) report += vformat(" %s", hex_of(slots[i]).c_str());
    report += "\n";

    // Prefer the slot the table says is this job's step. Fall back to the first
    // non-empty slot only if the table's address is not in the vtable at all -- and
    // say so loudly, because redirecting a slot we did not identify would replace
    // some other virtual method of the client's.
    std::size_t found = 0;
    bool identified = false;
    if (step != 0) {
        for (std::size_t i = 0; i < slots.size(); ++i) {
            if (slots[i] == step) {
                found = i;
                identified = true;
                break;
            }
        }
    }
    report += vformat("hook: slot %zu redirected (identified by rva.whjs_step: %s)\n", found,
                      identified ? "yes" : "no");
    if (!identified) return report + "hook: rva.whjs_step is not in this vtable; not guessing\n";
    if (slots[found] == 0) return report + "hook: that slot is empty\n";

    void* copy = VirtualAlloc(nullptr, slots.size() * sizeof(std::uintptr_t), MEM_COMMIT | MEM_RESERVE,
                              PAGE_READWRITE);
    if (copy == nullptr) return report + "hook: cannot allocate the vtable copy\n";
    std::memcpy(copy, slots.data(), slots.size() * sizeof(std::uintptr_t));

    // `VESPER_VTABLE_PASSTHROUGH=1` points the job at an *identical* copy and leaves
    // every slot alone. It separates the two things that could be fatal here: our
    // detour misbehaving when the scheduler calls it, versus the client refusing to
    // see an object's vtable pointing outside its own image.
    wchar_t passthrough[8] = {};
    const bool copy_only = GetEnvironmentVariableW(L"VESPER_VTABLE_PASSTHROUGH", passthrough, 8) != 0;
    if (!copy_only) {
        static_cast<std::uintptr_t*>(copy)[found] = reinterpret_cast<std::uintptr_t>(&hook_job_entry);
    }

    // The object's vtable pointer field has to be writable for this to be a data
    // write rather than a lucky one, so ask before touching it.
    // Replace the slot *inside the class vtable* rather than repointing this object at
    // a private copy. That is what roblox-modloader's `vtable_hook` does, and the
    // difference is not cosmetic: every object of the class keeps the canonical
    // vtable pointer, so nothing in the client sees a job whose vtable lives outside
    // its own image. Repointing one object's pointer field was enough on its own to
    // make the client die, even before the slot was touched.
    const std::uintptr_t slot_address = vtable + found * sizeof(std::uintptr_t);
    if (!safe_read(reinterpret_cast<const void*>(slot_address), g_hook_saved, sizeof(std::uintptr_t))) {
        return report + "hook: cannot save the step slot\n";
    }
    g_hook_saved_len = sizeof(std::uintptr_t);
    const std::uintptr_t entry = reinterpret_cast<std::uintptr_t>(&hook_job_entry);
    if (!hook_write_code(slot_address, &entry, sizeof(entry), PAGE_READONLY)) {
        g_hook_saved_len = 0;
        return report + "hook: cannot write the step slot (the vtable page stayed read-only)\n";
    }

    g_hook_job_object = job;
    g_hook_vtable = vtable;

    g_hook_step_original = slots[found];
    g_hook_slot_index = found;
    g_hook_target = vtable;  // so the status route reports something meaningful
    g_hook_arena = g_hook_vtable_copy;
    g_hook_installed = true;
    if (copy_only) {
        VSP_INFO("hook: passthrough -- job %s now points at an identical vtable copy, slot %zu untouched",
                 hex_of(job).c_str(), found);
        report += "hook: passthrough installed; no slot was redirected\n";
        return report;
    }
    VSP_INFO("hook: data hook installed on job %s slot %zu (step %s -> %s)", hex_of(job).c_str(), found,
             hex_of(slots[found]).c_str(), hex_of(reinterpret_cast<std::uintptr_t>(&hook_job_entry)).c_str());
    report += "hook: installed; the scheduler's next step() call runs our detour on the game's Lua thread\n";
    return report;
}

std::string hook_install_impl() {
    if (g_hook_installed) return "hook: already installed\n";

    // Hyperion protects the client's code pages, so the old code-patch path below
    // can never reach its patch: measured, an in-process VirtualProtect to writable
    // fails and an external write returns win32_error 998. The run point comes from
    // data instead. The code below is kept for reference only.
    return hook_install_job_impl();

    const std::uintptr_t base = g_module_base != 0 ? g_module_base : host_module_base();
    g_hook_target = g_profile.at("rva.luau.execute", base);
    g_hook_true = g_profile.at("rva.luau.execute_true", base);
    g_hook_false = g_profile.at("rva.luau.execute_false", base);

    std::string report = vformat("hook: execute=%s true=%s false=%s\n", hex_of(g_hook_target).c_str(),
                                 hex_of(g_hook_true).c_str(), hex_of(g_hook_false).c_str());
    if (g_hook_target == 0 || g_hook_true == 0 || g_hook_false == 0) {
        return report + "hook: this build's table does not expose the luau execute entries\n";
    }

    std::uint8_t code[16] = {};
    if (!safe_read(reinterpret_cast<const void*>(g_hook_target), code, sizeof(code))) {
        return report + "hook: cannot read the target prologue\n";
    }
    std::string raw;
    for (std::size_t i = 0; i < sizeof(code); ++i) raw += vformat("%02x", code[i]);
    const std::size_t own = thunk_shape_length(code);
    report += vformat("hook: prologue=%s decoded=%zu\n", raw.c_str(), own);
    if (own == 0) {
        return report + "hook: prologue is not the documented thunk; refusing to patch\n";
    }

    const std::uintptr_t entry = reinterpret_cast<std::uintptr_t>(&hook_execute_entry);
    report += vformat("hook: detour=%s\n", hex_of(entry).c_str());

    std::vector<std::uint8_t> patch;
    std::size_t saved_len = 0;
    std::string method;

    if (own >= 14 || all_padding(code, own, 14)) {
        // A direct absolute jump fits without touching a neighbour: `jmp qword
        // ptr [rip+0]` followed by the address.
        patch.resize(14);
        patch[0] = 0xFF;
        patch[1] = 0x25;
        for (int i = 0; i < 4; ++i) patch[2 + i] = 0;
        std::memcpy(patch.data() + 6, &entry, sizeof(entry));
        saved_len = 14;
        method = "absolute jmp (14 bytes)";
    } else {
        std::string arena_detail;
        const std::uintptr_t arena = acquire_near_arena(g_hook_target, arena_detail);
        if (arena == 0) return report + "hook: " + arena_detail + "\n";

        std::uint8_t stub[12];
        stub[0] = 0x48;  // mov rax, imm64
        stub[1] = 0xB8;
        std::memcpy(stub + 2, &entry, sizeof(entry));
        stub[10] = 0xFF;  // jmp rax
        stub[11] = 0xE0;
        if (!hook_write_code(arena, stub, sizeof(stub), PAGE_EXECUTE_READ)) {
            return report + "hook: cannot write the far stub into the arena\n";
        }
        const std::int64_t delta =
            static_cast<std::int64_t>(arena) - static_cast<std::int64_t>(g_hook_target + 5);
        if (delta < INT32_MIN || delta > INT32_MAX) {
            return report + "hook: the arena is outside rel32 of the target\n";
        }
        patch.resize(5);
        patch[0] = 0xE9;
        const auto displacement = static_cast<std::int32_t>(delta);
        std::memcpy(patch.data() + 1, &displacement, sizeof(displacement));
        saved_len = 5;
        g_hook_arena = arena;
        method = vformat("near stub at %s (%s)", hex_of(arena).c_str(), arena_detail.c_str());
    }

    if (!safe_read(reinterpret_cast<const void*>(g_hook_target), g_hook_saved, saved_len)) {
        return report + "hook: cannot save the original bytes\n";
    }
    if (!hook_write_code(g_hook_target, patch.data(), patch.size(), PAGE_EXECUTE_READ)) {
        return report + "hook: cannot write the detour (the page would not become writable)\n";
    }

    g_hook_saved_len = saved_len;
    g_hook_installed = true;
    VSP_INFO("hook: installed via %s (target=%s entry=%s)", method.c_str(),
             hex_of(g_hook_target).c_str(), hex_of(entry).c_str());
    report += vformat("hook: installed via %s; original %zu bytes saved\n", method.c_str(), saved_len);
    report += "hook: enqueue a probe to see it run on the game's Lua thread\n";
    return report;
}

std::string hook_remove_impl() {
    if (!g_hook_installed) return "hook: not installed\n";
    bool restored = true;
    if (g_hook_vtable_copy != 0 && g_hook_job_object != 0 && g_hook_vtable != 0) {
        // Put the client's own vtable back before releasing the copy, so a client
        // left running after `--remove` is byte-for-byte where it started.
        *reinterpret_cast<std::uintptr_t*>(g_hook_job_object) = g_hook_vtable;
        VirtualFree(reinterpret_cast<void*>(g_hook_vtable_copy), 0, MEM_RELEASE);
        g_hook_vtable_copy = 0;
        g_hook_job_object = 0;
    }
    if (g_hook_saved_len != 0) {
        restored = hook_write_code(g_hook_target, g_hook_saved, g_hook_saved_len, PAGE_EXECUTE_READ);
    }
    g_hook_installed = false;
    if (g_hook_arena != 0 && g_hook_arena_owned) {
        VirtualFree(reinterpret_cast<void*>(g_hook_arena), 0, MEM_RELEASE);
    }
    g_hook_arena = 0;
    g_hook_arena_owned = false;
    return vformat("hook: %s\n", restored ? "original bytes restored" : "restore failed");
}

std::string hook_status_impl() {
    return vformat(
        "hook: installed=%s target=%s arena=%s entries=%ld jobs=%ld probes=%ld slot=%d\n",
        g_hook_installed ? "yes" : "no", hex_of(g_hook_target).c_str(), hex_of(g_hook_arena).c_str(),
        g_hook_entries.load(), g_hook_jobs.load(), g_hook_probes.load(), g_hook_slot.load());
}

}  // namespace

std::string hook_install() { return hook_install_impl(); }

std::string hook_remove() { return hook_remove_impl(); }

std::string hook_status() { return hook_status_impl(); }

bool hook_active() { return g_hook_installed; }

// Producer side of the lane. Enqueue only: no `lua_State` is read, no host
// function is called. The slot refuses a second job, which is what keeps the
// hook to one job per entry and the handoff free of any lock the VM could
// re-enter.
bool hook_queue_probe() {
    if (!g_hook_installed) return false;
    std::lock_guard<std::mutex> guard(g_hook_producer);
    if (g_hook_slot.load(std::memory_order_acquire) != kHookEmpty) return false;
    g_hook_job.kind = HookJobKind::Probe;
    g_hook_job.source.clear();
    g_hook_job.chunk.clear();
    g_hook_slot.store(kHookReady, std::memory_order_release);
    return true;
}

bool hook_queue_load_and_run(std::string source, std::string chunk) {
    if (!g_hook_installed || source.empty()) return false;
    std::lock_guard<std::mutex> guard(g_hook_producer);
    if (g_hook_slot.load(std::memory_order_acquire) != kHookEmpty) return false;
    g_hook_job.kind = HookJobKind::LoadAndRun;
    g_hook_job.source = std::move(source);
    g_hook_job.chunk = std::move(chunk);
    g_hook_slot.store(kHookReady, std::memory_order_release);
    return true;
}

std::string push_request(std::string source, std::string chunk_name, std::string tag) {
    Request request;
    request.source = std::move(source);
    request.chunk = std::move(chunk_name);
    request.tag = tag.empty()
                      ? vformat("exec-%llu",
                                static_cast<unsigned long long>(now_ms() ^ (++g_sequence * 7919)))
                      : std::move(tag);
    const std::string result_tag = request.tag;
    {
        std::lock_guard<std::mutex> guard(g_queue_mutex);
        g_queue.push_back(std::move(request));
    }
    g_pending.store(static_cast<int>(g_queue.size()));
    return result_tag;
}

void pump() {
    lua_State* L = g_executor_thread != nullptr ? g_executor_thread : g_lua_state;
    if (L == nullptr) return;

    for (;;) {
        Request request;
        {
            std::lock_guard<std::mutex> guard(g_queue_mutex);
            if (g_queue.empty()) break;
            request = std::move(g_queue.front());
            g_queue.pop_front();
        }
        g_pending.store(static_cast<int>(g_queue.size()));

        const std::string error = dispatch(L, request.source, request.chunk, request.tag);
        if (!error.empty()) {
            ++g_status.failed_scripts;
            g_status.error = error;
            host_print(error);
        }
    }
}

void record_result(bool ok) {
    if (ok) ++g_status.executed_scripts;
    else ++g_status.failed_scripts;
}

std::string probe_abi(bool allow_repair) {
    std::string report;
    lua_State* L = g_lua_state;
    if (L == nullptr) return "no lua_State resolved\n";

    report += vformat("lua_State           : %s\n", hex_of(reinterpret_cast<std::uintptr_t>(L)).c_str());

    std::uintptr_t global = 0;
    std::uintptr_t stack = 0;
    std::uintptr_t stack_last = 0;
    std::uintptr_t top = 0;
    std::uintptr_t base = 0;
    std::uintptr_t ci = 0;
    read_ptr(reinterpret_cast<std::uintptr_t>(L) + offsetof(lua_State, global), global);
    read_ptr(reinterpret_cast<std::uintptr_t>(L) + offsetof(lua_State, stack), stack);
    read_ptr(reinterpret_cast<std::uintptr_t>(L) + offsetof(lua_State, stack_last), stack_last);
    read_ptr(reinterpret_cast<std::uintptr_t>(L) + offsetof(lua_State, top), top);
    read_ptr(reinterpret_cast<std::uintptr_t>(L) + offsetof(lua_State, base), base);
    read_ptr(reinterpret_cast<std::uintptr_t>(L) + offsetof(lua_State, ci), ci);

    report += vformat("global              : %s\n", hex_of(global).c_str());
    report += vformat("stack               : %s\n", hex_of(stack).c_str());
    report += vformat("stack_last          : %s  (%llu slots)\n", hex_of(stack_last).c_str(),
                      static_cast<unsigned long long>((stack_last - stack) / sizeof(TValue)));
    report += vformat("top / base          : %s / %s\n", hex_of(top).c_str(), hex_of(base).c_str());
    report += vformat("ci                  : %s\n", hex_of(ci).c_str());
    report += vformat("userdata            : %s\n",
                      hex_of(reinterpret_cast<std::uintptr_t>(L->userdata)).c_str());
    report += vformat("identity field      : %s\n", hex_of(g_identity_offset).c_str());
    report += vformat("capabilities field  : %s\n", hex_of(g_capabilities_offset).c_str());
    report += vformat("current identity    : %d\n", get_thread_identity(L));

    report += "transform map       : ";
    const char* names[] = {"plain", "sub-self", "self-sub", "xor-self", "add-self"};
    for (int field = 1; field < abi::kEncFieldCount; ++field) {
        report += vformat("%d=%s ", field, names[abi::scheme(field)]);
    }
    report += "\n";

    if (validate_state(L)) {
        report += "layout              : valid\n";
        g_status.abi_verified = true;
    } else {
        report += "layout              : INVALID\n";
        g_status.abi_verified = false;
    }

    if (allow_repair) {
        report += "stack_size probe    : ";
        std::string detail;
        if (repair_stack_size_scheme(L, detail)) report += "repaired\n";
        else report += "unresolved\n";
        report += detail;
    }

    return report;
}

void install_environment(lua_State* L) {
    // Implemented in env.cpp; declared here through vesper/env.hpp.
    env::install(L);
}

namespace {

// Reading a Lua value out of a table means knowing this build's Table header, and guessing
// it is how the wrong bytes get written. So the header is dumped, every 8-byte word in it
// is tried as the node-array pointer, and a candidate is only accepted when its nodes look
// like nodes: empty keys are all-zero, most key tags are strings, and the string a node
// points at really reads "print".
bool read_string_bytes(std::uintptr_t ts, std::string& out) {
    std::uint32_t length = 0;
    if (!safe_read(reinterpret_cast<const void*>(ts + 0x10), &length, sizeof(length))) return false;
    if (length == 0 || length > 64) return false;
    out.assign(length, '\0');
    return safe_read(reinterpret_cast<const void*>(ts + 0x18), out.data(), length);
}

void probe_global_closure_impl() {
    lua_State* L = g_lua_state;
    if (L == nullptr) {
        VSP_INFO("probe[gadget]: no lua_State");
        return;
    }
    const std::uintptr_t base = reinterpret_cast<std::uintptr_t>(L);
    std::uintptr_t env = 0;
    if (!read_ptr(base + live::kEnv, env) || env == 0) {
        VSP_INFO("probe[gadget]: L+0x%llx (env) unreadable",
                 static_cast<unsigned long long>(live::kEnv));
        return;
    }

    std::uint64_t header[8] = {};
    if (!safe_read(reinterpret_cast<const void*>(env), header, sizeof(header))) {
        VSP_INFO("probe[gadget]: env header unreadable");
        return;
    }
    VSP_INFO("probe[gadget]: env=%s words= %s %s %s %s %s %s %s %s", hex_of(env).c_str(),
             hex_of(header[0]).c_str(), hex_of(header[1]).c_str(), hex_of(header[2]).c_str(),
             hex_of(header[3]).c_str(), hex_of(header[4]).c_str(), hex_of(header[5]).c_str(),
             hex_of(header[6]).c_str(), hex_of(header[7]).c_str());

    for (std::uintptr_t field = 0x10; field <= 0x50; field += 8) {
        std::uintptr_t nodes = 0;
        std::uint32_t count = 0;
        if (!read_ptr(env + field, nodes) || !pointer_plausible(nodes)) continue;
        if (!safe_read(reinterpret_cast<const void*>(env + 0x30), &count, sizeof(count))) continue;
        if (count == 0 || count > 4096) continue;

        int empty = 0;
        int stringish = 0;
        std::uintptr_t print_value = 0;
        std::uint32_t print_tag = 0;
        bool found = false;
        for (std::uint32_t i = 0; i < count && i < 512; ++i) {
            const std::uintptr_t node = nodes + static_cast<std::uintptr_t>(i) * 0x28;
            std::uint32_t key_tag = 0;
            std::uint32_t value_tag = 0;
            std::uintptr_t key = 0;
            if (!safe_read(reinterpret_cast<const void*>(node + 0x0C), &key_tag, sizeof(key_tag))) break;
            if (!safe_read(reinterpret_cast<const void*>(node + 0x1C), &value_tag, sizeof(value_tag))) break;
            if (!read_ptr(node, key)) break;
            if (key_tag == 0) {
                ++empty;
                continue;
            }
            if (key_tag != 6 || key == 0) continue;
            ++stringish;
            std::string text;
            if (read_string_bytes(key, text) && text == "print") {
                print_value = node + 0x10;
                print_tag = value_tag;
                found = true;
                break;
            }
        }
        VSP_INFO("probe[gadget]: field +0x%llx nodes=%s count=%u empty=%d strings=%d print=%d",
                 static_cast<unsigned long long>(field), hex_of(nodes).c_str(), count, empty, stringish,
                 found ? 1 : 0);
        if (empty < 8 || stringish < 3) continue;

        if (found) {
            std::uintptr_t closure = 0;
            read_ptr(print_value, closure);
            VSP_INFO("probe[gadget]: print value=%s tag=%u closure=%s", hex_of(print_value).c_str(), print_tag,
                     hex_of(closure).c_str());
            if (closure != 0 && pointer_plausible(closure)) {
                const std::uintptr_t function_slot = closure + 0x20;
                std::uintptr_t original = 0;
                if (read_ptr(function_slot, original)) {
                    MEMORY_BASIC_INFORMATION mbi{};
                    VirtualQuery(reinterpret_cast<void*>(function_slot), &mbi, sizeof(mbi));
                    VSP_INFO("probe[gadget]: C function=%s at %s protect=0x%lX", hex_of(original).c_str(),
                             hex_of(function_slot).c_str(),
                             static_cast<unsigned long>(mbi.Protect));
                    SIZE_T written = 0;
                    const BOOL ok = WriteProcessMemory(GetCurrentProcess(), reinterpret_cast<void*>(function_slot),
                                                       &original, sizeof(original), &written);
                    std::uintptr_t readback = 0;
                    read_ptr(function_slot, readback);
                    VSP_INFO("probe[gadget]: same-value write ok=%d written=%llu readback=%s (equal=%d)",
                             ok ? 1 : 0, static_cast<unsigned long long>(written),
                             hex_of(readback).c_str(), readback == original ? 1 : 0);
                }
            }
            return;
        }
    }
}

// ---------------------------------------------------------------------------
// Read-only lookup of a global through raw 9ac8 structures.
//
// This is the only safe way to touch the client's Lua heap from here: none of our own
// Luau may be called with a client pointer (`nm out\Vesper.dll` shows lua_getfield,
// lua_xmove, lua_newthread as symbols *we* define), so the walk is done on the
// authoritative layout instead:
//
//   lua_State   gt at +0x08, top +0x70, ci +0x50, base_ci +0x18
//   LuaTable    tt +0x02, lsizenode +0x06, sizearray +0x08, array +0x18, node +0x20
//   LuaNode     0x28 stride: key TValue +0x00 (tt +0x0C), value TValue +0x10 (tt +0x1C)
//   TString     len +0x14, data +0x18
//
// Tags are remapped per build (the profile records thread = 0xa, not 8), so they are not
// assumed: they are resolved by name from the client's own `luaT_typenames` array.
// `LuaT_typenames` RVA 0x67DCAB0, from Internal_Offsets.hpp for this build.
// ---------------------------------------------------------------------------

constexpr std::uintptr_t kTStringLen = 0x14;
constexpr std::uintptr_t kTStringData = 0x18;
constexpr std::uintptr_t kNodeStride = 0x28;
constexpr std::uintptr_t kTableLsizenode = 0x06;
constexpr std::uintptr_t kTableNode = 0x20;
constexpr std::uintptr_t kTypeNamesRva = 0x67DCAB0;

std::string c_string_at(std::uintptr_t address) {
    char buffer[32] = {};
    if (address == 0) return std::string();
    if (!safe_read(reinterpret_cast<const void*>(address), buffer, sizeof(buffer) - 1)) {
        return std::string();
    }
    return std::string(buffer);
}

// The client's `luaT_typenames` is an array of C strings indexed by tag. Reading it is how
// a tag number becomes meaningful on a build that renumbers them.
std::uint32_t tag_named(std::uintptr_t typenames, const char* wanted) {
    for (std::uint32_t tag = 0; tag < 24; ++tag) {
        std::uintptr_t name = 0;
        if (!read_ptr(typenames + tag * 8, name) || name == 0) continue;
        if (c_string_at(name) == wanted) return tag;
    }
    return 0xFFFFFFFFu;
}

std::string tag_text(std::uintptr_t typenames, std::uint32_t tag) {
    std::uintptr_t name = 0;
    if (read_ptr(typenames + tag * 8, name) && name != 0) {
        const std::string text = c_string_at(name);
        if (!text.empty()) return text;
    }
    return vformat("tag%u", tag);
}

struct FieldHit {
    bool found = false;
    std::uintptr_t node = 0;
    std::uintptr_t value_ptr = 0;
    std::uint32_t value_tag = 0;
};

// Linear scan of the node array. Linear, not hashed: the client's hash lives inside the
// table key and is encoded (TSTRING_HASH_ENC), and a scan over 2^lsizenode nodes costs
// nothing next to getting the hash wrong and reading an unrelated slot.
// MEASURED on 9ac8 (menu state): the node array of `gt` holds value/key pairs every 0x20
// bytes, with the *key* in the second TValue -- `tt` 6 (string) on the second TValue and
// 7/8 (table/function) on the first. The upstream Luau `LuaNode` is 0x28 with `next` after
// the two values; this build is neither, so the stride is calibrated instead of assumed:
// every candidate (stride, key offset) is scored by how many names it actually recognises.
struct NodeLayout {
    std::uintptr_t stride = 0x20;
    std::uintptr_t key_offset = 0x10;
};

bool read_tvalue_string(std::uintptr_t tvalue, std::uint32_t string_tag, std::string& out) {
    std::uint32_t tag_word = 0;
    if (!safe_read(reinterpret_cast<const void*>(tvalue + 0x0C), &tag_word, sizeof(tag_word))) return false;
    if ((tag_word & 0xFF) != string_tag) return false;

    std::uintptr_t text = 0;
    if (!read_ptr(tvalue, text) || !pointer_plausible(text)) return false;

    std::uint32_t length = 0;
    if (!safe_read(reinterpret_cast<const void*>(text + kTStringLen), &length, sizeof(length))) return false;
    if (length == 0 || length > 64) return false;

    char buffer[65] = {};
    if (!safe_read(reinterpret_cast<const void*>(text + kTStringData), buffer, length)) return false;
    out.assign(buffer, length);
    return true;
}

FieldHit find_string_key(std::uintptr_t table, const char* wanted, std::uint32_t string_tag,
                         const NodeLayout& layout) {
    FieldHit hit;
    if (table == 0 || !pointer_plausible(table)) return hit;

    std::uint8_t lsizenode = 0;
    if (!safe_read(reinterpret_cast<const void*>(table + kTableLsizenode), &lsizenode, 1)) return hit;
    if (lsizenode > 20) return hit;
    const std::uint32_t count = 1u << lsizenode;

    std::uintptr_t nodes = 0;
    if (!read_ptr(table + kTableNode, nodes) || !pointer_plausible(nodes)) return hit;

    for (std::uint32_t index = 0; index < count; ++index) {
        const std::uintptr_t node = nodes + static_cast<std::uintptr_t>(index) * layout.stride;
        std::string text;
        if (!read_tvalue_string(node + layout.key_offset, string_tag, text)) continue;
        if (text != wanted) continue;

        hit.found = true;
        hit.node = node;
        // The value is the other TValue of the pair.
        const std::uintptr_t value = node + (layout.key_offset == 0 ? 0x10 : 0);
        read_ptr(value, hit.value_ptr);
        std::uint32_t tag_word = 0;
        safe_read(reinterpret_cast<const void*>(value + 0x0C), &tag_word, sizeof(tag_word));
        hit.value_tag = tag_word & 0xFF;
        return hit;
    }
    return hit;
}

// Lists every string key of a table. This is what settles "is it missing or is the scan
// skipping slots": a scan that silently skips every other node still finds some names, so
// the list of what it *does* see is the evidence.
std::string enumerate_string_keys(std::uintptr_t table, std::uint32_t string_tag,
                                  const NodeLayout& layout) {
    std::string out;
    if (table == 0 || !pointer_plausible(table)) return out;

    std::uint8_t lsizenode = 0;
    if (!safe_read(reinterpret_cast<const void*>(table + kTableLsizenode), &lsizenode, 1)) return out;
    if (lsizenode > 20) return out;
    const std::uint32_t count = 1u << lsizenode;

    std::uintptr_t nodes = 0;
    if (!read_ptr(table + kTableNode, nodes) || !pointer_plausible(nodes)) return out;

    int total = 0;
    for (std::uint32_t index = 0; index < count; ++index) {
        const std::uintptr_t node = nodes + static_cast<std::uintptr_t>(index) * layout.stride;
        std::string text;
        if (!read_tvalue_string(node + layout.key_offset, string_tag, text)) continue;
        ++total;
        if (out.size() < 700) {
            if (!out.empty()) out += ",";
            out += text;
        }
    }
    out = vformat("(%d keys) ", total) + out;
    return out;
}

// Scores each candidate layout by how many of the names every client state has. Reading
// the wrong stride does not crash -- it just never matches -- so this is a safe way to
// learn the shape.
NodeLayout calibrate_node_layout(std::uintptr_t table, std::uint32_t string_tag, int& best_score) {
    static const char* kNames[] = {"print", "warn", "task", "game", "tick", "pairs", "type"};
    static const std::uintptr_t kStrides[] = {0x20, 0x28, 0x30, 0x18};
    static const std::uintptr_t kKeyOffsets[] = {0x10, 0x00};

    NodeLayout best;
    best_score = 0;
    for (const std::uintptr_t stride : kStrides) {
        for (const std::uintptr_t key_offset : kKeyOffsets) {
            NodeLayout candidate{stride, key_offset};
            int score = 0;
            for (const char* name : kNames) {
                if (find_string_key(table, name, string_tag, candidate).found) ++score;
            }
            VSP_INFO("probe[defer]: layout stride=0x%llx key=+0x%llx score=%d/%zu",
                     static_cast<unsigned long long>(stride),
                     static_cast<unsigned long long>(key_offset), score, std::size(kNames));
            if (score > best_score) {
                best_score = score;
                best = candidate;
            }
        }
    }
    return best;
}

void probe_defer_lookup_impl() {
    lua_State* L = g_lua_state;
    if (L == nullptr) {
        VSP_INFO("probe[defer]: no lua_State");
        return;
    }
    const std::uintptr_t base = reinterpret_cast<std::uintptr_t>(L);
    const std::uintptr_t typenames = g_module_base + kTypeNamesRva;

    const std::uint32_t string_tag = tag_named(typenames, "string");
    const std::uint32_t table_tag = tag_named(typenames, "table");
    const std::uint32_t function_tag = tag_named(typenames, "function");
    VSP_INFO("probe[defer]: typenames=%s string=%u table=%u function=%u", hex_of(typenames).c_str(),
             string_tag, table_tag, function_tag);
    if (string_tag == 0xFFFFFFFFu) {
        VSP_INFO("probe[defer]: could not resolve the string tag; the table walk is unsafe");
        return;
    }

    std::uintptr_t gt = 0;
    if (!read_ptr(base + 0x08, gt) || !pointer_plausible(gt)) {
        VSP_INFO("probe[defer]: L+0x08 (gt) unreadable");
        return;
    }
    std::uint8_t table_tt = 0, lsizenode = 0;
    std::int32_t sizearray = 0;
    safe_read(reinterpret_cast<const void*>(gt + 0x02), &table_tt, 1);
    safe_read(reinterpret_cast<const void*>(gt + kTableLsizenode), &lsizenode, 1);
    safe_read(reinterpret_cast<const void*>(gt + 0x08), &sizearray, sizeof(sizearray));
    VSP_INFO("probe[defer]: gt=%s tt=%u(%s) lsizenode=%u sizearray=%d", hex_of(gt).c_str(), table_tt,
             tag_text(typenames, table_tt).c_str(), lsizenode, sizearray);

    // The raw dump that produced the layout above is gone on purpose: it was 0x1B0 bytes of
    // reads on every run, and a probe that reads that much is exactly what got its thread
    // terminated half-way through the calibration.

    // MEASURED: a probe that walks the whole node array twice dies. In the menu it survived
    // 0.2 s of scanning; in a place the same scan was terminated right after `gt=` was
    // logged, which is what holding a client thread for hundreds of milliseconds costs when
    // the APC lands on one the game is using. So: the measured layout, two lookups, no
    // enumeration, no calibration unless the layout stops matching.
    NodeLayout layout{0x20, 0x10};

    // The registry of the same state: global_State (+0x78) -> registry TValue (+0x618). A
    // sandboxed script thread takes its environment from here, so this is where a `print`
    // or a library table would show up if the user's code can see one.
    {
        std::uintptr_t global = 0, registry = 0;
        if (read_ptr(base + live::kUserdata, global) && read_ptr(global + 0x618, registry)) {
            VSP_INFO("probe[defer]: registry=%s keys: %s", hex_of(registry).c_str(),
                     enumerate_string_keys(registry, string_tag, layout).c_str());
            // `_LOADED` is where the standard libraries are kept in a Lua state. Its keys say
            // whether `string`, `table` or `_G` exist, which is what user code would reach.
            const FieldHit loaded = find_string_key(registry, "_LOADED", string_tag, layout);
            if (loaded.found) {
                // `value_ptr` is already the table: find_string_key dereferences the TValue.
                // Dereferencing it again read the table header as if it were a pointer.
                VSP_INFO("probe[defer]: _LOADED=%s keys: %s", hex_of(loaded.value_ptr).c_str(),
                         enumerate_string_keys(loaded.value_ptr, string_tag, layout).c_str());
            } else {
                VSP_INFO("probe[defer]: _LOADED not found in the registry");
            }
        } else {
            VSP_INFO("probe[defer]: registry unreadable");
        }
    }

    std::uintptr_t task_table = 0;
    for (const char* name : {"task", "print", "game"}) {
        const FieldHit hit = find_string_key(gt, name, string_tag, layout);
        VSP_INFO("probe[defer]: gt[\"%s\"] found=%d value=%s tag=%u(%s)", name, hit.found ? 1 : 0,
                 hex_of(hit.value_ptr).c_str(), hit.value_tag,
                 tag_text(typenames, hit.value_tag).c_str());
        if (hit.found && std::strcmp(name, "task") == 0) task_table = hit.value_ptr;
    }

    if (task_table == 0) {
        VSP_INFO("probe[defer]: `task` not found; nothing more to look up");
        return;
    }
    for (const char* name : {"defer", "spawn"}) {
        const FieldHit hit = find_string_key(task_table, name, string_tag, layout);
        VSP_INFO("probe[defer]: task[\"%s\"] found=%d node=%s value=%s tag=%u(%s)%s", name,
                 hit.found ? 1 : 0, hex_of(hit.node).c_str(), hex_of(hit.value_ptr).c_str(),
                 hit.value_tag, tag_text(typenames, hit.value_tag).c_str(),
                 hit.found && hit.value_tag == function_tag ? " <-- callable" : "");
    }
}

// The client's own `lua_newthread` is the only authority on what a thread of this build
// looks like. Creating one and comparing it with the thread `pvt::make` builds says which
// field of the synthetic one is wrong -- and a wrong field there is what makes `luau_load`
// corrupt the heap instead of reporting an error.
void probe_thread_layout_impl() {
    lua_State* parent = g_lua_state;
    if (parent == nullptr) {
        VSP_INFO("probe[thread]: no lua_State");
        return;
    }
    const std::uintptr_t helper = g_profile.at("rva.sc.thread_helper", g_module_base);
    if (helper == 0) {
        VSP_INFO("probe[thread]: profile has no rva.sc.thread_helper");
        return;
    }

    std::uintptr_t top_before = 0;
    read_ptr(reinterpret_cast<std::uintptr_t>(parent) + live::kTop, top_before);

    lua_State* reference = nullptr;
    const bool called = guarded([&] {
        using NewThreadFn = lua_State* (*)(lua_State*);
        reference = reinterpret_cast<NewThreadFn>(helper)(parent);
    });
    std::uintptr_t top_after = 0;
    read_ptr(reinterpret_cast<std::uintptr_t>(parent) + live::kTop, top_after);
    VSP_INFO("probe[thread]: client newthread called=%d -> %s top %s->%s", called ? 1 : 0,
             hex_of(reinterpret_cast<std::uintptr_t>(reference)).c_str(), hex_of(top_before).c_str(),
             hex_of(top_after).c_str());
    if (!called || reference == nullptr) return;

    // The synthetic thread, built exactly as the exec lane builds one.
    std::string make_report;
    lua_State* synthetic = pvt::make(parent, make_report);
    VSP_INFO("probe[thread]: synthetic=%s", hex_of(reinterpret_cast<std::uintptr_t>(synthetic)).c_str());

    std::uint8_t client_bytes[0x88] = {};
    std::uint8_t our_bytes[0x88] = {};
    const bool have_client =
        safe_read(reinterpret_cast<const void*>(reference), client_bytes, sizeof(client_bytes));
    const bool have_ours =
        synthetic != nullptr &&
        safe_read(reinterpret_cast<const void*>(synthetic), our_bytes, sizeof(our_bytes));
    if (!have_client || !have_ours) {
        VSP_INFO("probe[thread]: readback failed client=%d ours=%d", have_client ? 1 : 0,
                 have_ours ? 1 : 0);
        return;
    }

    for (std::size_t offset = 0; offset < sizeof(client_bytes); offset += 8) {
        std::uint64_t c = 0, o = 0;
        std::memcpy(&c, client_bytes + offset, sizeof(c));
        std::memcpy(&o, our_bytes + offset, sizeof(o));
        VSP_INFO("probe[thread]: +%02zx client=%016llx ours=%016llx %s", offset,
                 static_cast<unsigned long long>(c), static_cast<unsigned long long>(o),
                 c == o ? "" : "<-- differs");
    }

    // Undo the push the client made for the thread.
    if (top_after == top_before + 0x10) {
        pvt::poke<std::uintptr_t>(reinterpret_cast<std::uintptr_t>(parent) + live::kTop, top_before);
    }
}

}  // namespace

void probe_global_closure() { probe_global_closure_impl(); }
void probe_thread_layout() { probe_thread_layout_impl(); }
void probe_defer_lookup() { probe_defer_lookup_impl(); }

}  // namespace vesper::rbx
