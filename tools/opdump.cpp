// opdump: compile a Luau source file with the vendored compiler and print the
// opcode sequence (vendored enum) of every function, with instruction lengths.
// Build: see tools/build_opdump.ps1. Used to map the 11f1 internal opcode space.
#include "Luau/BytecodeBuilder.h"
#include "Luau/Compiler.h"

#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>
#include <vector>

namespace {

const char* kNames[] = {
    "NOP","BREAK","LOADNIL","LOADB","LOADN","LOADK","MOVE","GETGLOBAL","SETGLOBAL","GETUPVAL",
    "SETUPVAL","CLOSEUPVALS","GETIMPORT","GETTABLE","SETTABLE","GETTABLEKS","SETTABLEKS","GETTABLEN",
    "SETTABLEN","NEWCLOSURE","NAMECALL","CALL","RETURN","JUMP","JUMPBACK","JUMPIF","JUMPIFNOT",
    "JUMPIFEQ","JUMPIFLE","JUMPIFLT","JUMPIFNOTEQ","JUMPIFNOTLE","JUMPIFNOTLT","ADD","SUB","MUL","DIV",
    "MOD","POW","ADDK","SUBK","MULK","DIVK","MODK","POWK","AND","OR","ANDK","ORK","CONCAT","NOT",
    "MINUS","LENGTH","NEWTABLE","DUPTABLE","SETLIST","FORNPREP","FORNLOOP","FORGLOOP","FORGPREP_INEXT",
    "FASTCALL3","FORGPREP_NEXT","NATIVECALL","GETVARARGS","DUPCLOSURE","PREPVARARGS","LOADKX","JUMPX",
    "FASTCALL","COVERAGE","CAPTURE","SUBRK","DIVRK","FASTCALL1","FASTCALL2","FASTCALL2K","FORGPREP",
    "JUMPXEQKNIL","JUMPXEQKB","JUMPXEQKN","JUMPXEQKS","IDIV","IDIVK","GETUDATAKS","SETUDATAKS",
    "NAMECALLUDATA","NEWCLASSMEMBER","CALLFB","CMPPROTO",
};

int opLength(std::uint32_t insn) {
    switch (insn & 0xff) {
        case 0x07: case 0x08: case 0x0C: case 0x0F: case 0x10: case 0x14: case 0x1B:
        case 0x1C: case 0x1D: case 0x1E: case 0x1F: case 0x20: case 0x35: case 0x37:
        case 0x3A: case 0x42: case 0x4A: case 0x4B: case 0x3C: case 0x4D: case 0x4E:
        case 0x4F: case 0x50: case 0x53: case 0x54: case 0x55: case 0x56: case 0x57: case 0x58:
            return 2;
        default: return 1;
    }
}

const char* nameOf(int op) {
    if (op >= 0 && op < static_cast<int>(sizeof(kNames) / sizeof(kNames[0]))) return kNames[op];
    return "?";
}

struct TraceEncoder : Luau::BytecodeEncoder {
    int fn = 0;
    void encode(std::uint32_t* data, std::size_t count) override {
        std::printf("--- function %d (%zu words) ---\n", fn, count);
        for (std::size_t i = 0; i < count;) {
            const std::uint32_t insn = data[i];
            const int op = static_cast<int>(insn & 0xff);
            std::printf("  %3zu: %02x %-14s", i, op, nameOf(op));
            const int len = opLength(insn);
            std::printf(" A=%d B=%d C=%d D=%d", (insn >> 8) & 0xff, (insn >> 16) & 0xff,
                        (insn >> 24) & 0xff, (int)(int16_t)(insn >> 16));
            if (len == 2) {
                std::printf(" aux=%08x", data[i + 1]);
            }
            std::printf("\n");
            i += static_cast<std::size_t>(len);
        }
        fn++;
    }
};

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::printf("usage: opdump <file.lua>\n");
        return 2;
    }
    FILE* f = std::fopen(argv[1], "rb");
    if (!f) {
        std::printf("cannot open %s\n", argv[1]);
        return 2;
    }
    std::string source;
    char buf[4096];
    std::size_t n;
    while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0) source.append(buf, n);
    std::fclose(f);

    Luau::CompileOptions options{};
    options.optimizationLevel = 1;
    options.debugLevel = 2;
    static const char* kCommonGlobals[] = {"Game", "Workspace", "game", "plugin", "script",
                                           "shared", "workspace", "_G", "_ENV", nullptr};
    options.mutableGlobals = kCommonGlobals;

    TraceEncoder encoder;
    std::string bytecode = Luau::compile(source, options, {}, &encoder);
    if (bytecode.empty()) {
        std::printf("compile failed\n");
        return 1;
    }
    std::printf("bytecode %zu bytes\n", bytecode.size());
    return 0;
}
