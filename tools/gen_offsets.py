#!/usr/bin/env python3
"""
Vesper offset table compiler.

Turns the per-build JSON descriptors in `offsets/src/*.json` into encrypted
binary tables (`offsets/dist/<build>.vtb`) plus a single C++ blob include
(`engine/src/generated/tables_blob.inc`) that ships inside the shell and the
engine DLL.

This is the piece that makes Vesper survive Roblox updates: build-specific
numbers are DATA, never code. Porting a new Roblox build means dropping a new
JSON file here and running this script.

Container layout (little endian):

    +0   magic        "VSPR"                      4
    +4   format       u16 = 1
    +6   flags        u16
    +8   build_len    u8
    +9   build        char[build_len]             e.g. "version-7a0c6d10fcb34a2c"
    +..  body_len     u32                         ciphertext length
    +..  iv           16
    +..  body         AES-256-CBC(PKCS7)          encrypted entry table
    +..  mac          32                          HMAC-SHA256(key, build||iv||body)

Encrypted entry table:

    u32 count
    count * { u16 name_len; char name[name_len]; u64 value }

Usage:
    python tools/gen_offsets.py                 # build all tables
    python tools/gen_offsets.py --check         # validate only, no output
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import struct
import sys
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:  # pragma: no cover
    print("error: pip install cryptography", file=sys.stderr)
    raise SystemExit(2)

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "offsets" / "src"
DIST = ROOT / "offsets" / "dist"
BLOB = ROOT / "engine" / "src" / "generated" / "tables_blob.inc"

MAGIC = b"VSPR"
FORMAT = 1

# Shared with engine/src/vesper/crypto.hpp. Rotating this invalidates every
# shipped table, so bump it only alongside a format bump.
MASTER_SECRET = b"vesper::table::k1::7b1f0a5c9e3d2648"


def derive_key(build: str) -> bytes:
    return hashlib.sha256(MASTER_SECRET + b"\x00" + build.encode("utf-8")).digest()


def parse_value(raw) -> int:
    if isinstance(raw, bool):
        raise ValueError("bool is not a valid offset value")
    if isinstance(raw, int):
        value = raw
    elif isinstance(raw, str):
        text = raw.strip()
        value = int(text, 16) if text.lower().startswith("0x") else int(text, 10)
    else:
        raise ValueError(f"unsupported value type: {type(raw).__name__}")
    if not 0 <= value <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError(f"value out of u64 range: {raw}")
    return value


def load_descriptor(path: Path) -> tuple[str, dict[str, int]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    build = data["build"]
    entries = data.get("entries") or {}
    if not entries:
        raise ValueError(f"{path.name}: no entries")

    resolved: dict[str, int] = {}
    for name, raw in entries.items():
        if not name or len(name) > 0xFFFF:
            raise ValueError(f"{path.name}: bad entry name {name!r}")
        if name in resolved:
            raise ValueError(f"{path.name}: duplicate entry {name}")
        resolved[name] = parse_value(raw)

    # A table that cannot describe how to reach a lua_State is useless; catch it
    # here rather than at runtime inside somebody's game process.
    required = [
        "rva.get_global_state",
        "rva.task_scheduler",
        "struct.data_model.script_context",
        "struct.task_scheduler.job_start",
        "struct.task_scheduler.job_end",
        "struct.task_scheduler.job_name",
    ]
    missing = [key for key in required if key not in resolved]
    if missing:
        raise ValueError(f"{path.name}: missing required entries: {', '.join(missing)}")

    return build, resolved


def encode_body(entries: dict[str, int]) -> bytes:
    out = bytearray()
    out += struct.pack("<I", len(entries))
    for name in sorted(entries):
        raw = name.encode("utf-8")
        out += struct.pack("<H", len(raw))
        out += raw
        out += struct.pack("<Q", entries[name])
    return bytes(out)


def pad(data: bytes) -> bytes:
    n = 16 - (len(data) % 16)
    return data + bytes([n]) * n


def build_table(build: str, entries: dict[str, int]) -> bytes:
    key = derive_key(build)
    iv = os.urandom(16)
    body = encode_body(entries)

    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(pad(body)) + encryptor.finalize()

    build_raw = build.encode("utf-8")
    header = bytearray()
    header += MAGIC
    header += struct.pack("<HH", FORMAT, 0)
    header += struct.pack("<B", len(build_raw))
    header += build_raw
    header += struct.pack("<I", len(ciphertext))
    header += iv

    mac = hmac.new(key, bytes(header[8:]) + ciphertext, hashlib.sha256).digest()
    return bytes(header) + ciphertext + mac


def c_ident(build: str) -> str:
    return "".join(ch if ch.isalnum() else "_" for ch in build)


def emit_blob(tables: list[tuple[str, bytes]], out: Path) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    lines.append("// Generated by tools/gen_offsets.py -- do not edit.")
    lines.append("// Embedded offset tables. Regenerate after adding a build descriptor.")
    lines.append("")
    lines.append("#pragma once")
    lines.append("#include <cstddef>")
    lines.append("#include <cstdint>")
    lines.append("")
    lines.append("namespace vesper::tables {")
    lines.append("")
    lines.append("struct Entry { const char* build; const unsigned char* data; size_t len; };")
    lines.append("")

    total = 0
    for build, blob in tables:
        ident = c_ident(build)
        lines.append(f"inline const unsigned char k_{ident}[] = {{")
        for i in range(0, len(blob), 16):
            chunk = blob[i : i + 16]
            lines.append("    " + ", ".join(f"0x{b:02x}" for b in chunk) + ",")
        lines.append("};")
        lines.append("")
        total += len(blob)

    lines.append("inline const Entry kTables[] = {")
    for build, blob in tables:
        lines.append(f'    {{ "{build}", k_{c_ident(build)}, sizeof(k_{c_ident(build)}) }},')
    lines.append("};")
    lines.append("")
    lines.append("inline const size_t kTableCount = sizeof(kTables) / sizeof(kTables[0]);")
    lines.append("")
    lines.append("}  // namespace vesper::tables")
    lines.append("")
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"  blob  {out.relative_to(ROOT)}  {total} bytes across {len(tables)} table(s)")


def main() -> int:
    ap = argparse.ArgumentParser(description="Vesper offset table compiler")
    ap.add_argument("--check", action="store_true", help="validate descriptors only")
    ap.add_argument("--only", help="compile a single build by its version string")
    args = ap.parse_args()

    if not SRC.is_dir():
        print(f"error: {SRC} does not exist", file=sys.stderr)
        return 1

    descriptors = sorted(SRC.glob("*.json"))
    if not descriptors:
        print(f"error: no descriptors in {SRC}", file=sys.stderr)
        return 1

    tables: list[tuple[str, bytes]] = []
    failures = 0

    for path in descriptors:
        try:
            build, entries = load_descriptor(path)
        except Exception as exc:  # noqa: BLE001
            print(f"  FAIL  {path.name}: {exc}", file=sys.stderr)
            failures += 1
            continue

        if args.only and build != args.only:
            continue

        if args.check:
            print(f"  ok    {build}  ({len(entries)} entries)")
            continue

        blob = build_table(build, entries)
        DIST.mkdir(parents=True, exist_ok=True)
        target = DIST / f"{build}.vtb"
        target.write_bytes(blob)
        print(f"  table {build}  {len(entries):4d} entries  {len(blob):6d} bytes -> {target.name}")
        tables.append((build, blob))

    if failures:
        return 1
    if not args.check and tables:
        emit_blob(tables, BLOB)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
