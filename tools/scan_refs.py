#!/usr/bin/env python3
"""Count in-image references to candidate RVAs (verification aid for ports).

For each candidate RVA this reports how many places in the image refer to it:

  * call  — `E8 rel32` whose target equals the candidate    (for function entries)
  * rip   — `mov/lea/cmp [rip+d32]` targeting the candidate  (for data cells)
  * ptr   — 8-byte slots holding `base + candidate`          (absolute tables)

A wrong candidate shows a near-empty result next to its real neighbours, so
this is the quick sanity check for ports that could not be confirmed with two
independent reference sites.

Usage:
  scan_refs.py --image <dump-or-exe> --base 0x... --rva name=0x... [--rva ...]
"""

from __future__ import annotations

import argparse
import struct
import sys

IMAGE_SCN_MEM_EXECUTE = 0x20000000


def parse_pe(path: str):
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < 0x1000 or data[:2] != b"MZ":
        raise ValueError(f"{path}: not a PE image")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        raise ValueError(f"{path}: no PE signature")
    coff = e_lfanew + 4
    num_sections = struct.unpack_from("<H", data, coff + 2)[0]
    opt_size = struct.unpack_from("<H", data, coff + 16)[0]
    opt = coff + 20
    size_of_image = struct.unpack_from("<I", data, opt + 56)[0]
    sec = opt + opt_size
    sections = []
    for i in range(num_sections):
        off = sec + i * 40
        vsize, vaddr = struct.unpack_from("<II", data, off + 8)
        rawsize, rawptr = struct.unpack_from("<II", data, off + 16)
        ch = struct.unpack_from("<I", data, off + 36)[0]
        sections.append(dict(vaddr=vaddr, vsize=vsize, rawptr=rawptr,
                             rawsize=rawsize, chars=ch))
    return dict(data=data, size_of_image=size_of_image, sections=sections,
                image_mode=len(data) >= size_of_image)


def build_image(pe: dict) -> bytes:
    if pe["image_mode"]:
        return pe["data"][:pe["size_of_image"]]
    img = bytearray(pe["size_of_image"])
    for s in pe["sections"]:
        n = min(s["vsize"], s["rawsize"])
        if n:
            img[s["vaddr"]:s["vaddr"] + n] = pe["data"][s["rawptr"]:s["rawptr"] + n]
    return bytes(img)


def _rip_entries():
    out = []
    for rex in (b"", b"\x48", b"\x4c"):
        for op in (0x8B, 0x8D, 0x89, 0x03, 0x0B, 0x39, 0x3B):
            for modrm in (0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D):
                pat = rex + bytes((op, modrm))
                out.append((pat, len(pat), len(pat) + 4))
    return out


RIP_ACCESSES = _rip_entries()


def find_all(img: bytes, seed: bytes, limit: int = 64):
    out = []
    start = 0
    while len(out) < limit:
        i = img.find(seed, start)
        if i < 0:
            break
        out.append(i)
        start = i + 1
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Reference scanner for candidate RVAs")
    ap.add_argument("--image", required=True)
    ap.add_argument("--base", default=None, help="module base for pointer-slot scan")
    ap.add_argument("--rva", action="append", default=[],
                    help="candidate as name=0xRVA (repeatable)")
    args = ap.parse_args()

    candidates: dict[int, str] = {}
    for item in args.rva:
        name, _, raw = item.partition("=")
        if not raw:
            print(f"bad --rva {item!r}", file=sys.stderr)
            return 2
        candidates[int(raw, 16)] = name

    base = int(args.base, 16) if args.base else None

    pe = parse_pe(args.image)
    img = build_image(pe)
    print(f"image: {args.image}  SizeOfImage {pe['size_of_image']:#x}  "
          f"image_mode={pe['image_mode']}")

    counts: dict[int, dict[str, list[int]]] = {
        rva: {"call": [], "rip": [], "ptr": []} for rva in candidates
    }

    for lo, hi in [(0, len(img))]:
        i = img.find(b"\xE8", lo, hi)
        while i >= 0:
            if i + 5 <= hi:
                target = i + 5 + struct.unpack_from("<i", img, i + 1)[0]
                entry = counts.get(target)
                if entry is not None:
                    entry["call"].append(i)
            i = img.find(b"\xE8", i + 1, hi)
        for pat, disp_off, next_off in RIP_ACCESSES:
            i = img.find(pat, lo, hi)
            while i >= 0:
                if i + next_off <= hi:
                    target = i + next_off + struct.unpack_from("<i", img, i + disp_off)[0]
                    entry = counts.get(target)
                    if entry is not None:
                        entry["rip"].append(i)
                i = img.find(pat, i + 1, hi)

    if base is not None:
        for rva in candidates:
            slot = struct.pack("<Q", base + rva)
            for i in find_all(img, slot, limit=32):
                counts[rva]["ptr"].append(i)

    for rva, name in sorted(candidates.items(), key=lambda kv: kv[1]):
        c = counts[rva]
        print(f"\n{name} = {rva:#x}")
        for kind in ("call", "rip", "ptr"):
            sites = c[kind]
            shown = ", ".join(f"{s:#x}" for s in sites[:8])
            more = f" (+{len(sites) - 8})" if len(sites) > 8 else ""
            print(f"  {kind:<4} sites : {len(sites):3d}   {shown}{more}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
