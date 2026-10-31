#!/usr/bin/env python3
"""Vesper offset porter: relocate a descriptor from one Roblox build to another.

Inputs on each side may be either an on-disk `RobloxPlayerBeta.exe` (PE file
layout) or a runtime image dump produced by `Vesper.exe --dump` (file offset ==
RVA, unreadable pages are zero-filled).  A file at least as large as
`SizeOfImage` is treated as an image.

Every `rva.*` entry is re-located with the first of these methods that works:

  1. ``direct``  — byte-signature window matching over the mapped image, for
     regions whose bytes are build-stable and readable in both images;
  2. ``ref``     — a code/data *site* that mentions the old address is
     re-located by its surrounding context (excluding the address field), and
     the new address is read back from the new build.  Site kinds, in order:
     direct calls (``E8 rel32``), rip-relative accesses
     (``mov/lea/cmp ... [rip+disp32]``), and absolute pointer slots
     (``u64 == base + rva``; requires ``--from-base`` / ``--to-base``).

Entries that cannot be relocated are removed from ``entries`` and listed under
``unported``, so a partially ported table can never silently carry a stale
address.  ``rva.hyperion.*`` entries live in RobloxPlayerBeta.dll (unused by
the engine today) and are copied through untouched.

Usage:
  port_offsets.py --descriptor <in.json> --from-exe <A> --to-exe <B>
                  [--from-base 0x... --to-base 0x...]
                  [--out <out.json>] [--report <report.md>] [--build version-...]

Exit code is 0 when every non-hyperion rva.* entry was relocated.
"""

from __future__ import annotations

import argparse
import json
import os
import struct
import sys
import time
from datetime import datetime, timezone

IMAGE_SCN_MEM_EXECUTE = 0x20000000

# --------------------------------------------------------------------------- PE


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
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic != 0x20B:
        raise ValueError(f"{path}: not PE32+ (magic {magic:#x})")
    size_of_image = struct.unpack_from("<I", data, opt + 56)[0]
    size_of_headers = struct.unpack_from("<I", data, opt + 60)[0]
    entry = struct.unpack_from("<I", data, opt + 16)[0]
    sec = opt + opt_size
    sections = []
    for i in range(num_sections):
        off = sec + i * 40
        name = data[off:off + 8].rstrip(b"\0").decode("latin1")
        vsize, vaddr = struct.unpack_from("<II", data, off + 8)
        rawsize, rawptr = struct.unpack_from("<II", data, off + 16)
        ch = struct.unpack_from("<I", data, off + 36)[0]
        sections.append(dict(name=name, vaddr=vaddr, vsize=vsize,
                             rawptr=rawptr, rawsize=rawsize, chars=ch))
    return dict(path=path, data=data, size_of_image=size_of_image,
                size_of_headers=size_of_headers, entry=entry, sections=sections,
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


def section_of(pe: dict, rva: int):
    for s in pe["sections"]:
        if s["vaddr"] <= rva < s["vaddr"] + max(s["vsize"], s["rawsize"]):
            return s
    return None


# ------------------------------------------------------------------- matching


def find_all(img: bytes, seed: bytes, limit: int = 500):
    out = []
    start = 0
    while len(out) < limit:
        i = img.find(seed, start)
        if i < 0:
            break
        out.append(i)
        start = i + 1
    return out


def mostly_zero(bs: bytes, tolerance: int = 2) -> bool:
    if not bs:
        return True
    return bs.count(0) >= len(bs) - tolerance


def region_zeroed(img: bytes, pos: int, n: int, threshold: float = 0.98) -> bool:
    chunk = img[pos:pos + n]
    if not chunk:
        return True
    return chunk.count(0) >= len(chunk) * threshold


def score_bytes(a: bytes, b: bytes):
    n = min(len(a), len(b))
    if n <= 0:
        return 0, 0
    same = 0
    for i in range(n):
        if a[i] == b[i]:
            same += 1
    return same, n


def score_window(imgA: bytes, posA: int, imgB: bytes, posB: int, window: int):
    return score_bytes(imgA[posA:posA + window], imgB[posB:posB + window])


CODE_PROBES = tuple(range(0, 0x101, 0x10))
WINDOW = 256


def relocate_code(imgA: bytes, imgB: bytes, rva: int):
    """Signature-relocate a code/rodata RVA. Returns (new_rva, conf, note)."""
    if rva < 0 or rva + 0x40 > len(imgA):
        return None, 0.0, "rva outside image A"
    if region_zeroed(imgA, rva, 0x100):
        return None, 0.0, "source region zero-filled (encrypted or never mapped)"

    # pass 1: exact unique seeds
    for seed_len in (32, 24):
        for off in CODE_PROBES:
            seed = imgA[rva + off: rva + off + seed_len]
            if len(seed) < seed_len or mostly_zero(seed):
                continue
            hits = find_all(imgB, seed, limit=128)
            if len(hits) != 1:
                continue
            cand = hits[0] - off
            if cand < 0:
                continue
            same, n = score_window(imgA, rva, imgB, cand, WINDOW)
            ratio = same / n if n else 0.0
            if ratio >= 0.90:
                return cand, 0.99 if off == 0 else 0.95, \
                    f"direct: seed{seed_len} probe+{off:#x} unique, window {ratio:.2f}"

    # pass 2: short seeds scored by neighbourhood agreement
    for off in CODE_PROBES:
        seed = imgA[rva + off: rva + off + 16]
        if len(seed) < 16 or mostly_zero(seed):
            continue
        hits = find_all(imgB, seed, limit=1200)
        if not hits:
            continue
        scored = []
        for h in hits:
            cand = h - off
            if cand < 0:
                continue
            same, n = score_window(imgA, rva, imgB, cand, WINDOW)
            scored.append((same, cand))
        if not scored:
            continue
        scored.sort(key=lambda t: (-t[0], t[1]))
        best_same, best = scored[0]
        second = scored[1][0] if len(scored) > 1 else -1
        ratio = best_same / WINDOW
        if ratio >= 0.80 and (best_same - second) >= 10:
            return best, 0.85 if off == 0 else 0.75, \
                f"direct: seed16 probe+{off:#x} scored {best_same}/{WINDOW} ({len(hits)} hits)"
    return None, 0.0, "direct: no candidate"


# ------------------------------------------------- data refs (calls / rip / ptr)


def _rip_entries():
    out = []
    for rex in (b"", b"\x48", b"\x4c"):
        for op in (0x8B, 0x8D, 0x89, 0x03, 0x0B, 0x39, 0x3B):
            for modrm in (0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D):
                pat = rex + bytes((op, modrm))
                out.append((pat, len(pat), len(pat) + 4))
    return out


RIP_ACCESSES = _rip_entries()


def scan_ranges(pe: dict, img: bytes):
    if pe["image_mode"]:
        return [(0, len(img))]
    ranges = []
    for s in pe["sections"]:
        if not (s["chars"] & IMAGE_SCN_MEM_EXECUTE):
            continue
        lo = s["vaddr"]
        hi = min(s["vaddr"] + max(s["vsize"], s["rawsize"]), len(img))
        ranges.append((lo, hi))
    return ranges


def build_ref_index(pe: dict, img: bytes, wanted: set, base: int | None,
                    progress=None):
    """Map target rva -> list of (kind, site) references in readable regions."""
    refs: dict[int, list] = {}

    def add(target: int, kind: str, site: int):
        lst = refs.setdefault(target, [])
        if len(lst) < 64:
            lst.append((kind, site))

    n_calls = n_rips = n_ptrs = 0
    for lo, hi in scan_ranges(pe, img):
        i = img.find(b"\xE8", lo, hi)
        while i >= 0:
            if i + 5 <= hi:
                target = i + 5 + struct.unpack_from("<i", img, i + 1)[0]
                if target in wanted:
                    add(target, "call", i)
                    n_calls += 1
            i = img.find(b"\xE8", i + 1, hi)
        for pat, disp_off, next_off in RIP_ACCESSES:
            i = img.find(pat, lo, hi)
            while i >= 0:
                if i + next_off <= hi:
                    target = i + next_off + struct.unpack_from("<i", img, i + disp_off)[0]
                    if target in wanted:
                        add(target, "rip", i)
                        n_rips += 1
                i = img.find(pat, i + 1, hi)

    if base is not None:
        thin = [t for t in sorted(wanted) if len(refs.get(t, [])) < 2]
        for target in thin:
            slot = struct.pack("<Q", base + target)
            i = img.find(slot)
            while i >= 0:
                add(target, "ptr", i)
                n_ptrs += 1
                i = img.find(slot, i + 1)

    if progress:
        progress(n_calls, n_rips, n_ptrs, len(refs))
    return refs


MLEN = {"call": 5, "rip": 7, "ptr": 8}


def relocate_site(imgA: bytes, imgB: bytes, kind: str, site: int):
    """Relocate one reference site by its 24-byte context on both sides."""
    mlen = MLEN[kind]
    if site < 24 or site + mlen + 24 > len(imgA):
        return None
    pre = imgA[site - 24:site]
    post = imgA[site + mlen: site + mlen + 24]
    cands = set()
    if not mostly_zero(post, tolerance=4):
        for h in find_all(imgB, post, limit=800):
            cands.add(h - mlen)
    if not cands and not mostly_zero(pre, tolerance=4):
        for h in find_all(imgB, pre, limit=800):
            cands.add(h)
    if not cands:
        return None
    scored = []
    for s2 in cands:
        if s2 < 24 or s2 + mlen + 24 > len(imgB):
            continue
        if kind == "call" and imgB[s2] != 0xE8:
            continue
        if kind == "rip" and imgB[s2:s2 + 2] != imgA[site:site + 2]:
            continue
        same_pre, _ = score_bytes(pre, imgB[s2 - 24:s2])
        same_post, _ = score_bytes(post, imgB[s2 + mlen:s2 + mlen + 24])
        scored.append((same_pre + same_post, s2))
    if not scored:
        return None
    scored.sort(key=lambda t: (-t[0], t[1]))
    best_same, best = scored[0]
    second = scored[1][0] if len(scored) > 1 else -1
    if len(scored) == 1:
        return best if best_same >= 34 else None
    if best_same >= 34 and (best_same - second) >= 8:
        return best
    return None


def extract_target(kind: str, imgB: bytes, s2: int, baseB: int | None):
    if kind == "call":
        t = s2 + 5 + struct.unpack_from("<i", imgB, s2 + 1)[0]
    elif kind == "rip":
        t = s2 + 7 + struct.unpack_from("<i", imgB, s2 + 3)[0]
    else:
        if baseB is None:
            return None
        v = struct.unpack_from("<Q", imgB, s2)[0]
        if not (baseB <= v < baseB + len(imgB)):
            return None
        t = v - baseB
    if not (0 <= t < len(imgB)):
        return None
    return t


def relocate_via_refs(imgA: bytes, imgB: bytes, rva: int, refs: dict,
                      baseB: int | None):
    sites = refs.get(rva, [])
    votes: dict[int, list] = {}
    for kind, site in sites:
        s2 = relocate_site(imgA, imgB, kind, site)
        if s2 is None:
            continue
        target = extract_target(kind, imgB, s2, baseB)
        if target is None or target == rva:
            continue
        votes.setdefault(target, []).append((kind, site, s2))
    if not votes:
        return None, 0.0, f"ref: no relocated site ({len(sites)} sites seen)"
    ranked = sorted(votes.items(), key=lambda kv: -len(kv[1]))
    best_target, hit_list = ranked[0]
    if len(ranked) > 1 and len(hit_list) <= len(ranked[1][1]):
        return None, 0.0, f"ref: ambiguous ({len(ranked)} targets)"
    kinds = ",".join(sorted({k for k, _, _ in hit_list}))
    conf = 0.95 if len(hit_list) >= 3 else (0.85 if len(hit_list) == 2 else 0.60)
    return best_target, conf, \
        f"ref: {len(hit_list)}/{len(sites)} sites agree ({kinds})"


# ---------------------------------------------------------------------- main


def hexv(v) -> str:
    return v if isinstance(v, str) else hex(v)


def parse_hex(v):
    if v is None:
        return None
    return int(v, 16) if isinstance(v, str) else int(v)


def main() -> int:
    ap = argparse.ArgumentParser(description="Port vesper offsets between builds")
    ap.add_argument("--descriptor", required=True)
    ap.add_argument("--from-exe", required=True)
    ap.add_argument("--to-exe", required=True)
    ap.add_argument("--from-base", default=None,
                    help="module base of image A (hex), enables pointer-slot refs")
    ap.add_argument("--to-base", default=None, help="module base of image B (hex)")
    ap.add_argument("--out")
    ap.add_argument("--report")
    ap.add_argument("--build", default=None, help="build id for the output table")
    args = ap.parse_args()

    t0 = time.time()
    with open(args.descriptor, "r", encoding="utf-8") as f:
        desc = json.load(f)
    entries: dict[str, str] = desc["entries"]
    src_build = desc.get("build", "?")

    to_build = args.build
    if not to_build:
        to_build = os.path.basename(os.path.dirname(os.path.abspath(args.to_exe)))

    baseA = parse_hex(args.from_base)
    baseB = parse_hex(args.to_base)
    ptr_ok = baseA is not None and baseB is not None

    print(f"porter: {src_build} -> {to_build}")
    peA = parse_pe(args.from_exe)
    peB = parse_pe(args.to_exe)
    imgA = build_image(peA)
    imgB = build_image(peB)
    print(f"  A: {os.path.basename(peA['path'])}  SizeOfImage {peA['size_of_image']:#x}"
          f"  image_mode={peA['image_mode']}")
    print(f"  B: {os.path.basename(peB['path'])}  SizeOfImage {peB['size_of_image']:#x}"
          f"  image_mode={peB['image_mode']}")
    if not ptr_ok:
        print("  note: --from-base/--to-base not both given; pointer-slot refs disabled")

    # collect work
    todo = []      # (key, rva)
    passthrough = []
    skipped = []
    for key, val in entries.items():
        if key.startswith("rva.hyperion."):
            skipped.append((key, val, "hyperion module (unused by engine)"))
            passthrough.append((key, val))
        elif key.startswith("rva."):
            todo.append((key, parse_hex(val)))
        else:
            passthrough.append((key, val))

    if peA["image_mode"] or peB["image_mode"]:
        za = sum(1 for _, r in todo if region_zeroed(imgA, r, 0x40))
        zb = sum(1 for _, r in todo if region_zeroed(imgB, r, 0x40))
        print(f"  readability census: {za}/{len(todo)} targets zeroed in A, "
              f"{zb}/{len(todo)} in B")

    # pass 1: direct signature relocation
    results: dict[str, tuple[int | None, float, str]] = {}
    cache: dict[int, tuple[int | None, float, str]] = {}
    for key, rva in todo:
        if rva in cache:
            results[key] = cache[rva]
            continue
        res = relocate_code(imgA, imgB, rva)
        cache[rva] = res
        results[key] = res

    # pass 2: ref-based for failures
    failures = [k for k, (n, c, _) in results.items() if n is None]
    refs_used = False
    if failures:
        wanted = {rva for k, rva in todo if k in failures}
        print(f"  scanning refs for {len(wanted)} unrelocated targets…")
        refs = build_ref_index(
            peA, imgA, wanted, baseA if ptr_ok else None,
            progress=lambda c, r, p, t: print(
                f"    call sites: {c}, rip sites: {r}, ptr slots: {p}, "
                f"targets with refs: {t}"))
        print(f"  ref index: {len(refs)} of {len(wanted)} targets have refs")
        for key, rva in todo:
            if key not in failures:
                continue
            new, conf, note = relocate_via_refs(imgA, imgB, rva, refs,
                                                baseB if ptr_ok else None)
            if new is not None:
                results[key] = (new, conf, note)
                cache[rva] = (new, conf, note)
                refs_used = True
            else:
                results[key] = (None, 0.0, note)

    # assemble output
    out_entries: dict[str, str] = {}
    unported: dict[str, str] = {}
    report_lines = []
    n_ok = n_fail = 0
    for key, val in passthrough:
        out_entries[key] = val
    for key, rva in todo:
        new, conf, note = results[key]
        if new is None:
            n_fail += 1
            unported[key] = hexv(entries[key])
            report_lines.append(f"| {key} | {hex(rva)} | — | FAIL | {note} |")
        else:
            n_ok += 1
            delta = new - rva
            out_entries[key] = hex(new)
            print(f"  {key:<44} {rva:#010x} -> {new:#010x}  "
                  f"({delta:+#x}, conf {conf:.2f}, {note})")
            report_lines.append(
                f"| {key} | {hex(rva)} | {hex(new)} | {conf:.2f} | {delta:+#x} | {note} |")

    out = dict(desc)
    out["build"] = to_build
    out["source"] = (f"ported from {src_build} by vesper/tools/port_offsets.py "
                     f"({datetime.now(timezone.utc).strftime('%Y-%m-%d')})")
    notes = list(desc.get("notes", []))
    notes.append(f"Ported {src_build} -> {to_build}: {n_ok} relocated, {n_fail} unported"
                 + (", ref-based relocation used" if refs_used else ""))
    out["notes"] = notes
    out["entries"] = out_entries
    if unported:
        out["unported"] = unported

    out_path = args.out or args.descriptor.replace(src_build, to_build)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)
        f.write("\n")
    print(f"  wrote {out_path}")

    if args.report:
        with open(args.report, "w", encoding="utf-8") as f:
            f.write(f"# Offset port {src_build} -> {to_build}\n\n")
            f.write(f"- generated {datetime.now(timezone.utc).isoformat(timespec='seconds')}\n")
            f.write(f"- from `{peA['path']}`\n- to `{peB['path']}`\n")
            if baseA is not None:
                f.write(f"- bases: A {baseA:#x}, B {baseB:#x}\n")
            f.write(f"- relocated {n_ok}, unported {n_fail}, skipped {len(skipped)}\n\n")
            f.write("| key | old rva | new rva | conf | delta | note |\n")
            f.write("|---|---|---|---|---|---|\n")
            for line in report_lines:
                f.write(line + "\n")
            if skipped:
                f.write("\n## skipped\n\n")
                for key, val, why in skipped:
                    f.write(f"- `{key}` = {val} — {why}\n")
        print(f"  wrote {args.report}")

    print(f"done in {time.time() - t0:.1f}s: {n_ok} relocated, {n_fail} unported")
    return 0 if n_fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
