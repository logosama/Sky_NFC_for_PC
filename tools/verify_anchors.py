#!/usr/bin/env python3
"""Offline anchor verification for the Sky badge hook.

Parses FIXED_* / MAGIC_* / SIG_* out of hook/common.c and checks them against a
Sky.exe build: magic bytes at the fixed addresses, unique signature matches in
.text, and the vtable derived from OnOpenedWithURL. Read-only; exits 0 only if
every check passes.

Usage:
    python3 tools/verify_anchors.py [--exe PATH] [--source PATH]

The executable is auto-detected from the usual Steam locations when --exe is
omitted; SKY_EXE overrides the search.
"""
from __future__ import annotations

import argparse
import os
import re
import struct
import sys

IMAGE_SCN_MEM_EXECUTE = 0x20000000


class PEError(Exception):
    pass


class PE:
    """Minimal PE32/PE32+ reader: section table and VA->file-offset mapping."""

    def __init__(self, data: bytes):
        self.data = data
        if data[:2] != b"MZ":
            raise PEError("not a PE file (missing MZ header)")
        e_lfanew = self._u32(0x3C)
        if data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
            raise PEError("not a PE file (missing PE signature)")
        coff = e_lfanew + 4
        nsec = self._u16(coff + 2)
        opt_size = self._u16(coff + 16)
        opt = coff + 20
        magic = self._u16(opt)
        if magic == 0x20B:      # PE32+
            self.image_base = self._u64(opt + 24)
        elif magic == 0x10B:    # PE32
            self.image_base = self._u32(opt + 28)
        else:
            raise PEError(f"unknown optional-header magic 0x{magic:x}")

        sec_off = opt + opt_size
        self.sections = []      # (name, va, vsize, raw_ptr, raw_size, characteristics)
        for i in range(nsec):
            o = sec_off + i * 40
            name = data[o:o + 8].rstrip(b"\0").decode("ascii", "replace")
            vsize, va, rawsize, rawptr = struct.unpack_from("<IIII", data, o + 8)
            chars = self._u32(o + 36)
            self.sections.append((name, va, vsize, rawptr, rawsize, chars))

    def _u16(self, off: int) -> int:
        return struct.unpack_from("<H", self.data, off)[0]

    def _u32(self, off: int) -> int:
        return struct.unpack_from("<I", self.data, off)[0]

    def _u64(self, off: int) -> int:
        return struct.unpack_from("<Q", self.data, off)[0]

    def section(self, name: str):
        for sec in self.sections:
            if sec[0] == name:
                return sec
        return None

    def text_section(self):
        for sec in self.sections:
            if sec[5] & IMAGE_SCN_MEM_EXECUTE:
                return sec
        raise PEError("no executable section found")

    def va_to_off(self, va: int):
        rva = va - self.image_base
        for name, sva, vsize, rawptr, rawsize, _chars in self.sections:
            if sva <= rva < sva + max(vsize, rawsize):
                delta = rva - sva
                if delta >= rawsize:
                    return None
                return rawptr + delta
        return None

    def read(self, va: int, size: int) -> bytes:
        off = self.va_to_off(va)
        if off is None:
            raise PEError(f"VA 0x{va:x} is not backed by file data")
        return self.data[off:off + size]

    def u64_at_va(self, va: int) -> int:
        return struct.unpack("<Q", self.read(va, 8))[0]


def parse_source(path: str):
    src = open(path, encoding="utf-8").read()

    def define(name: str) -> int:
        m = re.search(r"#define\s+" + re.escape(name) + r"\s+(0x[0-9A-Fa-f]+)ULL\b", src)
        if not m:
            raise ValueError(f"#define {name} 0x...ULL not found in {path}")
        return int(m.group(1), 16)

    def array(name: str) -> bytes:
        m = re.search(
            r"static\s+const\s+uint8_t\s+" + re.escape(name) + r"\s*\[\s*\]\s*=\s*\{(.*?)\};",
            src, re.S)
        if not m:
            raise ValueError(f"array {name} not found in {path}")
        body = re.sub(r"/\*.*?\*/", "", m.group(1), flags=re.S)
        vals = [int(x, 16) for x in re.findall(r"0x([0-9A-Fa-f]{2})", body)]
        if not vals:
            raise ValueError(f"array {name} is empty")
        return bytes(vals)

    out = {name: define(name) for name in
           ("FIXED_ONOPENURL", "FIXED_HOOK_TARGET", "FIXED_VTABLE")}
    for name in ("MAGIC_ONOPENURL", "MAGIC_HOOK_TARGET", "SIG_ONOPENURL", "SIG_HOOK_ADDR"):
        out[name] = array(name)
    return out


def wildcard_hits(blob: bytes, sig: bytes):
    """All offsets where sig matches blob, with 0xFF in sig matching any byte."""
    n = len(sig)
    if n == 0 or n > len(blob):
        return []
    # Anchor the search on the longest run of exact bytes, then verify the rest.
    best_start = best_len = 0
    i = 0
    while i < n:
        if sig[i] == 0xFF:
            i += 1
            continue
        j = i
        while j < n and sig[j] != 0xFF:
            j += 1
        if j - i > best_len:
            best_start, best_len = i, j - i
        i = j
    if best_len == 0:
        return [off for off in range(len(blob) - n + 1)
                if all(s == 0xFF or blob[off + k] == s for k, s in enumerate(sig))]

    needle = sig[best_start:best_start + best_len]
    hits = []
    pos = 0
    while True:
        k = blob.find(needle, pos)
        if k < 0:
            break
        start = k - best_start
        if start >= 0 and start + n <= len(blob):
            if all(s == 0xFF or blob[start + j] == s for j, s in enumerate(sig)):
                hits.append(start)
        pos = k + 1
    return hits


def default_exe():
    env = os.environ.get("SKY_EXE")
    if env:
        return env
    home = os.path.expanduser("~")
    rel = os.path.join("steamapps", "common", "Sky Children of the Light", "Sky.exe")
    candidates = [
        os.path.join(home, ".local/share/Steam", rel),
        os.path.join(home, ".steam/steam", rel),
        os.path.join(home, ".steam/root", rel),
        os.path.join(home, "Steam", rel),
        r"C:\Program Files (x86)\Steam" + "\\" + rel,
        r"C:\Program Files\Steam" + "\\" + rel,
        r"D:\SteamLibrary" + "\\" + rel,
        r"E:\SteamLibrary" + "\\" + rel,
    ]
    for p in candidates:
        if os.path.isfile(p):
            return p
    return None


def main() -> int:
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--exe", help="path to Sky.exe (default: auto-detect Steam install)")
    ap.add_argument("--source", default=os.path.join(root, "hook", "common.c"),
                    help="path to hook/common.c")
    args = ap.parse_args()

    exe = args.exe or default_exe()
    if not exe:
        print("error: Sky.exe not found; pass --exe PATH", file=sys.stderr)
        return 2
    if not os.path.isfile(exe):
        print(f"error: {exe} not found", file=sys.stderr)
        return 2

    try:
        anchors = parse_source(args.source)
    except (OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    data = open(exe, "rb").read()
    try:
        pe = PE(data)
    except PEError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    print(f"source: {args.source}")
    print(f"exe:    {exe} ({len(data)} bytes, image base 0x{pe.image_base:x})")

    ok = True

    def check(cond: bool, msg: str):
        nonlocal ok
        ok = ok and cond
        print(f"  {'OK  ' if cond else 'FAIL'} {msg}")

    fixed_onopen = anchors["FIXED_ONOPENURL"]
    fixed_hook = anchors["FIXED_HOOK_TARGET"]
    fixed_vt = anchors["FIXED_VTABLE"]

    print("\n[magic bytes at fixed addresses]")
    for label, addr, magic in (
            ("FIXED_ONOPENURL", fixed_onopen, anchors["MAGIC_ONOPENURL"]),
            ("FIXED_HOOK_TARGET", fixed_hook, anchors["MAGIC_HOOK_TARGET"])):
        try:
            got = pe.read(addr, len(magic))
        except PEError as e:
            check(False, f"{label} 0x{addr:x}: {e}")
            continue
        check(got == magic,
              f"{label} 0x{addr:x} ({len(magic)} bytes)"
              + ("" if got == magic else f": got {got.hex(' ')}"))

    text = pe.text_section()
    _tname, text_va, _tvsize, text_raw, text_rawsize, _tc = text
    text_start = pe.image_base + text_va
    text_end = text_start + text_rawsize
    text_blob = data[text_raw:text_raw + text_rawsize]

    print("\n[signature uniqueness in .text]")
    for label, sig, expect in (
            ("SIG_ONOPENURL", anchors["SIG_ONOPENURL"], fixed_onopen),
            ("SIG_HOOK_ADDR", anchors["SIG_HOOK_ADDR"], fixed_hook)):
        hits = [text_start + off for off in wildcard_hits(text_blob, sig)]
        check(hits == [expect],
              f"{label} ({len(sig)} bytes): {len(hits)} hit(s) "
              f"{[hex(h) for h in hits[:5]]}" + ("" if hits == [expect] else f" expected [{hex(expect)}]"))

    print("\n[vtable]")
    try:
        first = pe.u64_at_va(fixed_vt)
        check(text_start <= first < text_end,
              f"FIXED_VTABLE 0x{fixed_vt:x}: first entry 0x{first:x} is in .text")
    except PEError as e:
        check(False, f"FIXED_VTABLE 0x{fixed_vt:x}: {e}")

    rdata = pe.section(".rdata")
    if rdata is None:
        check(False, ".rdata section not found")
    else:
        _rname, rva, _rvsize, rraw, rrawsize, _rc = rdata
        rdata_start = pe.image_base + rva
        rdata_blob = data[rraw:rraw + rrawsize]
        ptr = struct.pack("<Q", fixed_onopen)
        positions = []
        pos = 0
        while True:
            k = rdata_blob.find(ptr, pos)
            if k < 0:
                break
            positions.append(k)
            pos = k + 1
        if not positions:
            check(False, f"no .rdata pointer to FIXED_ONOPENURL 0x{fixed_onopen:x}")
        else:
            off = positions[0]
            while off >= 8:
                prev = struct.unpack_from("<Q", rdata_blob, off - 8)[0]
                if not (text_start <= prev < text_end):
                    break
                off -= 8
            derived = rdata_start + off
            check(derived == fixed_vt,
                  f"pointer at 0x{rdata_start + positions[0]:x} -> vtable start "
                  f"0x{derived:x}" + ("" if derived == fixed_vt else f" expected 0x{fixed_vt:x}"))

    print("\nRESULT:", "ALL OK" if ok else "FAILURES PRESENT")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
