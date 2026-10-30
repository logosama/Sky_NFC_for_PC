# Ghidra helpers for re-deriving hook anchors

These scripts are used when a game update breaks the fixed addresses in
`hook/common.c`. They run under Ghidra's headless analyzer and are read-only
toward the analyzed executable.

Requirements: Ghidra 11+ (tested with 12.1.2) and a JDK 21+ available to it.

## One-time import and analysis

The 45 MB executable needs a decent heap; set `GHIDRA_HEADLESS_MAXMEM` if the
default is too small.

```bash
export GHIDRA_HEADLESS_MAXMEM=12G
analyzeHeadless /tmp/sky-ghidra SkyBadge \
    -import "/path/to/Sky Children of the Light/Sky.exe" \
    -overwrite -analysisTimeoutPerFile 3600 -max-cpu 8
```

Notes:

- Ghidra rejects a project path containing a dot-prefixed directory component
  (for example `~/.claude/...`). Use a plain path such as `/tmp/sky-ghidra`.
- Analysis takes several minutes. Once the project exists, reuse it with
  `-process Sky.exe -noanalysis`; do not re-import.

## Find anchor strings and the functions referencing them

```bash
analyzeHeadless /tmp/sky-ghidra SkyBadge -process Sky.exe -noanalysis \
    -scriptPath tools/ghidra \
    -postScript FindStringXrefs.java /tmp/sky-out \
    "Game::OnOpenedWithURL" \
    "No name for AnalyticsEvent enum: "
cat /tmp/sky-out/find_string_xrefs_report.txt
```

The report lists every occurrence of each string, its code/data references, and
the containing functions (entry, size, matched strings), sorted by how many
anchor strings each function references. This is how the new
`OnOpenedWithURL` and the AnalyticsEvent name→ID mapper are located.

## Decompile candidate functions

```bash
analyzeHeadless /tmp/sky-ghidra SkyBadge -process Sky.exe -noanalysis \
    -scriptPath tools/ghidra \
    -postScript DumpFunctions.java /tmp/sky-out 0x141172670 0x141925c10
cat /tmp/sky-out/dump_functions_report.txt
ls /tmp/sky-out/decomp_0x*.c
```

Addresses may be written with or without `0x`. For each address the script
prints the entry, size, callers, referenced data strings, and writes the full
decompilation to `decomp_0x<addr>.c`.

## What to look for

- `OnOpenedWithURL`: references the `Game::OnOpenedWithURL ...` log strings,
  takes `(this, url, fromNFC)`, accesses `this + 0x11B8` on the current build,
  and appears in its class vtable.
- Hook target: the AnalyticsEvent name→ID mapper. Its body is a long
  `strcmp(name, "...")` chain starting with the `"null"` sentinel; the analytics
  logger (`"No name for AnalyticsEvent enum: "`) calls it to validate names.
- Vtable: find the `.rdata` qword pointing at `OnOpenedWithURL`, then walk
  backwards over consecutive `.text` pointers to the table start. Constructors
  that store the address (`lea rax,[vtable]; mov [rsi],rax`) confirm it.

After updating `hook/common.c`, run `python3 tools/verify_anchors.py` and require
`RESULT: ALL OK` before building or launching the game.
