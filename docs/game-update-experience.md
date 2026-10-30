# Game update experience log

This file is the accumulated, per-build companion to
[`game-updates.md`](game-updates.md). The playbook explains how to re-anchor the
hook; this log records what actually changed on each update, what broke, and
what to re-check in the scripts.

Maintenance rules:

- Append one entry per game build; do not rewrite old entries.
- Update the [version index](#version-index) and record the verification date
  and platforms.
- Keep exact values and commands, not just conclusions.
- Newest entries go at the end; the index is the quick way in.

## Version index

| Version | CL | Verified | Anchor delta | Notes |
|---|---|---|---|---|
| 0.34.5 | 410941 | Linux (historical) | baseline for the 0.35.1 update | `player_shout` still present |
| 0.35.1 | 423272 | Linux in-game; native Windows (2026-10-31) | all three addresses, frame/field offsets | three shout event names replaced `player_shout`; Windows path verified |

## Post-update checklist

Run this for every build; record the results in the new version entry.

| Area | Action | Required result |
|---|---|---|
| Build ID | Read `Version:` from `Sky.log` (Linux/Proton and native Windows installs) | every install used reports the same `x.y.z.CL` |
| OnOpenedWithURL | Re-derive `FIXED_ONOPENURL` / `MAGIC_ONOPENURL` / `SIG_ONOPENURL` | function contains the `Game::OnOpenedWithURL` strings, takes `(this, url, fromNFC)`, appears in its vtable |
| Tick source | Re-derive `FIXED_HOOK_TARGET` / `MAGIC_HOOK_TARGET` / `SIG_HOOK_ADDR` from the AnalyticsEvent mapper | mapper is called from the analytics logger; `"null"` sentinel + `strcmp` chain; prologue stable |
| Vtable | Derive from the `.rdata` pointer walk; confirm with constructors | `FIXED_VTABLE` first entry points into `.text` |
| `hook/common.c` | Update all `FIXED_*`, `MAGIC_*`, `SIG_*`; keep exact anchor bytes; update the build comment | no wildcard loosening |
| Offline check | `python3 tools/verify_anchors.py --exe <Sky.exe>` | `RESULT: ALL OK` (magic, one signature hit, vtable) |
| Build | `./build.sh` | `sky_hook.so` + `sky_hook.dll` |
| Linux in-game | `ping`, `hook`, badge scan | `fn`/`vt` non-zero, `hook OK`, ticks increase, `INJECT done` |
| Windows in-game | `verify_anchors.py` on the Windows `Sky.exe`, then `inject_dll.py`, `ping`/`hook`/scan | same as Linux; check `%APPDATA%\sky-badge\hook.log` for full 64-bit addresses |
| Docs | Update the `ping` example, Windows status, and this log | — |
| Phone relay | Android app protocol + `nfc/remote.py` | usually unchanged; verify only if the URL format changed |

### Files to touch

- `hook/common.c`: `FIXED_*`, `MAGIC_*`, `SIG_*`, and the build comment.
- `README.md`: the `ping` example and the Windows verification status.
- `docs/game-updates.md`: add/refresh the case study if the derivation method
  changed.
- `docs/game-update-experience.md`: append the new version entry and update
  the index.
- `tools/verify_anchors.py`, `nfc/`, `android/`: normally unchanged; touch only
  if the signature/URL/NFC format changed.

## Per-build entry template

```markdown
### <version> (<CL>)

- Date:
- `Sky.log`: `Version: x.y.z.CL`
- Executable: path, file size, `ImageBase`, `DllCharacteristics`
- OnOpenedWithURL: frame size, class field offset, signature lengths
- Hook target: mapper size, event count, call sites, structural checks
- Vtable: address and derivation evidence

| Anchor | Previous build | This build |
|---|---|---|
| `FIXED_ONOPENURL` | | |
| `FIXED_HOOK_TARGET` | | |
| `FIXED_VTABLE` | | |

- Script changes:
- Verification: `verify_anchors.py` / Linux in-game / Windows in-game
- Pitfalls:
- Follow-ups:
```

## 0.35.1 (423272)

Windows verification date: 2026-10-31. Linux in-game verification was part of
the original 0.35.1 work (see below).

### Anchor delta

| Anchor | 0.34.5 (410941) | 0.35.1 (423272) |
|---|---|---|
| `FIXED_ONOPENURL` | `0x1411221e0` | `0x141172670` |
| `FIXED_HOOK_TARGET` | `0x1418b0b10` | `0x141925c10` |
| `FIXED_VTABLE` | `0x141e8a390` | `0x141f0ed80` |
| OnOpenedWithURL frame / field | `0x998` / `+0x11A0` | `0x0F18` / `+0x11B8` |
| First `je` in mapper | `0x1B59` | `0x1B9E` |

Anchor lengths for this build: `MAGIC_ONOPENURL` 19 bytes,
`SIG_ONOPENURL` 49 bytes, `MAGIC_HOOK_TARGET` 17 bytes,
`SIG_HOOK_ADDR` 34 bytes. The 34-byte signature keeps the first LEA
displacement exact and wildcards only the `call`/`je` rel32 fields.

### What changed in the binary

- `OnOpenedWithURL` grew its stack frame (`0x998` -> `0x0F18`) and moved the
  class field from `+0x11A0` to `+0x11B8`. Both are part of the signature and
  are what make it unique in `.text`.
- The AnalyticsEvent mapper is 10,119 bytes with 308 event names and 276 call
  sites. Its first `je` offset grew by `0x45` (`0x1B59` -> `0x1B9E`):
  `player_shout` disappeared and `short_shout` / `medium_shout` /
  `deep_shout` were added.
- `player_shout` must not be used as an anchor; use the structural/analytics
  anchors instead.

### Windows findings

The 0.35.1 update also covered the Windows bring-up. These findings are
version-independent and should be re-checked after every update:

- The target is the same Windows PE on Proton and native Windows for the same
  Steam build. Anchors are host-OS independent; verify the exact Windows
  `Sky.exe` with `verify_anchors.py` before relying on the fixed addresses.
- The local 0.35.1 `Sky.exe` is a PE32+ image with `ImageBase = 0x140000000`,
  `DllCharacteristics = 0x8020` (no `DYNAMICBASE`) and a 0x10-byte reloc
  directory. Fixed addresses are therefore valid on native Windows for this
  build. Re-check these flags after every update.
- Fixed-address probes on Windows must be fault-safe (`ReadProcessMemory`);
  a plain `memcpy` from a stale or unmapped anchor kills the game instead of
  falling back to the pattern scan.
- The trampoline lives in the hook DLL's read-only `.text`. Windows needs
  `VirtualProtect` on that page before the replay bytes are filled; Linux can
  write it through `/proc/self/mem`.
- `DllMain` must not run `common_init()` (WSAStartup, file I/O, threads) under
  the loader lock. Start a short-delay init thread and probe for the fully
  mapped `Sky.exe` there.
- Host-instance discovery is platform-specific. Windows uses `VirtualQuery`;
  skip candidates that are on the current thread's stack
  (`GetCurrentThreadStackLimits`), because a spilled vtable value plus a
  pointer to that stack slot looks like a live object.
- The instance is found once and cached in `g_onurl_this`; `ticks` increasing
  in `ping` proves the trampoline is live.
- Log 64-bit addresses with `%llx` on Windows; `unsigned long` is 32-bit there
  and `%lx` silently truncates anchors.
- The injector only needs
  `PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE`, must run
  as 64-bit Python, and needs elevation only if the game is elevated.
  `WINFUNCTYPE` belongs to `ctypes`, not `ctypes.wintypes`.
- PC/SC details: `SCardEstablishContext` takes four arguments,
  `SCardTransmit` requires a valid `SCARD_IO_REQUEST`, and the `FF B0` read
  pseudo-APDU is ACR122-style rather than generic CCID.
- Tests can run without hardware: a mock `libpcsclite.so.1` for the PC/SC
  backend, and a synthetic `Sky.exe` under Wine for the full
  `ping -> hook -> inject -> unhook` chain. When placing fake anchors with
  `VirtualAlloc` in such a harness, reserve the containing 64 KiB region and
  write at the exact anchor address; `VirtualAlloc` rounds fixed addresses
  down.

### Verification

- `python3 tools/verify_anchors.py`: `RESULT: ALL OK` against 0.35.1
  (magic bytes, unique signature hits, vtable pointer walk).
- Linux in-game: `ping` shows non-zero `fn`/`vt`, `hook OK`, a scan logs
  `INJECT done`, and `ticks` keeps increasing. This was the original 0.35.1
  verification; after the cross-platform refactor the Linux instance scan was
  exercised with a synthetic object, so a fresh in-game Linux regression is
  still worth running.
- Native Windows in-game (2026-10-31): same flow through `inject_dll.py`.
- Wine synthetic `Sky.exe`: `ping -> hook OK -> inject -> INJECT done ->
  unhook`, plus the unmapped-anchor path (`fn=0x0`, `hook FAIL`, process
  stays alive).

## Known failure modes

| Symptom | Likely cause | Action |
|---|---|---|
| `fn=0x0`, `hook FAIL` after an update | anchors moved; signature scan found nothing | re-derive all three anchors; run `verify_anchors.py` |
| `verify_anchors.py` reports 0 hits | candidate derived from the wrong build/function | re-decompile with `DumpFunctions.java` |
| multiple signature hits | anchor too generic | add exact bytes (second LEA, frame, field offset); never wildcard them |
| crash right after `hook` | wrong detour length / hot-target race | inspect the crash address; try the analytics logger or a colder tick source |
| `INJECT: no instance` | vtable or class layout changed, or scan false negative | re-derive the vtable; confirm `FIXED_VTABLE` rejection; check the stack filter |
| injection queued but never executed | tick source not called often enough | choose a function on the game-thread hot path |
| Windows crash at startup after an update | unguarded fixed-address read | keep `plat_read_mem` fault-safe; confirm pattern-scan fallback |
| `OpenProcess failed (code 5)` | game elevated | run the injector from an elevated shell |
| `LoadLibraryA returned 0x0` | DLL missing/blocked | check `sky_hook.dll` path and `%APPDATA%\sky-badge\hook.log` |
| "No NFC backend available" | no reader / libnfc missing / generic CCID | use `--remote` with the phone relay or an ACR122-style reader |
