# Handling Sky game updates

The hook depends on three addresses inside `Sky.exe` that are fixed per game
build, plus magic bytes and fallback signatures that identify them. A game update
moves those addresses, so the hook must be re-anchored after every update.

This document is the procedure used for 0.35.1 (CL 423272) and the reference for
future builds. The current values live in `hook/common.c`; do not trust the
values quoted here after a new update.

`Sky.exe` is the same Windows PE that Proton runs on Linux, so the anchors and
the verification workflow are host-OS independent; a native Windows install can
run the same Ghidra scripts (`analyzeHeadless.bat`) and
`python3 tools/verify_anchors.py`.

For accumulated per-build findings, the post-update checklist, and the entry
template, see
[game-update-experience.md](game-update-experience.md).

## Symptoms

- `python3 badge_inject.py` reports `fn=0x0` and `hook` returns `hook FAIL`.
- `~/.config/sky-badge/hook.log` contains lines like:

  ```
  fixed onopenurl 0x... mismatch - falling back to pattern scan
  fixed hook target 0x... mismatch - falling back to pattern scan
  resolve: onopenurl=0x0 hook_target=0x0
  WARNING: resolve incomplete - inject may not work (game updated?)
  ```

## 1. Confirm the new build

Read the version from the game log next to `Sky.exe`:

```bash
grep -m1 '^Version:' \
  "$HOME/.local/share/Steam/steamapps/common/Sky Children of the Light/Sky.log"
# Version: 0.35.1.423272
```

Record the version and build in the comment above the `FIXED_*` defines.

## 2. Re-derive the anchors

Use the headless Ghidra helpers in `tools/ghidra/` (see
[`tools/ghidra/README.md`](../tools/ghidra/README.md) for setup and commands).
They assume the executable has already been imported and analyzed once.

### 2.1 `FIXED_ONOPENURL` (Game::OnOpenedWithURL)

The function still contains distinctive log strings. Search for them:

```bash
analyzeHeadless /tmp/sky-ghidra SkyBadge -process Sky.exe -noanalysis \
    -scriptPath tools/ghidra \
    -postScript FindStringXrefs.java /tmp/sky-out "Game::OnOpenedWithURL"
```

The candidate function:

- references `Game::OnOpenedWithURL ...` log strings;
- takes `(this, url, fromNFC)` (`rcx`, `rdx`, `r8`);
- accesses a class field at `this + 0x11B8` on 0.35.1 (was `+0x11A0` on 0.34.5);
- has a large stack frame (0x0F18 on 0.35.1, 0x998 on 0.34.5);
- appears in its class vtable.

Confirm it with `DumpFunctions.java` on the candidate address, then build the
new anchors:

- `MAGIC_ONOPENURL`: first 19 bytes of the function (through `sub rsp, imm32`);
- `SIG_ONOPENURL`: the first 49 bytes; the whole sequence must be unique in
  `.text`. On 0.35.1 the frame size and field offset alone are enough to make it
  unique.

### 2.2 `FIXED_HOOK_TARGET` (AnalyticsEvent name→ID mapper)

The hook is installed at a function that the game calls frequently on the game
thread; its only job is to run `do_inject` when a URL is queued.

On 0.35.1 this is the AnalyticsEvent name→ID mapper. Locate it from the
analytics logger's error string:

```bash
analyzeHeadless /tmp/sky-ghidra SkyBadge -process Sky.exe -noanalysis \
    -scriptPath tools/ghidra \
    -postScript FindStringXrefs.java /tmp/sky-out \
    "No name for AnalyticsEvent enum: "
```

The containing function is the analytics logger. Decompile it and look for a
call that validates an event name; that callee is the mapper. Its body is a long
chain:

```c
strcmp(name, "null");            /* sentinel compared first */
strcmp(name, "app_open");
strcmp(name, "level_loaded");
...
```

On 0.35.1 the mapper is `0x141925c10` (10,119 bytes, 308 event names) and is
called from the logger with 276 call sites. Cross-checks that this is still the
same function family:

- the first `je` after the `"null"` comparison jumps to the null-case handler;
  its relative offset grows with the event list. It was 0x1B59 in 0.34.5 and
  0x1B9E in 0.35.1 - exactly the growth from one `player_shout` entry to the
  three `short_shout` / `medium_shout` / `deep_shout` entries;
- the prologue is stable: `55 56 48 83 EC 28 48 8D 6C 24 20 48 89 CE 48 8D 15`.

Build `SIG_HOOK_ADDR` as the 34-byte prologue through the first
`test eax,eax; je`, keeping the first LEA displacement exact and wildcarding
only the `call` and `je` rel32 fields. On 0.35.1 the first LEA points at the
`"null"` string.

If this mapper stops being a reliable tick source, alternatives are:

- the analytics logger itself (one call per event, many call sites);
- a low-frequency, user-triggered function (safer to install, but injection
  latency depends on the user action).

### 2.3 `FIXED_VTABLE`

The host class vtable is derived from `OnOpenedWithURL` rather than stored as a
signature:

1. search `.rdata` for an 8-byte pointer equal to `OnOpenedWithURL`;
2. walk backwards while the preceding 8-byte value is a `.text` pointer; the
   first non-code value marks the table start;
3. confirm the table is real by finding constructors that store it:
   `lea rax, [vtable]; mov [rsi], rax`.

At runtime `find_vtable()` performs the same walk and is authoritative.
`FIXED_VTABLE` is only a fallback, and `common_init()` now rejects it unless its
first entry points into `.text`.

## 3. Update `hook/common.c`

- `FIXED_ONOPENURL`, `FIXED_HOOK_TARGET`, `FIXED_VTABLE`;
- `MAGIC_ONOPENURL`, `MAGIC_HOOK_TARGET`;
- `SIG_ONOPENURL`, `SIG_HOOK_ADDR`;
- the comments: build number, frame size / field offset, and which anchor bytes
  are kept exact.

Signature rules:

- Keep the exact anchor bytes (first LEA displacement, frame size, field
  offsets, distinctive instructions).
- Wildcard only rel32 call/branch targets.
- Never loosen an anchor to wildcards just to make it match; if a signature is
  not unique, add more exact bytes instead.

Also update the build number and the `ping` example in `README.md`.

## 4. Verify offline (required)

```bash
python3 tools/verify_anchors.py
```

The tool parses the constants directly out of `hook/common.c` and checks them
against the installed `Sky.exe`:

- magic bytes at both fixed addresses;
- exactly one hit for `SIG_ONOPENURL` at `FIXED_ONOPENURL`;
- exactly one hit for `SIG_HOOK_ADDR` at `FIXED_HOOK_TARGET`;
- `FIXED_VTABLE` starts with a `.text` pointer and matches the vtable derived
  from the `.rdata` pointer to `FIXED_ONOPENURL`.

It prints `RESULT: ALL OK` and exits 0 only if everything passes. Pass
`--exe PATH` for a non-standard install, `--source PATH` to check another copy
of `common.c`.

Do not build or launch the game until this passes: a wrong signature that still
matches something else can corrupt the game process.

## 5. Build and verify in game

```bash
./build.sh
```

Launch with the rebuilt library:

```
LD_PRELOAD=/path/to/sky_hook.so %command%
```

After logging in:

1. `python3 badge_inject.py` - the startup line must show
   `main=1 hook=0 fn=<new address> vt=<new vtable> ticks=N`;
2. enter `h` (or `hook`) - expect `hook OK`;
3. scan a badge - the log must contain `INJECT done`, and `ticks` must keep
   increasing between pings.

## 6. When it goes wrong

| Symptom | Likely cause | Action |
|---|---|---|
| `verify_anchors.py` reports 0 hits | signature derived from the wrong build/function | re-check the candidate with `DumpFunctions.java` |
| multiple signature hits | anchor too generic | add exact bytes (second LEA, frame, field offset); never wildcard them |
| `fn=0x0` in ping | game image not mapped yet or resolution failed | wait for login; check `hook.log` |
| crash right after `hook` | installing on a hot function raced with its execution, or the trampoline/detour length is wrong | try the analytics logger or a low-frequency tick source; check the crash address |
| `INJECT: no instance` in `hook.log` | `FIXED_VTABLE` is wrong or the class layout changed | re-derive the vtable and the field offsets |
| injection queued but not executed | the tick source is not called often enough | choose a function on the game-thread hot path |

## Case study: 0.34.5 (410941) → 0.35.1 (423272)

| Anchor | 0.34.5 | 0.35.1 |
|---|---|---|
| `FIXED_ONOPENURL` | 0x1411221e0 | 0x141172670 |
| `FIXED_HOOK_TARGET` | 0x1418b0b10 | 0x141925c10 |
| `FIXED_VTABLE` | 0x141e8a390 | 0x141f0ed80 |
| OnOpenedWithURL frame / field | 0x998 / 0x11A0 | 0x0F18 / 0x11B8 |
| first `je` offset in mapper | 0x1B59 | 0x1B9E |

The mapper's event list gained the three shout variants, which explains the
0x45-byte growth of the prefix before the null-case handler. `player_shout` no
longer exists in 0.35.1, so anchoring only on that string would fail - use the
structural/analytics anchors above.
