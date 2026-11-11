# Sky Badge Injection Tool

AI-assisted tool to trigger NFC badge effects in Sky: Children of the Light on PC
(Linux + Windows).

## How it works

```
NFC badge -> reader extracts NDEF URL -> TCP IPC -> hook in game process
          -> game main thread calls its own OnOpenedWithURL -> server verification -> badge effect
```

Function addresses are **fixed** for the current game build (0.35.2, build 426499),
validated by magic bytes at startup. If a game update breaks them, a pattern scan
falls back to the signatures compiled into the hook (`SIG_*` in `hook/common.c`).

## Project structure

```
├── runtime.py          # Shared runtime-path logic (mirrors hook-side resolution)
├── config.json         # Configuration (NFC backend, timeouts)
├── badge_inject.py     # Always-listening scan + auto-inject tool (cross-platform)
├── inject_dll.py       # Windows DLL injector
├── build.sh            # One-shot build for Linux .so + Windows .dll
├── requirements-build.txt  # PyInstaller toolchain for Windows CI
├── .github/workflows/windows-release.yml  # Windows exe + rolling release
├── hook/
│   ├── common.c/h      # Shared core (trampoline/fixed addresses/TCP IPC/injection)
│   ├── linux.c         # Linux platform layer (LD_PRELOAD)
│   └── windows.c       # Windows platform layer (DLL)
├── nfc/
│   ├── __init__.py     # NFC backend abstraction + auto-selection
│   ├── libnfc_cli.py   # libnfc backend (PN532/ACR122)
│   ├── pcsc_ctypes.py  # PC/SC backend (USB readers, cross-platform)
│   └── remote.py       # Remote backend (receives dumps from the Android app)
├── tools/
│   ├── verify_anchors.py   # Offline check of common.c anchors against Sky.exe
│   └── ghidra/             # Headless Ghidra scripts for re-deriving anchors
└── docs/
    ├── game-updates.md            # Playbook for game version updates
    └── game-update-experience.md  # Per-build experience log and checklist
```

`android/` is a separate Gradle project: the Sky Badge Relay app that turns a
phone's NFC into a badge reader (add-on feature, the local reader path is
untouched).

## Runtime directory

Runtime files (`ipc_port`, `hook.log`, `badge.mfd`) live in:
- `SKY_BADGE_DIR` env var, if set and writable
- otherwise `~/.config/sky-badge/` (Linux) / `%APPDATA%\sky-badge` (Windows)

**Proton caveat**: Steam's pressure-vessel bind-mounts the `LD_PRELOAD` directory
read-only inside the game sandbox, so pointing `SKY_BADGE_DIR` at the project dir
makes it unwritable for the hook. The hook detects this and silently falls back
to the config dir; the Python tools probe both locations, so everything keeps
working without configuration.

## Download (Windows, no Python required)

Every push to `main` rebuilds a rolling `latest` release with standalone Windows
binaries. Download the complete package:

<https://github.com/logosama/Sky_NFC_for_PC/releases/latest/download/SkyBadge-Windows.zip>

1. Start Sky and log in.
2. Run `SkyBadgeInjector.exe` (run as Administrator if Sky/Steam is elevated).
   It injects `sky_hook.dll`; keep both files next to each other.
3. Run `SkyBadgeInject.exe`, choose `1` (external reader) or `2` (phone remote),
   then scan badges. No Python installation is required.

`config.json` next to the exe overrides the bundled defaults (remote port/token,
cooldown, inject timeout). `SkyBadgeInject-onedir.zip` is an alternative folder
build with faster startup and fewer antivirus false positives. The onefile exe
is unsigned, so SmartScreen may require **More info -> Run anyway**. Only
download from this repository's Releases page.

## Usage (Linux)

1. Build: `./build.sh`
2. Steam launch options:
   ```
   LD_PRELOAD=/path/to/sky_hook.so %command%
   ```
3. Launch the game and log in.
4. Run `python3 badge_inject.py`, choose `1` (external reader) or `2` (phone
   remote), then tap badges - each scan is parsed and injected automatically.
   Ctrl+C stops the tool. Use `--reader` / `--remote` to skip the menu for
   background use, and `--once` for a single scan.

## Usage (Windows, from source)

For a no-Python install, use the standalone release above. To run from source:

1. Cross-compile on Linux: `./build.sh` (produces sky_hook.dll)
   or build on Windows: `x86_64-w64-mingw32-gcc -shared -O2 -o sky_hook.dll hook/common.c hook/windows.c -lws2_32`
2. After starting the game run (64-bit Python; use an elevated shell if the
   game runs elevated): `python3 inject_dll.py`
3. Run `python3 badge_inject.py`, choose `1` or `2`, then scan badges - injection
   is automatic; Ctrl+C stops it (`--remote` is recommended on Windows).

The Windows path is implemented and was verified on native Windows against Sky
0.35.1 (CL 423272): `ping` -> `hook OK` -> badge scan -> `INJECT done`,
including in-process instance discovery (`VirtualQuery`) and writable trampoline
pages. The same path is covered by a synthetic end-to-end Wine smoke test,
including the unmapped-anchor fallback. The most reliable reader path on
Windows is the phone relay (`python3 badge_inject.py --remote`), since the
PC/SC backend only supports ACR122-style readers.

## Supported NFC devices

| Backend | Devices | Platform |
|---------|---------|----------|
| libnfc | PN532 (UART/SPI), ACR122U and more | Linux |
| PC/SC | Readers supporting the ACR122-style `FF B0` read pseudo-APDU | Linux + Windows |
| remote | Android phone via Sky Badge Relay app | LAN (Linux + Windows) |

The PC/SC backend reads NTAG215 pages with the ACR122-style `FF B0` pseudo-APDU;
generic CCID readers that only accept standard APDUs are not supported.

Auto-detected by default (fix via `nfc.backend` in config.json: `auto`/`libnfc`/`pcsc`).

Optional dependencies: [pyscard](https://pypi.org/project/pyscard/) can replace the
built-in ctypes PC/SC backend if needed - the abstraction layer allows plugging in
any Python PC/SC implementation.

## Phone NFC relay (Android)

Use a phone's NFC as an additional badge reader:

```
Android app reads NTAG215 -> raw 540-byte dump -> HTTP POST /inject on the PC
                          -> remote backend -> same parse/inject pipeline
```

Each injection still requires a fresh physical scan (badge counter anti-replay),
so the app never caches dumps.

**PC side**:

1. Run `python3 badge_inject.py --remote` (starts the HTTP listener on port 8799,
   configurable via `remote.port` in config.json; optional auth via `remote.token`).
   Scans are auto-injected; no scan-window command is needed.
2. Allow inbound TCP 8799 through the firewall

**Phone side**:

1. Build: `cd android && ./gradlew assembleDebug`
2. Install: `adb install app/build/outputs/apk/debug/app-debug.apk`
   (or open `android/` in Android Studio)
3. Open Sky Badge Relay, enter the PC's LAN IP (port/token optional), Save
4. Hold the badge against the phone - a short vibration confirms success

Protocol: `POST /inject` with JSON `{"data_base64": "<540-byte NTAG dump>"}`,
optional `X-Auth-Token` header. The PC responds `200 {"status":"accepted"}`.

### Building the Android app (developer notes)

**Prerequisites**

- JDK 17+
- Android SDK with platform 34 (`sdk.dir` in `android/local.properties`, or
  `ANDROID_HOME`)
- Gradle 9.5 via the wrapper (`android/gradlew`) - no system Gradle needed

**Commands**

```bash
cd android
./gradlew assembleDebug        # debug APK -> app/build/outputs/apk/debug/
./gradlew assembleRelease      # unsigned release APK (no minify in this project)
adb install -r app/build/outputs/apk/debug/app-debug.apk
adb logcat -s SkyBadgeRelay    # app log (read errors, POST failures)
```

**Build setup notes**

- Toolchain: Kotlin 2.2.0 + AGP 8.13.0, pinned via the Gradle wrapper
  (`gradle/wrapper/gradle-wrapper.properties`). AGP 8.x is incompatible with
  Gradle 9.6+; do not bump the wrapper past 9.5 without upgrading AGP.
- `compileSdk 34 / minSdk 26` (NTAG215 reading needs `NfcA` + reader mode,
  both available since API 26; vibration uses `VibrationEffect`)
- If dependencies fail to download behind a proxy, put
  `systemProp.http(s).proxyHost/Port` in `~/.gradle/gradle.properties`
  (user-level; the wrapper honors it) rather than in the repo.
- `android/local.properties` is gitignored (machine-specific `sdk.dir`).

**App internals**

- `MainActivity.kt`: NFC reader mode (`FLAG_READER_NFC_A |
  SKIP_NDEF_CHECK | NO_PLATFORM_SOUNDS`) keeps scans in-app and suppresses the
  system browser; reads 135 NTAG215 pages via `NfcA.transceive` READ (0x30)
  with a 250 ms per-command timeout, then POSTs the base64 dump on a background
  executor; UI state runs on the main thread only.
- Anti-replay: 3 s debounce between accepted scans plus a busy flag, so a scan
  can never be sent twice.
- Feedback: status text (UID + page progress) and vibration - short buzz on
  success, double buzz on failure.

## Running continuously (background)

Remote mode is the lowest-overhead always-on option: the HTTP thread blocks on
`accept()` and the main loop blocks on the scan queue, so idle CPU is
essentially zero (measured `0.000%` over 20 s idle, roughly 27 MB RSS on the
development machine). The menu is only shown on a TTY; use a flag in the
background:

```bash
nohup python3 -u badge_inject.py --remote > badge-relay.log 2>&1 &
```

For an external reader, PC/SC polling is in-process and light. The libnfc
backend spawns `nfc-mfultralight` for each poll; idle cost is still modest
(measured `0.25%` CPU / ~21 MB RSS over 20 s with libnfc on the development
machine), but for long-running use prefer PC/SC or raise `nfc.poll_interval`
to 1-2 seconds. `nfc.cooldown` (default 3 s) suppresses duplicate scans, and
`nfc.inject_timeout` (default 10 s) bounds the wait for `INJECT done`. Use
`--once` for a single scan.

## Troubleshooting

- **Hook status**: the tool waits for the game hook and prints
  `OK hook connected (pong main=1 hook=0 fn=0x141172680 vt=0x141f0ed80 ticks=N)`.
  `fn=0x0` means the game image was not fully mapped yet or the game updated;
  check `hook.log`.
- **Logs**: `~/.config/sky-badge/hook.log` (or `SKY_BADGE_DIR/hook.log`); trimmed to its
  newest half once it passes 256 KB (every process that loads the hook appends to it, so
  it would otherwise grow across sessions). After a scan the tool prints just that
  injection's entries, matched by URL.
- **"NFC device busy"**: libnfc marks the serial port claimed via a termios bit
  that survives crashed readers. The libnfc backend clears it automatically and
  retries; if all else fails, replug the USB adapter.
- **Badge not detected**: keep the badge still on the reader for a few seconds;
  the reader polls continuously while the tool is running.
- **Remote listener won't start**: port 8799 is already in use (often an older
  `badge_inject.py --remote`); stop it or change `remote.port` in config.json.
- **Standalone build ignores config**: `config.json` must be next to
  `SkyBadgeInject.exe`; the copy bundled inside the exe is only a fallback.
- **SkyBadgeInjector access denied (code 5)**: run `SkyBadgeInjector.exe` as
  Administrator when Sky/Steam is elevated.

## Handling game updates

Fixed addresses are in `hook/common.c` (`FIXED_ONOPENURL`, `FIXED_HOOK_TARGET`,
`FIXED_VTABLE`), each guarded by magic bytes (`MAGIC_*`). A game update moves
them, so the hook must be re-anchored. The full procedure is in
[docs/game-updates.md](docs/game-updates.md); accumulated per-build findings,
the post-update checklist, and the entry template are in
[docs/game-update-experience.md](docs/game-update-experience.md). In short:

1. Confirm the new build in `Sky.log` (`Version: x.y.z.CL`).
2. Re-derive the three addresses and their `MAGIC_*`/`SIG_*` guards with the
   Ghidra helpers in `tools/ghidra/`. Keep the exact anchor bytes - do not loosen
   signatures to wildcards just to make them match.
3. Run `python3 tools/verify_anchors.py`; it must print `RESULT: ALL OK`
   (magic bytes, unique signature hits, consistent vtable) before anything else.
4. `./build.sh`, then verify in game: `ping` shows the new fn/vt, `hook` returns
   `hook OK`, and a badge scan logs `INJECT done`.

## Disclaimer

Use at your own risk.
