# Sky Badge Injection Tool

AI-assisted tool to trigger NFC badge effects in Sky: Children of the Light on PC
(Linux + Windows).

## How it works

```
NFC badge -> reader extracts NDEF URL -> TCP IPC -> hook in game process
          -> game main thread calls its own OnOpenedWithURL -> server verification -> badge effect
```

Function addresses are **fixed** for the current game build (0.34.5, build 410941),
validated by magic bytes at startup. If a game update breaks them, a pattern scan
falls back to the signatures in `patterns.json`.

## Project structure

```
├── runtime.py          # Shared runtime-path logic (mirrors hook-side resolution)
├── config.json         # Configuration (NFC backend, timeouts)
├── patterns.json       # Signature library (fallback when fixed addresses break)
├── badge_inject.py     # Main tool (scan + inject, cross-platform)
├── inject_dll.py       # Windows DLL injector
├── build.sh            # One-shot build for Linux .so + Windows .dll
├── hook/
│   ├── common.c/h      # Shared core (trampoline/fixed addresses/TCP IPC/injection)
│   ├── linux.c         # Linux platform layer (LD_PRELOAD)
│   └── windows.c       # Windows platform layer (DLL)
└── nfc/
    ├── __init__.py     # NFC backend abstraction + auto-selection
    ├── libnfc_cli.py   # libnfc backend (PN532/ACR122)
    ├── pcsc_ctypes.py  # PC/SC backend (USB readers, cross-platform)
    └── remote.py       # Remote backend (receives dumps from the Android app)
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

## Usage (Linux)

1. Build: `./build.sh`
2. Steam launch options:
   ```
   LD_PRELOAD=/path/to/sky_hook.so %command%
   ```
3. Launch the game, log in, then run: `python3 badge_inject.py`
4. Enter `s` and place the badge on the reader

## Usage (Windows, untested)

1. Cross-compile on Linux: `./build.sh` (produces sky_hook.dll)
   or build on Windows: `x86_64-w64-mingw32-gcc -shared -O2 -o sky_hook.dll hook/common.c hook/windows.c -lws2_32`
2. After starting the game run: `python3 inject_dll.py`
3. `python3 badge_inject.py` -> `s` -> place the badge

The Windows path (DLL injection + inject_dll.py) has not been verified on real
hardware yet.

## Supported NFC devices

| Backend | Devices | Platform |
|---------|---------|----------|
| libnfc | PN532 (UART/SPI), ACR122U and more | Linux |
| PC/SC | Any CCID/PCSC reader | Linux + Windows |
| remote | Android phone via Sky Badge Relay app | LAN (Linux + Windows) |

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
   configurable via `remote.port` in config.json; optional auth via `remote.token`)
2. Enter `s` to open the scan window
3. Allow inbound TCP 8799 through the firewall

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

## Troubleshooting

- **Hook status**: run `python3 badge_inject.py` - the startup line shows
  `pong main=1 hook=0 fn=0x1411221e0 vt=0x141e8a390 ticks=N`.
  `fn=0x0` means the game image was not fully mapped yet or the game updated;
  check `hook.log`.
- **Logs**: `~/.config/sky-badge/hook.log` (or `SKY_BADGE_DIR/hook.log`).
- **"NFC device busy"**: libnfc marks the serial port claimed via a termios bit
  that survives crashed readers. The libnfc backend clears it automatically and
  retries; if all else fails, replug the USB adapter.
- **Badge not detected**: keep the badge still on the reader for a few seconds;
  the reader polls continuously during the scan window.

## Handling game updates

Fixed addresses are in `hook/common.c` (`FIXED_ONOPENURL`, `FIXED_HOOK_TARGET`,
`FIXED_VTABLE`), each guarded by magic bytes (`MAGIC_*`). On a major update:

1. Reverse-engineer the new addresses
2. Update the `FIXED_*` constants and the `MAGIC_*` bytes
3. Optionally update the signatures in `patterns.json` and `SIG_*` in
   `hook/common.c` (used as fallback)

## Disclaimer

Use at your own risk.
