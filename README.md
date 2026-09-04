# Sky Badge Injection Tool

AI-assisted tool to trigger NFC badge effects in Sky: Children of the Light on PC (Linux + Windows).

## How it works

```
NFC badge -> reader extracts NDEF URL -> TCP IPC -> hook in game process
          -> game main thread calls its own OnOpenedWithURL -> server verification -> badge effect
```

Pattern scanning auto-locates game functions (survives minor game updates), no hardcoded addresses.

## Project structure

```
├── config.json         # Configuration (NFC backend, timeouts, paths)
├── patterns.json       # Function signature library (append on major game updates)
├── badge_inject.py     # Main tool (scan + inject, cross-platform)
├── skyctl.py           # Injection control client
├── injector.py         # Windows DLL injector
├── build.sh            # One-shot build for Linux .so + Windows .dll
├── hook/
│   ├── common.c/h      # Shared core (trampoline/pattern scan/TCP IPC/injection)
│   ├── linux.c         # Linux platform layer (LD_PRELOAD)
│   └── windows.c       # Windows platform layer (DLL)
└── nfc/
    ├── __init__.py     # NFC backend abstraction + auto-selection
    ├── libnfc_cli.py   # libnfc backend (PN532/ACR122)
    └── pcsc_ctypes.py  # PC/SC backend (USB readers, cross-platform)
```

## Usage (Linux)

1. Build: `./build.sh`
2. Steam launch options:
   ```
   LD_PRELOAD=/path/to/sky_hook.so %command%
   ```
   (Optional: add `SKY_BADGE_DIR=/path/to/project` to set the runtime directory;
   defaults to `~/.config/sky-badge/`)
3. Launch the game, log in, then run: `python3 badge_inject.py`
4. Enter `s` and place the badge on the reader

## Usage (Windows)

1. Cross-compile on Linux: `./build.sh` (produces sky_hook.dll)
   or build on Windows: `x86_64-w64-mingw32-gcc -shared -O2 -o sky_hook.dll hook/common.c hook/windows.c -lws2_32`
2. After starting the game run: `python3 injector.py`
3. `python3 badge_inject.py` -> `s` -> place the badge

## Supported NFC devices

| Backend | Devices | Platform |
|---------|---------|----------|
| libnfc | PN532 (UART/SPI), ACR122U and more | Linux |
| PC/SC | Any CCID/PCSC reader | Linux + Windows |

Auto-detected by default (fix via `nfc.backend` in config.json: `auto`/`libnfc`/`pcsc`).

Optional dependencies: [pyscard](https://pypi.org/project/pyscard/) can replace the
built-in ctypes PC/SC backend if needed - the abstraction layer allows plugging in
any Python PC/SC implementation.

## Handling game updates

When a major game update changes function prologues:
1. Reverse-engineer the new function addresses
2. Extract the first 16-32 bytes of each function (use `??` wildcards for
   RIP-relative offsets and immediates)
3. Append to `patterns.json` and sync the signature arrays in `hook/common.c`

## Disclaimer

Use at your own risk.
