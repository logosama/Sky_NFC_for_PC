#!/bin/bash
# build.sh - Build Linux .so and Windows .dll in one go
set -e
cd "$(dirname "$0")"

echo "=== Building Linux sky_hook.so ==="
gcc -shared -fPIC -O2 -o sky_hook.so hook/common.c hook/linux.c
echo "  ✓ sky_hook.so"

echo "=== Cross-compiling Windows sky_hook.dll ==="
if command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then
    x86_64-w64-mingw32-gcc -shared -O2 -o sky_hook.dll hook/common.c hook/windows.c -lws2_32
    echo "  ✓ sky_hook.dll"
else
    echo "  x x86_64-w64-mingw32-gcc not installed, skipping Windows DLL"
    echo "    Install: sudo pacman -S mingw-w64-gcc"
fi

echo ""
echo "Done. Steam launch options (Linux):"
echo "  SKY_BADGE_DIR=$(pwd) LD_PRELOAD=$(pwd)/sky_hook.so %command%"
