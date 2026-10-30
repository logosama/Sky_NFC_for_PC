/* windows.c - Windows platform layer (DLL injection)
 * Implements plat_* interfaces: direct pointer access (DLL runs inside game process), VirtualProtect, GetModuleHandle
 * Build: x86_64-w64-mingw32-gcc -shared -O2 -o sky_hook.dll common.c windows.c -lws2_32
 */
#include "common.h"
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>

/* ============ Platform Logging ============ */
void plat_log(const char *fmt, ...) {
    char path[512];
    badge_dir_path(path, sizeof(path), "hook.log");
    log_trim_if_needed(path);
    FILE *f = fopen(path, "a");
    if (!f) return;
    setvbuf(f, NULL, _IONBF, 0);
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    fprintf(f, "[%02d:%02d:%02d] %lu ", tm->tm_hour, tm->tm_min, tm->tm_sec,
            (unsigned long)GetCurrentProcessId());
    va_list ap;
    va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);
    fprintf(f, "\n");
    fclose(f);
}

/* ============ Memory read/write (DLL is inside game process) ============ */
/* ReadProcessMemory/WriteProcessMemory instead of plain memcpy: an invalid
 * address (stale fixed anchor after a game update, unmapped scan region) must
 * return an error, not raise an access violation and kill the game. Writes to
 * read-only code pages still require plat_protect_rwx first. */
int plat_read_mem(uint64_t addr, void *buf, size_t len) {
    SIZE_T got = 0;
    if (len == 0) return 0;
    if (!ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(uintptr_t)addr, buf, len, &got))
        return -1;
    return got == len ? 0 : -1;
}

int plat_write_mem(uint64_t addr, const void *buf, size_t len) {
    SIZE_T put = 0;
    if (len == 0) return 0;
    if (!WriteProcessMemory(GetCurrentProcess(), (LPVOID)(uintptr_t)addr, buf, len, &put))
        return -1;
    return put == len ? 0 : -1;
}

int plat_protect_rwx(uint64_t addr, size_t len) {
    DWORD old;
    return VirtualProtect((LPVOID)(uintptr_t)addr, len,
                          PAGE_EXECUTE_READWRITE, &old) ? 0 : -1;
}

/* ============ Sky.exe module info ============ */
int plat_get_module(module_info_t *mi) {
    memset(mi, 0, sizeof(*mi));
    HMODULE h = GetModuleHandleA("Sky.exe");
    if (!h) return -1;
    uint8_t *base = (uint8_t *)h;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return -1;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return -1;
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    mi->base = (uint64_t)base;
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        char name[9] = {0};
        memcpy(name, sec[i].Name, 8);
        uint64_t va = (uint64_t)base + sec[i].VirtualAddress;
        uint64_t vs = sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize : sec[i].SizeOfRawData;
        if (!strcmp(name, ".text")) { mi->text_start = va; mi->text_size = vs; }
        else if (!strcmp(name, ".rdata")) { mi->rdata_start = va; mi->rdata_size = vs; }
    }
    /* Total module size (max across sections) */
    mi->size = (uint64_t)nt->OptionalHeader.SizeOfImage;
    return (mi->text_start && mi->rdata_start) ? 0 : -1;
}

int plat_is_main_process(void) {
    return GetModuleHandleA("Sky.exe") != NULL;
}

/* ============ Host instance scan (VirtualQuery over the process) ============ */
/* Mirrors the Linux /proc/self/maps scan: walk every committed readable
 * region, look for a qword that points at a live object whose first qword is
 * the host vtable. */
static int region_readable(DWORD protect) {
    if (protect & (PAGE_GUARD | PAGE_NOACCESS)) return 0;
    switch (protect & 0xFF) {
    case PAGE_READONLY:
    case PAGE_READWRITE:
    case PAGE_WRITECOPY:
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
        return 1;
    default:
        return 0;
    }
}

uint64_t plat_find_instance(uint64_t vtable) {
    if (!vtable) return 0;
    const uint64_t chunk = 4 * 1024 * 1024;
    uint8_t *buf = malloc(chunk);
    if (!buf) return 0;

    /* A vtable address spilled on the current stack (and a pointer to that
     * stack slot) can look like a live object. The host instance is never
     * stack-allocated, so skip candidates on this thread's stack. */
    ULONG_PTR stack_lo = 0, stack_hi = 0;
    GetCurrentThreadStackLimits(&stack_lo, &stack_hi);

    uint64_t found = 0;
    uint64_t addr = 0;
    while (!found && addr < 0x7fffffffffffULL) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery((LPCVOID)(uintptr_t)addr, &mbi, sizeof(mbi)) != sizeof(mbi)) break;
        uint64_t base = (uint64_t)(uintptr_t)mbi.BaseAddress;
        uint64_t size = (uint64_t)mbi.RegionSize;
        if (size == 0) break;

        if (mbi.State == MEM_COMMIT && region_readable(mbi.Protect) &&
            size >= 0x1000 && size <= 300ULL * 1024 * 1024) {
            for (uint64_t o = 0; o < size && !found; o += chunk) {
                uint64_t rs = (o + chunk > size) ? (size - o) : chunk;
                SIZE_T got = 0;
                if (!ReadProcessMemory(GetCurrentProcess(),
                                       (LPCVOID)(uintptr_t)(base + o), buf, rs, &got) ||
                    got != rs)
                    break;
                for (uint64_t i = 0; i + 8 <= rs && !found; i += 8) {
                    uint64_t obj;
                    memcpy(&obj, buf + i, 8);
                    if (obj < 0x100000 || obj > 0x7fffffffffffULL) continue;
                    if (obj >= (uint64_t)stack_lo && obj < (uint64_t)stack_hi) continue;
                    uint64_t vt;
                    if (plat_read_mem(obj, &vt, sizeof(vt)) == 0 && vt == vtable)
                        found = obj;
                }
            }
        }

        uint64_t next = base + size;
        if (next <= addr) break;
        addr = next;
    }
    free(buf);
    return found;
}

/* ============ Entry point (DllMain) ============ */
/* DllMain runs under the loader lock: do not initialize or create worker
 * threads there (WSAStartup/fopen/CreateThread can deadlock). The init thread
 * waits for DllMain to return, then probes for the fully mapped Sky.exe. */
static DWORD WINAPI init_thread(LPVOID arg) {
    (void)arg;
    Sleep(200);  /* let DllMain return and the loader lock be released */
    for (int i = 0; i < 600; i++) {
        module_info_t mi;
        if (plat_is_main_process() && plat_get_module(&mi) == 0) {
            common_init();
            return 0;
        }
        Sleep(500);
    }
    plat_log("probe: timed out waiting for Sky.exe module");
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved) {
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinst);
        plat_log("loaded");
        if (!plat_is_main_process()) {
            plat_log("skip: not main process");
            return TRUE;
        }
        HANDLE h = CreateThread(NULL, 0, init_thread, NULL, 0, NULL);
        if (h) CloseHandle(h);
    }
    return TRUE;
}
