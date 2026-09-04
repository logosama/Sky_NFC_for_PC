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

/* ============ Memory read/write (DLL is inside game process, direct pointers) ============ */
int plat_read_mem(uint64_t addr, void *buf, size_t len) {
    memcpy(buf, (void *)(uintptr_t)addr, len);
    return 0;
}

int plat_write_mem(uint64_t addr, const void *buf, size_t len) {
    memcpy((void *)(uintptr_t)addr, buf, len);
    return 0;
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

/* ============ Entry point (DllMain) ============ */
BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved) {
    (void)hinst; (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        plat_log("loaded");
        if (!plat_is_main_process()) {
            plat_log("skip: not main process");
            return TRUE;
        }
        common_init();
    }
    return TRUE;
}
