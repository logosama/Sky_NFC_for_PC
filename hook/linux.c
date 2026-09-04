/* linux.c - Linux platform layer (LD_PRELOAD injection)
 * Implements plat_* interfaces: /proc/self/mem read/write, mprotect, /proc/self/maps module info
 */
#define _GNU_SOURCE
#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
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
    fprintf(f, "[%02d:%02d:%02d] %d ", tm->tm_hour, tm->tm_min, tm->tm_sec, getpid());
    va_list ap;
    va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);
    fprintf(f, "\n");
    fclose(f);
}

/* ============ Memory read/write (/proc/self/mem can write read-only mappings) ============ */
int plat_read_mem(uint64_t addr, void *buf, size_t len) {
    static int fd = -1;
    if (fd < 0) fd = open("/proc/self/mem", O_RDONLY);
    if (fd < 0) return -1;
    if (lseek(fd, (off_t)addr, SEEK_SET) != (off_t)addr) return -1;
    return (read(fd, buf, len) == (ssize_t)len) ? 0 : -1;
}

int plat_write_mem(uint64_t addr, const void *buf, size_t len) {
    static int fd = -1;
    if (fd < 0) fd = open("/proc/self/mem", O_RDWR);
    if (fd < 0) return -1;
    if (lseek(fd, (off_t)addr, SEEK_SET) != (off_t)addr) return -1;
    return (write(fd, buf, len) == (ssize_t)len) ? 0 : -1;
}

int plat_protect_rwx(uint64_t addr, size_t len) {
    uint64_t page = addr & ~0xFFFULL;
    return mprotect((void *)(uintptr_t)page, len, PROT_READ | PROT_WRITE | PROT_EXEC);
}

/* ============ Sky.exe module info（/proc/self/maps） ============ */
int plat_get_module(module_info_t *mi) {
    memset(mi, 0, sizeof(*mi));
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return -1;
    char l[512];
    int is_sky = 0;
    while (fgets(l, sizeof(l), f)) {
        uint64_t s, e; char p[8], n[256] = {0};
        sscanf(l, "%lx-%lx %7s %*x %*s %*s %255s", &s, &e, p, n);
        if (s == 0x140000000ULL && strstr(n, "Sky")) is_sky = 1;
    }
    if (!is_sky) { fclose(f); return -1; }
    rewind(f);
    /* .text and .rdata section addresses (Sky.exe PE layout, version independent) */
    while (fgets(l, sizeof(l), f)) {
        uint64_t s, e; char p[8];
        if (sscanf(l, "%lx-%lx %7s", &s, &e, p) != 3) continue;
        if (s < 0x140000000ULL || s >= 0x146000000ULL) continue;
        if (mi->base == 0 || s < mi->base) mi->base = s;
        if (s + (e - s) > mi->size) mi->size = (s - mi->base) + (e - s);
        if (strchr(p, 'x') && mi->text_size == 0) {
            /* first executable segment = .text */
            if (s >= 0x140001000ULL) { mi->text_start = s; mi->text_size = e - s; }
        }
        if (strchr(p, 'r') && !strchr(p, 'x') && !strchr(p, 'w') && s > mi->text_start && mi->rdata_size == 0) {
            /* first read-only segment after .text = .rdata */
            mi->rdata_start = s; mi->rdata_size = e - s;
        }
    }
    fclose(f);
    /* .text size limit (may be large; only readable portion is used during scan) */
    return (mi->text_start && mi->rdata_start) ? 0 : -1;
}

int plat_is_main_process(void) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return 0;
    char l[512];
    while (fgets(l, sizeof(l), f)) {
        uint64_t s;
        if (sscanf(l, "%lx-", &s) == 1 && s == 0x140000000ULL && strstr(l, "Sky")) { fclose(f); return 1; }
    }
    fclose(f);
    return 0;
}

/* ============ Entry point (LD_PRELOAD constructor) ============ */
__attribute__((constructor))
static void sky_hook_init(void) {
    plat_log("loaded");
    /* Initialize only in main process (actual Sky.exe); skip other processes that loaded the hook */
    if (!plat_is_main_process()) {
        plat_log("skip: not main process");
        return;
    }
    common_init();
}
