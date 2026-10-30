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
    log_trim_if_needed(path);
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

/* ============ Sky.exe module info (/proc/self/maps) ============ */
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
    /* Pass 1: find .text (first executable segment at/after 0x140001000) */
    while (fgets(l, sizeof(l), f)) {
        uint64_t s, e; char p[8];
        if (sscanf(l, "%lx-%lx %7s", &s, &e, p) != 3) continue;
        if (s < 0x140000000ULL || s >= 0x146000000ULL) continue;
        if (mi->base == 0 || s < mi->base) mi->base = s;
        if (s + (e - s) > mi->size) mi->size = (s - mi->base) + (e - s);
        if (strchr(p, 'x') && s >= 0x140001000ULL && mi->text_size == 0) {
            mi->text_start = s; mi->text_size = e - s;
        }
    }
    /* Pass 2: find .rdata (first read-only non-exec segment after .text).
     * The PE header mapping at 0x140000000 must NOT qualify, so require
     * text_start to already be set and s to be past the .text region. */
    rewind(f);
    while (fgets(l, sizeof(l), f)) {
        uint64_t s, e; char p[8];
        if (sscanf(l, "%lx-%lx %7s", &s, &e, p) != 3) continue;
        if (s < 0x140000000ULL || s >= 0x146000000ULL) continue;
        if (mi->text_start && s >= mi->text_start + mi->text_size &&
            strchr(p, 'r') && !strchr(p, 'x') && !strchr(p, 'w') &&
            mi->rdata_size == 0) {
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

/* ============ Host instance scan (/proc/self/maps) ============ */
/* Find a live object whose first qword is the host vtable. Objects are found
 * by scanning memory by value, so this works across process restarts. */
uint64_t plat_find_instance(uint64_t vtable) {
    if (!vtable) return 0;
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return 0;
    uint64_t found = 0;
    char l[512];
    while (!found && fgets(l, sizeof(l), f)) {
        uint64_t s, e; char p[8];
        if (sscanf(l, "%lx-%lx %7s", &s, &e, p) != 3) continue;
        if (!strchr(p, 'r')) continue;
        if (e - s < 0x1000 || e - s > 300 * 1024 * 1024) continue;
        uint64_t cs = 4 * 1024 * 1024;
        uint8_t *buf = malloc(cs);
        if (!buf) continue;
        for (uint64_t o = 0; o < e - s && !found; o += cs) {
            uint64_t rs = (o + cs > e - s) ? (e - s - o) : cs;
            if (plat_read_mem(s + o, buf, rs) != 0) break;
            for (uint64_t i = 0; i + 8 <= rs && !found; i += 8) {
                uint64_t obj;
                memcpy(&obj, buf + i, 8);
                if (obj < 0x100000 || obj > 0x7fffffffffffULL) continue;
                uint64_t vt;
                if (plat_read_mem(obj, &vt, sizeof(vt)) != 0) continue;
                if (vt == vtable) found = obj;
            }
        }
        free(buf);
    }
    fclose(f);
    return found;
}

/* ============ Entry point (LD_PRELOAD constructor) ============ */
/* Under Proton, the .so is loaded into the wine process BEFORE Sky.exe's
 * PE image is mapped, so a constructor-time check would always fail.
 * Instead, spawn a detached thread that polls /proc/self/maps for the
 * Sky.exe mapping and then initializes. Non-game processes that load the
 * hook simply never find the mapping and give up after a timeout. */
#include <pthread.h>

static void *probe_thread(void *arg) {
    (void)arg;
    plat_log("probe: waiting for Sky.exe module");
    for (int i = 0; i < 600; i++) {
        /* Qualify: the game image must be FULLY mapped. Other wine processes
         * (e.g. the steam.exe DRM wrapper) may map only the PE header plus a
         * small slice of .text while verifying the executable - they must not
         * trigger initialization (or they would hijack the IPC port file). */
        module_info_t mi;
        if (plat_is_main_process() && plat_get_module(&mi) == 0 &&
            mi.text_size >= 0x100000 && mi.rdata_start > mi.text_start) {
            common_init();
            return NULL;
        }
        struct timespec ts = {0, 500 * 1000 * 1000}; /* 500 ms */
        nanosleep(&ts, NULL);
    }
    plat_log("probe: timed out waiting for Sky.exe module");
    return NULL;
}

__attribute__((constructor))
static void sky_hook_init(void) {
    plat_log("loaded");
    pthread_t t;
    if (pthread_create(&t, NULL, probe_thread, NULL) == 0)
        pthread_detach(t);
}
