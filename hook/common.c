/* common.c - Sky badge injection tool shared core (platform-independent)
 * Compiled together with platform layer (linux.c / windows.c) into a shared library.
 */
#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <sys/stat.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/stat.h>
#endif

/* ============ Runtime directory (unified cross-platform location) ============ */
/* NOTE: under Steam Proton, the directory referenced by LD_PRELOAD is
 * bind-mounted READ-ONLY inside the pressure-vessel sandbox, so a
 * SKY_BADGE_DIR pointing at the project dir becomes unwritable there.
 * Resolve once with a write probe and fall back to the user config dir. */
static char g_base_dir[512];
static int g_base_dir_set = 0;

static void resolve_base_dir(void) {
    if (g_base_dir_set) return;
    g_base_dir_set = 1;
    const char *dir = getenv("SKY_BADGE_DIR");
    if (dir && *dir) {
        char test[600];
        snprintf(test, sizeof(test), "%s/.wtest", dir);
        FILE *f = fopen(test, "w");
        if (f) {
            fclose(f);
            unlink(test);
            snprintf(g_base_dir, sizeof(g_base_dir), "%s", dir);
            return;
        }
    }
#ifdef _WIN32
    const char *appdata = getenv("APPDATA");
    if (appdata && *appdata) snprintf(g_base_dir, sizeof(g_base_dir), "%s\\sky-badge", appdata);
    else snprintf(g_base_dir, sizeof(g_base_dir), "sky-badge");
#else
    const char *xdg = getenv("XDG_CONFIG_HOME");
    const char *home = getenv("HOME");
    if (xdg && *xdg) snprintf(g_base_dir, sizeof(g_base_dir), "%s/sky-badge", xdg);
    else if (home && *home) snprintf(g_base_dir, sizeof(g_base_dir), "%s/.config/sky-badge", home);
    else snprintf(g_base_dir, sizeof(g_base_dir), "sky-badge");
#endif
#ifdef _WIN32
    CreateDirectoryA(g_base_dir, NULL);
#else
    mkdir(g_base_dir, 0755);
#endif
}

void badge_dir_path(char *buf, size_t len, const char *subpath) {
    resolve_base_dir();
    snprintf(buf, len, "%s/%s", g_base_dir, subpath);
}

/* ============ Logging ============ */
static FILE *g_logfp;
static char g_log_path[512];

/* Keep hook.log bounded. Every Wine/Proton child process inherits LD_PRELOAD and
 * appends to the same file, so it never stops growing on its own. Past
 * LOG_MAX_BYTES the oldest half is dropped, cutting at a line boundary to keep
 * the newest entries readable. Writers must open the file append-mode (O_APPEND)
 * so a rewrite behind a held stream cannot leave a sparse hole. */
void log_trim_if_needed(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0 || st.st_size <= LOG_MAX_BYTES) return;
    FILE *in = fopen(path, "rb");
    if (!in) return;
    if (fseek(in, (long)(st.st_size - LOG_KEEP_BYTES), SEEK_SET) != 0) { fclose(in); return; }
    char *buf = malloc(LOG_KEEP_BYTES + 1);
    if (!buf) { fclose(in); return; }
    size_t n = fread(buf, 1, LOG_KEEP_BYTES, in);
    fclose(in);
    size_t off = 0;
    while (off < n && buf[off] != '\n') off++;  /* drop the partial first line */
    if (off < n) off++;
    FILE *out = fopen(path, "wb");
    if (out) {
        fwrite(buf + off, 1, n - off, out);
        fclose(out);
    }
    free(buf);
}

void common_log(const char *fmt, ...) {
    if (!g_logfp) {
        badge_dir_path(g_log_path, sizeof(g_log_path), "hook.log");
        g_logfp = fopen(g_log_path, "a");
        if (g_logfp) setvbuf(g_logfp, NULL, _IONBF, 0);
    }
    if (!g_logfp) return;
    log_trim_if_needed(g_log_path);
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
#ifdef _WIN32
    fprintf(g_logfp, "[%02d:%02d:%02d] %lu ", tm->tm_hour, tm->tm_min, tm->tm_sec,
            (unsigned long)GetCurrentProcessId());
#else
    fprintf(g_logfp, "[%02d:%02d:%02d] %d ", tm->tm_hour, tm->tm_min, tm->tm_sec, getpid());
#endif
    va_list ap;
    va_start(ap, fmt);
    vfprintf(g_logfp, fmt, ap);
    va_end(ap);
    fprintf(g_logfp, "\n");
}
#define LOG(...) common_log(__VA_ARGS__)

/* ============ Global state ============ */
volatile char *g_pending_url = NULL;
volatile int   g_pending = 0;
uint64_t       g_onopenurl_fn = 0;
uint64_t       g_onurl_vt = 0;
uint64_t       g_onurl_this = 0;
uint64_t       g_this = 0;
volatile long  g_tick_count = 0;

static uint64_t g_hook_target = 0;
static uint8_t  g_orig_bytes[20];
static int      g_detour_len = 0;
static int      g_hook_installed = 0;
static char     g_inject_buf[4096];

/* ============ Signature patterns (0xFF = wildcard; fallback when the FIXED_* magic check fails) ============
 * The bytes kept exact in each signature are deliberate: dozens of sibling functions in this
 * build share byte-identical prologues, and only these anchors tell them apart. If a game
 * update forces a re-scan, re-derive the anchors rather than loosening them to wildcards.
 */

/* AnalyticsEvent name -> id mapper (the hook's game-thread tick source). The first LEA
 * displacement (25 FB 6E 00, pointing at the "null" sentinel) is kept exact to disambiguate
 * it from the other functions sharing this prologue.
 */
static const uint8_t SIG_HOOK_ADDR[] = {
    0x55, 0x56, 0x48, 0x83, 0xEC, 0x28, 0x48, 0x8D, 0x6C, 0x24, 0x20,
    0x48, 0x89, 0xCE, 0x48, 0x8D, 0x15, 0x25, 0xFB, 0x6E, 0x00, 0xE8,
    0xFF, 0xFF, 0xFF, 0xFF, 0x85, 0xC0, 0x0F, 0x84, 0xFF, 0xFF, 0xFF, 0xFF
};
/* Game::OnOpenedWithURL. The full 49-byte sequence is unique in .text for this build; the
 * stack frame size (0F 18 00 00 = 0x0F18) and class field offset (B8 11 00 00 = 0x11B8)
 * changed from the previous build and are part of the anchor.
 *
 * The host class vtable is not stored as a signature: find_vtable() derives it at runtime by
 * scanning .rdata for entries referencing this function and walking backwards to the start.
 */
static const uint8_t SIG_ONOPENURL[] = {
    0x55, 0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54, 0x56, 0x57, 0x53,
    0x48, 0x81, 0xEC, 0x18, 0x0F, 0x00, 0x00, 0x48, 0x8D, 0xAC, 0x24, 0x80,
    0x00, 0x00, 0x00, 0x44, 0x89, 0xC3, 0x48, 0x89, 0xD7, 0x48, 0x89, 0xCE,
    0x4C, 0x8D, 0xB1, 0xB8, 0x11, 0x00, 0x00, 0x48, 0x89, 0xD1, 0x4C, 0x89, 0xF2
};

/* ============ Pattern scan ============ */
uint64_t pattern_scan(const module_info_t *mi, const uint8_t *sig, size_t sig_len) {
    if (!mi || !mi->text_start || !mi->text_size) return 0;
    size_t chunk = 4 * 1024 * 1024;
    uint8_t *buf = malloc(chunk);
    if (!buf) return 0;

    for (uint64_t off = 0; off < mi->text_size; off += chunk - sig_len) {
        size_t n = chunk;
        if (off + n > mi->text_size) n = mi->text_size - off;
        if (plat_read_mem(mi->text_start + off, buf, n) != 0) break;

        for (size_t i = 0; i + sig_len <= n; i++) {
            int match = 1;
            for (size_t j = 0; j < sig_len; j++) {
                if (sig[j] != 0xFF && buf[i + j] != sig[j]) { match = 0; break; }
            }
            if (match) {
                free(buf);
                return mi->text_start + off + i;
            }
        }
        if (n < chunk) break;
    }
    free(buf);
    return 0;
}

/* Derive vtable from function address: scan .rdata for entries referencing fn, walk backwards for consecutive code pointers */
uint64_t find_vtable(const module_info_t *mi, uint64_t fn_addr) {
    if (!mi || !mi->rdata_start || !mi->rdata_size || !fn_addr) return 0;
    uint8_t *buf = malloc(mi->rdata_size);
    if (!buf) return 0;
    if (plat_read_mem(mi->rdata_start, buf, mi->rdata_size) != 0) {
        free(buf);
        return 0;
    }
    uint64_t result = 0;
    for (uint64_t i = 0; i + 8 <= mi->rdata_size; i += 8) {
        uint64_t val;
        memcpy(&val, buf + i, 8);
        if (val != fn_addr) continue;
        /* Entry found, walk backwards to vtable start (consecutive .text code pointers) */
        uint64_t vt = mi->rdata_start + i;
        while (vt >= mi->rdata_start + 8) {
            uint64_t prev;
            memcpy(&prev, buf + (vt - 8 - mi->rdata_start), 8);
            if (prev < mi->text_start || prev >= mi->text_start + mi->text_size) break;
            vt -= 8;
        }
        result = vt;
        break;
    }
    free(buf);
    return result;
}

/* ============ x86-64 instruction length decoder ============ */
static int insn_len(const uint8_t *p) {
    if (p[0] >= 0x50 && p[0] <= 0x57) return 1;
    if (p[0] == 0x55) return 1;
    if (p[0] == 0x5d || p[0] == 0xc3) return 1;
    if (p[0] == 0x41 && p[1] >= 0x50 && p[1] <= 0x57) return 2;
    if (p[0] == 0x48 && p[1] == 0x81 && p[2] == 0xec) return 7;
    if (p[0] == 0x48 && p[1] == 0x83 && p[2] == 0xec) return 4;
    if (p[0] == 0x48 && p[1] == 0x83 && p[2] == 0xe4) return 4;
    if (p[0] == 0x48 && (p[1] == 0x8d || p[1] == 0x89 || p[1] == 0x8b)) {
        uint8_t modrm = p[2];
        int sib = ((modrm & 0x07) == 0x04) ? 1 : 0;
        if ((modrm & 0xc7) == 0x05) return 7;
        if ((modrm & 0xc0) == 0x80) return 7 + sib;
        if ((modrm & 0xc0) == 0x40) return 4 + sib;
        return 3 + sib;
    }
    if (p[0] == 0xc7) {
        uint8_t modrm = p[1];
        if ((modrm & 0xc0) == 0x80) return 11;
        if ((modrm & 0xc0) == 0x40) return 8;
        return 7;
    }
    if (p[0] == 0xe8 || p[0] == 0xe9) return 5;
    if (p[0] == 0x0f && (p[1] == 0x84 || p[1] == 0x85)) return 6;
    if (p[0] == 0x74 || p[0] == 0x75 || p[0] == 0xeb) return 2;
    if (p[0] == 0x90 || p[0] == 0xcc) return 1;
    if (p[0] == 0x44 && p[1] == 0x89) return 3;
    if (p[0] == 0x85) {
        uint8_t modrm = p[1];
        if ((modrm & 0xc0) == 0x80) return 6;
        if ((modrm & 0xc0) == 0x40) return 3;
        return 2;
    }
    if (p[0] >= 0xb8 && p[0] <= 0xbf) return 5;
    if (p[0] == 0x48 && p[1] == 0xc7) return 7;
    if (p[0] == 0x31 || p[0] == 0x33) return 2;
    if (p[0] == 0xff && p[1] == 0x15) return 6;
    return 1;
}

static int calc_detour_len(uint64_t addr, int min_len) {
    uint8_t buf[40];
    if (plat_read_mem(addr, buf, sizeof(buf)) != 0) return min_len;
    int total = 0;
    while (total < min_len && total < 24) {
        int l = insn_len(buf + total);
        if (l < 1) l = 1;
        total += l;
    }
    if (total < min_len) total = min_len;
    if (total > 20) total = 20;
    return total;
}

/* ============ Trampoline ============ */
__asm__(
    ".global _sky_tramp\n"
    ".global _sky_tramp_orig\n"
    ".global _sky_tramp_ret\n"
    "_sky_tramp:\n"
    "    pushfq\n"
    "    push %rax\n    push %rbx\n    push %rcx\n    push %rdx\n    push %rsi\n"
    "    push %rdi\n    push %r8\n     push %r9\n     push %r10\n    push %r11\n"
    "    sub $0x100, %rsp\n"
    "    movaps %xmm0, 0x00(%rsp)\n    movaps %xmm1, 0x10(%rsp)\n"
    "    movaps %xmm2, 0x20(%rsp)\n    movaps %xmm3, 0x30(%rsp)\n"
    "    movaps %xmm4, 0x40(%rsp)\n    movaps %xmm5, 0x50(%rsp)\n"
    "    movaps %xmm6, 0x60(%rsp)\n    movaps %xmm7, 0x70(%rsp)\n"
    "    movaps %xmm8, 0x80(%rsp)\n    movaps %xmm9, 0x90(%rsp)\n"
    "    movaps %xmm10, 0xa0(%rsp)\n   movaps %xmm11, 0xb0(%rsp)\n"
    "    movaps %xmm12, 0xc0(%rsp)\n   movaps %xmm13, 0xd0(%rsp)\n"
    "    movaps %xmm14, 0xe0(%rsp)\n   movaps %xmm15, 0xf0(%rsp)\n"
#ifdef _WIN32
    "    mov %rcx, g_this(%rip)\n"
    "    incq g_tick_count(%rip)\n"
    "    cmpl $0, g_pending(%rip)\n"
#else
    "    mov g_this@GOTPCREL(%rip), %r11\n"
    "    mov %rcx, (%r11)\n"
    "    mov g_tick_count@GOTPCREL(%rip), %r11\n"
    "    incq (%r11)\n"
    "    mov g_pending@GOTPCREL(%rip), %r11\n"
    "    cmpl $0, (%r11)\n"
#endif
    "    je 1f\n"
#ifdef _WIN32
    "    call do_inject\n"
#else
    "    call do_inject@PLT\n"
#endif
    "1:\n"
    "    movaps 0x00(%rsp), %xmm0\n   movaps 0x10(%rsp), %xmm1\n"
    "    movaps 0x20(%rsp), %xmm2\n   movaps 0x30(%rsp), %xmm3\n"
    "    movaps 0x40(%rsp), %xmm4\n   movaps 0x50(%rsp), %xmm5\n"
    "    movaps 0x60(%rsp), %xmm6\n   movaps 0x70(%rsp), %xmm7\n"
    "    movaps 0x80(%rsp), %xmm8\n   movaps 0x90(%rsp), %xmm9\n"
    "    movaps 0xa0(%rsp), %xmm10\n  movaps 0xb0(%rsp), %xmm11\n"
    "    movaps 0xc0(%rsp), %xmm12\n  movaps 0xd0(%rsp), %xmm13\n"
    "    movaps 0xe0(%rsp), %xmm14\n  movaps 0xf0(%rsp), %xmm15\n"
    "    add $0x100, %rsp\n"
    "    pop %r11\n     pop %r10\n     pop %r9\n      pop %r8\n"
    "    pop %rdi\n     pop %rsi\n     pop %rdx\n     pop %rcx\n"
    "    pop %rbx\n     pop %rax\n"
    "    popfq\n"
    "_sky_tramp_orig:\n"
    ".fill 20, 1, 0x90\n"
    "_sky_tramp_ret:\n"
    "    movabs $0x4141414141414141, %r11\n"
    "    jmp *%r11\n"
);

extern void _sky_tramp(void);
extern void _sky_tramp_orig(void);
extern void _sky_tramp_ret(void);

/* ============ Hook install/uninstall ============ */
int hook_install(uint64_t target) {
    if (g_hook_installed) return 1;
    if (!target) return 0;

    g_hook_target = target;
    g_detour_len = calc_detour_len(target, 14);  /* far jump requires 14 bytes */
    LOG("install detour_len=%d", g_detour_len);

    if (plat_read_mem(target, g_orig_bytes, g_detour_len) != 0) {
        LOG("read fail"); return 0;
    }

    /* Fill trampoline replay area (NOP first, then original bytes). The
     * trampoline lives in our own read-only .text: Linux lets us write it
     * through /proc/self/mem, but on Windows the image section must be made
     * writable first or the memcpy faults. */
    if (plat_protect_rwx((uint64_t)(uintptr_t)&_sky_tramp_orig, 64) != 0) {
        LOG("tramp protect fail"); return 0;
    }
    static const uint8_t nops[20] = {[0 ... 19] = 0x90};
    plat_write_mem((uint64_t)(uintptr_t)&_sky_tramp_orig, nops, 20);
    if (plat_write_mem((uint64_t)(uintptr_t)&_sky_tramp_orig, g_orig_bytes, g_detour_len) != 0) {
        LOG("tramp fill fail"); return 0;
    }
    uint64_t ret = target + g_detour_len;
    if (plat_write_mem((uint64_t)(uintptr_t)&_sky_tramp_ret + 2, &ret, 8) != 0) {
        LOG("ret fill fail"); return 0;
    }

    /* Far jump FF 25 [rip+0] + absolute address (distance between game code and hook may exceed rel32 range) */
    if (plat_protect_rwx(target, 4096) != 0) {
        LOG("protect fail"); return 0;
    }
    uint8_t patch[20];
    memset(patch, 0x90, sizeof(patch));
    patch[0] = 0xFF; patch[1] = 0x25;
    patch[2] = patch[3] = patch[4] = patch[5] = 0;
    uint64_t tramp = (uint64_t)(uintptr_t)&_sky_tramp;
    memcpy(patch + 6, &tramp, 8);
    if (plat_write_mem(target, patch, g_detour_len) != 0) {
        LOG("jmp fail"); return 0;
    }

    g_hook_installed = 1;
    LOG("HOOK installed at 0x%llx", (unsigned long long)target);
    return 1;
}

int hook_uninstall(void) {
    if (!g_hook_installed) return 0;
    plat_protect_rwx(g_hook_target, 4096);
    plat_write_mem(g_hook_target, g_orig_bytes, g_detour_len);
    g_hook_installed = 0;
    g_pending = 0; g_pending_url = NULL;
    LOG("HOOK removed");
    return 1;
}

int hook_is_installed(void) { return g_hook_installed; }

/* ============ Injection execution (called on game main thread by trampoline) ============ */
void do_inject(void) {
    g_pending = 0;
    const char *url = (const char *)g_pending_url;
    g_pending_url = NULL;
    if (!url || !*url) return;

    uint64_t th = g_onurl_this;
    if (!th && g_onurl_vt) {
        /* Auto-scan readable process memory for a live object whose vptr is
         * the host vtable. The scan is platform-specific (see plat_find_instance). */
        th = plat_find_instance(g_onurl_vt);
        if (th) {
            g_onurl_this = th;
            LOG("INJECT: auto-found this=0x%llx", (unsigned long long)th);
        }
    }
    if (!th) { LOG("INJECT: no instance"); return; }

    if (!g_onopenurl_fn) { LOG("INJECT: no fn addr"); return; }
    LOG("INJECT: this=0x%llx url=%.60s", (unsigned long long)th, url);

    register uint64_t r1 __asm__("rcx") = th;
    register uint64_t r2 __asm__("rdx") = (uint64_t)url;
    register uint64_t r3 __asm__("r8") = 1;
    __asm__ volatile("call *%0" ::"r"(g_onopenurl_fn), "r"(r1), "r"(r2), "r"(r3) : "r9", "r10", "r11", "memory");
    LOG("INJECT done");
}

/* ============ TCP IPC (random port, cross-platform) ============ */
static int g_srv_sock = -1;
static void *ipc_thread(void *arg);  /* forward declaration */

static int ipc_start(uint16_t *out_port) {
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) { LOG("WSAStartup fail"); return -1; }
#endif
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) { LOG("socket fail"); return -1; }
    struct sockaddr_in ad;
    memset(&ad, 0, sizeof(ad));
    ad.sin_family = AF_INET;
    ad.sin_addr.s_addr = inet_addr(IPC_HOST);
    ad.sin_port = 0;  /* random port */
    if (bind(s, (struct sockaddr *)&ad, sizeof(ad)) < 0) {
        LOG("bind fail");
#ifdef _WIN32
        closesocket(s);
#else
        close(s);
#endif
        return -1;
    }
    if (listen(s, 5) < 0) {
#ifdef _WIN32
        closesocket(s);
#else
        close(s);
#endif
        return -1;
    }
    /* Get actual port and write to announcement file */
#ifdef _WIN32
    int alen = sizeof(ad);
#else
    socklen_t alen = sizeof(ad);
#endif
    getsockname(s, (struct sockaddr *)&ad, &alen);
    uint16_t port = ntohs(ad.sin_port);
    if (out_port) *out_port = port;

    char path[512];
    badge_dir_path(path, sizeof(path), "ipc_port");
    FILE *f = fopen(path, "w");
    if (f) { fprintf(f, "%d\n", port); fclose(f); }
    LOG("IPC listening on %s:%d (port file %s)", IPC_HOST, port, path);    g_srv_sock = s;
    return 0;
}

static void ipc_handle(int cl) {
    char b[4096] = {0};
    int n = recv(cl, b, 4095, 0);
    if (n <= 0) return;
    while (n > 0 && (b[n - 1] == '\n' || b[n - 1] == '\r')) b[--n] = 0;
    LOG("CMD:%s", b);

    char r[512] = {0};
    if (!strcmp(b, "ping"))
        snprintf(r, sizeof(r), "pong main=%d hook=%d fn=0x%llx vt=0x%llx ticks=%ld",
                 plat_is_main_process(), g_hook_installed,
                 (unsigned long long)g_onopenurl_fn, (unsigned long long)g_onurl_vt,
                 g_tick_count);
    else if (!strcmp(b, "hook")) {
        hook_install(g_hook_target);
        snprintf(r, sizeof(r), g_hook_installed ? "hook OK" : "hook FAIL");
    }
    else if (!strcmp(b, "unhook")) { hook_uninstall(); snprintf(r, sizeof(r), "unhooked"); }
    else if (!strncmp(b, "inject ", 7)) {
        if (!g_hook_installed) snprintf(r, sizeof(r), "hook not installed");
        else if (g_pending) snprintf(r, sizeof(r), "busy");
        else {
            const char *url = b + 7;
            while (*url == ' ') url++;
            strncpy(g_inject_buf, url, sizeof(g_inject_buf) - 1);
            g_inject_buf[sizeof(g_inject_buf) - 1] = 0;
            g_pending_url = g_inject_buf;
            g_pending = 1;
            snprintf(r, sizeof(r), "queued");
        }
    }
    else snprintf(r, sizeof(r), "?");

    if (r[0]) send(cl, r, (int)strlen(r), 0);
#ifdef _WIN32
    closesocket(cl);
#else
    close(cl);
#endif
}

static void *ipc_thread(void *arg) {
    (void)arg;
    uint16_t port = 0;
    if (ipc_start(&port) != 0) return NULL;
    while (1) {
        int cl = accept(g_srv_sock, NULL, NULL);
        if (cl < 0) continue;
        ipc_handle(cl);
    }
    return NULL;
}

/* ============ Threading (cross-platform) ============ */
#ifdef _WIN32
static DWORD WINAPI ipc_thread_entry(LPVOID arg) {
    (void)arg;
    ipc_thread(NULL);
    return 0;
}
static int spawn_thread(void) {
    HANDLE h = CreateThread(NULL, 0, ipc_thread_entry, NULL, 0, NULL);
    if (h) { CloseHandle(h); return 0; }
    return -1;
}
#else
#include <pthread.h>
static pthread_t g_ipc_tid;
static void *ipc_thread_entry(void *arg) { (void)arg; return ipc_thread(NULL); }
static int spawn_thread(void) {
    return pthread_create(&g_ipc_tid, NULL, ipc_thread_entry, NULL);
}
#endif

/* ============ Initialization (called by platform layer) ============ */
/* Known-good addresses for game build 0.35.2 (CL 426499). Fixed addresses
 * are used as primary resolution per project decision; if the bytes at those
 * addresses no longer match (game update), fall back to pattern scan. */
#define FIXED_ONOPENURL   0x141172680ULL
#define FIXED_HOOK_TARGET 0x141925e80ULL
#define FIXED_VTABLE      0x141f0ed80ULL

static const uint8_t MAGIC_ONOPENURL[] = {
    0x55, 0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54, 0x56, 0x57, 0x53,
    0x48, 0x81, 0xEC, 0x18, 0x0F, 0x00, 0x00
};
static const uint8_t MAGIC_HOOK_TARGET[] = {
    0x55, 0x56, 0x48, 0x83, 0xEC, 0x28, 0x48, 0x8D, 0x6C, 0x24, 0x20,
    0x48, 0x89, 0xCE, 0x48, 0x8D, 0x15
};

static int mem_matches(uint64_t addr, const uint8_t *magic, size_t len) {
    uint8_t buf[32];
    if (len > sizeof(buf) || plat_read_mem(addr, buf, len) != 0) return 0;
    return memcmp(buf, magic, len) == 0;
}

/* A vtable's first entry must point into .text. This rejects a stale FIXED_VTABLE
 * instead of reporting an address that cannot be a class vptr. */
static int vtable_ptr_in_text(const module_info_t *mi, uint64_t vt) {
    uint64_t first = 0;
    if (!vt || plat_read_mem(vt, &first, sizeof(first)) != 0) return 0;
    return first >= mi->text_start && first < mi->text_start + mi->text_size;
}

int common_init(void) {
    LOG("common init, main_process=%d", plat_is_main_process());

    module_info_t mi;
    if (plat_get_module(&mi) != 0) {
        LOG("no Sky.exe module");
        return -1;
    }
    LOG("module base=0x%llx text=0x%llx+0x%llx rdata=0x%llx+0x%llx",
        (unsigned long long)mi.base, (unsigned long long)mi.text_start,
        (unsigned long long)mi.text_size, (unsigned long long)mi.rdata_start,
        (unsigned long long)mi.rdata_size);

    /* Fixed addresses first (fast and reliable), pattern scan as fallback */
    g_onopenurl_fn = FIXED_ONOPENURL;
    if (!mem_matches(FIXED_ONOPENURL, MAGIC_ONOPENURL, sizeof(MAGIC_ONOPENURL))) {
        LOG("fixed onopenurl 0x%llx mismatch - falling back to pattern scan",
            (unsigned long long)FIXED_ONOPENURL);
        g_onopenurl_fn = pattern_scan(&mi, SIG_ONOPENURL, sizeof(SIG_ONOPENURL));
    }
    g_hook_target = FIXED_HOOK_TARGET;
    if (!mem_matches(FIXED_HOOK_TARGET, MAGIC_HOOK_TARGET, sizeof(MAGIC_HOOK_TARGET))) {
        LOG("fixed hook target 0x%llx mismatch - falling back to pattern scan",
            (unsigned long long)FIXED_HOOK_TARGET);
        g_hook_target = pattern_scan(&mi, SIG_HOOK_ADDR, sizeof(SIG_HOOK_ADDR));
    }
    LOG("resolve: onopenurl=0x%llx hook_target=0x%llx",
        (unsigned long long)g_onopenurl_fn, (unsigned long long)g_hook_target);

    if (g_onopenurl_fn)
        g_onurl_vt = find_vtable(&mi, g_onopenurl_fn);
    if (!g_onurl_vt && vtable_ptr_in_text(&mi, FIXED_VTABLE))
        g_onurl_vt = FIXED_VTABLE;
    LOG("vtable=0x%llx", (unsigned long long)g_onurl_vt);

    if (!g_onopenurl_fn || !g_hook_target || !g_onurl_vt)
        LOG("WARNING: resolve incomplete - inject may not work (game updated?)");

    spawn_thread();
    return 0;
}
