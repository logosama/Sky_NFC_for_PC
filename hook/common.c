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
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

/* ============ Runtime directory (unified cross-platform location) ============ */
void badge_dir_path(char *buf, size_t len, const char *subpath) {
    const char *dir = getenv("SKY_BADGE_DIR");  /* Priority: explicitly specified project directory */
    if (dir && *dir) {
        snprintf(buf, len, "%s/%s", dir, subpath);
        return;
    }
#ifdef _WIN32
    const char *appdata = getenv("APPDATA");
    if (appdata && *appdata) snprintf(buf, len, "%s\\sky-badge\\%s", appdata, subpath);
    else snprintf(buf, len, "sky-badge\\%s", subpath);
#else
    const char *xdg = getenv("XDG_CONFIG_HOME");
    const char *home = getenv("HOME");
    if (xdg && *xdg) snprintf(buf, len, "%s/sky-badge/%s", xdg, subpath);
    else if (home && *home) snprintf(buf, len, "%s/.config/sky-badge/%s", home, subpath);
    else snprintf(buf, len, "sky-badge/%s", subpath);
#endif
}

/* ============ Logging ============ */
static FILE *g_logfp;

void common_log(const char *fmt, ...) {
    if (!g_logfp) {
        char path[512];
        badge_dir_path(path, sizeof(path), "hook.log");
        g_logfp = fopen(path, "a");
        if (g_logfp) setvbuf(g_logfp, NULL, _IONBF, 0);
    }
    if (!g_logfp) return;
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    fprintf(g_logfp, "[%02d:%02d:%02d] ", tm->tm_hour, tm->tm_min, tm->tm_sec);
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

/* ============ Signature patterns (synced with patterns.json; 0xFF=wildcard) ============ */
static const uint8_t SIG_HOOK_ADDR[] = {
    0x55, 0x56, 0x48, 0x83, 0xEC, 0x28, 0x48, 0x8D, 0x6C, 0x24, 0x20,
    0x48, 0x89, 0xCE, 0x48, 0x8D, 0x15, 0xFF, 0xFF, 0xFF, 0xFF, 0xE8,
    0xFF, 0xFF, 0xFF, 0xFF
};
static const uint8_t SIG_ONOPENURL[] = {
    0x55, 0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54, 0x56, 0x57, 0x53,
    0x48, 0x81, 0xEC, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x8D, 0xAC, 0x24, 0x80,
    0x00, 0x00, 0x00, 0x44, 0x89, 0xC3, 0x48, 0x89
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

    /* Fill trampoline replay area (NOP first, then original bytes) */
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
    LOG("HOOK installed at 0x%lx", target);
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
        /* Auto-scan for vtable instance */
        module_info_t mi;
        if (plat_get_module(&mi) == 0) {
            char maps[512];
            /* Scan all readable memory regions for vtable instance (platform layer provides simplified scan) */
            /* Simplified: full scan only on Linux; Windows uses process memory APIs */
#ifndef _WIN32
            FILE *f = fopen("/proc/self/maps", "r");
            if (f) {
                char l[512];
                while (fgets(l, sizeof(l), f)) {
                    uint64_t s, e; char p[8];
                    if (sscanf(l, "%lx-%lx %7s", &s, &e, p) != 3) continue;
                    if (!strchr(p, 'r')) continue;
                    if (e - s < 0x1000 || e - s > 300 * 1024 * 1024) continue;
                    uint64_t cs = 4 * 1024 * 1024; uint8_t *buf = malloc(cs); if (!buf) continue;
                    for (uint64_t o = 0; o < e - s && !th; o += cs) {
                        uint64_t rs = (o + cs > e - s) ? (e - s - o) : cs;
                        if (plat_read_mem(s + o, buf, rs)) break;
                        for (uint64_t i = 0; i + 8 <= rs && !th; i += 8) {
                            uint64_t obj; memcpy(&obj, buf + i, 8);
                            if (obj < 0x100000 || obj > 0x7fffffffffffULL) continue;
                            uint64_t vt; if (plat_read_mem(obj, &vt, 8) != 0) continue;
                            if (vt == g_onurl_vt) { th = obj; g_onurl_this = obj; break; }
                        }
                    }
                    free(buf);
                }
                fclose(f);
            }
#endif
        }
        if (!th) { LOG("INJECT: no instance"); return; }
        LOG("INJECT: auto-found this=0x%lx", th);
    }

    if (!g_onopenurl_fn) { LOG("INJECT: no fn addr"); return; }
    LOG("INJECT: this=0x%lx url=%.60s", th, url);

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

    const char *dir = getenv("SKY_BADGE_DIR");
    char path[512];
    badge_dir_path(path, sizeof(path), "ipc_port");
    FILE *f = fopen(path, "w");
    if (f) { fprintf(f, "%d\n", port); fclose(f); }
    LOG("IPC listening on %s:%d (port file %s)", IPC_HOST, port, path);
    g_srv_sock = s;
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
        snprintf(r, sizeof(r), "pong main=%d hook=%d fn=0x%lx vt=0x%lx ticks=%ld",
                 plat_is_main_process(), g_hook_installed, g_onopenurl_fn, g_onurl_vt, g_tick_count);
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
static int spawn_thread(void) {
    HANDLE h = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ipc_thread, NULL, 0, NULL);
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
int common_init(void) {
    LOG("common init, main_process=%d", plat_is_main_process());

    module_info_t mi;
    if (plat_get_module(&mi) != 0) {
        LOG("no Sky.exe module");
        return -1;
    }
    LOG("module base=0x%lx text=0x%lx+0x%lx rdata=0x%lx+0x%lx",
        (unsigned long)mi.base, (unsigned long)mi.text_start, (unsigned long)mi.text_size,
        (unsigned long)mi.rdata_start, (unsigned long)mi.rdata_size);

    /* Pattern scan to locate functions */
    g_onopenurl_fn = pattern_scan(&mi, SIG_ONOPENURL, sizeof(SIG_ONOPENURL));
    g_hook_target = pattern_scan(&mi, SIG_HOOK_ADDR, sizeof(SIG_HOOK_ADDR));
    LOG("pattern scan: onopenurl=0x%lx hook_target=0x%lx",
        (unsigned long)g_onopenurl_fn, (unsigned long)g_hook_target);

    if (g_onopenurl_fn)
        g_onurl_vt = find_vtable(&mi, g_onopenurl_fn);
    LOG("vtable=0x%lx", (unsigned long)g_onurl_vt);

    if (!g_onopenurl_fn || !g_hook_target || !g_onurl_vt)
        LOG("WARNING: pattern scan incomplete - inject may not work (game updated?)");

    spawn_thread();
    return 0;
}
