/* sky_hook.c - Sky 徽章注入 hook
 * 通过 LD_PRELOAD 注入游戏进程，hook 消息分发器函数，
 * 在游戏主线程用游戏自己的 OnOpenedWithURL 处理 NFC 徽章 URL。
 *
 * 使用: Steam 启动选项 LD_PRELOAD=/path/sky_hook.so %command%
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <pthread.h>
#include <errno.h>
#include <time.h>

#define SOCK_PATH  "/tmp/sky_inject.sock"
#define LOG_PATH   "/tmp/sky_inject.log"
#define HOOK_ADDR  0x1418b0b10ULL   /* 消息分发器（游戏线程高频调用点） */
#define ONOPENURL  0x1411221e0ULL   /* Game::OnOpenedWithURL 处理函数 */
#define ONURL_VT   0x141e8a390ULL   /* OnOpenedWithURL 宿主类 vtable */

/* ============ 日志 ============ */
static FILE *_rf; static int _pid;
#define LOG(f, ...) do { \
    if (!_rf) { _rf = fopen(LOG_PATH, "a"); if (_rf) setvbuf(_rf, NULL, _IONBF, 0); } \
    if (_rf) { time_t _lt = time(NULL); struct tm *_tm = localtime(&_lt); \
        fprintf(_rf, "[%02d:%02d:%02d] %d " f "\n", _tm->tm_hour, _tm->tm_min, _tm->tm_sec, _pid, ##__VA_ARGS__); } \
} while (0)

/* ============ 内存读写（通过 /proc/self/mem，可写只读段） ============ */
static int rm(uint64_t a, void *b, size_t l) {
    static int f = -1; if (f < 0) f = open("/proc/self/mem", O_RDONLY);
    if (f < 0) return -1;
    if (lseek(f, (off_t)a, SEEK_SET) != (off_t)a) return -1;
    return (read(f, b, l) == (ssize_t)l) ? 0 : -1;
}
static int wm(uint64_t a, const void *b, size_t l) {
    static int f = -1; if (f < 0) f = open("/proc/self/mem", O_RDWR);
    if (f < 0) return -1;
    if (lseek(f, (off_t)a, SEEK_SET) != (off_t)a) return -1;
    return (write(f, b, l) == (ssize_t)l) ? 0 : -1;
}
/* 主进程检测（Sky.exe 基址 0x140000000 且路径含 Sky） */
static int chk(void) {
    FILE *f = fopen("/proc/self/maps", "r"); if (!f) return 0;
    char l[512];
    while (fgets(l, sizeof(l), f)) {
        uint64_t s;
        if (sscanf(l, "%lx-", &s) == 1 && s == 0x140000000ULL && strstr(l, "Sky")) { fclose(f); return 1; }
    }
    fclose(f); return 0;
}

/* ============ 注入状态 ============ */
uint64_t g_this = 0;                    /* trampoline 保存的 this */
uint64_t g_onurl_this = 0;              /* OnOpenedWithURL 实例（自动查找缓存） */
volatile char *g_pending_url = NULL;    /* socket 线程设置待注入 URL */
volatile int g_pending = 0;
volatile long g_tick_count = 0;         /* hook 调用计数 */

/* 注入执行——在游戏主线程被 trampoline 调用 */
void do_inject(void) {
    g_pending = 0;
    const char *url = (const char *)g_pending_url;
    g_pending_url = NULL;
    if (!url || !*url) return;

    uint64_t th = g_onurl_this;
    if (!th) {
        /* 自动扫描 vtable 0x141e8a390 的实例 */
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
                    if (rm(s + o, buf, rs)) break;
                    for (uint64_t i = 0; i + 8 <= rs && !th; i += 8) {
                        uint64_t obj; memcpy(&obj, buf + i, 8);
                        if (obj < 0x100000 || obj > 0x7fffffffffffULL) continue;
                        uint64_t vt; if (rm(obj, &vt, 8) != 0) continue;
                        if (vt == ONURL_VT) { th = obj; g_onurl_this = obj; break; }
                    }
                }
                free(buf);
            }
            fclose(f);
        }
        if (!th) { LOG("INJECT: no OnOpenedWithURL instance"); return; }
        LOG("INJECT: auto-found this=0x%lx", th);
    }

    LOG("INJECT: this=0x%lx url=%.60s", th, url);

    /* 调用 OnOpenedWithURL(this, url, fromNFC=1) — 游戏自己的函数 */
    register uint64_t r1 __asm__("rcx") = th;
    register uint64_t r2 __asm__("rdx") = (uint64_t)url;
    register uint64_t r3 __asm__("r8") = 1;
    __asm__ volatile("call *%0" ::"r"((uint64_t)ONOPENURL), "r"(r1), "r"(r2), "r"(r3) : "r9", "r10", "r11", "memory");
    LOG("INJECT done");
}

/* ============ Trampoline（保存寄存器→计数→注入→恢复→重放） ============ */
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
    "    mov g_this@GOTPCREL(%rip), %r11\n"
    "    mov %rcx, (%r11)\n"
    "    mov g_tick_count@GOTPCREL(%rip), %r11\n"
    "    incq (%r11)\n"
    "    mov g_pending@GOTPCREL(%rip), %r11\n"
    "    cmpl $0, (%r11)\n"
    "    je 1f\n"
    "    call do_inject@PLT\n"
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

/* ============ x86-64 指令长度解码（函数 prologue 常见指令） ============ */
static int insn_len(const uint8_t *p) {
    if (p[0] >= 0x50 && p[0] <= 0x57) return 1;              /* push reg */
    if (p[0] == 0x55) return 1;                              /* push rbp */
    if (p[0] == 0x5d || p[0] == 0xc3) return 1;              /* pop rbp / ret */
    if (p[0] == 0x41 && p[1] >= 0x50 && p[1] <= 0x57) return 2;  /* push r8-r15 */
    if (p[0] == 0x48 && p[1] == 0x81 && p[2] == 0xec) return 7;  /* sub rsp, imm32 */
    if (p[0] == 0x48 && p[1] == 0x83 && p[2] == 0xec) return 4;  /* sub rsp, imm8 */
    if (p[0] == 0x48 && p[1] == 0x83 && p[2] == 0xe4) return 4;  /* and rsp, imm8 */
    if (p[0] == 0x48 && (p[1] == 0x8d || p[1] == 0x89 || p[1] == 0x8b)) {
        uint8_t modrm = p[2];
        int sib = ((modrm & 0x07) == 0x04) ? 1 : 0;
        if ((modrm & 0xc7) == 0x05) return 7;                /* [rip+disp32] */
        if ((modrm & 0xc0) == 0x80) return 7 + sib;
        if ((modrm & 0xc0) == 0x40) return 4 + sib;
        return 3 + sib;
    }
    if (p[0] == 0xc7) {                                      /* mov [..], imm32 */
        uint8_t modrm = p[1];
        if ((modrm & 0xc0) == 0x80) return 11;
        if ((modrm & 0xc0) == 0x40) return 8;
        return 7;
    }
    if (p[0] == 0xe8 || p[0] == 0xe9) return 5;              /* call/jmp rel32 */
    if (p[0] == 0x0f && (p[1] == 0x84 || p[1] == 0x85)) return 6;  /* jz/jnz rel32 */
    if (p[0] == 0x74 || p[0] == 0x75 || p[0] == 0xeb) return 2;    /* jz/jnz/jmp rel8 */
    if (p[0] == 0x90 || p[0] == 0xcc) return 1;              /* nop / int3 */
    if (p[0] == 0x44 && p[1] == 0x89) return 3;
    if (p[0] == 0x85) {
        uint8_t modrm = p[1];
        if ((modrm & 0xc0) == 0x80) return 6;
        if ((modrm & 0xc0) == 0x40) return 3;
        return 2;
    }
    if (p[0] >= 0xb8 && p[0] <= 0xbf) return 5;              /* mov reg, imm32 */
    if (p[0] == 0x48 && p[1] == 0xc7) return 7;              /* mov r64, imm32 */
    if (p[0] == 0x31 || p[0] == 0x33) return 2;              /* xor reg, reg */
    if (p[0] == 0xff && p[1] == 0x15) return 6;              /* call [rip+disp32] */
    return 1;                                                /* 未知：保守 1 字节 */
}

/* 计算覆盖 >=min 字节的完整指令边界 */
static int calc_detour_len(uint64_t addr, int min_len) {
    uint8_t buf[40];
    if (rm(addr, buf, sizeof(buf)) != 0) return min_len;
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

/* ============ Hook 安装/卸载 ============ */
static uint8_t orig_bytes[20];
static int detour_len = 14;
static int hook_installed = 0;
static uint64_t hook_target = HOOK_ADDR;

static int install_hook(void) {
    if (hook_installed) return 1;
    if (!chk()) { LOG("not sky"); return 0; }

    detour_len = calc_detour_len(hook_target, 14);   /* 远跳转 14 字节 */
    LOG("detour_len=%d", detour_len);

    if (rm(hook_target, orig_bytes, detour_len) != 0) { LOG("read fail"); return 0; }
    LOG("orig: %02x%02x%02x%02x%02x...", orig_bytes[0], orig_bytes[1], orig_bytes[2], orig_bytes[3], orig_bytes[4]);

    /* 填充 trampoline（wm 通过 /proc/self/mem 写只读 .text 段） */
    {
        static const uint8_t nops[20] = {[0 ... 19] = 0x90};
        wm((uint64_t)&_sky_tramp_orig, nops, 20);
    }
    if (wm((uint64_t)&_sky_tramp_orig, orig_bytes, detour_len) != 0) { LOG("fill fail"); return 0; }
    uint64_t ret = hook_target + detour_len;
    if (wm((uint64_t)&_sky_tramp_ret + 2, &ret, 8) != 0) { LOG("ret fill fail"); return 0; }

    /* mprotect + 14 字节远跳转（FF 25 绝对地址，游戏代码与 hook.so 距离超 rel32 范围） */
    uint64_t page = hook_target & ~0xFFFULL;
    if (mprotect((void *)(uintptr_t)page, 4096, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        LOG("mprotect fail: %s", strerror(errno)); return 0;
    }
    uint8_t patch[20];
    memset(patch, 0x90, sizeof(patch));
    patch[0] = 0xFF; patch[1] = 0x25;   /* jmp [rip+0] */
    patch[2] = patch[3] = patch[4] = patch[5] = 0x00;
    uint64_t tramp_addr = (uint64_t)(uintptr_t)&_sky_tramp;
    memcpy(patch + 6, &tramp_addr, 8);
    if (wm(hook_target, patch, detour_len) != 0) { LOG("jmp fail"); return 0; }

    hook_installed = 1;
    LOG("HOOK installed at 0x%lx (len %d)", hook_target, detour_len);
    return 1;
}

static int unhook(void) {
    if (!hook_installed) return 0;
    uint64_t page = hook_target & ~0xFFFULL;
    mprotect((void *)(uintptr_t)page, 4096, PROT_READ | PROT_WRITE | PROT_EXEC);
    wm(hook_target, orig_bytes, detour_len);
    hook_installed = 0;
    g_pending = 0; g_pending_url = NULL;
    LOG("HOOK removed from 0x%lx", hook_target);
    return 1;
}

/* ============ Socket 控制 ============ */
static volatile int run = 1;
static char inject_buf[4096];

static void *st(void *a) {
    char p[256]; snprintf(p, sizeof(p), "%s.%d", SOCK_PATH, _pid);
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s < 0) return NULL;
    struct sockaddr_un ad = {.sun_family = AF_UNIX};
    strncpy(ad.sun_path, p, sizeof(ad.sun_path) - 1); unlink(p);
    if (bind(s, (struct sockaddr *)&ad, sizeof(ad)) < 0) { close(s); return NULL; }
    listen(s, 5);
    LOG("sock=%s", p);

    while (run) {
        fd_set fd; FD_ZERO(&fd); FD_SET(s, &fd);
        struct timeval tv = {1, 0};
        if (select(s + 1, &fd, NULL, NULL, &tv) <= 0) continue;
        int cl = accept(s, NULL, NULL); if (cl < 0) continue;
        char b[4096] = {0};
        ssize_t n = read(cl, b, 4095);
        if (n <= 0) { close(cl); continue; }
        while (n > 0 && (b[n - 1] == '\n' || b[n - 1] == '\r')) b[--n] = 0;
        LOG("CMD:%s", b);

        char r[512] = {0};
        if (!strcmp(b, "ping"))
            snprintf(r, sizeof(r), "pong main=%d hook=%d ticks=%ld", chk(), hook_installed, g_tick_count);
        else if (!strcmp(b, "hook")) { install_hook(); snprintf(r, sizeof(r), hook_installed ? "hook OK" : "hook FAIL"); }
        else if (!strcmp(b, "unhook")) { unhook(); snprintf(r, sizeof(r), "unhooked"); }
        else if (!strncmp(b, "inject ", 7)) {
            if (!hook_installed) snprintf(r, sizeof(r), "hook not installed");
            else if (g_pending) snprintf(r, sizeof(r), "busy");
            else {
                const char *url = b + 7;
                while (*url == ' ') url++;
                strncpy(inject_buf, url, sizeof(inject_buf) - 1);
                inject_buf[sizeof(inject_buf) - 1] = 0;
                g_pending_url = inject_buf;
                g_pending = 1;
                snprintf(r, sizeof(r), "queued (%.50s)", inject_buf);
            }
        }
        else snprintf(r, sizeof(r), "?");

        if (r[0]) write(cl, r, strlen(r));
        close(cl);
    }
    close(s); unlink(p);
    return NULL;
}

__attribute__((constructor))
static void init(void) {
    _pid = getpid();
    LOG("loaded");
    pthread_t t;
    pthread_create(&t, NULL, st, NULL);
    pthread_detach(t);
}
