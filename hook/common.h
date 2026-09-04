/* common.h - Sky badge injection tool shared core (platform-independent)
 * Platform layer must implement plat_* interfaces (see hook/linux.c and hook/windows.c)
 */
#ifndef SKY_HOOK_COMMON_H
#define SKY_HOOK_COMMON_H

#include <stdint.h>
#include <stddef.h>

/* ============ Configuration constants ============ */
#define IPC_HOST "127.0.0.1"

/* ============ Platform abstraction interfaces (implemented by platform layer) ============ */
typedef struct {
    uint64_t base;
    uint64_t size;
    uint64_t text_start, text_size;    /* code section */
    uint64_t rdata_start, rdata_size;  /* read-only data section (contains vtables) */
} module_info_t;

int  plat_read_mem(uint64_t addr, void *buf, size_t len);
int  plat_write_mem(uint64_t addr, const void *buf, size_t len);
int  plat_protect_rwx(uint64_t addr, size_t len);   /* make page writable and executable */
int  plat_get_module(module_info_t *mi);            /* Sky.exe module info */
int  plat_is_main_process(void);
void plat_log(const char *fmt, ...);                /* platform logging */

/* ============ Pattern scan ============ */
/* wildcard 0xFF matches any byte */
uint64_t pattern_scan(const module_info_t *mi, const uint8_t *sig, size_t sig_len);

/* Derive vtable start from function address (walk backwards from .rdata entries referencing fn) */
uint64_t find_vtable(const module_info_t *mi, uint64_t fn_addr);

/* ============ Hook Core ============ */
int  hook_install(uint64_t target);
int  hook_uninstall(void);
int  hook_is_installed(void);

/* ============ Injection queue (set by IPC thread, executed on game thread) ============ */
extern volatile char *g_pending_url;
extern volatile int   g_pending;
extern uint64_t       g_onopenurl_fn;   /* OnOpenedWithURL function address (fixed addr, pattern-scan fallback) */
extern uint64_t       g_onurl_vt;       /* host class vtable */
extern uint64_t       g_onurl_this;     /* host class instance (auto-found cache) */
extern volatile long  g_tick_count;

void do_inject(void);   /* called on game main thread by trampoline */

/* ============ Main entry (called by platform layer) ============ */
int  common_init(void);  /* resolve addresses + IPC start, returns 0 on success */

/* Unified runtime directory: SKY_BADGE_DIR env var first (with write probe;
 * falls back if read-only, e.g. Proton sandbox), then user config dir
 * Linux: ~/.config/sky-badge/   Windows: %APPDATA%\sky-badge\ */
void badge_dir_path(char *buf, size_t len, const char *subpath);

#endif /* SKY_HOOK_COMMON_H */
