/*
 * hook_engine.h - ARM64 Inline Hook Engine
 *
 * Provides inline hooking functionality for ARM64 Android.
 * Uses MOVZ/MOVK + BR X16 jump sequences (up to 20 bytes).
 */

#ifndef HOOK_ENGINE_H
#define HOOK_ENGINE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Error codes */
#define HOOK_OK                     0
#define HOOK_ERROR_NOT_INITIALIZED  -1
#define HOOK_ERROR_INVALID_PARAM    -2
#define HOOK_ERROR_ALREADY_HOOKED   -3
#define HOOK_ERROR_ALLOC_FAILED     -4
#define HOOK_ERROR_MPROTECT_FAILED  -5
#define HOOK_ERROR_NOT_FOUND        -6
#define HOOK_ERROR_BUFFER_TOO_SMALL -7
#define HOOK_ERROR_WXSHADOW_FAILED  -8

/* Hook context - contains all ARM64 registers */
typedef struct {
    uint64_t x[31];     /* x0-x30 */
    uint64_t sp;        /* Stack pointer */
    uint64_t pc;        /* Program counter (original) */
    uint64_t nzcv;      /* Condition flags */
} HookContext;

/* Callback function types */
typedef void (*HookCallback)(HookContext* ctx, void* user_data);

/* Hook entry structure */
typedef struct HookEntry {
    void* target;                   /* Original function address */
    void* trampoline;               /* Trampoline to call original */
    void* replacement;              /* Replacement function (for replace mode) */
    HookCallback on_enter;          /* Enter callback (for attach mode) */
    HookCallback on_leave;          /* Leave callback (for attach mode) */
    void* user_data;                /* User data for callbacks */
    uint8_t original_bytes[24];     /* Saved original bytes (up to 20 needed) */
    size_t original_size;           /* Number of bytes saved */
    int stealth;                    /* 1 if installed via wxshadow stealth mode */
    struct HookEntry* next;         /* Next entry in list */
} HookEntry;

/* Global hook engine state */
typedef struct {
    void* exec_mem;                 /* Executable memory pool */
    size_t exec_mem_size;           /* Total pool size */
    size_t exec_mem_used;           /* Used bytes */
    HookEntry* hooks;               /* Linked list of hooks */
    int initialized;                /* Initialization flag */
    int stealth_mode;               /* 1 to use wxshadow for new hooks */
} HookEngine;

/*
 * Initialize the hook engine
 *
 * @param exec_mem      Pointer to executable memory region (RWX)
 * @param size          Size of the memory region
 * @return              0 on success, -1 on failure
 */
int hook_engine_init(void* exec_mem, size_t size);

/*
 * Install a simple replacement hook
 *
 * @param target        Address to hook
 * @param replacement   Replacement function address
 * @return              Pointer to trampoline (to call original), NULL on failure
 */
void* hook_install(void* target, void* replacement);

/*
 * Install a Frida-style hook with callbacks
 *
 * @param target        Address to hook
 * @param on_enter      Callback called before the function (can be NULL)
 * @param on_leave      Callback called after the function (can be NULL)
 * @param user_data     User data passed to callbacks
 * @return              0 on success, -1 on failure
 */
int hook_attach(void* target, HookCallback on_enter, HookCallback on_leave, void* user_data);

/*
 * Remove a hook
 *
 * @param target        Address that was hooked
 * @return              0 on success, -1 on failure
 */
int hook_remove(void* target);

/*
 * Get the trampoline for a hooked function
 *
 * @param target        Original function address
 * @return              Trampoline address, NULL if not found
 */
void* hook_get_trampoline(void* target);

/*
 * Cleanup and free all hooks
 */
void hook_engine_cleanup(void);

/* Internal functions - exposed for advanced use */

/*
 * Allocate memory from the executable pool
 *
 * @param size          Number of bytes to allocate
 * @return              Pointer to allocated memory, NULL on failure
 */
void* hook_alloc(size_t size);

/*
 * Relocate ARM64 instruction(s) from src to dst
 *
 * @param src           Source address
 * @param dst           Destination address
 * @param count         Number of instructions to relocate
 * @return              Number of bytes written to dst
 */
size_t hook_relocate_instructions(void* src, void* dst, size_t count);

/*
 * Generate an absolute jump (MOVZ/MOVK + BR, up to 20 bytes)
 *
 * @param dst           Where to write the jump
 * @param target        Jump target address
 * @return              Number of bytes written on success, or negative error code
 */
int hook_write_jump(void* dst, void* target);

/*
 * Clear instruction cache for modified code
 *
 * @param start         Start address
 * @param size          Size of region
 */
void hook_flush_cache(void* start, size_t size);

/*
 * Enable or disable wxshadow stealth mode
 *
 * When enabled, new hooks use prctl(PR_WXSHADOW_PATCH) to write jump
 * instructions via shadow pages, making the hook invisible to memory reads.
 *
 * @param enabled       1 to enable, 0 to disable
 */
void hook_set_stealth(int enabled);

/*
 * Get current stealth mode setting
 *
 * @return              1 if stealth mode is enabled, 0 otherwise
 */
int hook_get_stealth(void);

#ifdef __cplusplus
}
#endif

#endif /* HOOK_ENGINE_H */
