//! Hook registry: HookData, HOOK_REGISTRY, error constants

use crate::jsapi::callback_util::ensure_registry_initialized;
use std::collections::HashMap;
use std::sync::Mutex;

// Error codes from hook_engine.h
pub(crate) const HOOK_OK: i32 = 0;
const HOOK_ERROR_NOT_INITIALIZED: i32 = -1;
const HOOK_ERROR_INVALID_PARAM: i32 = -2;
const HOOK_ERROR_ALREADY_HOOKED: i32 = -3;
const HOOK_ERROR_ALLOC_FAILED: i32 = -4;
const HOOK_ERROR_MPROTECT_FAILED: i32 = -5;
const HOOK_ERROR_NOT_FOUND: i32 = -6;
const HOOK_ERROR_BUFFER_TOO_SMALL: i32 = -7;
const HOOK_ERROR_WXSHADOW_FAILED: i32 = -8;

/// Convert hook error code to error message
pub(crate) fn hook_error_message(code: i32) -> &'static [u8] {
    match code {
        HOOK_ERROR_NOT_INITIALIZED => b"hook engine not initialized\0",
        HOOK_ERROR_INVALID_PARAM => b"invalid parameter\0",
        HOOK_ERROR_ALREADY_HOOKED => b"address already hooked\0",
        HOOK_ERROR_ALLOC_FAILED => b"memory allocation failed\0",
        HOOK_ERROR_MPROTECT_FAILED => b"mprotect failed: cannot change memory protection\0",
        HOOK_ERROR_NOT_FOUND => b"hook not found at address\0",
        HOOK_ERROR_BUFFER_TOO_SMALL => b"buffer too small for jump instruction\0",
        HOOK_ERROR_WXSHADOW_FAILED => b"wxshadow prctl failed: kernel may not support shadow pages\0",
        _ => b"unknown hook error\0",
    }
}

/// Stored hook callback data - stores raw bytes to avoid Send/Sync issues
pub(crate) struct HookData {
    pub(crate) ctx: usize,               // Store as usize to avoid Send/Sync issues
    pub(crate) callback_bytes: [u8; 16], // JSValue is 16 bytes (u64 + i64)
    pub(crate) trampoline: u64,          // Trampoline address for callOriginal (replace mode)
}

// SAFETY: HookData only contains Copy types now (usize, [u8; 16])
// The actual pointer usage is only done within unsafe blocks on the JS thread
unsafe impl Send for HookData {}
unsafe impl Sync for HookData {}

/// Global hook registry
pub(crate) static HOOK_REGISTRY: Mutex<Option<HashMap<u64, HookData>>> = Mutex::new(None);

/// Initialize hook registry
pub(crate) fn init_registry() {
    ensure_registry_initialized(&HOOK_REGISTRY);
}
