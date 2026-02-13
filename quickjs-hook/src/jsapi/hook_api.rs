//! hook() and unhook() API implementation

use crate::context::JSContext;
use crate::ffi;
use crate::ffi::hook as hook_ffi;
use crate::value::JSValue;
use crate::jsapi::ptr::get_native_pointer_addr;
use std::collections::HashMap;
use std::ffi::CString;
use std::sync::Mutex;

// Error codes from hook_engine.h
const HOOK_OK: i32 = 0;
const HOOK_ERROR_NOT_INITIALIZED: i32 = -1;
const HOOK_ERROR_INVALID_PARAM: i32 = -2;
const HOOK_ERROR_ALREADY_HOOKED: i32 = -3;
const HOOK_ERROR_ALLOC_FAILED: i32 = -4;
const HOOK_ERROR_MPROTECT_FAILED: i32 = -5;
const HOOK_ERROR_NOT_FOUND: i32 = -6;
const HOOK_ERROR_BUFFER_TOO_SMALL: i32 = -7;
const HOOK_ERROR_WXSHADOW_FAILED: i32 = -8;

/// Convert hook error code to error message
fn hook_error_message(code: i32) -> &'static [u8] {
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
struct HookData {
    ctx: usize,  // Store as usize to avoid Send/Sync issues
    callback_bytes: [u8; 16],  // JSValue is 16 bytes (u64 + i64)
}

// SAFETY: HookData only contains Copy types now (usize, [u8; 16])
// The actual pointer usage is only done within unsafe blocks on the JS thread
unsafe impl Send for HookData {}
unsafe impl Sync for HookData {}

/// Global hook registry
static HOOK_REGISTRY: Mutex<Option<HashMap<u64, HookData>>> = Mutex::new(None);

/// Initialize hook registry
fn init_registry() {
    let mut guard = HOOK_REGISTRY.lock().unwrap();
    if guard.is_none() {
        *guard = Some(HashMap::new());
    }
}

/// Hook callback that calls the JS function
unsafe extern "C" fn hook_callback_wrapper(
    ctx_ptr: *mut hook_ffi::HookContext,
    user_data: *mut std::ffi::c_void,
) {
    if ctx_ptr.is_null() || user_data.is_null() {
        return;
    }

    let target_addr = user_data as u64;

    // Get the stored callback
    let guard = HOOK_REGISTRY.lock().unwrap();
    let registry = match guard.as_ref() {
        Some(r) => r,
        None => return,
    };

    let hook_data = match registry.get(&target_addr) {
        Some(d) => d,
        None => return,
    };

    let ctx = hook_data.ctx as *mut ffi::JSContext;
    // Reconstruct JSValue from bytes
    let callback: ffi::JSValue = std::ptr::read(hook_data.callback_bytes.as_ptr() as *const ffi::JSValue);

    // Create context object for JS callback
    let js_ctx = ffi::JS_NewObject(ctx);

    // Populate context with register values
    let hook_ctx = &*ctx_ptr;

    // Add x0-x30
    for i in 0..31 {
        let prop_name = format!("x{}", i);
        let cprop = CString::new(prop_name).unwrap();
        let atom = ffi::JS_NewAtom(ctx, cprop.as_ptr());
        let val = ffi::JS_NewBigUint64(ctx, hook_ctx.x[i]);
        ffi::qjs_set_property(ctx, js_ctx, atom, val);
        ffi::JS_FreeAtom(ctx, atom);
    }

    // Add sp
    {
        let cprop = CString::new("sp").unwrap();
        let atom = ffi::JS_NewAtom(ctx, cprop.as_ptr());
        let val = ffi::JS_NewBigUint64(ctx, hook_ctx.sp);
        ffi::qjs_set_property(ctx, js_ctx, atom, val);
        ffi::JS_FreeAtom(ctx, atom);
    }

    // Add pc
    {
        let cprop = CString::new("pc").unwrap();
        let atom = ffi::JS_NewAtom(ctx, cprop.as_ptr());
        let val = ffi::JS_NewBigUint64(ctx, hook_ctx.pc);
        ffi::qjs_set_property(ctx, js_ctx, atom, val);
        ffi::JS_FreeAtom(ctx, atom);
    }

    // Call the JS callback
    let global = ffi::JS_GetGlobalObject(ctx);
    let result = ffi::JS_Call(ctx, callback, global, 1, &js_ctx as *const _ as *mut _);

    // Check if callback modified any registers
    // Read back x0-x7 (commonly modified)
    for i in 0..8 {
        let prop_name = format!("x{}", i);
        let cprop = CString::new(prop_name).unwrap();
        let atom = ffi::JS_NewAtom(ctx, cprop.as_ptr());
        let val = ffi::qjs_get_property(ctx, js_ctx, atom);
        ffi::JS_FreeAtom(ctx, atom);

        let js_val = JSValue(val);
        if let Some(new_val) = js_val.to_u64(ctx) {
            (*ctx_ptr).x[i] = new_val;
        }
        js_val.free(ctx);
    }

    // Cleanup
    ffi::qjs_free_value(ctx, js_ctx);
    ffi::qjs_free_value(ctx, result);
    ffi::qjs_free_value(ctx, global);
}

/// hook(ptr, callback) - Install a hook at the given address
unsafe extern "C" fn js_hook(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return ffi::JS_ThrowTypeError(ctx, b"hook() requires 2 arguments\0".as_ptr() as *const _);
    }

    let ptr_arg = JSValue(*argv);
    let callback_arg = JSValue(*argv.add(1));

    // Get the address
    let addr = match get_native_pointer_addr(ctx, ptr_arg) {
        Some(a) => a,
        None => {
            // Try to convert directly
            match ptr_arg.to_u64(ctx) {
                Some(a) => a,
                None => return ffi::JS_ThrowTypeError(ctx, b"hook() first argument must be a pointer\0".as_ptr() as *const _),
            }
        }
    };

    // Check callback is a function
    if !callback_arg.is_function(ctx) {
        return ffi::JS_ThrowTypeError(ctx, b"hook() second argument must be a function\0".as_ptr() as *const _);
    }

    // Initialize registry
    init_registry();

    // Duplicate the callback to prevent GC
    let callback_dup = ffi::qjs_dup_value(ctx, callback_arg.raw());

    // Store in registry - convert to bytes for Send/Sync safety
    let mut callback_bytes = [0u8; 16];
    std::ptr::copy_nonoverlapping(
        &callback_dup as *const ffi::JSValue as *const u8,
        callback_bytes.as_mut_ptr(),
        16
    );

    {
        let mut guard = HOOK_REGISTRY.lock().unwrap();
        let registry = guard.as_mut().unwrap();
        registry.insert(addr, HookData {
            ctx: ctx as usize,
            callback_bytes,
        });
    }

    // Install the hook
    let result = hook_ffi::hook_attach(
        addr as *mut std::ffi::c_void,
        Some(hook_callback_wrapper),
        None, // No on_leave callback for now
        addr as *mut std::ffi::c_void, // Use address as user_data to look up callback
    );

    if result != HOOK_OK {
        // Failed - cleanup
        let mut guard = HOOK_REGISTRY.lock().unwrap();
        if let Some(registry) = guard.as_mut() {
            if let Some(data) = registry.remove(&addr) {
                let callback: ffi::JSValue = std::ptr::read(data.callback_bytes.as_ptr() as *const ffi::JSValue);
                ffi::qjs_free_value(ctx, callback);
            }
        }
        let err_msg = hook_error_message(result);
        return ffi::JS_ThrowInternalError(ctx, err_msg.as_ptr() as *const _);
    }

    JSValue::bool(true).raw()
}

/// unhook(ptr) - Remove a hook at the given address
unsafe extern "C" fn js_unhook(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(ctx, b"unhook() requires 1 argument\0".as_ptr() as *const _);
    }

    let ptr_arg = JSValue(*argv);

    // Get the address
    let addr = match get_native_pointer_addr(ctx, ptr_arg) {
        Some(a) => a,
        None => {
            match ptr_arg.to_u64(ctx) {
                Some(a) => a,
                None => return ffi::JS_ThrowTypeError(ctx, b"unhook() argument must be a pointer\0".as_ptr() as *const _),
            }
        }
    };

    // Remove from registry and free callback
    {
        let mut guard = HOOK_REGISTRY.lock().unwrap();
        if let Some(registry) = guard.as_mut() {
            if let Some(data) = registry.remove(&addr) {
                let ctx = data.ctx as *mut ffi::JSContext;
                let callback: ffi::JSValue = std::ptr::read(data.callback_bytes.as_ptr() as *const ffi::JSValue);
                ffi::qjs_free_value(ctx, callback);
            }
        }
    }

    // Remove the hook
    let result = hook_ffi::hook_remove(addr as *mut std::ffi::c_void);

    if result != HOOK_OK {
        let err_msg = hook_error_message(result);
        return ffi::JS_ThrowInternalError(ctx, err_msg.as_ptr() as *const _);
    }

    JSValue::bool(true).raw()
}

/// setStealthMode(enabled) - Enable or disable wxshadow stealth hooking
unsafe extern "C" fn js_set_stealth_mode(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(ctx, b"setStealthMode() requires 1 argument\0".as_ptr() as *const _);
    }

    let arg = JSValue(*argv);
    let enabled = arg.to_bool().unwrap_or(false);

    hook_ffi::hook_set_stealth(if enabled { 1 } else { 0 });

    JSValue::bool(enabled).raw()
}

/// Register hook API
pub fn register_hook_api(ctx: &JSContext) {
    let global = ctx.global_object();

    unsafe {
        // Register hook()
        let cname = CString::new("hook").unwrap();
        let func_val = ffi::qjs_new_cfunction(ctx.as_ptr(), Some(js_hook), cname.as_ptr(), 2);
        global.set_property(ctx.as_ptr(), "hook", JSValue(func_val));

        // Register unhook()
        let cname = CString::new("unhook").unwrap();
        let func_val = ffi::qjs_new_cfunction(ctx.as_ptr(), Some(js_unhook), cname.as_ptr(), 1);
        global.set_property(ctx.as_ptr(), "unhook", JSValue(func_val));

        // Register setStealthMode()
        let cname = CString::new("setStealthMode").unwrap();
        let func_val = ffi::qjs_new_cfunction(ctx.as_ptr(), Some(js_set_stealth_mode), cname.as_ptr(), 1);
        global.set_property(ctx.as_ptr(), "setStealthMode", JSValue(func_val));
    }

    global.free(ctx.as_ptr());
}

/// Cleanup all hooks (call before dropping context)
pub fn cleanup_hooks() {
    let mut guard = HOOK_REGISTRY.lock().unwrap();
    if let Some(registry) = guard.take() {
        for (addr, data) in registry {
            unsafe {
                hook_ffi::hook_remove(addr as *mut std::ffi::c_void);
                let ctx = data.ctx as *mut ffi::JSContext;
                let callback: ffi::JSValue = std::ptr::read(data.callback_bytes.as_ptr() as *const ffi::JSValue);
                ffi::qjs_free_value(ctx, callback);
            }
        }
    }
}
