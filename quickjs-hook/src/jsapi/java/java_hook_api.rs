//! JS API: Java.hook / Java.unhook

use crate::ffi;
use crate::ffi::hook as hook_ffi;
use crate::jsapi::console::output_message;
use crate::value::JSValue;
use std::ffi::CString;

use super::jni_core::*;
use super::reflect::*;
use super::art_method::*;
use super::callback::*;

// ============================================================================
// JS API: Java.hook(class, method, sig, callback)
// ============================================================================

pub(super) unsafe extern "C" fn js_java_hook(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 4 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"Java.hook() requires 4 arguments: class, method, signature, callback\0".as_ptr()
                as *const _,
        );
    }

    let class_arg = JSValue(*argv);
    let method_arg = JSValue(*argv.add(1));
    let sig_arg = JSValue(*argv.add(2));
    let callback_arg = JSValue(*argv.add(3));

    // Extract string arguments
    let class_name = match class_arg.to_string(ctx) {
        Some(s) => s,
        None => {
            return ffi::JS_ThrowTypeError(
                ctx,
                b"Java.hook() first argument must be a class name string\0".as_ptr() as *const _,
            )
        }
    };

    let method_name = match method_arg.to_string(ctx) {
        Some(s) => s,
        None => {
            return ffi::JS_ThrowTypeError(
                ctx,
                b"Java.hook() second argument must be a method name string\0".as_ptr() as *const _,
            )
        }
    };

    let sig_str = match sig_arg.to_string(ctx) {
        Some(s) => s,
        None => {
            return ffi::JS_ThrowTypeError(
                ctx,
                b"Java.hook() third argument must be a signature string\0".as_ptr() as *const _,
            )
        }
    };

    if !callback_arg.is_function(ctx) {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"Java.hook() fourth argument must be a function\0".as_ptr() as *const _,
        );
    }

    // Parse "static:" prefix
    let (actual_sig, force_static) = if let Some(stripped) = sig_str.strip_prefix("static:") {
        (stripped.to_string(), true)
    } else {
        (sig_str.clone(), false)
    };

    // Initialize JNI
    let env = match ensure_jni_initialized() {
        Ok(e) => e,
        Err(msg) => {
            let err = CString::new(msg).unwrap();
            return ffi::JS_ThrowInternalError(ctx, err.as_ptr());
        }
    };

    // Resolve ArtMethod
    let (art_method, is_static) = match resolve_art_method(env, &class_name, &method_name, &actual_sig, force_static) {
        Ok(r) => r,
        Err(msg) => {
            let err = CString::new(msg).unwrap();
            return ffi::JS_ThrowInternalError(ctx, err.as_ptr());
        }
    };

    // Check if already hooked
    init_java_registry();
    {
        let guard = JAVA_HOOK_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(ref registry) = *guard {
            if registry.contains_key(&art_method) {
                return ffi::JS_ThrowInternalError(
                    ctx,
                    b"method already hooked (unhook first)\0".as_ptr() as *const _,
                );
            }
        }
    }

    // Probe entry_point offset (lazy, one-time)
    let ep_offset = get_entry_point_offset(env, art_method);

    // ================================================================
    // Replace-with-native hooking
    //
    // Convert the method to native so ART routes calls through
    // art_quick_generic_jni_trampoline → data_ (our thunk).
    //
    // This ensures the JNI calling convention:
    //   x0=JNIEnv*, x1=jobject/jclass, x2-x7=Java args
    //
    // Steps:
    //   1. Write thunk to data_ (JNI function pointer slot)
    //   2. Set kAccNative + kAccCompileDontBother flags
    //   3. Write art_quick_generic_jni_trampoline to entry_point_
    //
    // GC safety: ArtMethod::VisitRoots() only visits declaring_class_,
    // NOT data_. With kAccNative set, ART treats data_ as an opaque
    // JNI function pointer. Writing data_ BEFORE setting flags avoids
    // any window where GC sees inconsistent state.
    // ================================================================

    // Find the JNI trampoline (required for native hook path)
    let jni_trampoline = find_jni_trampoline(env, ep_offset);
    if jni_trampoline == 0 {
        let err = CString::new("failed to find art_quick_generic_jni_trampoline").unwrap();
        return ffi::JS_ThrowInternalError(ctx, err.as_ptr());
    }
    output_message(&format!(
        "[java hook] JNI trampoline={:#x}", jni_trampoline
    ));

    // Save original method state for unhook
    let original_access_flags = {
        std::ptr::read_volatile(
            (art_method as usize + ART_METHOD_ACCESS_FLAGS_OFFSET) as *const u32,
        )
    };
    let original_data = {
        std::ptr::read_volatile(
            (art_method as usize + data_offset_for(ep_offset)) as *const u64,
        )
    };
    let original_entry_point = read_entry_point(art_method, ep_offset);

    output_message(&format!(
        "[java hook] art_method={:#x}, orig_flags={:#x}, orig_data={:#x}, orig_entry={:#x}",
        art_method, original_access_flags, original_data, original_entry_point
    ));

    // Clone ArtMethod for callOriginal (Frida pattern)
    // The clone preserves the original method state. callOriginal() invokes the clone
    // via JNI CallNonvirtual*MethodA which reads the clone's original quickCode.
    let clone_size = ep_offset + 8; // includes entry_point field
    let clone_addr = {
        let ptr = libc::malloc(clone_size);
        if ptr.is_null() {
            let err = CString::new("malloc failed for ArtMethod clone").unwrap();
            return ffi::JS_ThrowInternalError(ctx, err.as_ptr());
        }
        std::ptr::copy_nonoverlapping(
            art_method as *const u8,
            ptr as *mut u8,
            clone_size,
        );
        ptr as u64
    };
    output_message(&format!(
        "[java hook] ArtMethod clone at {:#x} (size={})", clone_addr, clone_size
    ));

    // Create JNI global ref to the class for callOriginal JNI calls
    let class_global_ref = {
        let cls = find_class_safe(env, &class_name);
        if cls.is_null() {
            libc::free(clone_addr as *mut std::ffi::c_void);
            let err = CString::new(format!("FindClass('{}') failed for global ref", class_name)).unwrap();
            return ffi::JS_ThrowInternalError(ctx, err.as_ptr());
        }
        let new_global_ref: NewGlobalRefFn = jni_fn!(env, NewGlobalRefFn, JNI_NEW_GLOBAL_REF);
        let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
        let gref = new_global_ref(env, cls);
        delete_local_ref(env, cls);
        gref as usize
    };

    // Extract return type from signature
    let return_type = get_return_type_from_sig(&actual_sig);

    // Create native hook thunk (saves context → calls callback → restores x0 → RET)
    let thunk = hook_ffi::hook_create_native_trampoline(
        art_method,                          // key = ArtMethod*
        Some(java_hook_callback),            // on_enter callback
        art_method as *mut std::ffi::c_void, // user_data = ArtMethod* for registry lookup
    );

    if thunk.is_null() {
        libc::free(clone_addr as *mut std::ffi::c_void);
        let err = CString::new("hook_create_native_trampoline failed").unwrap();
        return ffi::JS_ThrowInternalError(ctx, err.as_ptr());
    }

    // Duplicate callback and store in registry BEFORE modifying ArtMethod
    let callback_dup = ffi::qjs_dup_value(ctx, callback_arg.raw());
    let mut callback_bytes = [0u8; 16];
    std::ptr::copy_nonoverlapping(
        &callback_dup as *const ffi::JSValue as *const u8,
        callback_bytes.as_mut_ptr(),
        16,
    );

    {
        let mut guard = JAVA_HOOK_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
        let registry = guard.as_mut().unwrap();
        registry.insert(
            art_method,
            JavaHookData {
                art_method,
                original_access_flags,
                original_data,
                original_entry_point,
                clone_addr,
                class_global_ref,
                return_type,
                method_id_raw: art_method, // decoded art_method is the raw pointer
                ctx: ctx as usize,
                callback_bytes,
                method_key: method_key(&class_name, &method_name, &actual_sig),
                is_static,
                param_count: count_jni_params(&actual_sig),
                param_types: parse_jni_param_types(&actual_sig),
                class_name: class_name.clone(),
            },
        );
    }

    // === Modify ArtMethod: convert to native with our thunk as JNI impl ===
    // Order: data_ first → flags → entry_point_ (GC sees consistent state)

    // 1. Write thunk to data_ (native function pointer slot)
    {
        let data_ptr = (art_method as usize + data_offset_for(ep_offset)) as *mut u64;
        std::ptr::write_volatile(data_ptr, thunk as u64);
    }

    // 2. Set kAccNative + kAccCompileDontBother, clear fast-path flags
    set_native_hook_flags(art_method);

    // 3. Write JNI trampoline to entry_point_
    {
        let ep_ptr = (art_method as usize + ep_offset) as *mut u64;
        std::ptr::write_volatile(ep_ptr, jni_trampoline);
        hook_ffi::hook_flush_cache(
            (art_method as usize) as *mut std::ffi::c_void,
            ep_offset + 8,
        );
    }

    // Verify writes
    let verify_flags = {
        std::ptr::read_volatile(
            (art_method as usize + ART_METHOD_ACCESS_FLAGS_OFFSET) as *const u32,
        )
    };
    let verify_ep = read_entry_point(art_method, ep_offset);
    let verify_data = {
        std::ptr::read_volatile(
            (art_method as usize + data_offset_for(ep_offset)) as *const u64,
        )
    };

    output_message(&format!(
        "[java hook] hook installed: flags={:#x}, entry(trampoline)={:#x}, data(thunk)={:#x}",
        verify_flags, verify_ep, verify_data
    ));

    // Pre-cache field info for this class (safe from init thread)
    cache_fields_for_class(env, &class_name);

    output_message(&format!(
        "[java hook] hooked {}.{}{} (ArtMethod={:#x}, strategy=replace-with-native)",
        class_name, method_name, actual_sig, art_method
    ));

    JSValue::bool(true).raw()
}

// ============================================================================
// JS API: Java.unhook(class, method, sig)
// ============================================================================

pub(super) unsafe extern "C" fn js_java_unhook(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 3 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"Java.unhook() requires 3 arguments: class, method, signature\0".as_ptr()
                as *const _,
        );
    }

    let class_arg = JSValue(*argv);
    let method_arg = JSValue(*argv.add(1));
    let sig_arg = JSValue(*argv.add(2));

    let class_name = match class_arg.to_string(ctx) {
        Some(s) => s,
        None => {
            return ffi::JS_ThrowTypeError(
                ctx,
                b"Java.unhook() first argument must be a string\0".as_ptr() as *const _,
            )
        }
    };

    let method_name = match method_arg.to_string(ctx) {
        Some(s) => s,
        None => {
            return ffi::JS_ThrowTypeError(
                ctx,
                b"Java.unhook() second argument must be a string\0".as_ptr() as *const _,
            )
        }
    };

    let sig_str = match sig_arg.to_string(ctx) {
        Some(s) => s,
        None => {
            return ffi::JS_ThrowTypeError(
                ctx,
                b"Java.unhook() third argument must be a string\0".as_ptr() as *const _,
            )
        }
    };

    // Handle "static:" prefix
    let actual_sig = if let Some(stripped) = sig_str.strip_prefix("static:") {
        stripped.to_string()
    } else {
        sig_str
    };

    let key = method_key(&class_name, &method_name, &actual_sig);

    // Find and remove from registry
    let hook_data = {
        let mut guard = JAVA_HOOK_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(registry) = guard.as_mut() {
            // Find by method_key
            let art_method = registry
                .iter()
                .find(|(_, v)| v.method_key == key)
                .map(|(k, _)| *k);

            if let Some(am) = art_method {
                registry.remove(&am)
            } else {
                None
            }
        } else {
            None
        }
    };

    let hook_data = match hook_data {
        Some(d) => d,
        None => {
            return ffi::JS_ThrowInternalError(
                ctx,
                b"method not hooked\0".as_ptr() as *const _,
            );
        }
    };

    // Remove the native trampoline from the hook engine
    hook_ffi::hook_remove_redirect(hook_data.art_method);

    // Restore original ArtMethod state (data_ + access_flags_ + entry_point_)
    // Order: entry_point_ first → flags → data_ (reverse of hook installation)
    if let Some(&ep_offset) = ENTRY_POINT_OFFSET.get() {
        // Restore entry_point_ first (stop routing to our thunk)
        let ep_ptr = (hook_data.art_method as usize + ep_offset) as *mut u64;
        std::ptr::write_volatile(ep_ptr, hook_data.original_entry_point);

        // Restore access_flags_ (clears kAccNative)
        let flags_ptr = (hook_data.art_method as usize + ART_METHOD_ACCESS_FLAGS_OFFSET)
            as *mut u32;
        std::ptr::write_volatile(flags_ptr, hook_data.original_access_flags);

        // Restore data_
        let data_ptr = (hook_data.art_method as usize + data_offset_for(ep_offset))
            as *mut u64;
        std::ptr::write_volatile(data_ptr, hook_data.original_data);

        hook_ffi::hook_flush_cache(
            (hook_data.art_method as usize) as *mut std::ffi::c_void,
            ep_offset + 8,
        );
    }

    // Free the ArtMethod clone
    if hook_data.clone_addr != 0 {
        libc::free(hook_data.clone_addr as *mut std::ffi::c_void);
    }

    // Delete the JNI global ref to the class
    if hook_data.class_global_ref != 0 {
        if let Ok(env) = get_thread_env() {
            let delete_global_ref: DeleteGlobalRefFn =
                jni_fn!(env, DeleteGlobalRefFn, JNI_DELETE_GLOBAL_REF);
            delete_global_ref(env, hook_data.class_global_ref as *mut std::ffi::c_void);
        }
    }

    // Free the JS callback
    let js_ctx = hook_data.ctx as *mut ffi::JSContext;
    let callback: ffi::JSValue =
        std::ptr::read(hook_data.callback_bytes.as_ptr() as *const ffi::JSValue);
    ffi::qjs_free_value(js_ctx, callback);

    output_message(&format!(
        "[java hook] unhooked {}.{}{}",
        class_name, method_name, actual_sig
    ));

    JSValue::bool(true).raw()
}
