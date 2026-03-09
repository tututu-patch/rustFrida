// ============================================================================
// Java._invokeMethod(objPtr, className, methodName, methodSig, ...args)
// ============================================================================
//
// Instance method invocation helper used by Java Proxy wrappers.
// - objPtr:    BigUint64 / Number / NativePointer (jobject mirror pointer)
// - className: "java.lang.Foo" / "java/lang/Foo"
// - methodName: Java method name (e.g. "bar")
// - methodSig: JNI signature string, e.g. "(Ljava/lang/String;I)V"
// - args...:   JS arguments, converted to jvalue[] according to methodSig
//
// Return value:
// - primitives → JS number / boolean / BigInt (for long)
// - String     → JS string
// - Object/[]  → {__jptr, __jclass} wrapper (Proxy-wrapped on JS side)
pub(super) unsafe extern "C" fn js_java_invoke_method(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 4 {
        return js_throw_type_error(
            ctx,
            b"Java._invokeMethod() requires at least 4 arguments: objPtr, className, methodName, methodSig\0",
        );
    }

    let obj_arg = JSValue(*argv);
    let class_arg = JSValue(*argv.add(1));
    let method_arg = JSValue(*argv.add(2));
    let sig_arg = JSValue(*argv.add(3));

    let obj_ptr = match read_invoke_target_ptr(ctx, obj_arg) {
        Ok(ptr) => ptr,
        Err(err) => return err,
    };
    let class_name = match read_string_arg(
        ctx,
        class_arg,
        b"Java._invokeMethod() className must be a string\0",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let method_name = match read_string_arg(
        ctx,
        method_arg,
        b"Java._invokeMethod() methodName must be a string\0",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let method_sig = match read_string_arg(
        ctx,
        sig_arg,
        b"Java._invokeMethod() methodSig must be a JNI signature string\0",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };

    // Parse parameter + return types from JNI signature
    let param_types = parse_jni_param_types(&method_sig);
    let param_count = param_types.len();
    if (argc - 4) < param_count as i32 {
        return js_throw_type_error(
            ctx,
            b"Java._invokeMethod() not enough JS arguments for method signature\0",
        );
    }

    let return_type = get_return_type_from_sig(&method_sig);
    let return_type_sig = get_return_type_sig(&method_sig);

    // Get JNIEnv* for current thread
    let env = match get_thread_env() {
        Ok(e) => e,
        Err(msg) => return js_throw_internal_error(ctx, msg),
    };

    // Resolve declaring class
    let cls = find_class_safe(env, &class_name);
    if cls.is_null() || jni_check_exc(env) {
        return js_throw_internal_error(
            ctx,
            format!("Java._invokeMethod: FindClass('{}') failed", class_name),
        );
    }

    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
    let new_local_ref: NewLocalRefFn = jni_fn!(env, NewLocalRefFn, JNI_NEW_LOCAL_REF);

    // Wrap raw mirror pointer as a proper local ref
    let local_obj = new_local_ref(env, obj_ptr as *mut std::ffi::c_void);
    if local_obj.is_null() || jni_check_exc(env) {
        delete_local_ref(env, cls);
        return js_throw_internal_error(ctx, "Java._invokeMethod: NewLocalRef failed for objPtr");
    }

    // Resolve method ID
    let get_mid: GetMethodIdFn = jni_fn!(env, GetMethodIdFn, JNI_GET_METHOD_ID);
    let c_name = match CString::new(method_name.as_str()) {
        Ok(c) => c,
        Err(_) => {
            return cleanup_and_throw_type(
                ctx,
                env,
                local_obj,
                cls,
                b"Java._invokeMethod() invalid methodName\0",
            );
        }
    };
    let c_sig = match CString::new(method_sig.as_str()) {
        Ok(c) => c,
        Err(_) => {
            return cleanup_and_throw_type(
                ctx,
                env,
                local_obj,
                cls,
                b"Java._invokeMethod() invalid methodSig\0",
            );
        }
    };

    let mid = get_mid(env, cls, c_name.as_ptr(), c_sig.as_ptr());
    if mid.is_null() || jni_check_exc(env) {
        return cleanup_and_throw_internal(
            ctx,
            env,
            local_obj,
            cls,
            format!(
                "Java._invokeMethod: GetMethodID failed: {}.{}{}",
                class_name, method_name, method_sig
            ),
        );
    }

    // Build jvalue args from JS values
    let jargs = build_invoke_jargs(ctx, env, argv, &param_types);
    let jargs_ptr = if param_count > 0 {
        jargs.as_ptr() as *const std::ffi::c_void
    } else {
        std::ptr::null()
    };
    let invoke_exception = || {
        format!(
            "Java._invokeMethod: exception in {}.{}{}",
            class_name, method_name, method_sig
        )
    };

    // Dispatch based on return type using CallNonvirtual*MethodA (avoids needing all Call*MethodA indices)
    let result = match return_type {
        b'V' => {
            type F = unsafe extern "C" fn(
                JniEnv,
                *mut std::ffi::c_void,
                *mut std::ffi::c_void,
                *mut std::ffi::c_void,
                *const std::ffi::c_void,
            );
            let f: F = jni_fn!(env, F, JNI_CALL_NONVIRTUAL_VOID_METHOD_A);
            f(env, local_obj, cls, mid, jargs_ptr);
            if jni_check_exc(env) {
                return cleanup_and_throw_internal(ctx, env, local_obj, cls, invoke_exception());
            }
            ffi::qjs_undefined()
        }
        b'Z' => {
            type F = unsafe extern "C" fn(
                JniEnv,
                *mut std::ffi::c_void,
                *mut std::ffi::c_void,
                *mut std::ffi::c_void,
                *const std::ffi::c_void,
            ) -> u8;
            let f: F = jni_fn!(env, F, JNI_CALL_NONVIRTUAL_BOOLEAN_METHOD_A);
            let ret = f(env, local_obj, cls, mid, jargs_ptr);
            if jni_check_exc(env) {
                return cleanup_and_throw_internal(ctx, env, local_obj, cls, invoke_exception());
            }
            JSValue::bool(ret != 0).raw()
        }
        b'I' | b'B' | b'C' | b'S' => {
            type F = unsafe extern "C" fn(
                JniEnv,
                *mut std::ffi::c_void,
                *mut std::ffi::c_void,
                *mut std::ffi::c_void,
                *const std::ffi::c_void,
            ) -> i32;
            let f: F = jni_fn!(env, F, JNI_CALL_NONVIRTUAL_INT_METHOD_A);
            let ret = f(env, local_obj, cls, mid, jargs_ptr);
            if jni_check_exc(env) {
                return cleanup_and_throw_internal(ctx, env, local_obj, cls, invoke_exception());
            }
            match return_type {
                b'I' => JSValue::int(ret).raw(),
                b'B' => JSValue::int(ret as i8 as i32).raw(),
                b'C' => {
                    let ch = std::char::from_u32(ret as u32).unwrap_or('\0');
                    JSValue::string(ctx, &ch.to_string()).raw()
                }
                b'S' => JSValue::int(ret as i16 as i32).raw(),
                _ => ffi::qjs_undefined(),
            }
        }
        b'J' => {
            type F = unsafe extern "C" fn(
                JniEnv,
                *mut std::ffi::c_void,
                *mut std::ffi::c_void,
                *mut std::ffi::c_void,
                *const std::ffi::c_void,
            ) -> i64;
            let f: F = jni_fn!(env, F, JNI_CALL_NONVIRTUAL_LONG_METHOD_A);
            let ret = f(env, local_obj, cls, mid, jargs_ptr);
            if jni_check_exc(env) {
                return cleanup_and_throw_internal(ctx, env, local_obj, cls, invoke_exception());
            }
            ffi::JS_NewBigUint64(ctx, ret as u64)
        }
        b'F' => {
            type F = unsafe extern "C" fn(
                JniEnv,
                *mut std::ffi::c_void,
                *mut std::ffi::c_void,
                *mut std::ffi::c_void,
                *const std::ffi::c_void,
            ) -> f32;
            let f: F = jni_fn!(env, F, JNI_CALL_NONVIRTUAL_FLOAT_METHOD_A);
            let ret = f(env, local_obj, cls, mid, jargs_ptr);
            if jni_check_exc(env) {
                return cleanup_and_throw_internal(ctx, env, local_obj, cls, invoke_exception());
            }
            JSValue::float(ret as f64).raw()
        }
        b'D' => {
            type F = unsafe extern "C" fn(
                JniEnv,
                *mut std::ffi::c_void,
                *mut std::ffi::c_void,
                *mut std::ffi::c_void,
                *const std::ffi::c_void,
            ) -> f64;
            let f: F = jni_fn!(env, F, JNI_CALL_NONVIRTUAL_DOUBLE_METHOD_A);
            let ret = f(env, local_obj, cls, mid, jargs_ptr);
            if jni_check_exc(env) {
                return cleanup_and_throw_internal(ctx, env, local_obj, cls, invoke_exception());
            }
            JSValue::float(ret).raw()
        }
        b'L' | b'[' => {
            // Object/array return — use CallNonvirtualObjectMethodA, then wrap result.
            type F = unsafe extern "C" fn(
                JniEnv,
                *mut std::ffi::c_void,
                *mut std::ffi::c_void,
                *mut std::ffi::c_void,
                *const std::ffi::c_void,
            ) -> *mut std::ffi::c_void;
            let f: F = jni_fn!(env, F, JNI_CALL_NONVIRTUAL_OBJECT_METHOD_A);
            let obj = f(env, local_obj, cls, mid, jargs_ptr);
            if jni_check_exc(env) {
                if !obj.is_null() {
                    delete_local_ref(env, obj);
                }
                return cleanup_and_throw_internal(ctx, env, local_obj, cls, invoke_exception());
            }
            match wrap_invoke_return_object(ctx, env, obj, &return_type_sig) {
                Ok(value) => value,
                Err(message) => {
                    return cleanup_and_throw_internal(ctx, env, local_obj, cls, message);
                }
            }
        }
        _ => ffi::qjs_undefined(),
    };

    cleanup_local_refs(env, local_obj, cls);
    result
}
