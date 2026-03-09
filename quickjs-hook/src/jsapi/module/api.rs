// ============================================================================
// JS API: Module namespace
// ============================================================================

/// Module.findExportByName(moduleName, symbolName) → NativePointer | null
///
/// moduleName == null → dlsym(RTLD_DEFAULT, symbolName)
/// moduleName != null → module_dlsym(moduleName, symbolName)
unsafe extern "C" fn js_module_find_export(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"Module.findExportByName(moduleName, symbolName) requires 2 arguments\0".as_ptr()
                as *const _,
        );
    }

    let arg0 = JSValue(*argv);
    let arg1 = JSValue(*argv.add(1));

    // Get symbol name (required)
    let symbol_name = match arg1.to_string(ctx) {
        Some(s) => s,
        None => {
            return ffi::JS_ThrowTypeError(
                ctx,
                b"symbolName must be a string\0".as_ptr() as *const _,
            );
        }
    };

    let addr: *mut std::ffi::c_void = if arg0.is_null() || arg0.is_undefined() {
        // null module → search all loaded modules (跳过 RTLD_DEFAULT，soinfo 摘除后会崩溃)
        let c_sym = CString::new(symbol_name.as_str()).unwrap();
        let api = UNRESTRICTED_LINKER_API.get_or_init(|| init_unrestricted_linker_api());
        if let Some(api) = api {
            (api.dlsym)(
                libc::RTLD_DEFAULT as _,
                c_sym.as_ptr() as *const i8,
                std::ptr::null(),
                api.trusted_caller,
            )
        } else {
            std::ptr::null_mut()
        }
    } else {
        // Specific module
        let module_name = match arg0.to_string(ctx) {
            Some(s) => s,
            None => {
                return ffi::JS_ThrowTypeError(
                    ctx,
                    b"moduleName must be a string or null\0".as_ptr() as *const _,
                );
            }
        };
        module_dlsym(&module_name, &symbol_name)
    };

    if addr.is_null() {
        JSValue::null().raw()
    } else {
        create_native_pointer(ctx, addr as u64).raw()
    }
}

/// Module.findBaseAddress(moduleName) → NativePointer | null
unsafe extern "C" fn js_module_find_base(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"Module.findBaseAddress(moduleName) requires 1 argument\0".as_ptr() as *const _,
        );
    }

    let arg0 = JSValue(*argv);
    let module_name = match arg0.to_string(ctx) {
        Some(s) => s,
        None => {
            return ffi::JS_ThrowTypeError(
                ctx,
                b"moduleName must be a string\0".as_ptr() as *const _,
            );
        }
    };

    let base = find_module_base(&module_name);
    if base == 0 {
        JSValue::null().raw()
    } else {
        create_native_pointer(ctx, base).raw()
    }
}

/// Module.enumerateModules() → Array of {name, base, size, path}
unsafe extern "C" fn js_module_enumerate(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let modules = enumerate_modules_from_maps();

    let arr = ffi::JS_NewArray(ctx);
    for (i, m) in modules.iter().enumerate() {
        let obj = ffi::JS_NewObject(ctx);
        let obj_val = JSValue(obj);

        let name_val = JSValue::string(ctx, &m.name);
        let base_val = create_native_pointer(ctx, m.base);
        let size_val = JSValue(ffi::JS_NewBigUint64(ctx, m.size));
        let path_val = JSValue::string(ctx, &m.path);

        obj_val.set_property(ctx, "name", name_val);
        obj_val.set_property(ctx, "base", base_val);
        obj_val.set_property(ctx, "size", size_val);
        obj_val.set_property(ctx, "path", path_val);

        ffi::JS_SetPropertyUint32(ctx, arr, i as u32, obj);
    }

    arr
}

/// Register Module JS API
pub fn register_module_api(ctx: &JSContext) {
    let global = ctx.global_object();

    unsafe {
        let ctx_ptr = ctx.as_ptr();
        let module_obj = ffi::JS_NewObject(ctx_ptr);

        add_cfunction_to_object(
            ctx_ptr,
            module_obj,
            "findExportByName",
            js_module_find_export,
            2,
        );
        add_cfunction_to_object(
            ctx_ptr,
            module_obj,
            "findBaseAddress",
            js_module_find_base,
            1,
        );
        add_cfunction_to_object(
            ctx_ptr,
            module_obj,
            "enumerateModules",
            js_module_enumerate,
            0,
        );

        global.set_property(ctx.as_ptr(), "Module", JSValue(module_obj));
    }

    global.free(ctx.as_ptr());
}
