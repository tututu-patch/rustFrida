//! ptr() function implementation

use crate::context::JSContext;
use crate::ffi;
use crate::value::JSValue;
use std::ffi::CString;

use std::cell::Cell;

/// Class ID for NativePointer - stored in thread-local to avoid Sync issues
thread_local! {
    static NATIVE_POINTER_CLASS_ID: Cell<u32> = const { Cell::new(0) };
}

/// NativePointer class name
const NATIVE_POINTER_CLASS_NAME: &[u8] = b"NativePointer\0";

/// Initialize NativePointer class and get the class ID
fn get_or_init_class_id(ctx: *mut ffi::JSContext) -> u32 {
    NATIVE_POINTER_CLASS_ID.with(|id| {
        if id.get() == 0 {
            unsafe {
                let rt = ffi::JS_GetRuntime(ctx);
                let mut new_id: u32 = 0;
                new_id = ffi::JS_NewClassID(&mut new_id);

                let class_def = ffi::JSClassDef {
                    class_name: NATIVE_POINTER_CLASS_NAME.as_ptr() as *const _,
                    finalizer: None,
                    gc_mark: None,
                    call: None,
                    exotic: std::ptr::null_mut(),
                };
                ffi::JS_NewClass(rt, new_id, &class_def);
                id.set(new_id);
            }
        }
        id.get()
    })
}

/// Create a NativePointer object
pub fn create_native_pointer(ctx: *mut ffi::JSContext, addr: u64) -> JSValue {
    let class_id = get_or_init_class_id(ctx);

    unsafe {
        let obj = ffi::JS_NewObjectClass(ctx, class_id as i32);

        // Store the address as opaque data
        let addr_ptr = Box::into_raw(Box::new(addr));
        ffi::JS_SetOpaque(obj, addr_ptr as *mut _);

        JSValue(obj)
    }
}

/// Get address from NativePointer object
pub fn get_native_pointer_addr(ctx: *mut ffi::JSContext, val: JSValue) -> Option<u64> {
    let class_id = get_or_init_class_id(ctx);

    unsafe {
        let opaque = ffi::JS_GetOpaque(val.raw(), class_id);
        if opaque.is_null() {
            return None;
        }
        Some(*(opaque as *const u64))
    }
}

/// ptr() function implementation
/// Accepts: number, string (hex), or NativePointer
unsafe extern "C" fn js_ptr(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(ctx, b"ptr() requires 1 argument\0".as_ptr() as *const _);
    }

    let arg = JSValue(*argv);
    let addr: u64;

    // Check argument type
    if arg.is_string() {
        // Parse hex string
        let s = match arg.to_string(ctx) {
            Some(s) => s,
            None => return ffi::JS_ThrowTypeError(ctx, b"Invalid string\0".as_ptr() as *const _),
        };

        // Remove 0x prefix if present
        let s = s.trim().trim_start_matches("0x").trim_start_matches("0X");

        addr = match u64::from_str_radix(s, 16) {
            Ok(v) => v,
            Err(_) => return ffi::JS_ThrowTypeError(ctx, b"Invalid hex string\0".as_ptr() as *const _),
        };
    } else if arg.is_int() || arg.is_float() {
        // Number
        addr = arg.to_i64(ctx).unwrap_or(0) as u64;
    } else if let Some(ptr_addr) = get_native_pointer_addr(ctx, arg) {
        // Already a NativePointer
        addr = ptr_addr;
    } else {
        return ffi::JS_ThrowTypeError(ctx, b"ptr() argument must be number or string\0".as_ptr() as *const _);
    }

    create_native_pointer(ctx, addr).raw()
}

/// NativePointer.add() implementation
unsafe extern "C" fn native_pointer_add(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let this_val = JSValue(this);
    let addr = match get_native_pointer_addr(ctx, this_val) {
        Some(a) => a,
        None => return ffi::JS_ThrowTypeError(ctx, b"Not a NativePointer\0".as_ptr() as *const _),
    };

    if argc < 1 {
        return ffi::JS_ThrowTypeError(ctx, b"add() requires 1 argument\0".as_ptr() as *const _);
    }

    let offset = JSValue(*argv).to_i64(ctx).unwrap_or(0) as i64;
    let new_addr = (addr as i64 + offset) as u64;

    create_native_pointer(ctx, new_addr).raw()
}

/// NativePointer.sub() implementation
unsafe extern "C" fn native_pointer_sub(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let this_val = JSValue(this);
    let addr = match get_native_pointer_addr(ctx, this_val) {
        Some(a) => a,
        None => return ffi::JS_ThrowTypeError(ctx, b"Not a NativePointer\0".as_ptr() as *const _),
    };

    if argc < 1 {
        return ffi::JS_ThrowTypeError(ctx, b"sub() requires 1 argument\0".as_ptr() as *const _);
    }

    let offset = JSValue(*argv).to_i64(ctx).unwrap_or(0) as i64;
    let new_addr = (addr as i64 - offset) as u64;

    create_native_pointer(ctx, new_addr).raw()
}

/// NativePointer.toString() implementation
unsafe extern "C" fn native_pointer_to_string(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let this_val = JSValue(this);
    let addr = match get_native_pointer_addr(ctx, this_val) {
        Some(a) => a,
        None => return ffi::JS_ThrowTypeError(ctx, b"Not a NativePointer\0".as_ptr() as *const _),
    };

    let s = format!("0x{:x}", addr);
    JSValue::string(ctx, &s).raw()
}

/// NativePointer.toInt() / toNumber() implementation
unsafe extern "C" fn native_pointer_to_number(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let this_val = JSValue(this);
    let addr = match get_native_pointer_addr(ctx, this_val) {
        Some(a) => a,
        None => return ffi::JS_ThrowTypeError(ctx, b"Not a NativePointer\0".as_ptr() as *const _),
    };

    // Return as BigInt for 64-bit addresses
    ffi::JS_NewBigUint64(ctx, addr)
}

/// Register ptr() function and NativePointer class
pub fn register_ptr(ctx: &JSContext) {
    let class_id = get_or_init_class_id(ctx.as_ptr());

    let global = ctx.global_object();

    // Register ptr() function
    unsafe {
        let cname = CString::new("ptr").unwrap();
        let func_val = ffi::qjs_new_cfunction(ctx.as_ptr(), Some(js_ptr), cname.as_ptr(), 1);
        global.set_property(ctx.as_ptr(), "ptr", JSValue(func_val));
    }

    // Create NativePointer prototype with methods
    unsafe {
        let proto = ffi::JS_NewObject(ctx.as_ptr());

        // Add methods to prototype
        macro_rules! add_method {
            ($name:expr, $func:expr, $argc:expr) => {
                let cname = CString::new($name).unwrap();
                let func_val = ffi::qjs_new_cfunction(ctx.as_ptr(), Some($func), cname.as_ptr(), $argc);
                let atom = ffi::JS_NewAtom(ctx.as_ptr(), cname.as_ptr());
                ffi::qjs_set_property(ctx.as_ptr(), proto, atom, func_val);
                ffi::JS_FreeAtom(ctx.as_ptr(), atom);
            };
        }

        add_method!("add", native_pointer_add, 1);
        add_method!("sub", native_pointer_sub, 1);
        add_method!("toString", native_pointer_to_string, 0);
        add_method!("toNumber", native_pointer_to_number, 0);
        add_method!("toInt", native_pointer_to_number, 0);

        // Set as class prototype
        ffi::JS_SetClassProto(ctx.as_ptr(), class_id, proto);
    }

    global.free(ctx.as_ptr());
}
