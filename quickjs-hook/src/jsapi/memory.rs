//! Memory API implementation

use crate::context::JSContext;
use crate::ffi;
use crate::value::JSValue;
use crate::jsapi::ptr::{create_native_pointer, get_native_pointer_addr};
use std::ffi::CString;

/// Helper to get address from argument
unsafe fn get_addr_from_arg(ctx: *mut ffi::JSContext, val: JSValue) -> Option<u64> {
    get_native_pointer_addr(ctx, val).or_else(|| val.to_u64(ctx))
}

/// Memory.readU8(ptr)
unsafe extern "C" fn memory_read_u8(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(ctx, b"readU8() requires 1 argument\0".as_ptr() as *const _);
    }

    let addr = match get_addr_from_arg(ctx, JSValue(*argv)) {
        Some(a) => a,
        None => return ffi::JS_ThrowTypeError(ctx, b"Invalid pointer\0".as_ptr() as *const _),
    };

    let val = *(addr as *const u8);
    JSValue::int(val as i32).raw()
}

/// Memory.readU16(ptr)
unsafe extern "C" fn memory_read_u16(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(ctx, b"readU16() requires 1 argument\0".as_ptr() as *const _);
    }

    let addr = match get_addr_from_arg(ctx, JSValue(*argv)) {
        Some(a) => a,
        None => return ffi::JS_ThrowTypeError(ctx, b"Invalid pointer\0".as_ptr() as *const _),
    };

    let val = *(addr as *const u16);
    JSValue::int(val as i32).raw()
}

/// Memory.readU32(ptr)
unsafe extern "C" fn memory_read_u32(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(ctx, b"readU32() requires 1 argument\0".as_ptr() as *const _);
    }

    let addr = match get_addr_from_arg(ctx, JSValue(*argv)) {
        Some(a) => a,
        None => return ffi::JS_ThrowTypeError(ctx, b"Invalid pointer\0".as_ptr() as *const _),
    };

    let val = *(addr as *const u32);
    // Use BigInt for values that might overflow i32
    ffi::JS_NewBigUint64(ctx, val as u64)
}

/// Memory.readU64(ptr)
unsafe extern "C" fn memory_read_u64(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(ctx, b"readU64() requires 1 argument\0".as_ptr() as *const _);
    }

    let addr = match get_addr_from_arg(ctx, JSValue(*argv)) {
        Some(a) => a,
        None => return ffi::JS_ThrowTypeError(ctx, b"Invalid pointer\0".as_ptr() as *const _),
    };

    let val = *(addr as *const u64);
    ffi::JS_NewBigUint64(ctx, val)
}

/// Memory.readPointer(ptr)
unsafe extern "C" fn memory_read_pointer(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(ctx, b"readPointer() requires 1 argument\0".as_ptr() as *const _);
    }

    let addr = match get_addr_from_arg(ctx, JSValue(*argv)) {
        Some(a) => a,
        None => return ffi::JS_ThrowTypeError(ctx, b"Invalid pointer\0".as_ptr() as *const _),
    };

    let val = *(addr as *const u64);
    create_native_pointer(ctx, val).raw()
}

/// Memory.readCString(ptr)
unsafe extern "C" fn memory_read_cstring(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(ctx, b"readCString() requires 1 argument\0".as_ptr() as *const _);
    }

    let addr = match get_addr_from_arg(ctx, JSValue(*argv)) {
        Some(a) => a,
        None => return ffi::JS_ThrowTypeError(ctx, b"Invalid pointer\0".as_ptr() as *const _),
    };

    let cstr = std::ffi::CStr::from_ptr(addr as *const _);
    let s = cstr.to_string_lossy();
    JSValue::string(ctx, &s).raw()
}

/// Memory.readUtf8String(ptr)
unsafe extern "C" fn memory_read_utf8_string(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    // Same as readCString for now
    memory_read_cstring(ctx, _this, argc, argv)
}

/// Memory.readByteArray(ptr, length)
unsafe extern "C" fn memory_read_byte_array(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return ffi::JS_ThrowTypeError(ctx, b"readByteArray() requires 2 arguments\0".as_ptr() as *const _);
    }

    let addr = match get_addr_from_arg(ctx, JSValue(*argv)) {
        Some(a) => a,
        None => return ffi::JS_ThrowTypeError(ctx, b"Invalid pointer\0".as_ptr() as *const _),
    };

    let length = JSValue(*argv.add(1)).to_i64(ctx).unwrap_or(0) as usize;

    // Create ArrayBuffer
    let slice = std::slice::from_raw_parts(addr as *const u8, length);
    let arr = ffi::JS_NewArrayBufferCopy(ctx, slice.as_ptr(), length);
    arr
}

/// Memory.writeU8(ptr, value)
unsafe extern "C" fn memory_write_u8(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return ffi::JS_ThrowTypeError(ctx, b"writeU8() requires 2 arguments\0".as_ptr() as *const _);
    }

    let addr = match get_addr_from_arg(ctx, JSValue(*argv)) {
        Some(a) => a,
        None => return ffi::JS_ThrowTypeError(ctx, b"Invalid pointer\0".as_ptr() as *const _),
    };

    let val = JSValue(*argv.add(1)).to_i64(ctx).unwrap_or(0) as u8;
    *(addr as *mut u8) = val;
    JSValue::undefined().raw()
}

/// Memory.writeU16(ptr, value)
unsafe extern "C" fn memory_write_u16(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return ffi::JS_ThrowTypeError(ctx, b"writeU16() requires 2 arguments\0".as_ptr() as *const _);
    }

    let addr = match get_addr_from_arg(ctx, JSValue(*argv)) {
        Some(a) => a,
        None => return ffi::JS_ThrowTypeError(ctx, b"Invalid pointer\0".as_ptr() as *const _),
    };

    let val = JSValue(*argv.add(1)).to_i64(ctx).unwrap_or(0) as u16;
    *(addr as *mut u16) = val;
    JSValue::undefined().raw()
}

/// Memory.writeU32(ptr, value)
unsafe extern "C" fn memory_write_u32(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return ffi::JS_ThrowTypeError(ctx, b"writeU32() requires 2 arguments\0".as_ptr() as *const _);
    }

    let addr = match get_addr_from_arg(ctx, JSValue(*argv)) {
        Some(a) => a,
        None => return ffi::JS_ThrowTypeError(ctx, b"Invalid pointer\0".as_ptr() as *const _),
    };

    let val = JSValue(*argv.add(1)).to_i64(ctx).unwrap_or(0) as u32;
    *(addr as *mut u32) = val;
    JSValue::undefined().raw()
}

/// Memory.writeU64(ptr, value)
unsafe extern "C" fn memory_write_u64(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return ffi::JS_ThrowTypeError(ctx, b"writeU64() requires 2 arguments\0".as_ptr() as *const _);
    }

    let addr = match get_addr_from_arg(ctx, JSValue(*argv)) {
        Some(a) => a,
        None => return ffi::JS_ThrowTypeError(ctx, b"Invalid pointer\0".as_ptr() as *const _),
    };

    let val = JSValue(*argv.add(1)).to_u64(ctx).unwrap_or(0);
    *(addr as *mut u64) = val;
    JSValue::undefined().raw()
}

/// Memory.writePointer(ptr, value)
unsafe extern "C" fn memory_write_pointer(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    // Same as writeU64
    memory_write_u64(ctx, _this, argc, argv)
}

/// Register Memory API
pub fn register_memory_api(ctx: &JSContext) {
    let global = ctx.global_object();
    let memory = ctx.new_object();

    macro_rules! add_method {
        ($name:expr, $func:expr) => {
            unsafe {
                let cname = CString::new($name).unwrap();
                let func_val = ffi::qjs_new_cfunction(ctx.as_ptr(), Some($func), cname.as_ptr(), 0);
                let prop_name = CString::new($name).unwrap();
                let atom = ffi::JS_NewAtom(ctx.as_ptr(), prop_name.as_ptr());
                ffi::qjs_set_property(ctx.as_ptr(), memory.raw(), atom, func_val);
                ffi::JS_FreeAtom(ctx.as_ptr(), atom);
            }
        };
    }

    add_method!("readU8", memory_read_u8);
    add_method!("readU16", memory_read_u16);
    add_method!("readU32", memory_read_u32);
    add_method!("readU64", memory_read_u64);
    add_method!("readPointer", memory_read_pointer);
    add_method!("readCString", memory_read_cstring);
    add_method!("readUtf8String", memory_read_utf8_string);
    add_method!("readByteArray", memory_read_byte_array);
    add_method!("writeU8", memory_write_u8);
    add_method!("writeU16", memory_write_u16);
    add_method!("writeU32", memory_write_u32);
    add_method!("writeU64", memory_write_u64);
    add_method!("writePointer", memory_write_pointer);

    // Set Memory on global object
    global.set_property(ctx.as_ptr(), "Memory", memory);
    global.free(ctx.as_ptr());
}
