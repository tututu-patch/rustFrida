//! Memory write operations

use super::helpers::{get_addr_this_or_arg, write_with_perm};
use crate::ffi;
use crate::jsapi::util::is_addr_accessible;
use crate::value::JSValue;

/// 生成 Memory.writeXXX(ptr, value) 和 ptr.writeXXX(value) 双风格 write 函数。
/// rem_argv 指向 value（自动剥离 Memory 风格的 addr 参数）。
macro_rules! define_memory_write {
    ($name:ident, $js_name:literal, $rust_type:ty, $size:expr,
     ($ctx_id:ident, $argv_id:ident) => $extract:expr) => {
        pub(super) unsafe extern "C" fn $name(
            $ctx_id: *mut ffi::JSContext,
            this: ffi::JSValue,
            argc: i32,
            argv: *mut ffi::JSValue,
        ) -> ffi::JSValue {
            let (addr, rem_argv, rem_argc) = match get_addr_this_or_arg($ctx_id, this, argc, argv) {
                Some(v) => v,
                None => return ffi::JS_ThrowTypeError(
                    $ctx_id,
                    concat!($js_name, "() requires a pointer\0").as_ptr() as *const _,
                ),
            };
            if rem_argc < 1 {
                return ffi::JS_ThrowTypeError(
                    $ctx_id,
                    concat!($js_name, "() requires value argument\0").as_ptr() as *const _,
                );
            }
            let $argv_id = rem_argv;
            if !is_addr_accessible(addr, $size) {
                return ffi::JS_ThrowRangeError($ctx_id, b"Invalid memory address\0".as_ptr() as *const _);
            }
            let val: $rust_type = $extract;
            if !write_with_perm(addr, $size, || {
                std::ptr::write_unaligned(addr as *mut $rust_type, val);
            }) {
                return ffi::JS_ThrowRangeError(
                    $ctx_id,
                    concat!($js_name, "(): cannot make page writable (mprotect failed)\0").as_ptr() as *const _,
                );
            }
            JSValue::undefined().raw()
        }
    };
}

define_memory_write!(memory_write_u8, "writeU8", u8, 1,
    (ctx, argv) => JSValue(*argv).to_i64(ctx).unwrap_or(0) as u8);
define_memory_write!(memory_write_u16, "writeU16", u16, 2,
    (ctx, argv) => JSValue(*argv).to_i64(ctx).unwrap_or(0) as u16);
define_memory_write!(memory_write_u32, "writeU32", u32, 4,
    (ctx, argv) => JSValue(*argv).to_i64(ctx).unwrap_or(0) as u32);
define_memory_write!(memory_write_u64, "writeU64", u64, 8,
    (ctx, argv) => JSValue(*argv).to_u64(ctx).unwrap_or(0));

/// Memory.writePointer(ptr, value) / ptr.writePointer(value)
pub(super) unsafe extern "C" fn memory_write_pointer(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    // Same as writeU64
    memory_write_u64(ctx, this, argc, argv)
}
