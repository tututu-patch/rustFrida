//! Memory write operations

use super::helpers::{get_addr_from_arg, write_with_perm};
use crate::ffi;
use crate::jsapi::util::is_addr_accessible;
use crate::value::JSValue;

/// 生成标准 Memory.writeXXX(ptr, value) 函数。
/// 使用 `($ctx, $argv) => expr` 语法传递 ctx 和 argv 到值提取表达式。
macro_rules! define_memory_write {
    ($name:ident, $js_name:literal, $rust_type:ty, $size:expr,
     ($ctx_id:ident, $argv_id:ident) => $extract:expr) => {
        pub(super) unsafe extern "C" fn $name(
            $ctx_id: *mut ffi::JSContext,
            _this: ffi::JSValue,
            argc: i32,
            $argv_id: *mut ffi::JSValue,
        ) -> ffi::JSValue {
            if argc < 2 {
                return ffi::JS_ThrowTypeError(
                    $ctx_id,
                    concat!($js_name, "() requires 2 arguments\0").as_ptr() as *const _,
                );
            }
            let addr = match get_addr_from_arg($ctx_id, JSValue(*$argv_id)) {
                Some(a) => a,
                None => return ffi::JS_ThrowTypeError($ctx_id, b"Invalid pointer\0".as_ptr() as *const _),
            };
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
    (ctx, argv) => JSValue(*argv.add(1)).to_i64(ctx).unwrap_or(0) as u8);
define_memory_write!(memory_write_u16, "writeU16", u16, 2,
    (ctx, argv) => JSValue(*argv.add(1)).to_i64(ctx).unwrap_or(0) as u16);
define_memory_write!(memory_write_u32, "writeU32", u32, 4,
    (ctx, argv) => JSValue(*argv.add(1)).to_i64(ctx).unwrap_or(0) as u32);
define_memory_write!(memory_write_u64, "writeU64", u64, 8,
    (ctx, argv) => JSValue(*argv.add(1)).to_u64(ctx).unwrap_or(0));

/// Memory.writePointer(ptr, value)
pub(super) unsafe extern "C" fn memory_write_pointer(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    // Same as writeU64
    memory_write_u64(ctx, _this, argc, argv)
}
