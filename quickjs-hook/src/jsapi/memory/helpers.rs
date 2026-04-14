//! Memory helper functions

use crate::ffi;
use crate::jsapi::ptr::get_native_pointer_addr;
use crate::jsapi::util::{proc_maps_entries, read_proc_self_maps};
use crate::value::JSValue;

/// Helper to get address from argument
pub(super) unsafe fn get_addr_from_arg(ctx: *mut ffi::JSContext, val: JSValue) -> Option<u64> {
    get_native_pointer_addr(ctx, val).or_else(|| val.to_u64(ctx))
}

/// 从 NativePointer this 或 argv[0] 取地址，返回 (addr, remaining_argv, remaining_argc)。
/// 适配两种调用风格:
///   - `Memory.readU32(addr)` → this 不是 NativePointer, addr = argv[0]
///   - `ptr(addr).readU32()` → this 是 NativePointer, addr = this
pub(super) unsafe fn get_addr_this_or_arg(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> Option<(u64, *mut ffi::JSValue, i32)> {
    // 先尝试从 this 取（NativePointer 方法风格）
    if let Some(addr) = get_native_pointer_addr(ctx, JSValue(this)) {
        return Some((addr, argv, argc));
    }
    // Fallback: Memory.readXxx(addr, ...) 风格，argv[0] 是地址
    if argc < 1 { return None; }
    let addr = get_addr_from_arg(ctx, JSValue(*argv))?;
    Some((addr, argv.add(1), argc - 1))
}

/// Parse page permissions for `addr` from /proc/self/maps.
/// Returns the libc PROT_* flags for the page, or `None` if not found.
fn get_page_prot(addr: u64) -> Option<i32> {
    let maps = read_proc_self_maps()?;
    let prot = proc_maps_entries(&maps)
        .find(|entry| entry.contains(addr))
        .map(|entry| entry.prot_flags());
    prot
}

/// Perform `write_fn` at `addr`, temporarily making the containing page(s) writable
/// if they are currently mapped R-X (e.g. code pages).
///
/// Returns `true` on success, `false` if mprotect fails.
pub(super) unsafe fn write_with_perm(addr: u64, size: usize, write_fn: impl FnOnce()) -> bool {
    let orig_prot = get_page_prot(addr);
    if orig_prot.map_or(true, |p| (p & libc::PROT_WRITE) != 0) {
        // Already writable (or can't determine)
        write_fn();
        return true;
    }
    let orig_prot = orig_prot.unwrap(); // safe: we checked Some above
                                        // Page is not writable. Temporarily add PROT_WRITE.
    const PAGE_SIZE: usize = 0x1000;
    let start_page = (addr as usize) & !(PAGE_SIZE - 1);
    // 计算写入是否跨页，只对需要的页进行 mprotect
    let end_page = ((addr as usize) + size - 1) & !(PAGE_SIZE - 1);
    let mprotect_len = if start_page == end_page {
        PAGE_SIZE
    } else {
        PAGE_SIZE * 2
    };
    if libc::mprotect(
        start_page as *mut libc::c_void,
        mprotect_len,
        orig_prot | libc::PROT_WRITE,
    ) != 0
    {
        return false;
    }
    write_fn();
    // 恢复原始权限，检查返回值
    if libc::mprotect(start_page as *mut libc::c_void, mprotect_len, orig_prot) != 0 {
        crate::jsapi::console::output_message(&format!(
            "[warn] mprotect 恢复权限失败: addr=0x{:x}, len=0x{:x}",
            start_page, mprotect_len
        ));
    }
    true
}
