//! QuickJS loader module for the agent
//!
//! This module provides JavaScript loading and execution capabilities
//! using the quickjs-hook crate.

#![cfg(feature = "quickjs")]

use libc::{
    mmap, munmap, sysconf, MAP_ANONYMOUS, MAP_PRIVATE, PROT_EXEC, PROT_READ, PROT_WRITE,
    _SC_PAGESIZE,
};
use quickjs_hook::{
    cleanup_engine, cleanup_hook_engine, cleanup_hooks, complete_script, get_or_init_engine,
    init_hook_engine, load_script, set_console_callback,
};
use std::io::Write;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

static ENGINE_INITIALIZED: AtomicBool = AtomicBool::new(false);

use crate::{log_msg, GLOBAL_STREAM};

/// Executable memory for hooks
static EXEC_MEM: OnceLock<ExecMemory> = OnceLock::new();

/// Executable memory region wrapper
struct ExecMemory {
    ptr: *mut u8,
    size: usize,
}

impl ExecMemory {
    /// Allocate new executable memory
    fn new(size: usize) -> Option<Self> {
        let page_size = unsafe { sysconf(_SC_PAGESIZE) as usize };
        let alloc_size = ((size + page_size - 1) / page_size) * page_size;

        unsafe {
            let ptr = mmap(
                ptr::null_mut(),
                alloc_size,
                PROT_READ | PROT_WRITE | PROT_EXEC,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0,
            );

            if ptr == libc::MAP_FAILED {
                return None;
            }

            Some(ExecMemory {
                ptr: ptr as *mut u8,
                size: alloc_size,
            })
        }
    }

    fn as_ptr(&self) -> *mut u8 {
        self.ptr
    }

    fn size(&self) -> usize {
        self.size
    }
}

impl Drop for ExecMemory {
    fn drop(&mut self) {
        unsafe {
            munmap(self.ptr as *mut _, self.size);
        }
    }
}

// Safety: ExecMemory is only accessed from the JS thread
unsafe impl Send for ExecMemory {}
unsafe impl Sync for ExecMemory {}

/// Initialize the QuickJS engine and hook system
pub fn init() -> Result<(), String> {
    if ENGINE_INITIALIZED.load(Ordering::SeqCst) {
        return Err("JS 引擎已初始化".to_string());
    }

    // Allocate executable memory for hooks (64KB)
    let exec_mem = EXEC_MEM
        .get_or_init(|| ExecMemory::new(64 * 1024).expect("Failed to allocate executable memory"));

    // Initialize hook engine
    init_hook_engine(exec_mem.as_ptr(), exec_mem.size())?;

    // 初始化 JS 引擎（complete_script 依赖它）
    get_or_init_engine()?;

    // Set up console callback to send output to socket
    set_console_callback(|msg| {
        if let Some(mut stream) = GLOBAL_STREAM.get() {
            let _ = stream.write_all(format!("[JS] {}\n", msg).as_bytes());
        }
    });

    ENGINE_INITIALIZED.store(true, Ordering::SeqCst);
    log_msg("[quickjs] Initialized successfully\n".to_string());

    Ok(())
}

/// Load and execute a JavaScript script
///
/// # Arguments
/// * `script` - The JavaScript code to execute
///
/// # Returns
/// * `Ok(String)` with the result string (empty for `undefined`) on success
/// * `Err(String)` with error message on failure
pub fn execute_script(script: &str) -> Result<String, String> {
    if !ENGINE_INITIALIZED.load(Ordering::SeqCst) {
        return Err("JS 引擎未初始化，请先执行 jsinit".to_string());
    }

    load_script(script)
}

/// Get tab-completion candidates for the given prefix from the live JS engine.
///
/// Returns a newline-joined string of matching property names, or an empty string
/// if the engine is not initialised.
pub fn complete(prefix: &str) -> String {
    if !ENGINE_INITIALIZED.load(Ordering::SeqCst) {
        return String::new();
    }
    let candidates = complete_script(prefix);
    candidates.join("\n")
}

/// 检查 JS 引擎是否已初始化
pub fn is_initialized() -> bool {
    ENGINE_INITIALIZED.load(Ordering::SeqCst)
}

/// Cleanup QuickJS resources
pub fn cleanup() {
    ENGINE_INITIALIZED.store(false, Ordering::SeqCst);
    cleanup_engine(); // 销毁 JSEngine (context + runtime)
    cleanup_hooks(); // 清理所有 hooks
    cleanup_hook_engine(); // 清理 hook 引擎内存
    log_msg("[quickjs] Cleanup complete\n".to_string());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init() {
        // Test initialization (may fail without proper environment)
    }
}
