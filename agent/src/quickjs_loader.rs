//! QuickJS loader module for the agent
//!
//! This module provides JavaScript loading and execution capabilities
//! using the quickjs-hook crate.

#![cfg(feature = "quickjs")]

use quickjs_hook::{init_hook_engine, load_script, set_console_callback, cleanup_hook_engine, cleanup_hooks, cleanup_engine};
use std::sync::OnceLock;
use std::io::Write;
use libc::{mmap, munmap, PROT_READ, PROT_WRITE, PROT_EXEC, MAP_PRIVATE, MAP_ANONYMOUS, sysconf, _SC_PAGESIZE};
use std::ptr;

use crate::{GLOBAL_STREAM, log_msg};

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
    // Allocate executable memory for hooks (64KB)
    let exec_mem = EXEC_MEM.get_or_init(|| {
        ExecMemory::new(64 * 1024).expect("Failed to allocate executable memory")
    });

    // Initialize hook engine
    init_hook_engine(exec_mem.as_ptr(), exec_mem.size())?;

    // Set up console callback to send output to socket
    set_console_callback(|msg| {
        if let Some(mut stream) = GLOBAL_STREAM.get() {
            let _ = stream.write_all(format!("[JS] {}\n", msg).as_bytes());
        }
    });

    log_msg("[quickjs] Initialized successfully\n".to_string());
    Ok(())
}

/// Load and execute a JavaScript script
///
/// # Arguments
/// * `script` - The JavaScript code to execute
///
/// # Returns
/// * `Ok(())` on success
/// * `Err(String)` with error message on failure
pub fn execute_script(script: &str) -> Result<(), String> {
    // Ensure engine is initialized
    if EXEC_MEM.get().is_none() {
        init()?;
    }

    load_script(script)
}

/// Cleanup QuickJS resources
pub fn cleanup() {
    cleanup_engine();      // 销毁 JSEngine (context + runtime)
    cleanup_hooks();       // 清理所有 hooks
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
