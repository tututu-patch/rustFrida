//! quickjs-hook - QuickJS JavaScript engine with inline hook support for ARM64 Android
//!
//! This crate provides:
//! - QuickJS JavaScript engine bindings
//! - ARM64 inline hook engine
//! - Frida-style JavaScript API for hooking
//!
//! # Example
//!
//! ```rust,ignore
//! use quickjs_hook::{JSEngine, init_hook_engine};
//!
//! // Initialize hook engine with executable memory
//! init_hook_engine(exec_mem, size).unwrap();
//!
//! // Create JS engine and run script
//! let engine = JSEngine::new().unwrap();
//! engine.eval(r#"
//!     console.log("Hello from QuickJS!");
//!     hook(ptr("0x12345678"), function(ctx) {
//!         console.log("Hooked! x0=" + ctx.x0);
//!     });
//! "#).unwrap();
//! ```

#![allow(clippy::missing_safety_doc)]

pub mod ffi;
pub mod runtime;
pub mod context;
pub mod value;
pub mod jsapi;

pub use context::JSContext;
pub use runtime::JSRuntime;
pub use value::JSValue;
pub use jsapi::console::set_console_callback;
pub use jsapi::hook_api::cleanup_hooks;

use std::sync::Mutex;

/// Global JS engine instance (protected by Mutex)
static JS_ENGINE: Mutex<Option<JSEngine>> = Mutex::new(None);

/// Initialize the hook engine with executable memory
///
/// # Arguments
/// * `exec_mem` - Pointer to executable memory region (must be RWX)
/// * `size` - Size of the memory region in bytes
///
/// # Returns
/// * `Ok(())` on success
/// * `Err(String)` on failure
pub fn init_hook_engine(exec_mem: *mut u8, size: usize) -> Result<(), String> {
    let result = unsafe {
        ffi::hook::hook_engine_init(exec_mem as *mut _, size)
    };

    if result == 0 {
        Ok(())
    } else {
        Err("Failed to initialize hook engine".to_string())
    }
}

/// Cleanup the hook engine
pub fn cleanup_hook_engine() {
    unsafe {
        ffi::hook::hook_engine_cleanup();
    }
}

/// High-level JS engine wrapper
/// Note: Field order matters for drop order - context must be dropped before runtime
pub struct JSEngine {
    context: JSContext,
    runtime: JSRuntime,
}

impl JSEngine {
    /// Create a new JS engine with all APIs registered
    pub fn new() -> Option<Self> {
        let runtime = JSRuntime::new()?;
        let context = runtime.new_context()?;

        // Register all JavaScript APIs
        jsapi::register_all_apis(&context);

        Some(JSEngine { runtime, context })
    }

    /// Evaluate a JavaScript script
    pub fn eval(&self, script: &str) -> Result<JSValue, String> {
        self.context.eval(script, "<eval>")
    }

    /// Evaluate a script with a specific filename
    pub fn eval_file(&self, script: &str, filename: &str) -> Result<JSValue, String> {
        self.context.eval(script, filename)
    }

    /// Get the JS context
    pub fn context(&self) -> &JSContext {
        &self.context
    }

    /// Get the JS runtime
    pub fn runtime(&self) -> &JSRuntime {
        &self.runtime
    }

    /// Execute pending jobs (for promises)
    pub fn run_pending_jobs(&self) {
        while self.context.execute_pending_job() {}
    }
}

impl Drop for JSEngine {
    fn drop(&mut self) {
        // Cleanup hooks before dropping context
        cleanup_hooks();
    }
}

// Safety: JSEngine is protected by Mutex, ensuring single-threaded access
unsafe impl Send for JSEngine {}
unsafe impl Sync for JSEngine {}

/// Get or initialize the global JS engine
pub fn get_or_init_engine() -> Result<(), String> {
    let mut engine = JS_ENGINE.lock().map_err(|e| format!("Failed to lock JS engine: {}", e))?;
    if engine.is_none() {
        *engine = Some(JSEngine::new().ok_or_else(|| "Failed to create JS engine".to_string())?);
    }
    Ok(())
}

/// Load and execute a JavaScript script using the global engine
pub fn load_script(script: &str) -> Result<(), String> {
    let mut engine = JS_ENGINE.lock().map_err(|e| format!("Failed to lock JS engine: {}", e))?;
    if engine.is_none() {
        *engine = Some(JSEngine::new().ok_or_else(|| "Failed to create JS engine".to_string())?);
    }
    let engine = engine.as_ref().ok_or("JS engine not initialized")?;
    engine.eval(script)?;
    engine.run_pending_jobs();
    Ok(())
}

/// Cleanup the global JS engine
pub fn cleanup_engine() {
    if let Ok(mut engine) = JS_ENGINE.lock() {
        *engine = None;
    }
}

/// Get completion candidates for a given prefix from the global JS engine.
///
/// Evaluates `Object.keys(globalThis)` (and prototype chain via a helper) in the
/// running engine and returns all property names that start with `prefix`.
/// Returns an empty vec if the engine is not initialised or on any error.
pub fn complete_script(prefix: &str) -> Vec<String> {
    let engine = match JS_ENGINE.lock() {
        Ok(g) => g,
        Err(_) => return vec![],
    };
    let engine = match engine.as_ref() {
        Some(e) => e,
        None => return vec![],
    };

    let script = r#"
        (function() {
            var names = [];
            var obj = globalThis;
            while (obj !== null && obj !== undefined) {
                try {
                    var keys = Object.getOwnPropertyNames(obj);
                    for (var i = 0; i < keys.length; i++) { names.push(keys[i]); }
                } catch(e) {}
                obj = Object.getPrototypeOf(obj);
            }
            return JSON.stringify(names);
        })()
    "#;

    let result = match engine.eval(script) {
        Ok(v) => v,
        Err(_) => return vec![],
    };

    let json_str = match result.to_string(engine.context().as_ptr()) {
        Some(s) => s,
        None => {
            result.free(engine.context().as_ptr());
            return vec![];
        },
    };
    result.free(engine.context().as_ptr());

    // Parse the JSON array manually (avoid pulling in serde just for this)
    let trimmed = json_str.trim().trim_start_matches('[').trim_end_matches(']');
    if trimmed.is_empty() {
        return vec![];
    }

    let prefix_lower = prefix.to_lowercase();
    let mut candidates: Vec<String> = trimmed
        .split(',')
        .filter_map(|s| {
            let s = s.trim().trim_matches('"');
            if s.is_empty() { None } else { Some(s.to_string()) }
        })
        .filter(|name| name.to_lowercase().starts_with(&prefix_lower))
        .collect();

    // Deduplicate while preserving order
    candidates.sort();
    candidates.dedup();
    candidates
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_creation() {
        // This test may fail if QuickJS is not built
        // It's mainly for development verification
    }
}
