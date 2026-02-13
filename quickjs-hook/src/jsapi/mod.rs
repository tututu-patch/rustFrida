//! JavaScript API implementations

pub mod console;
pub mod hook_api;
pub mod memory;
pub mod ptr;

pub use console::register_console;
pub use hook_api::register_hook_api;
pub use memory::register_memory_api;
pub use ptr::register_ptr;

use crate::context::JSContext;

/// Register all JavaScript APIs
pub fn register_all_apis(ctx: &JSContext) {
    register_console(ctx);
    register_ptr(ctx);
    register_hook_api(ctx);
    register_memory_api(ctx);
}
