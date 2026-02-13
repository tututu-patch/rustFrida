//! Console API implementation

use crate::context::JSContext;
use crate::ffi;
use crate::value::JSValue;
use std::ffi::CString;
use std::sync::Mutex;

/// Callback type for console output
pub type ConsoleCallback = Box<dyn Fn(&str) + Send + 'static>;

/// Global console output callback
static CONSOLE_CALLBACK: Mutex<Option<ConsoleCallback>> = Mutex::new(None);

/// Set the console output callback
pub fn set_console_callback<F>(callback: F)
where
    F: Fn(&str) + Send + 'static,
{
    let mut guard = CONSOLE_CALLBACK.lock().unwrap();
    *guard = Some(Box::new(callback));
}

/// Clear the console callback
pub fn clear_console_callback() {
    let mut guard = CONSOLE_CALLBACK.lock().unwrap();
    *guard = None;
}

/// Internal function to output console message
fn output_message(msg: &str) {
    let guard = CONSOLE_CALLBACK.lock().unwrap();
    if let Some(callback) = guard.as_ref() {
        callback(msg);
    } else {
        // Default: print to stderr (for Android logcat)
        eprintln!("[JS] {}", msg);
    }
}

/// Format JS values for console output
fn format_args(ctx: *mut ffi::JSContext, argc: i32, argv: *mut ffi::JSValue) -> String {
    let mut parts = Vec::new();

    for i in 0..argc {
        let val = JSValue(unsafe { *argv.add(i as usize) });
        let s = val.to_string(ctx).unwrap_or_else(|| "[object]".to_string());
        parts.push(s);
    }

    parts.join(" ")
}

/// console.log implementation
unsafe extern "C" fn console_log(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let msg = format_args(ctx, argc, argv);
    output_message(&msg);
    JSValue::undefined().raw()
}

/// console.warn implementation
unsafe extern "C" fn console_warn(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let msg = format_args(ctx, argc, argv);
    output_message(&format!("[WARN] {}", msg));
    JSValue::undefined().raw()
}

/// console.error implementation
unsafe extern "C" fn console_error(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let msg = format_args(ctx, argc, argv);
    output_message(&format!("[ERROR] {}", msg));
    JSValue::undefined().raw()
}

/// console.info implementation
unsafe extern "C" fn console_info(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let msg = format_args(ctx, argc, argv);
    output_message(&format!("[INFO] {}", msg));
    JSValue::undefined().raw()
}

/// console.debug implementation
unsafe extern "C" fn console_debug(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let msg = format_args(ctx, argc, argv);
    output_message(&format!("[DEBUG] {}", msg));
    JSValue::undefined().raw()
}

/// Register console API on the context
pub fn register_console(ctx: &JSContext) {
    let global = ctx.global_object();
    let console = ctx.new_object();

    // Helper macro to add console methods
    macro_rules! add_method {
        ($name:expr, $func:expr) => {
            unsafe {
                let cname = CString::new($name).unwrap();
                let func_val = ffi::qjs_new_cfunction(ctx.as_ptr(), Some($func), cname.as_ptr(), 0);
                let prop_name = CString::new($name).unwrap();
                let atom = ffi::JS_NewAtom(ctx.as_ptr(), prop_name.as_ptr());
                ffi::qjs_set_property(ctx.as_ptr(), console.raw(), atom, func_val);
                ffi::JS_FreeAtom(ctx.as_ptr(), atom);
            }
        };
    }

    add_method!("log", console_log);
    add_method!("warn", console_warn);
    add_method!("error", console_error);
    add_method!("info", console_info);
    add_method!("debug", console_debug);

    // Set console on global object
    global.set_property(ctx.as_ptr(), "console", console);
    global.free(ctx.as_ptr());
}
