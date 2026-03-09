// ============================================================================
// /proc/self/maps parsing
// ============================================================================

/// Parse /proc/self/maps to find the libart.so address range and file path.
pub(crate) fn probe_libart_range() -> (u64, u64) {
    let maps = match super::util::read_proc_self_maps() {
        Some(s) => s,
        None => return (0, 0),
    };

    let mut range_start: u64 = u64::MAX;
    let mut range_end: u64 = 0;
    let mut found_path: Option<String> = None;

    for line in maps.lines() {
        if !line.contains("libart.so") {
            continue;
        }
        let addr_part = match line.split_whitespace().next() {
            Some(a) => a,
            None => continue,
        };
        let mut parts = addr_part.split('-');
        let start = parts.next().and_then(|s| u64::from_str_radix(s, 16).ok());
        let end = parts.next().and_then(|s| u64::from_str_radix(s, 16).ok());

        if let (Some(s), Some(e)) = (start, end) {
            if s < range_start {
                range_start = s;
            }
            if e > range_end {
                range_end = e;
            }
        }

        if found_path.is_none() {
            if let Some(path) = line.split_whitespace().last() {
                if path.contains("libart.so") {
                    found_path = Some(path.to_string());
                }
            }
        }
    }

    let _ = LIBART_PATH.set(found_path.clone());

    if range_start == u64::MAX {
        (0, 0)
    } else {
        output_message(&format!(
            "[module] libart.so range: {:#x}-{:#x}, path: {:?}",
            range_start, range_end, found_path
        ));
        (range_start, range_end)
    }
}

/// 通过 /proc/self/maps 获取指定模块的地址范围 (start, end)。
/// 返回 (0, 0) 表示未找到。
pub(crate) fn probe_module_range(module_name: &str) -> (u64, u64) {
    let maps = match super::util::read_proc_self_maps() {
        Some(s) => s,
        None => return (0, 0),
    };

    let mut range_start: u64 = u64::MAX;
    let mut range_end: u64 = 0;

    for line in maps.lines() {
        if !line.contains(module_name) {
            continue;
        }
        // Verify the path field actually contains the module name
        let path = match line.split_whitespace().last() {
            Some(p) if p.contains(module_name) => p,
            _ => continue,
        };
        let basename = path.rsplit('/').next().unwrap_or(path);
        if basename != module_name {
            continue;
        }

        let addr_part = match line.split_whitespace().next() {
            Some(a) => a,
            None => continue,
        };
        let mut parts = addr_part.split('-');
        let start = parts.next().and_then(|s| u64::from_str_radix(s, 16).ok());
        let end = parts.next().and_then(|s| u64::from_str_radix(s, 16).ok());

        if let (Some(s), Some(e)) = (start, end) {
            if s < range_start {
                range_start = s;
            }
            if e > range_end {
                range_end = e;
            }
        }
    }

    if range_start == u64::MAX {
        (0, 0)
    } else {
        (range_start, range_end)
    }
}

/// Parse /proc/self/maps to find a module's base address.
fn find_module_base(module_name: &str) -> u64 {
    let maps = match super::util::read_proc_self_maps() {
        Some(s) => s,
        None => return 0,
    };

    for line in maps.lines() {
        if !line.contains(module_name) {
            continue;
        }
        // Only match lines where the path field actually contains the module name
        let path = match line.split_whitespace().last() {
            Some(p) if p.contains(module_name) => p,
            _ => continue,
        };
        // Verify exact filename match (avoid "libfoo.so" matching "libfoo.so.1")
        let basename = path.rsplit('/').next().unwrap_or(path);
        if basename != module_name && !basename.starts_with(&format!("{}.", module_name)) {
            // Also check if module_name is a path suffix
            if !path.ends_with(module_name) {
                continue;
            }
        }

        let addr_part = match line.split_whitespace().next() {
            Some(a) => a,
            None => continue,
        };
        if let Some(start) = addr_part
            .split('-')
            .next()
            .and_then(|s| u64::from_str_radix(s, 16).ok())
        {
            return start;
        }
    }
    0
}

/// Module info from /proc/self/maps
struct ModuleInfo {
    name: String,
    base: u64,
    size: u64,
    path: String,
}

/// Parse /proc/self/maps and aggregate VMAs per unique path.
fn enumerate_modules_from_maps() -> Vec<ModuleInfo> {
    let maps = match super::util::read_proc_self_maps() {
        Some(s) => s,
        None => return Vec::new(),
    };

    // Collect (path -> (min_start, max_end)) using insertion-order Vec
    let mut modules: Vec<(String, u64, u64)> = Vec::new();

    for line in maps.lines() {
        let mut fields = line.split_whitespace();
        let addr_part = match fields.next() {
            Some(a) => a,
            None => continue,
        };
        // Skip non-file mappings (no path field, or path starts with '[')
        // fields: perms, offset, dev, inode, path
        let _perms = fields.next();
        let _offset = fields.next();
        let _dev = fields.next();
        let _inode = fields.next();
        let path = match fields.next() {
            Some(p) if !p.starts_with('[') && p.contains('/') => p,
            _ => continue,
        };

        let mut parts = addr_part.split('-');
        let start = match parts.next().and_then(|s| u64::from_str_radix(s, 16).ok()) {
            Some(s) => s,
            None => continue,
        };
        let end = match parts.next().and_then(|s| u64::from_str_radix(s, 16).ok()) {
            Some(e) => e,
            None => continue,
        };

        // Find or insert
        if let Some(entry) = modules.iter_mut().find(|(p, _, _)| p == path) {
            if start < entry.1 {
                entry.1 = start;
            }
            if end > entry.2 {
                entry.2 = end;
            }
        } else {
            modules.push((path.to_string(), start, end));
        }
    }

    modules
        .into_iter()
        .map(|(path, base, end)| {
            let name = path.rsplit('/').next().unwrap_or(&path).to_string();
            ModuleInfo {
                name,
                base,
                size: end - base,
                path,
            }
        })
        .collect()
}
