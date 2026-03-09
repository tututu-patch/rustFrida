// ============================================================================
// ELF symbol lookup — Frida-style (gum_elf_module)
//
// Strategy: file from disk first, memory at base_address as fallback.
// One read, one pass through .symtab, batch-extract all needed symbols.
//
// Reference: gumelfmodule.c — gum_elf_module_load_file_data():
//   1. g_mapped_file_new(path) → mmap from disk
//   2. If file not readable (ONLINE mode) → use base_address as data pointer
// ============================================================================

/// Batch lookup symbols from an ELF module's .symtab.
///
/// Strategy (Frida-style, gum_elf_module):
/// 1. Try read file from disk → parse .symtab in one pass
/// 2. If file not accessible → read from in-memory ELF mapping at base_address
///
/// Returns HashMap of found symbols: name -> runtime_address (load_bias applied).
unsafe fn elf_module_find_symbols(
    file_path: &str,
    base_address: u64,
    wanted: &[&str],
) -> HashMap<String, u64> {
    if wanted.is_empty() {
        return HashMap::new();
    }

    let wanted_set: HashSet<&str> = wanted.iter().copied().collect();
    let mut result = HashMap::new();

    // Compute load_bias from in-memory program headers
    let load_bias = elf_compute_load_bias(base_address);

    // Strategy 1: read file from disk (one read, one pass)
    if let Ok(data) = std::fs::read(file_path) {
        elf_find_symbols_in_data(&data, &wanted_set, load_bias, &mut result);
        if !result.is_empty() {
            return result;
        }
    }

    // Strategy 2: read from in-memory ELF at base_address (Frida fallback)
    output_message(&format!(
        "[module] file read failed for {}, trying memory at {:#x}",
        file_path, base_address
    ));
    elf_find_symbols_in_memory(base_address, &wanted_set, load_bias, &mut result);

    result
}

/// Compute load_bias from in-memory ELF at base_address.
/// load_bias = base_address - first_PT_LOAD.p_vaddr
unsafe fn elf_compute_load_bias(base_address: u64) -> u64 {
    if base_address == 0 {
        return 0;
    }
    let ehdr = &*(base_address as *const Elf64Ehdr);
    if ehdr.e_ident[0..4] != *b"\x7fELF" || ehdr.e_ident[4] != 2 {
        return base_address;
    }
    let phdr_base = base_address + ehdr.e_phoff;
    for i in 0..ehdr.e_phnum as u64 {
        let phdr = &*((phdr_base + i * ehdr.e_phentsize as u64) as *const Elf64Phdr);
        if phdr.p_type == PT_LOAD {
            return base_address.wrapping_sub(phdr.p_vaddr);
        }
    }
    base_address
}

/// Find symbols in .symtab from file data (byte slice). One pass.
fn elf_find_symbols_in_data(
    data: &[u8],
    wanted: &HashSet<&str>,
    load_bias: u64,
    result: &mut HashMap<String, u64>,
) {
    if data.len() < std::mem::size_of::<Elf64Ehdr>() {
        return;
    }

    unsafe {
        let ehdr = &*(data.as_ptr() as *const Elf64Ehdr);
        if ehdr.e_ident[0..4] != *b"\x7fELF" || ehdr.e_ident[4] != 2 {
            return;
        }

        let shdr_off = ehdr.e_shoff as usize;
        let shdr_size = std::mem::size_of::<Elf64Shdr>();
        let shnum = ehdr.e_shnum as usize;

        if shdr_off == 0 || shdr_off + shnum * shdr_size > data.len() {
            return;
        }

        // Find SHT_SYMTAB
        let mut symtab_shdr: Option<&Elf64Shdr> = None;
        for i in 0..shnum {
            let shdr = &*(data.as_ptr().add(shdr_off + i * shdr_size) as *const Elf64Shdr);
            if shdr.sh_type == SHT_SYMTAB {
                symtab_shdr = Some(shdr);
                break;
            }
        }

        let symtab = match symtab_shdr {
            Some(s) => s,
            None => return,
        };

        let strtab_idx = symtab.sh_link as usize;
        if strtab_idx >= shnum {
            return;
        }
        let strtab_shdr =
            &*(data.as_ptr().add(shdr_off + strtab_idx * shdr_size) as *const Elf64Shdr);
        if strtab_shdr.sh_type != SHT_STRTAB {
            return;
        }

        let strtab_off = strtab_shdr.sh_offset as usize;
        let strtab_size = strtab_shdr.sh_size as usize;
        if strtab_off + strtab_size > data.len() {
            return;
        }

        let symtab_off = symtab.sh_offset as usize;
        let sym_size = if symtab.sh_entsize > 0 {
            symtab.sh_entsize as usize
        } else {
            std::mem::size_of::<Elf64Sym>()
        };
        let nsyms = symtab.sh_size as usize / sym_size;

        if symtab_off + nsyms * sym_size > data.len() {
            return;
        }

        let mut remaining = wanted.len();

        for idx in 0..nsyms {
            if remaining == 0 {
                break;
            }

            let sym = &*(data.as_ptr().add(symtab_off + idx * sym_size) as *const Elf64Sym);
            if sym.st_name == 0 || sym.st_value == 0 {
                continue;
            }

            let name_off = strtab_off + sym.st_name as usize;
            if name_off >= strtab_off + strtab_size {
                continue;
            }

            // Read null-terminated name
            let name_slice = &data[name_off..strtab_off + strtab_size];
            let name_len = name_slice.iter().position(|&b| b == 0).unwrap_or(0);
            if name_len == 0 {
                continue;
            }

            if let Ok(name) = std::str::from_utf8(&name_slice[..name_len]) {
                if wanted.contains(name) && !result.contains_key(name) {
                    result.insert(name.to_string(), load_bias + sym.st_value);
                    remaining -= 1;
                }
            }
        }
    }
}

/// Find symbols in .symtab from in-memory ELF at base_address.
///
/// Fallback when file is not readable on disk.
/// Uses mincore(2) to check page accessibility before each read.
///
/// Reference: gumelfmodule.c line 570-572 — ONLINE mode fallback:
///   self->file_bytes = g_bytes_new_static(base_address, G_MAXSIZE - base_address)
unsafe fn elf_find_symbols_in_memory(
    base_address: u64,
    wanted: &HashSet<&str>,
    load_bias: u64,
    result: &mut HashMap<String, u64>,
) {
    if base_address == 0 {
        return;
    }

    // Check ELF header accessible
    if !is_addr_accessible(base_address, std::mem::size_of::<Elf64Ehdr>()) {
        return;
    }

    let ehdr = &*(base_address as *const Elf64Ehdr);
    if ehdr.e_ident[0..4] != *b"\x7fELF" || ehdr.e_ident[4] != 2 {
        return;
    }

    let shdr_size = std::mem::size_of::<Elf64Shdr>();
    let shnum = ehdr.e_shnum as usize;
    let shdr_addr = base_address + ehdr.e_shoff;

    // Check section headers accessible
    if !is_addr_accessible(shdr_addr, shnum * shdr_size) {
        output_message("[module] section headers not accessible in memory");
        return;
    }

    // Find SHT_SYMTAB
    let mut symtab_shdr: Option<Elf64ShdrCopy> = None;
    for i in 0..shnum {
        let shdr = &*((shdr_addr as usize + i * shdr_size) as *const Elf64Shdr);
        if shdr.sh_type == SHT_SYMTAB {
            symtab_shdr = Some(Elf64ShdrCopy {
                sh_offset: shdr.sh_offset,
                sh_size: shdr.sh_size,
                sh_link: shdr.sh_link,
                sh_entsize: shdr.sh_entsize,
            });
            break;
        }
    }

    let symtab = match symtab_shdr {
        Some(s) => s,
        None => {
            output_message("[module] .symtab not found in memory ELF");
            return;
        }
    };

    let strtab_idx = symtab.sh_link as usize;
    if strtab_idx >= shnum {
        return;
    }
    let strtab_shdr = &*((shdr_addr as usize + strtab_idx * shdr_size) as *const Elf64Shdr);
    if strtab_shdr.sh_type != SHT_STRTAB {
        return;
    }

    // Check .symtab and .strtab data accessible
    let symtab_data_addr = base_address + symtab.sh_offset;
    let strtab_data_addr = base_address + strtab_shdr.sh_offset;

    let sym_size = if symtab.sh_entsize > 0 {
        symtab.sh_entsize as usize
    } else {
        std::mem::size_of::<Elf64Sym>()
    };
    let nsyms = symtab.sh_size as usize / sym_size;
    let strtab_size = strtab_shdr.sh_size as usize;

    if !is_addr_accessible(symtab_data_addr, nsyms * sym_size) {
        output_message("[module] .symtab data not accessible in memory");
        return;
    }
    if !is_addr_accessible(strtab_data_addr, strtab_size) {
        output_message("[module] .strtab data not accessible in memory");
        return;
    }

    output_message(&format!(
        "[module] reading .symtab from memory: {} symbols",
        nsyms
    ));

    let mut remaining = wanted.len();

    for idx in 0..nsyms {
        if remaining == 0 {
            break;
        }

        let sym = &*((symtab_data_addr as usize + idx * sym_size) as *const Elf64Sym);
        if sym.st_name == 0 || sym.st_value == 0 {
            continue;
        }

        let name_off = sym.st_name as usize;
        if name_off >= strtab_size {
            continue;
        }

        let name_ptr = (strtab_data_addr as usize + name_off) as *const u8;
        let max_len = strtab_size - name_off;
        let name_slice = std::slice::from_raw_parts(name_ptr, max_len);
        let name_len = name_slice.iter().position(|&b| b == 0).unwrap_or(0);
        if name_len == 0 {
            continue;
        }

        if let Ok(name) = std::str::from_utf8(&name_slice[..name_len]) {
            if wanted.contains(name) && !result.contains_key(name) {
                result.insert(name.to_string(), load_bias + sym.st_value);
                remaining -= 1;
            }
        }
    }
}

/// Minimal copy of Elf64Shdr fields needed for .symtab processing.
/// Avoids holding a reference into memory that might be invalidated.
struct Elf64ShdrCopy {
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    sh_entsize: u64,
}
