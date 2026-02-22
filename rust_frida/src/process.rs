#![cfg(all(target_os = "android", target_arch = "aarch64"))]

use libc::{c_int, c_void, iovec, pid_t, PTRACE_CONT, PTRACE_GETREGSET, PTRACE_SETREGSET};
use nix::errno::Errno;
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::Pid;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::mem::size_of_val;
use std::path::Path;
use std::process;

use crate::log_success;
use crate::types::UserRegs;

/// 获取指定库的基址
///
/// # 参数
/// * `pid`      - 进程ID，`None` 表示查询当前进程
/// * `lib_name` - 要查找的库名称（如 "libc.so"、"libdl.so"）
pub(crate) fn get_lib_base(pid: Option<i32>, lib_name: &str) -> Result<usize, String> {
    let maps_path = match pid {
        Some(pid) => format!("/proc/{}/maps", pid),
        None => "/proc/self/maps".to_string(),
    };

    if !Path::new(&maps_path).exists() {
        return Err(format!("进程 {} 不存在", pid.unwrap_or(-1)));
    }

    let file = File::open(&maps_path).map_err(|e| format!("无法打开maps文件: {}", e))?;
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let line = line.map_err(|e| format!("读取maps文件失败: {}", e))?;
        if line.contains(lib_name) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some(addr_range) = parts.get(0) {
                if let Some(start_addr) = addr_range.split('-').next() {
                    return usize::from_str_radix(start_addr, 16)
                        .map_err(|e| format!("解析地址失败: {}", e));
                }
            }
        }
    }

    Err(format!(
        "未找到进程 {} 的{}加载地址",
        pid.unwrap_or(-1),
        lib_name
    ))
}

pub(crate) fn attach_to_process(pid: i32) -> Result<(), String> {
    let target_pid = Pid::from_raw(pid);

    // 尝试附加到目标进程
    match ptrace::attach(target_pid) {
        Ok(_) => {
            log_success!("成功附加到进程 {}，等待 SIGSTOP...", pid);
            match waitpid(target_pid, None) {
                Ok(WaitStatus::Stopped(_, _)) => {
                    log_success!("进程已停止，可以操作寄存器");
                    Ok(())
                }
                other => Err(format!("waitpid 状态异常: {:?}", other)),
            }
        }
        Err(errno) => {
            let err_msg = match errno {
                Errno::EPERM => "权限不足，请使用root权限运行",
                Errno::ESRCH => "目标进程不存在",
                _ => "附加失败，未知错误",
            };
            Err(err_msg.to_string())
        }
    }
}

/// 获取进程寄存器
fn get_registers(pid: i32) -> Result<UserRegs, String> {
    let mut regs = UserRegs::default();
    let mut iov = iovec {
        iov_base: &mut regs as *mut _ as *mut c_void,
        iov_len: size_of_val(&mut regs),
    };
    let result = unsafe {
        libc::ptrace(
            PTRACE_GETREGSET,
            pid as pid_t,
            1, // 通用寄存器
            &mut iov as *mut _ as *mut c_void,
        )
    };

    if result == -1 {
        let errno = unsafe { *libc::__errno() };
        return Err(format!("获取寄存器失败，错误码: {}", errno));
    }
    Ok(regs)
}

/// 设置进程寄存器
fn set_registers(pid: i32, regs: &UserRegs) -> Result<(), String> {
    let mut iov = iovec {
        iov_base: regs as *const _ as *mut c_void,
        iov_len: size_of_val(regs),
    };
    let result = unsafe {
        libc::ptrace(
            PTRACE_SETREGSET,
            pid as pid_t,
            1,
            &mut iov as *mut _ as *mut c_void,
        )
    };
    if result == -1 {
        let errno = unsafe { *libc::__errno() };
        return Err(format!("设置寄存器失败，错误码: {}", errno));
    }
    Ok(())
}

/// 调用目标进程的 libc 函数
///
/// # 参数
/// * `pid` - 目标进程ID
/// * `func_addr` - 要调用的函数地址
/// * `args` - 函数参数列表
///
/// # 返回值
/// * `Ok(usize)` - 函数返回值
/// * `Err(String)` - 错误信息
pub(crate) fn call_target_function(
    pid: i32,
    func_addr: usize,
    args: &[usize],
    debug: Option<bool>,
) -> Result<usize, String> {
    // 获取当前寄存器状态
    let orig_regs = get_registers(pid)?;

    // 设置新的寄存器状态
    let mut new_regs = orig_regs;

    // 设置参数寄存器（ARM64 使用 X0-X7 寄存器传递参数）
    for (i, &arg) in args.iter().enumerate() {
        if i < 8 {
            new_regs.regs[i] = arg as u64;
        } else {
            break;
        }
    }

    // 设置返回地址为 0x340
    new_regs.regs[30] = 0x340; // X30 是链接寄存器 (LR)

    // 设置 PC 指向函数地址
    new_regs.pc = func_addr as u64;

    // 写入新寄存器值
    set_registers(pid, &new_regs)?;

    // 继续执行
    if debug.unwrap_or(false) {
        let _ = ptrace::cont(Pid::from_raw(pid), Some(Signal::SIGSTOP));
        process::exit(1);
    }
    let result = unsafe { libc::ptrace(PTRACE_CONT as c_int, pid as pid_t, 0, 0) };

    if result == -1 {
        return Err(format!("继续执行失败，错误码: {}", unsafe {
            *libc::__errno()
        }));
    }

    // 等待进程停止
    let target_pid = Pid::from_raw(pid);
    match waitpid(target_pid, None).map_err(|e| format!("等待进程失败: {}", e))? {
        WaitStatus::Stopped(_, Signal::SIGSEGV) => {
            // 获取寄存器，检查 PC 是否为预期值
            let regs = get_registers(pid)?;

            if regs.pc == 0x340 {
                // 函数执行完成，获取返回值（ARM64 使用 X0 寄存器返回值）
                let return_value = regs.regs[0] as usize;

                // 恢复原始寄存器状态
                set_registers(pid, &orig_regs)?;

                Ok(return_value)
            } else {
                Err(format!("函数执行异常，PC = 0x{:x}", regs.pc))
            }
        }
        status => Err(format!("进程异常停止: {:?}", status)),
    }
}

/// 向远程进程内存写入任意类型的数据
///
/// # 参数
/// * `pid` - 目标进程ID
/// * `addr` - 目标地址
/// * `data` - 要写入的数据指针
/// * `size` - 数据大小（字节数）
fn write_remote_mem(pid: i32, addr: usize, data: *const u8, size: usize) -> Result<(), String> {
    // 去掉 MTE 标签位（高 byte），ptrace 不支持带标签的地址
    let addr = addr & 0x00FFFFFFFFFFFFFF;
    let mut offset = 0;
    while offset < size {
        let remaining = size - offset;
        let write_size = if remaining >= 8 { 8 } else { remaining };

        // 非对齐尾部（< 8 字节）：先 PEEKTEXT 读取原始 8 字节，再 merge 新字节，
        // 避免 POKETEXT 始终写满 8 字节时覆盖紧随其后的数据。
        let mut word: u64 = if write_size < 8 {
            unsafe { *libc::__errno() = 0 };
            let existing = unsafe {
                libc::ptrace(
                    libc::PTRACE_PEEKTEXT,
                    pid as pid_t,
                    (addr + offset) as *mut c_void,
                    std::ptr::null_mut::<c_void>(),
                )
            };
            let errno_val = unsafe { *libc::__errno() };
            if existing == -1 && errno_val != 0 {
                return Err(format!(
                    "读取内存失败(PEEKTEXT) addr=0x{:x} offset={} errno={}",
                    addr, offset, errno_val
                ));
            }
            existing as u64
        } else {
            0
        };

        // 合并新字节到 word（低字节 → 低地址，ARM64 小端序）
        unsafe {
            std::ptr::copy_nonoverlapping(
                data.add(offset),
                &mut word as *mut u64 as *mut u8,
                write_size,
            );
        }

        // 写入目标进程
        let result = unsafe {
            libc::ptrace(
                libc::PTRACE_POKETEXT,
                pid as pid_t,
                (addr + offset) as *mut c_void,
                word as usize as *mut c_void,
            )
        };

        if result == -1 {
            let errno = unsafe { *libc::__errno() };
            return Err(format!(
                "写入内存失败 addr=0x{:x} offset={} size={} errno={}",
                addr, offset, size, errno
            ));
        }

        offset += write_size;
    }

    Ok(())
}

/// 向远程进程内存写入任意类型的数据的泛型包装
///
/// # 参数
/// * `pid` - 目标进程ID
/// * `addr` - 目标地址
/// * `data` - 要写入的数据（任意类型）
pub(crate) fn write_memory<T>(pid: i32, addr: usize, data: &T) -> Result<(), String> {
    write_remote_mem(pid, addr, data as *const T as *const u8, size_of_val(data))
}

/// 向远程进程内存写入字节数组
///
/// # 参数
/// * `pid` - 目标进程ID
/// * `addr` - 目标地址
/// * `data` - 要写入的字节数组
pub(crate) fn write_bytes(pid: i32, addr: usize, data: &[u8]) -> Result<(), String> {
    write_remote_mem(pid, addr, data.as_ptr(), data.len())
}
