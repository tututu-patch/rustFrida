#![cfg(all(target_os = "android", target_arch = "aarch64"))]

use libc::{bind, listen, sockaddr_un, socket, AF_UNIX, SOCK_STREAM};
use nix::sys::socket::{sendmsg, ControlMessage, MsgFlags};
use once_cell::unsync::Lazy;
use std::io::{IoSlice, Read, Write};
use std::mem::{size_of_val, zeroed};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::mpsc::{channel, Sender};
use std::sync::{Condvar, Mutex, OnceLock, RwLock};
use std::thread;
use std::thread::JoinHandle;
use std::time::Duration;

use crate::{log_agent, log_error, log_info, log_success};

pub(crate) static AGENT_MEMFD: AtomicI32 = AtomicI32::new(-1);
pub(crate) static STOP_LISTENER: AtomicBool = AtomicBool::new(false);

/// 泛型同步通道：在多线程间传递单次值，支持超时等待。
pub(crate) struct SyncChannel<T> {
    mutex: Mutex<Option<T>>,
    cvar: Condvar,
}

impl<T: Clone> SyncChannel<T> {
    pub(crate) fn new() -> Self {
        SyncChannel {
            mutex: Mutex::new(None),
            cvar: Condvar::new(),
        }
    }

    /// 设置值并通知所有等待者（由 handle_socket_connection 调用）。
    pub(crate) fn send(&self, val: T) {
        if let Ok(mut guard) = self.mutex.lock() {
            *guard = Some(val);
            self.cvar.notify_all();
        }
    }

    /// 清除当前值。
    pub(crate) fn clear(&self) {
        if let Ok(mut guard) = self.mutex.lock() {
            *guard = None;
        }
    }

    /// 在持锁状态下清除值、调用 `f`（通常用于发送请求），再阻塞等待值到来或超时。
    /// 保证"清除→发请求→等待"之间不存在竞态窗口。
    pub(crate) fn clear_then_recv<F: FnOnce()>(&self, dur: Duration, f: F) -> Option<T> {
        let mut guard = match self.mutex.lock() {
            Ok(g) => g,
            Err(_) => return None,
        };
        *guard = None;
        f();
        let result = self
            .cvar
            .wait_timeout_while(guard, dur, |val| val.is_none());
        match result {
            Ok((guard, timeout_result)) => {
                if timeout_result.timed_out() {
                    None
                } else {
                    guard.clone()
                }
            }
            Err(_) => None,
        }
    }

    /// 阻塞等待值到来或超时（调用前需自行 clear）。
    pub(crate) fn recv_timeout(&self, dur: Duration) -> Option<T> {
        let guard = match self.mutex.lock() {
            Ok(g) => g,
            Err(_) => return None,
        };
        let result = self
            .cvar
            .wait_timeout_while(guard, dur, |val| val.is_none());
        match result {
            Ok((guard, timeout_result)) => {
                if timeout_result.timed_out() {
                    None
                } else {
                    guard.clone()
                }
            }
            Err(_) => None,
        }
    }
}

/// jscomplete 请求/响应的同步状态。
static COMPLETE_RESULT: OnceLock<SyncChannel<Vec<String>>> = OnceLock::new();

pub(crate) fn complete_state() -> &'static SyncChannel<Vec<String>> {
    COMPLETE_RESULT.get_or_init(SyncChannel::new)
}

/// jseval（loadjs）请求/响应的同步状态。
static EVAL_RESULT: OnceLock<SyncChannel<std::result::Result<String, String>>> = OnceLock::new();

pub(crate) fn eval_state() -> &'static SyncChannel<std::result::Result<String, String>> {
    EVAL_RESULT.get_or_init(SyncChannel::new)
}

pub(crate) static GLOBAL_SENDER: OnceLock<Sender<String>> = OnceLock::new();
pub(crate) static mut AGENT_STAT: Lazy<RwLock<bool>> = Lazy::new(|| RwLock::new(false));

/// 检查抽象 socket "rust_frida_socket" 是否已有监听者（表示另一个 rustfrida 实例正在运行）。
/// 在 start_socket_listener 之前调用，连接成功则说明已有 agent 会话。
/// 检查抽象 socket "rust_frida_socket" 是否已有监听者（表示另一个 rustfrida 实例正在运行）。
/// 在 start_socket_listener 之前调用，连接成功则说明已有 agent 会话。
pub(crate) fn check_agent_running() -> bool {
    use libc::{c_char, connect, socket, AF_UNIX, SOCK_STREAM};
    unsafe {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if fd < 0 {
            return false;
        }
        let name = b"rust_frida_socket";
        let mut addr: sockaddr_un = zeroed();
        addr.sun_family = AF_UNIX as u16;
        addr.sun_path[0] = 0; // abstract namespace
        for (i, &b) in name.iter().enumerate() {
            addr.sun_path[i + 1] = b as c_char;
        }
        let addr_len = (size_of_val(&addr.sun_family) + 1 + name.len()) as u32;
        let ret = connect(fd, &addr as *const _ as *const _, addr_len);
        libc::close(fd);
        ret == 0
    }
}

pub(crate) fn send_fd_over_unix_socket(
    stream: &UnixStream,
    fd_to_send: RawFd,
) -> Result<(), String> {
    let data = b"AGENT_SO";
    let iov = [IoSlice::new(data)];
    let fds = [fd_to_send];
    let cmsg = [ControlMessage::ScmRights(&fds)];
    let sock_fd = stream.as_raw_fd();
    sendmsg(sock_fd, &iov, &cmsg, MsgFlags::empty(), None::<&()>)
        .map_err(|e| format!("发送文件描述符失败: {}", e))?;
    Ok(())
}

pub(crate) fn handle_socket_connection(mut stream: UnixStream) {
    let mut buffer = [0; 1024];
    while let Ok(size) = stream.read(&mut buffer) {
        if size == 0 {
            break;
        }

        if let Ok(msg) = String::from_utf8(buffer[..size].to_vec()) {
            let trimmed = msg.trim();

            // 如果是 HELLO_LOADER，额外发送 memfd
            if trimmed == "HELLO_LOADER" {
                log_info!("{}", trimmed);
                let memfd = AGENT_MEMFD.load(Ordering::SeqCst);
                if memfd >= 0 {
                    if let Err(e) = send_fd_over_unix_socket(&stream, memfd) {
                        log_error!("发送 memfd 失败: {}", e);
                    }
                } else {
                    log_error!("memfd 无效，无法发送 agent.so");
                }
            } else if trimmed == "HELLO_AGENT" {
                log_success!("Agent 已连接");
                STOP_LISTENER.store(true, Ordering::SeqCst);
                let mut stream_clone = stream.try_clone().unwrap();
                thread::spawn(move || {
                    let (sd, rx) = channel();
                    match GLOBAL_SENDER.set(sd) {
                        Ok(_) => {}
                        Err(_) => {
                            log_error!("GLOBAL_SENDER already set!");
                            return;
                        }
                    }
                    unsafe {
                        *(AGENT_STAT.write().unwrap()) = true;
                    }
                    while let Ok(msg) = rx.recv() {
                        match stream_clone.write_all(format!("{}\n", msg).as_bytes()) {
                            Ok(_) => {}
                            Err(e) => {
                                log_error!("stream 写入失败: {}", e);
                                break;
                            }
                        }
                    }
                });
            } else if trimmed.contains("COMPLETE:") {
                // COMPLETE: 响应可能包含多行候选项，保持整体处理
                let complete_part = if let Some(pos) = trimmed.find("COMPLETE:") {
                    // Log any lines that appear before COMPLETE:
                    for line in trimmed[..pos].lines() {
                        let l = line.trim();
                        if !l.is_empty() {
                            log_agent!("{}", l);
                        }
                    }
                    &trimmed[pos + "COMPLETE:".len()..]
                } else {
                    ""
                };
                let candidates: Vec<String> = if complete_part.is_empty() {
                    vec![]
                } else {
                    complete_part
                        .lines()
                        .map(|s| s.to_string())
                        .filter(|s| !s.is_empty())
                        .collect()
                };
                complete_state().send(candidates);
            } else {
                // 按行处理：EVAL_ERR:/EVAL: 路由到 eval_state，其余（含 console.log）显示到终端
                for line in trimmed.lines() {
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    if line.starts_with("EVAL_ERR:") {
                        // agent 侧用 \r 替换 \n 传输多行错误（含堆栈），此处还原
                        let content = line["EVAL_ERR:".len()..].replace('\r', "\n");
                        eval_state().send(Err(content));
                    } else if line.starts_with("EVAL:") {
                        eval_state().send(Ok(line["EVAL:".len()..].to_string()));
                    } else {
                        log_agent!("{}", line);
                    }
                }
            }
        }
    }
}

pub(crate) fn start_socket_listener(
    socket_path: &str,
) -> Result<JoinHandle<()>, Box<dyn std::error::Error>> {
    // 创建 socket
    let fd = unsafe { socket(AF_UNIX, SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(Box::new(std::io::Error::last_os_error()));
    }

    // 构造 sockaddr_un，抽象socket: sun_path[0]=0, 后面跟名字
    let mut addr: sockaddr_un = unsafe { zeroed() };
    addr.sun_family = AF_UNIX as u16;
    let name_bytes = socket_path.as_bytes();
    let path_len = name_bytes.len().min(107); // sun_path最多108字节
    addr.sun_path[0] = 0; // 抽象socket
    addr.sun_path[1..=path_len].copy_from_slice(&name_bytes[..path_len]);
    let sockaddr_len = (size_of_val(&addr.sun_family) + 1 + path_len) as u32;

    // 绑定
    let ret = unsafe { bind(fd, &addr as *const _ as *const _, sockaddr_len) };
    if ret < 0 {
        return Err(Box::new(std::io::Error::last_os_error()));
    }

    // 监听
    let ret = unsafe { listen(fd, 128) };
    if ret < 0 {
        return Err(Box::new(std::io::Error::last_os_error()));
    }

    // 转为 Rust 的 UnixListener，设为非阻塞以便响应停止信号
    let listener = unsafe { std::os::unix::net::UnixListener::from_raw_fd(fd) };
    listener
        .set_nonblocking(true)
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
    let handle = thread::spawn(move || loop {
        if STOP_LISTENER.load(Ordering::SeqCst) {
            break;
        }
        match listener.accept() {
            Ok((stream, _)) => {
                thread::spawn(move || {
                    handle_socket_connection(stream);
                });
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(e) => log_error!("接受连接失败: {}", e),
        }
    });
    Ok(handle)
}
