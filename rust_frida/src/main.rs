#![cfg(all(target_os = "android", target_arch = "aarch64"))]

mod args;
mod communication;
mod injection;
mod logger;
mod process;
mod repl;
mod types;

use args::Args;
use clap::Parser;
use communication::{eval_state, start_socket_listener, AGENT_MEMFD, AGENT_STAT, GLOBAL_SENDER};
use injection::{create_memfd_with_data, inject_to_process, watch_and_inject, AGENT_SO};
use libc::{close, sleep};
use repl::{print_help, run_js_repl, CommandCompleter};
use rustyline::error::ReadlineError;
use rustyline::Editor;
use std::sync::atomic::Ordering;
use types::get_string_table_names;

fn main() {
    logger::print_banner();
    let args = Args::parse();
    // 初始化 verbose 模式
    logger::VERBOSE.store(args.verbose, Ordering::Relaxed);

    // 初始化 agent.so 的 memfd
    match create_memfd_with_data("wwb_so", AGENT_SO) {
        Ok(fd) => {
            AGENT_MEMFD.store(fd, Ordering::SeqCst);
            log_success!("已创建 agent.so memfd: {}", fd);
        }
        Err(e) => {
            log_error!("创建 agent.so memfd 失败: {}", e);
            std::process::exit(1);
        }
    }

    // 启动抽象套接字监听
    let handle = start_socket_listener("rust_frida_socket");

    // 解析字符串覆盖参数（格式：name=value）
    let mut string_overrides = std::collections::HashMap::new();
    let available_names = get_string_table_names();

    for s in &args.strings {
        if let Some((name, value)) = s.split_once('=') {
            if available_names.contains(&name) {
                string_overrides.insert(name.to_string(), value.to_string());
            } else {
                log_warn!(
                    "未知的字符串名称 '{}', 可用名称: {:?}",
                    name,
                    available_names
                );
            }
        } else {
            log_warn!("无效的字符串格式 '{}', 应为 name=value", s);
        }
    }

    // 打印字符串覆盖信息
    if !string_overrides.is_empty() {
        log_info!("字符串覆盖列表 ({} 个):", string_overrides.len());
        for (name, value) in &string_overrides {
            println!("     {} = {}", name, value);
        }
    }

    // 根据参数选择注入方式
    let result = if let Some(so_pattern) = &args.watch_so {
        // 使用 eBPF 监听 SO 加载
        watch_and_inject(so_pattern, args.timeout, &string_overrides)
    } else if let Some(pid) = args.pid {
        // 直接附加到指定 PID
        if pid <= 0 {
            log_error!("PID必须是正整数");
            std::process::exit(1);
        }
        inject_to_process(pid, &string_overrides)
    } else {
        log_error!("必须指定 --pid 或 --watch-so");
        std::process::exit(1);
    };

    if let Err(e) = result {
        log_error!("注入失败: {}", e);
        std::process::exit(1);
    }

    unsafe {
        while *(AGENT_STAT.read().unwrap()) == false {
            sleep(1);
            log_info!("等待 agent 连接...");
        }
    }
    let sender = GLOBAL_SENDER.get().unwrap();

    // If a script file was specified, load and send it
    if let Some(script_path) = &args.load_script {
        match std::fs::read_to_string(script_path) {
            Ok(script) => {
                log_info!("加载脚本: {}", script_path);
                // First initialize the JS engine
                if let Err(e) = sender.send("jsinit".to_string()) {
                    log_error!("发送 jsinit 失败: {}", e);
                }
                // Wait a bit for initialization
                unsafe { sleep(1) };
                // Send the script
                let cmd = format!("loadjs {}", script);
                if let Err(e) = sender.send(cmd) {
                    log_error!("发送 loadjs 失败: {}", e);
                }
            }
            Err(e) => {
                log_error!("读取脚本文件 '{}' 失败: {}", script_path, e);
            }
        }
    }

    let mut rl = match Editor::new() {
        Ok(e) => e,
        Err(e) => {
            log_error!("初始化行编辑器失败: {}", e);
            std::process::exit(1);
        }
    };
    rl.set_helper(Some(CommandCompleter::new()));
    println!(
        "  {}输入 help 查看命令，exit 退出{}",
        crate::logger::DIM,
        crate::logger::RESET
    );
    loop {
        match rl.readline("rustfrida> ") {
            Ok(line) => {
                let line = line.trim().to_string();
                if line.is_empty() {
                    continue;
                }
                let _ = rl.add_history_entry(&line);
                if line == "help" {
                    print_help();
                    continue;
                }
                if line == "exit" || line == "quit" {
                    log_info!("退出交互模式");
                    break;
                }
                if line == "jsrepl" {
                    run_js_repl(sender);
                    continue;
                }
                // 校验 hfl/qfl 必须带 <module> <offset> 两个参数
                {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if matches!(parts.first().copied(), Some("hfl") | Some("qfl"))
                        && parts.len() < 3
                    {
                        log_warn!("用法: {} <module> <offset>", parts[0]);
                        continue;
                    }
                }
                let is_jseval = line.starts_with("jseval ");
                if is_jseval {
                    eval_state().clear();
                }
                match sender.send(line) {
                    Ok(_) => {}
                    Err(e) => {
                        log_error!("发送命令失败: {}", e);
                        break;
                    }
                }
                if is_jseval {
                    match eval_state().recv_timeout(std::time::Duration::from_secs(5)) {
                        None => println!("\x1b[33m[timeout] 等待执行结果超时\x1b[0m"),
                        Some(Ok(output)) => {
                            if !output.is_empty() {
                                println!("\x1b[32m=> {}\x1b[0m", output);
                            }
                        }
                        Some(Err(err)) => println!("\x1b[31m[JS error] {}\x1b[0m", err),
                    }
                }
            }
            Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => {
                log_info!("退出交互模式");
                break;
            }
            Err(e) => {
                log_error!("读取输入失败: {}", e);
                break;
            }
        }
    }
    // 等待监听线程退出
    handle.unwrap().join().unwrap();

    // 清理资源
    let memfd = AGENT_MEMFD.load(Ordering::SeqCst);
    if memfd >= 0 {
        unsafe { close(memfd) };
        log_success!("已关闭 agent.so memfd");
    }
}
