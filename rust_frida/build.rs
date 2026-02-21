fn main() {
    // 当 agent.so 变化时重新编译 host（include_bytes! 缓存问题）
    println!("cargo::rerun-if-changed=../target/aarch64-linux-android/debug/libagent.so");
    println!("cargo::rerun-if-changed=../target/aarch64-linux-android/release/libagent.so");
    println!("cargo::rerun-if-changed=../loader/build/loader.bin");
}
