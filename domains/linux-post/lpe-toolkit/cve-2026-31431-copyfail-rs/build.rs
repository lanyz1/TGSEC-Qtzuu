fn main() {
    let target = std::env::var("TARGET").unwrap_or_default();
    if target.contains("musl") {
        // Self-contained musl: libc.a lives in rustup sysroot.
        let sysroot = std::process::Command::new("rustc")
            .args(["--print", "sysroot"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default();
        if !sysroot.is_empty() {
            println!(
                "cargo:rustc-link-search=native={}/lib/rustlib/{}/lib/self-contained",
                sysroot, target
            );
        }
        println!("cargo:rustc-link-lib=static=c");
    } else {
        // Host glibc / dynamic targets: bin is no_std + no_main and does not
        // pull libc through std, so request dynamic libc explicitly.
        println!("cargo:rustc-link-lib=c");
    }
}
