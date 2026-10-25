fn main() {
    // The target triple, so a dev build resolves `name-<triple>` exactly in
    // src-tauri/binaries/ (a prefix match confused `vault-holochain-` with
    // `vault-holochain-07-`).
    if let Ok(t) = std::env::var("TARGET") {
        println!("cargo:rustc-env=VAULT_TARGET_TRIPLE={}", t);
    }
    tauri_build::build()
}
