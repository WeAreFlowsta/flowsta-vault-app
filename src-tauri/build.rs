fn main() {
    let mut attributes = tauri_build::Attributes::new();
    // Cargo's test executables get no application manifest, and on Windows
    // they then fail to start (STATUS_ENTRYPOINT_NOT_FOUND: Common Controls
    // v6). In debug builds the linker embeds tauri-build's own manifest
    // (copied unchanged into windows-app-manifest.xml) in every executable
    // instead; release builds keep tauri-build's.
    let windows_msvc = std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows")
        && std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc");
    if windows_msvc && std::env::var("PROFILE").as_deref() == Ok("debug") {
        let manifest = std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("windows-app-manifest.xml");
        println!("cargo:rerun-if-changed={}", manifest.display());
        println!("cargo:rustc-link-arg=/MANIFEST:EMBED");
        println!("cargo:rustc-link-arg=/MANIFESTINPUT:{}", manifest.display());
        attributes = attributes.windows_attributes(tauri_build::WindowsAttributes::new_without_app_manifest());
    }
    if let Err(error) = tauri_build::try_build(attributes) {
        println!("{error:#}");
        std::process::exit(1);
    }
}
