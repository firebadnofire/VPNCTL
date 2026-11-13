use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-env-changed=VAM_HELPER_BUNDLE_DIR");
    let root = env::var_os("VAM_HELPER_BUNDLE_DIR").map_or_else(
        || PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../target/vam-server-dist"),
        PathBuf::from,
    );
    let mut source =
        String::from("pub fn bundled_helpers() -> Vec<vam_application::HelperPayload> { vec![\n");
    for (architecture, machine) in [("x86_64", [62, 0]), ("aarch64", [183, 0])] {
        let path = root.join(format!("{architecture}-unknown-linux-musl/vam-server"));
        println!("cargo:rerun-if-changed={}", path.display());
        if path.exists() {
            let bytes = fs::read(&path).expect("read bundled helper");
            assert!(
                bytes.len() >= 64
                    && bytes.len() <= 150 * 1024 * 1024
                    && &bytes[..6] == b"\x7fELF\x02\x01"
                    && bytes[18..20] == machine,
                "Bundled helper must be a matching 64-bit Linux ELF executable: {}",
                path.display()
            );
            let path = path.canonicalize().expect("resolve helper path");
            source.push_str(&format!("vam_application::HelperPayload {{ architecture: {architecture:?}, contents: include_bytes!({:?}) }},\n", path.to_str().expect("UTF-8 helper path")));
        } else if env::var("PROFILE").as_deref() == Ok("release") {
            panic!(
                "Missing trusted Linux helper: {}. Run bash build-helpers/server/bundle.sh or set VAM_HELPER_BUNDLE_DIR to the matching source build's helper bundle directory before packaging.",
                path.display()
            );
        } else {
            println!(
                "cargo:warning=No {architecture} helper bundle; automatic repair will report unavailable in this development build."
            );
        }
    }
    source.push_str("] }");
    fs::write(
        PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR")).join("helper_payloads.rs"),
        source,
    )
    .expect("write bundled helper module");
    tauri_build::build();
}
