//! Compile the proof-root slint, which re-imports the production client UI
//! (theme + primitives + screens) from `../comms-client/ui/` via relative path —
//! the harness never forks the UI, it renders the real thing.

use std::path::PathBuf;

fn main() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    println!("cargo:rerun-if-changed=ui/proof_root.slint");
    println!("cargo:rerun-if-changed=../comms-client/ui/theme.slint");
    println!("cargo:rerun-if-changed=../comms-client/ui/primitives.slint");
    if let Err(e) = slint_build::compile(root.join("ui/proof_root.slint")) {
        panic!("Slint compilation failed for proof_root.slint: {e}");
    }
}
