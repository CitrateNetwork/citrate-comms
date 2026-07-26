//! The split is only worth having if it is enforced.
//!
//! `comms-wire` + `comms-session` exist so that a program which merely *talks* to a
//! relay does not link the relay. That claim is a property of the dependency graph,
//! not of anyone's discipline, so it is asserted here the same way `comms-core`
//! asserts server-blindness — by checking what the build actually pulls in
//! (`PLANSET/02` §1).
//!
//! If this test fails, someone added a dependency that drags the server (or a UI
//! toolkit) into every client. That is allowed — but it should be a decision, not a
//! surprise discovered by a downstream app whose installer grew by 40 MB.

use std::process::Command;

/// Crates a *client* must never be forced to link, and what each would mean.
const FORBIDDEN: [(&str, &str); 4] = [
    (
        "rocksdb",
        "the relay's ciphertext store — a client keeps no relay state",
    ),
    (
        "axum",
        "the relay's loopback admin surface — a client serves nothing",
    ),
    (
        "keyring",
        "the relay's at-rest master key binding — a client's custody is its own",
    ),
    (
        "slint",
        "the desktop client's UI toolkit — a session has no UI",
    ),
];

fn tree_of(package: &str) -> String {
    let out = Command::new(env!("CARGO"))
        .args(["tree", "-p", package, "-e", "normal", "--prefix", "none"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("cargo tree must run");
    assert!(
        out.status.success(),
        "cargo tree -p {package} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).to_string()
}

#[test]
fn a_session_does_not_link_the_relay_server_or_a_ui_toolkit() {
    let tree = tree_of("comms-session");
    for (crate_name, why) in FORBIDDEN {
        assert!(
            !tree
                .lines()
                .any(|l| l.starts_with(&format!("{crate_name} v"))),
            "comms-session now links `{crate_name}` ({why}).\n\
             That is what this crate exists to avoid: citrate-quorum is a Tauri desktop \
             app that holds a member session, and it must not carry a storage engine, an \
             HTTP server, or a second UI toolkit to open a WebSocket."
        );
    }
}

#[test]
fn the_wire_crate_cannot_decrypt() {
    // The strongest form of the server-blind invariant: a crate with no MLS engine in
    // its dependency graph cannot read plaintext, whatever its code says. `comms-wire`
    // moves ciphertext; `comms-session` is where secrets live.
    let tree = tree_of("comms-wire");
    for mls_crate in ["openmls", "openmls_rust_crypto", "openmls_basic_credential"] {
        assert!(
            !tree
                .lines()
                .any(|l| l.starts_with(&format!("{mls_crate} v"))),
            "comms-wire links `{mls_crate}` — the wire crate must not be able to decrypt. \
             Group secrets belong in comms-session and nowhere else."
        );
    }
}
