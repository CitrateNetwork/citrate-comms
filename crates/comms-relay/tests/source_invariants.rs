//! Source-level tripwires for properties that have no runtime observable: secret
//! material held in wiping wrappers, key files created owner-only, and the at-rest AEAD
//! construction. Each checker has a negative control so it cannot pass vacuously.

const DAEMON_MAIN: &str = include_str!("../../comms-member-daemon/src/main.rs");
const KEYVAULT: &str = include_str!("../src/keyvault.rs");
const IDENTITY: &str = include_str!("../../comms-core/src/identity.rs");
const STORE: &str = include_str!("../../comms-core/src/store.rs");
const CORE_MANIFEST: &str = include_str!("../../comms-core/Cargo.toml");
const BOOTSTRAP: &str = include_str!("../../../deploy/bootstrap-droplet.sh");

// ───────────────────────────── secret wrappers ─────────────────────────────

/// The `let` statements binding each named secret, each of which must construct or
/// declare a `Zeroizing` wrapper. Returns the names that are missing or unwrapped.
fn unwrapped_secret_bindings(src: &str, names: &[&str]) -> Vec<String> {
    let mut bad = Vec::new();
    for name in names {
        let stmt = [format!("let {name} ="), format!("let {name}:")]
            .iter()
            .find_map(|head| src.find(head.as_str()).map(|i| &src[i..]))
            .map(|rest| rest.split(';').next().unwrap_or(""));
        match stmt {
            Some(s) if s.contains("Zeroizing") => {}
            _ => bad.push(name.to_string()),
        }
    }
    bad
}

#[test]
fn member_daemon_wallet_seed_copies_are_wiped() {
    let bad = unwrapped_secret_bindings(DAEMON_MAIN, &["seed_hex", "seed_bytes", "seed"]);
    assert!(bad.is_empty(), "seed material not held in Zeroizing: {bad:?}");
}

#[test]
fn secret_returning_helpers_return_wiping_wrappers() {
    assert!(
        KEYVAULT.contains("pub fn load_or_create_master_key(")
            && KEYVAULT
                .split("pub fn load_or_create_master_key(")
                .nth(1)
                .and_then(|s| s.split('{').next())
                .is_some_and(|sig| sig.contains("Zeroizing<[u8; 32]>")),
        "the master-key loader must return Zeroizing<[u8; 32]>"
    );
    assert!(
        IDENTITY.contains("pub fn secret_bytes(&self) -> zeroize::Zeroizing<[u8; 32]>"),
        "EthWallet::secret_bytes must return a Zeroizing copy"
    );
}

#[test]
fn secret_binding_checker_negative_control() {
    let plain = "let seed_bytes = hex::decode(s)?;\nlet seed: [u8; 32] = x;";
    assert_eq!(
        unwrapped_secret_bindings(plain, &["seed_bytes", "seed", "seed_hex"]),
        vec!["seed_bytes", "seed", "seed_hex"]
    );
    let wrapped = "let seed_bytes = Zeroizing::new(hex::decode(s)?);";
    assert!(unwrapped_secret_bindings(wrapped, &["seed_bytes"]).is_empty());
}

// ─────────────────────────── owner-only key files ───────────────────────────

/// Lines of a shell script that create a secret without `umask 077` in effect for the
/// statement: any `openssl rand` and any redirect into the env file.
fn world_readable_secret_writes(script: &str) -> Vec<String> {
    let lines: Vec<&str> = script.lines().collect();
    let mut bad = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let code = line.split('#').next().unwrap_or("");
        if !(code.contains("openssl rand") || code.contains(">\"$PREFIX/.env\"")) {
            continue;
        }
        // Walk back to the start of a backslash-continued statement.
        let mut j = i;
        while j > 0 && lines[j - 1].trim_end().ends_with('\\') {
            j -= 1;
        }
        if !lines[j].contains("( umask 077;") {
            bad.push(line.trim().to_string());
        }
    }
    bad
}

#[test]
fn bootstrap_creates_key_and_env_files_owner_only() {
    assert!(BOOTSTRAP.contains("openssl rand"), "bootstrap no longer generates the key here");
    assert!(BOOTSTRAP.contains(">\"$PREFIX/.env\""), "bootstrap no longer writes the env file here");
    let bad = world_readable_secret_writes(BOOTSTRAP);
    assert!(bad.is_empty(), "secret files written without umask 077: {bad:?}");
}

#[test]
fn umask_checker_negative_control() {
    let bad = "openssl rand -hex 32 >\"$KEYFILE\"\nchmod 600 \"$KEYFILE\"\n\
               sed -e x \\\n\t\"$SRC/x\" >\"$PREFIX/.env\"\n";
    assert_eq!(world_readable_secret_writes(bad).len(), 2);
    let good = "( umask 077; openssl rand -hex 32 >\"$KEYFILE\" )\n\
                ( umask 077; sed -e x \\\n\t\"$SRC/x\" >\"$PREFIX/.env\" )\n";
    assert!(world_readable_secret_writes(good).is_empty());
}

// ─────────────────────────── at-rest AEAD construction ───────────────────────────

/// Every mention of the AES-GCM type family must be the nonce-misuse-resistant SIV
/// variant, and the plain `aes-gcm` crate must not be a dependency.
fn non_siv_gcm_uses(src: &str) -> usize {
    src.match_indices("Aes256Gcm")
        .filter(|(i, _)| !src[i + "Aes256Gcm".len()..].starts_with("Siv"))
        .count()
        + src.matches("aes_gcm::").count()
}

#[test]
fn at_rest_store_uses_aes_gcm_siv_only() {
    assert!(STORE.contains("Aes256GcmSiv::new("), "the store must construct AES-256-GCM-SIV");
    assert_eq!(non_siv_gcm_uses(STORE), 0, "the store must not use plain AES-256-GCM");
    assert!(
        !CORE_MANIFEST.lines().any(|l| l.trim_start().starts_with("aes-gcm ")
            || l.trim_start().starts_with("aes-gcm=")),
        "comms-core must not depend on the plain aes-gcm crate"
    );
}

#[test]
fn aead_checker_negative_control() {
    assert_eq!(non_siv_gcm_uses("use aes_gcm::{Aes256Gcm, Key};"), 2);
    assert_eq!(non_siv_gcm_uses("use aes_gcm_siv::{Aes256GcmSiv, Key};"), 0);
}
