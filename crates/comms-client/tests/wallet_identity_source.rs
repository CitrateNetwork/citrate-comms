//! The networked client loads its wallet from the OS keyring and must fail closed
//! when the keyring is unavailable: it must never fall back to a freshly generated
//! wallet, which would sign the user in under an address they do not control.
//!
//! `load_wallet` and the `run` driver that calls it are private and need a Slint
//! window, so this is a source tripwire over `src/netdrive.rs` (comments stripped),
//! with a negative control on the previous fallback shape.

use std::path::Path;

fn strip_line_comments(src: &str) -> String {
    src.lines()
        .map(|l| match l.find("//") {
            Some(i) => &l[..i],
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Body of `fn load_wallet` (from its signature to the matching close brace).
fn load_wallet_body(src: &str) -> Option<String> {
    let start = src.find("fn load_wallet(")?;
    let open = start + src[start..].find('{')?;
    let mut depth = 0usize;
    for (i, c) in src[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(src[start..open + i + 1].to_string());
                }
            }
            _ => {}
        }
    }
    None
}

/// Problems with the wallet-loading path in `src` (empty = fails closed).
fn wallet_fallback_problems(src: &str) -> Vec<String> {
    let code = strip_line_comments(src);
    let mut problems = Vec::new();
    if code.contains("EthWallet::generate") {
        problems.push("netdrive.rs mints a fresh wallet (EthWallet::generate)".to_string());
    }
    match load_wallet_body(&code) {
        None => problems.push("fn load_wallet not found".to_string()),
        Some(body) => {
            let sig = body.split('{').next().unwrap_or("");
            if !sig.contains("Result<") {
                problems.push("load_wallet does not return a Result".to_string());
            }
            if body.contains("unwrap_or_else")
                || body.contains("unwrap_or(")
                || body.contains(".ok()")
            {
                problems.push("load_wallet swallows a keyring/key error".to_string());
            }
        }
    }
    // The single caller must stop on the error rather than continue to login.
    match code.find("load_wallet(&cfg.wallet_account)") {
        None => problems.push("run() no longer calls load_wallet(&cfg.wallet_account)".to_string()),
        Some(i) => {
            let tail = &code[i..];
            let next_login = tail.find("NetSession::login").unwrap_or(tail.len());
            if !tail[..next_login].contains("return;") {
                problems.push("run() continues to login when load_wallet fails".to_string());
            }
        }
    }
    problems
}

#[test]
fn netdrive_wallet_load_fails_closed() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/netdrive.rs");
    let src = std::fs::read_to_string(&path).expect("read src/netdrive.rs");
    let problems = wallet_fallback_problems(&src);
    assert!(
        problems.is_empty(),
        "wallet load must fail closed: {problems:?}"
    );
}

#[test]
fn tripwire_negative_control_flags_the_ephemeral_fallback() {
    let old = r#"
async fn run(cfg: Cfg) {
    let wallet = load_wallet(&cfg.wallet_account);
    let mut session = match NetSession::login(&cfg.url, wallet).await { Ok(s) => s, Err(_) => return };
}
fn load_wallet(account: &str) -> EthWallet {
    match comms_relay::keyvault::load_or_create_master_key("citrate-comms", account) {
        Ok(secret) => EthWallet::from_secret_key(&secret).unwrap_or_else(|_| EthWallet::generate()),
        Err(_) => EthWallet::generate(),
    }
}
"#;
    let problems = wallet_fallback_problems(old);
    assert!(
        problems.len() >= 3,
        "the old fallback shape must be flagged: {problems:?}"
    );
}
