//! The relay binary's at-rest master-key source policy, exercised through the real
//! binary. Every case exits during startup, before the store is opened or a socket is
//! bound: HOME, the data dir and the bind address all point into a temp dir or at an
//! unusable address, and the environment is cleared, so nothing on the host is read or
//! written.

use std::path::Path;
use std::process::{Command, Output};

const OWNER: &str = "0x1111111111111111111111111111111111111111";
const DUMMY_KEY: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

fn run_relay(tmp: &Path, extra: &[(&str, String)]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_comms-relay"));
    cmd.env_clear()
        .env("HOME", tmp)
        .env("CITRATE_COMMS_OWNER", OWNER)
        .env("CITRATE_COMMS_DATA", tmp.join("data"))
        // Unparseable on purpose: if startup ever got past the key policy it would
        // fail here instead of listening.
        .env("CITRATE_COMMS_BIND", "not-a-socket-address")
        .env("CITRATE_COMMS_ADMIN_BIND", "not-a-socket-address");
    for (k, v) in extra {
        cmd.env(k, v);
    }
    cmd.output().expect("spawn relay binary")
}

/// An inline key in the environment is refused unless the explicit opt-in is set, and
/// the refusal happens before the store is opened.
#[test]
fn inline_env_master_key_is_refused_without_the_opt_in() {
    let tmp = tempfile::tempdir().unwrap();
    let out = run_relay(
        tmp.path(),
        &[("CITRATE_COMMS_MASTER_KEY", DUMMY_KEY.into())],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(
        stderr.contains("CITRATE_COMMS_MASTER_KEY is set inline"),
        "expected the inline-key refusal, got: {stderr}"
    );
    assert!(
        !tmp.path().join("data").exists(),
        "the store must not be opened when the key source is refused"
    );
}

/// The key file takes priority over an inline key, even with the opt-in set.
#[test]
fn master_key_file_takes_priority_over_an_inline_key() {
    let tmp = tempfile::tempdir().unwrap();
    let missing = tmp.path().join("absent.key");
    let out = run_relay(
        tmp.path(),
        &[
            (
                "CITRATE_COMMS_MASTER_KEY_FILE",
                missing.display().to_string(),
            ),
            ("CITRATE_COMMS_MASTER_KEY", DUMMY_KEY.into()),
            ("CITRATE_COMMS_ALLOW_ENV_KEY", "1".into()),
        ],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(
        stderr.contains("CITRATE_COMMS_MASTER_KEY_FILE") && stderr.contains("absent.key"),
        "the key file must be the source consulted first, got: {stderr}"
    );
    assert!(!tmp.path().join("data").exists());
}

/// Control: with the opt-in, the inline key is accepted and startup proceeds past the
/// key policy (and then stops at the deliberately unusable bind address).
#[test]
fn inline_env_master_key_is_accepted_with_the_opt_in() {
    let tmp = tempfile::tempdir().unwrap();
    let out = run_relay(
        tmp.path(),
        &[
            ("CITRATE_COMMS_MASTER_KEY", DUMMY_KEY.into()),
            ("CITRATE_COMMS_ALLOW_ENV_KEY", "1".into()),
        ],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "the unusable bind address must stop startup"
    );
    assert!(
        !stderr.contains("is set inline"),
        "opt-in must not be refused: {stderr}"
    );
    assert!(
        tmp.path().join("data").exists(),
        "startup must have reached the store"
    );
}
