// comms-member-daemon — `comms-send` client tests. Real socket, real daemon, real MLS underneath.

use super::*;
use crate::MemberDaemon;
use comms_core::identity::EthWallet;
use std::path::PathBuf;
use std::time::{Duration, Instant};

fn tmp_socket(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("citrate-send-{tag}-{nanos}.sock"))
}

/// Serve a fresh in-process daemon; returns (socket, bearer, the daemon's address).
fn spawn_daemon(tag: &str) -> (PathBuf, String, String) {
    let path = tmp_socket(tag);
    let bearer = "c".repeat(64);
    let wallet = EthWallet::generate();
    let address = format!("0x{}", hex::encode(wallet.address().0));
    let daemon = MemberDaemon::new(wallet, "relay.test", 1000).expect("daemon");
    let (p, b) = (path.clone(), bearer.clone());
    std::thread::spawn(move || {
        let _ = crate::server::serve(daemon, &p, &b);
    });
    let start = Instant::now();
    while !path.exists() && start.elapsed() < Duration::from_secs(3) {
        std::thread::sleep(Duration::from_millis(10));
    }
    (path, bearer, address)
}

fn no_stdin() -> Result<String, String> {
    Err("stdin not expected".into())
}

fn argv(s: &[&str]) -> Vec<String> {
    s.iter().map(|x| x.to_string()).collect()
}

// --- invite links ---------------------------------------------------------------------------

/// The link citrate-core mints carries a base64url token; the owner publishes
/// BLAKE3(token.as_bytes()). What we send to the daemon must hash to the SAME value once the
/// daemon hex-decodes it — otherwise the relay never matches and the self-admit fails.
#[test]
fn invite_token_encoding_matches_what_the_owner_published() {
    let token = "q3J8m1Zx-_Pn0aBcDeFgHiJkLmNoPqRsTuVwXyZ01234"; // base64url, like random_state()
    let gid = "ab".repeat(32);
    let name_hex = hex::encode("ops room".as_bytes());
    let link = format!("citrate://invite?g={gid}&t={token}&k=02deadbeef&n={name_hex}");
    let inv = parse_invite_link(&link).expect("parses");
    assert_eq!(inv.group, gid);
    assert_eq!(inv.name, "ops room");
    let owner_published = blake3::hash(token.as_bytes());
    let raw_the_daemon_sends = hex::decode(&inv.token_hex).expect("hex");
    assert_eq!(blake3::hash(&raw_the_daemon_sends), owner_published);
}

#[test]
fn malformed_invite_links_are_refused() {
    assert!(parse_invite_link("citrate://invite").is_err());
    assert!(parse_invite_link("citrate://invite?t=abc").is_err());
    assert!(parse_invite_link("citrate://invite?g=nothex&t=abc").is_err());
    let gid = "0".repeat(64);
    assert!(parse_invite_link(&format!("citrate://invite?g={gid}")).is_err());
    assert!(parse_invite_link(&format!("citrate://invite?g={gid}&t=")).is_err());
    // A link without a name is fine; the name is cosmetic.
    let inv = parse_invite_link(&format!("citrate://invite?g={gid}&t=tok")).expect("ok");
    assert_eq!(inv.name, "");
}

// --- argv -----------------------------------------------------------------------------------

#[test]
fn send_args_parse_text_stdin_and_group() {
    let (o, c) = parse_args(
        &argv(&["--socket", "/s", "--bearer-file", "/b", "send", "--text", "hi"]),
        no_stdin,
    )
    .expect("parses");
    assert_eq!(o.socket.as_deref(), Some("/s"));
    assert_eq!(o.bearer_file.as_deref(), Some("/b"));
    assert_eq!(
        c,
        Command::Send {
            group: GroupSel::Auto,
            text: "hi".into()
        }
    );
    let g = "AB".repeat(32);
    let (_, c) = parse_args(&argv(&["send", "--group", &g, "--stdin"]), || {
        Ok("from stdin".into())
    })
    .expect("parses");
    assert_eq!(
        c,
        Command::Send {
            group: GroupSel::Id(g.to_ascii_lowercase()),
            text: "from stdin".into()
        }
    );
}

#[test]
fn bad_send_args_are_refused() {
    assert!(parse_args(&argv(&["send"]), no_stdin).is_err());
    assert!(parse_args(&argv(&["send", "--text", "  "]), no_stdin).is_err());
    assert!(parse_args(&argv(&["send", "--text", "a", "--stdin"]), no_stdin).is_err());
    let big = "x".repeat(MAX_TEXT_BYTES + 1);
    assert!(parse_args(&argv(&["send", "--text", &big]), no_stdin).is_err());
    assert!(parse_args(&argv(&["frobnicate"]), no_stdin).is_err());
    assert!(parse_args(&argv(&["join"]), no_stdin).is_err());
    assert!(parse_args(&argv(&[]), no_stdin).is_err());
}

// --- against a live daemon socket -----------------------------------------------------------

#[test]
fn whoami_and_status_report_the_member_and_its_groups() {
    let (path, bearer, address) = spawn_daemon("status");
    let mut c = IpcClient::connect(&path, &bearer).expect("connect");

    let who = run(&mut c, Command::Whoami);
    assert_eq!(who.code, EXIT_OK);
    assert_eq!(who.json["address"], address);

    // No groups yet: a member of nothing — the "not invited yet" state a checker must detect.
    let st = run(&mut c, Command::Status);
    assert_eq!(st.code, EXIT_OK);
    assert_eq!(st.json["member"], false);
    assert_eq!(st.json["relayConnected"], true);

    // Sending with no group is the honest "not a member" exit, not a generic failure.
    let s = run(
        &mut c,
        Command::Send {
            group: GroupSel::Auto,
            text: "disk 91% on rpc-1".into(),
        },
    );
    assert_eq!(s.code, EXIT_NOT_MEMBER, "{}", s.json);

    // Nothing pending to join.
    let jp = run(&mut c, Command::JoinPending);
    assert_eq!(jp.code, EXIT_OK, "{}", jp.json);
    assert_eq!(jp.json["joined"], serde_json::json!([]));
}

#[test]
fn send_targets_the_only_group_and_refuses_an_unknown_one() {
    let (path, bearer, _) = spawn_daemon("send");
    let mut c = IpcClient::connect(&path, &bearer).expect("connect");
    let gid = match c.call(&serde_json::json!({"op": "createGroup", "name": "ops"})) {
        Ok(crate::ipc::Response::GroupCreated { id }) => id,
        other => panic!("create: {other:?}"),
    };
    let st = run(&mut c, Command::Status);
    assert_eq!(st.json["member"], true);

    let sent = run(
        &mut c,
        Command::Send {
            group: GroupSel::Auto,
            text: "[CRIT] chain tip stalled".into(),
        },
    );
    assert_eq!(sent.code, EXIT_OK, "{}", sent.json);
    assert_eq!(sent.json["group"], gid);

    let other = run(
        &mut c,
        Command::Send {
            group: GroupSel::Id("f".repeat(64)),
            text: "x".into(),
        },
    );
    assert_eq!(other.code, EXIT_NOT_MEMBER, "{}", other.json);
}

#[test]
fn a_wrong_bearer_and_a_missing_daemon_fail_closed() {
    let (path, _bearer, _) = spawn_daemon("auth");
    assert!(matches!(
        IpcClient::connect(&path, &"z".repeat(64)),
        Err(ClientError::Unauthorized)
    ));
    let missing = tmp_socket("absent");
    let err = IpcClient::connect(&missing, "x").err().expect("must fail");
    assert!(matches!(err, ClientError::Connect(..)));
    assert_eq!(client_fail(err).code, EXIT_DAEMON);
}
