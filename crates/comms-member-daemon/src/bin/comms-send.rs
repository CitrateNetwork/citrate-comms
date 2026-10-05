//! `comms-send` — a scriptable client for a running `comms-member-daemon`.
//!
//! For a HEADLESS member (an ops bot posting alerts into a team group). Holds no key and no MLS
//! state — the daemon does; this speaks the daemon's bearer-authenticated loopback IPC. Prints one
//! JSON object on stdout; the exit code says what happened (see `comms_member_daemon::client`).
//!
//! The bearer is read from a FILE (`--bearer-file` / `CITRATE_MEMBER_BEARER_FILE`), never argv.

use std::io::Read;
use std::path::PathBuf;

use comms_member_daemon::client::{self, IpcClient, EXIT_DAEMON, EXIT_USAGE, USAGE};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|a| a == "-h" || a == "--help") {
        println!("{USAGE}");
        std::process::exit(if args.is_empty() { EXIT_USAGE } else { 0 });
    }
    let parsed = client::parse_args(&args, || {
        let mut s = String::new();
        std::io::stdin()
            .read_to_string(&mut s)
            .map_err(|e| format!("reading stdin: {e}"))?;
        Ok(s)
    });
    let (opts, cmd) = match parsed {
        Ok(v) => v,
        Err(m) => exit_with(EXIT_USAGE, &m),
    };
    let socket = opts
        .socket
        .or_else(|| std::env::var("CITRATE_MEMBER_SOCKET").ok())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            exit_with(
                EXIT_USAGE,
                "no socket: pass --socket or set CITRATE_MEMBER_SOCKET",
            )
        });
    let bearer_file = opts
        .bearer_file
        .or_else(|| std::env::var("CITRATE_MEMBER_BEARER_FILE").ok())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            exit_with(
                EXIT_USAGE,
                "no bearer: pass --bearer-file or set CITRATE_MEMBER_BEARER_FILE",
            )
        });
    let bearer = match std::fs::read_to_string(&bearer_file) {
        Ok(b) if !b.trim().is_empty() => b.trim().to_string(),
        Ok(_) => exit_with(EXIT_DAEMON, "bearer file is empty"),
        Err(e) => exit_with(
            EXIT_DAEMON,
            &format!("reading bearer file {bearer_file}: {e}"),
        ),
    };
    let mut c = match IpcClient::connect(&PathBuf::from(&socket), &bearer) {
        Ok(c) => c,
        Err(e) => exit_with(EXIT_DAEMON, &e.to_string()),
    };
    let out = client::run(&mut c, cmd);
    println!("{}", out.json);
    std::process::exit(out.code);
}

fn exit_with(code: i32, msg: &str) -> ! {
    println!("{}", serde_json::json!({"ok": false, "error": msg}));
    std::process::exit(code);
}
