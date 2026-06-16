//! `build-manifest` — hash a staging tree into `release.manifest.toml`, bound to the
//! two-machine reproducibility gate via `--expect` (COMMS-S4 WP-4.7).
//!
//! Usage:
//!   build-manifest --version v0.1.0 --git-rev <sha> --staging release-staging \
//!     --expect bin/comms-relay=<sha256> --expect bin/citrate-comms=<sha256> \
//!     --out release-staging/release.manifest.toml

use std::process::ExitCode;

use comms_release::Manifest;

fn main() -> ExitCode {
    match run() {
        Ok(out) => {
            eprintln!("wrote {out}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("build-manifest: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<String, String> {
    let mut version = None;
    let mut git_rev = None;
    let mut staging = None;
    let mut out = None;
    let mut expect: Vec<(String, String)> = Vec::new();

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--version" => version = args.next(),
            "--git-rev" => git_rev = args.next(),
            "--staging" => staging = args.next(),
            "--out" => out = args.next(),
            "--expect" => {
                let kv = args.next().ok_or("--expect needs PATH=SHA256")?;
                let (p, h) = kv.split_once('=').ok_or("--expect must be PATH=SHA256")?;
                expect.push((p.to_string(), h.to_string()));
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }

    let version = version.ok_or("--version is required")?;
    let git_rev = git_rev.ok_or("--git-rev is required")?;
    let staging = staging.ok_or("--staging is required")?;
    let out = out.ok_or("--out is required")?;

    let manifest = Manifest::build(&version, &git_rev, std::path::Path::new(&staging), &expect)
        .map_err(|e| e.to_string())?;
    let toml = manifest.to_toml().map_err(|e| e.to_string())?;
    std::fs::write(&out, toml).map_err(|e| e.to_string())?;
    Ok(out)
}
