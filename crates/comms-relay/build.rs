//! Bake the deployed git commit into the relay binary so `GET /health` can report
//! it (audit rescore #10, dim 8 — deploys probed, not attested).
//!
//! Resolution order, evaluated at build time:
//!   1. `GIT_SHA` env var — the sanctioned override. `deploy/push.sh` computes it
//!      from `git rev-parse HEAD` on the operator's machine and exports it into the
//!      droplet build, because `push.sh` rsyncs the tree WITHOUT `.git/`, so a
//!      `git` call on the droplet would find no repository.
//!   2. `git rev-parse HEAD` — works for a local / CI build inside a checkout.
//!   3. `"unknown"` — never fails the build.
//!
//! The value only ever surfaces on the loopback admin `/health` snapshot; it is not
//! a secret. Embedding the same commit's sha is deterministic, so it does not disturb
//! the reproducible-build (bit-for-bit) guarantee for a given commit.

use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=GIT_SHA");
    // Workspace `.git` lives two levels up from this crate.
    println!("cargo:rerun-if-changed=../../.git/HEAD");

    let sha = std::env::var("GIT_SHA")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            Command::new("git")
                .args(["rev-parse", "HEAD"])
                .output()
                .ok()
                .filter(|o| o.status.success())
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_else(|| "unknown".to_string());

    println!("cargo:rustc-env=GIT_SHA={sha}");
}
