#!/usr/bin/env bash
# citrate-comms supply-chain audit gate (CM2-B-A006).
#
# The release workflow's `cargo audit` step is tag-triggered AND the org's GitHub
# Actions have been failing at startup, so the advisory gate has never actually run
# — which is how the libcrux advisories under the MLS crypto provider accumulated
# unseen. It now runs on every PR, on push to main and weekly
# (.github/workflows/rust-deps-audit.yml); run it locally before pushing too.
#
# Accepted advisories live as reviewed `[advisories] ignore` entries in deny.toml
# (the audit trail). A NEW advisory that is not ignored fails this gate. Minimum
# versions the advisory DB does not cover yet are `[bans] deny` floors in deny.toml.
#
#   scripts/ci/audit.sh
#
set -euo pipefail
cd "$(dirname "$0")/../.."

if ! command -v cargo-deny >/dev/null 2>&1; then
  echo "cargo-deny not installed: cargo install cargo-deny" >&2
  exit 127
fi

echo "== cargo deny check advisories (vulnerabilities deny; accepted = deny.toml ignore) =="
cargo deny check advisories

echo "== cargo deny check bans sources =="
cargo deny check bans sources

echo "audit gate: OK"
