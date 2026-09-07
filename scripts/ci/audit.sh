#!/usr/bin/env bash
# citrate-comms supply-chain audit gate (CM2-B-A006).
#
# The release workflow's `cargo audit` step is tag-triggered AND the org's GitHub
# Actions have been failing at startup, so the advisory gate has never actually run
# — which is how the libcrux advisories under the MLS crypto provider accumulated
# unseen. Run this LOCALLY (and wire it into any working PR gate / pre-push hook) so
# the check fires before code lands, not only on a release tag that never builds.
#
# Accepted advisories live as reviewed `[advisories] ignore` entries in deny.toml
# (the audit trail). A NEW advisory that is not ignored fails this gate.
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
