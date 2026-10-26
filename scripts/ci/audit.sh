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

for tool in cargo-deny cargo-audit; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "$tool not installed: cargo install $tool" >&2
    exit 127
  fi
done

echo "== RUSTSEC-2026-0387 ignore guard (crypto-bigint < 0.7.6 only via elliptic-curve 0.13) =="
python3 scripts/ci/check_crypto_bigint_users.py --self-test
python3 scripts/ci/check_crypto_bigint_users.py

echo "== cargo deny check advisories (vulnerabilities deny; accepted = deny.toml ignore) =="
cargo deny check advisories

echo "== cargo audit (whole Cargo.lock; accepted = .cargo/audit.toml) =="
cargo audit

echo "== cargo deny check bans sources =="
cargo deny check bans sources

echo "audit gate: OK"
