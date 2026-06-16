---
created: 2026-06-16T00:00:00Z
branch: main
author: Saul Loveman + Claude Opus 4.8 (1M context)
status: active
audience: Operator validating citrate-comms on an air-gapped host before pilots / Tier-1 audit
---

# Air-Gap On-Prem Test — citrate-comms

> Step-by-step validation that the workspace builds, tests, and **exchanges an
> end-to-end-encrypted message with the public network OFF**. Pre-cache deps once with
> network, disable network, then exercise: build → test → relay bring-up → offline
> message exchange. Mirrors `nist-agent/docs/audit/AIRGAP_TEST.md` (locked decision #11).

## Why this exists

`PLANSET/07` §1.2 makes air-gap-capable, on-prem operation a load-bearing posture: the
relay is a single self-hostable binary that holds **no group secrets** (server-blind) and
encrypts its store at rest. Before any pilot or the Tier-1 audit, the operator confirms:

1. The workspace **builds with no network** once deps are pre-cached.
2. `cargo test --workspace --offline` passes **≥ the baseline** (`.agentile/coverage/baseline.json` → **71**).
3. The relay binary boots and reports its server-blind banner.
4. Two clients **create a channel and exchange an MLS message with the network off**, the
   relay store holds **only ciphertext**, and the BLAKE3 audit chain **self-verifies offline**.

If any phase fails on prem, every downstream consumer (pilots, the federation pin, the
Tier-1 audit) is gated until it's fixed. **A regression here is a finding**, not a warning.

## Phase 0 — One-time pre-cache (network ON)

Run on an internet-connected host with the **same OS/arch** as the air-gap target. Only the
build cache + binaries move across; nothing else.

```sh
# 1. Clone at the audit-boundary commit.
git clone git@github.com:CitrateNetwork/citrate-comms.git
cd citrate-comms
git checkout main                 # record the exact commit hash for the sign-off

# 2. Pre-cache the toolchain + every Cargo dep.
rustup show                       # honors rust-toolchain.toml (1.96.0)
cargo fetch --locked              # populates ~/.cargo/registry from Cargo.lock

# 3. Build the workspace once to populate target/ + proc-macro/build-script caches.
cargo build --workspace --release --locked

# 4. Build the two shipped binaries explicitly.
cargo build --release --locked -p comms-relay  --bin comms-relay
cargo build --release --locked -p comms-client --bin citrate-comms

# 5. (Recommended for strict air-gap) vendor every dependency source.
cargo vendor vendor/              # prints a [source] stanza for .cargo/config.toml

# 6. Tarball the workspace + cargo cache for transport.
tar czf citrate-comms-airgap.tgz \
    citrate-comms \
    ~/.cargo/registry ~/.cargo/git
```

Move `citrate-comms-airgap.tgz` to the air-gap host via approved media.

## Phase 1 — Bring up the air-gap host (network OFF)

```sh
# Confirm the public internet is UNREACHABLE — this MUST fail.
ping -c1 1.1.1.1            # expect: 100% packet loss / network unreachable

# Extract the bundle.
tar xzf citrate-comms-airgap.tgz
cd citrate-comms

# If you vendored, point Cargo at it (strict air-gap, no registry at all):
mkdir -p .cargo
cat >> .cargo/config.toml <<'EOF'
[source.crates-io]
replace-with = "vendored-sources"
[source.vendored-sources]
directory = "vendor"
EOF

# Sanity: the relay binary boots and prints its server-blind banner.
CITRATE_COMMS_OWNER=0x0000000000000000000000000000000000000001 \
  ./target/release/comms-relay --help 2>/dev/null || \
  CITRATE_COMMS_OWNER=0x0000000000000000000000000000000000000001 \
  CITRATE_COMMS_BIND=127.0.0.1:8787 CITRATE_COMMS_DATA=/tmp/relay-smoke \
  timeout 2 ./target/release/comms-relay   # prints "server-blind: …", then exit
```

## Phase 2 — Build + test without network

```sh
cargo build --workspace --release --offline --locked
cargo test  --workspace --offline --locked          # expect >= 71 passed (baseline.json)
cargo clippy --workspace --all-targets --offline --locked -- -D warnings
cargo fmt --all -- --check
```

**Any command that reaches the network means Phase 0 was incomplete** — return to Phase 0
and re-cache. (If clippy/fmt aren't part of your offline image, skip them; the build +
test gates are the load-bearing ones.)

## Phase 3 — Offline message-exchange smoke test (the headline proof)

The end-to-end E2E path is exercised by tests that run **entirely in-process, offline** —
they stand up a relay, run the SIWE handshake + KeyPackage publish, create a group, and
exchange a real MLS message, asserting the relay sees only ciphertext:

```sh
# Two clients exchange an MLS message over a real (loopback) WebSocket; the relay
# only ever sees opaque ciphertext.
cargo test --offline -p comms-client --test ws_e2e -- --nocapture

# The high-level networked session: two NetSessions chat end-to-end through login →
# KeyPackage → group create/join → bidirectional encrypted send/recv.
cargo test --offline -p comms-client two_sessions_chat_over_the_wire -- --nocapture

# Server-blind invariant, on disk: a plaintext canary sealed in a REAL MLS message,
# pushed through a PERSISTENT relay, appears in NEITHER the wire ciphertext NOR any
# RocksDB file (SST/WAL/MANIFEST).
cargo test --offline -p comms-agent-bridge relay_persists_only_ciphertext_on_disk -- --nocapture

# The BLAKE3 audit chain verifies offline (tamper-evident, no network/anchor needed).
cargo test --offline -p comms-relay ciphertext_only_store_and_audit_verifies -- --nocapture
```

### Optional: drive the real binaries on loopback (manual, offline)

```sh
# Terminal 1 — the relay on loopback (ws://, no TLS needed locally).
CITRATE_COMMS_OWNER=0x54a4cC2515C2EfeFA7956a7280F5653E00992257 \
CITRATE_COMMS_BIND=127.0.0.1:8787 CITRATE_COMMS_DATA=/tmp/relay-airgap \
  ./target/release/comms-relay

# Terminal 2 — joiner (loopback ws:// is allowed by the connection guard).
CITRATE_COMMS_RELAY=ws://127.0.0.1:8787 CITRATE_COMMS_DOMAIN=relay.citrate.ai \
CITRATE_COMMS_WALLET_ACCOUNT=client:bob:wallet \
  ./target/release/citrate-comms       # prints Bob's 0x address

# Terminal 3 — creator invites Bob.
CITRATE_COMMS_RELAY=ws://127.0.0.1:8787 CITRATE_COMMS_DOMAIN=relay.citrate.ai \
CITRATE_COMMS_WALLET_ACCOUNT=client:alice:wallet CITRATE_COMMS_PEER=0x<bob> \
  ./target/release/citrate-comms
```
(On a headless box with no OS keyring, also set `CITRATE_COMMS_MASTER_KEY=$(openssl rand -hex 32)`
for the relay; the client keyring may also be unavailable, in which case it falls back to an
ephemeral wallet — fine for a smoke test.)

## Pass / fail criteria

| # | Check | Pass |
|---|---|---|
| 1 | `ping` to the internet (Phase 1) | **fails** (network is off) |
| 2 | `cargo build --workspace --offline` | succeeds |
| 3 | `cargo test --workspace --offline` | **≥ 71 passed**, 0 failed |
| 4 | `comms-relay` boot banner | prints `server-blind: …` |
| 5 | `ws_e2e` / `two_sessions_chat` offline | pass — message decrypts on the far side |
| 6 | `relay_persists_only_ciphertext_on_disk` | pass — canary absent on disk |
| 7 | audit-chain `verify_integrity` offline | pass |

Any network access during Phases 1–3 ⇒ **FAIL** (Phase 0 incomplete).

## Operator sign-off

```
Air-gap validation — citrate-comms
  Commit:        ____________________________   (git rev-parse HEAD)
  Host OS/arch:  ____________________________
  Date:          ____________________________
  Offline tests: ______ passed / ______ failed   (>= 71 required)
  Checks 1–7:    [ ] all PASS
  Operator:      ____________________________   Signature: ______________
```

A failed check is a **finding** filed against this repo (feeds the Tier-1 audit packet,
`docs/audit/AUDIT_PACKET.md`), not a soft warning.
