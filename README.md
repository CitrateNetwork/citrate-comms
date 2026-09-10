# citrate-comms

> A self-hostable, end-to-end-encrypted agentic team workspace (Comms + CRM + PM) for the Citrate Network, delivered by a server-blind relay that can never read your messages.

## What it is

`citrate-comms` is an E2E-encrypted team workspace whose messages are routed by a
**server-blind relay**: the relay stores and forwards MLS (RFC 9420) ciphertext and
routing metadata only — all plaintext and all group secrets live exclusively on
member clients. AI agents join a conversation as **cryptographic members**, not
server-side wiretaps. It ships as two tracks: a native Rust workspace (the relay
+ Slint client + agent bridge) and a customer-facing web client
(`citrate-comms-web`). Login is via the Citrate identity authority (OIDC / SIWE);
the audit log is a BLAKE3 hash-chain optionally anchored to chain **40204**.

See the concept docs at https://docs.citrate.ai/comms. Login upstream is
[citrate-identity](https://github.com/CitrateNetwork/citrate-identity).

## Prerequisites

```bash
# Rust (pinned toolchain) + a C toolchain for RocksDB.
rustup show                 # rust-toolchain.toml pins 1.96.0 (auto-installed by rustup)
# System packages for the RocksDB / crypto build:
#   Debian/Ubuntu:
sudo apt-get install -y build-essential clang libclang-dev pkg-config
#   macOS: clang ships with Xcode command-line tools
# Web client (optional track): Node 20+ and pnpm/npm.
```

- OS: Linux or macOS. The relay defaults to a loopback / air-gap posture.
- The relay uses the OS keyring for its at-rest master key by default (or set one
  explicitly — see "Configuration").

## Build from source

```bash
git clone https://github.com/CitrateNetwork/citrate-comms.git
cd citrate-comms
cargo build --workspace --release --locked
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Expected artifact: `target/release/comms-relay` (the self-hostable relay binary),
plus the client/bridge crates. First build pulls RocksDB + OpenMLS and can take
several minutes and ~1–2 GB RAM. **Server-blind is enforced by the build graph**:
the relay links `comms-core` with `default-features=false`, so the `mls` module
(the only place group secrets live) is never compiled into the relay — build the
relay package-scoped (`-p comms-relay`), never let a `--workspace` build govern the
deployed binary.

## Run locally

The relay is the server component. It needs one required env var — the workspace
owner wallet (the RBAC trust anchor):

```bash
export CITRATE_COMMS_OWNER=0x1111111111111111111111111111111111111111  # 0x + 40 hex
cargo run -p comms-relay --release
```

Default listen: **`ws://127.0.0.1:8787`** (transport). Loopback admin surface:
**`http://127.0.0.1:8788`**. RocksDB store: `./data`. Verify it's up via the
unauthenticated, loopback-only admin health route:

```bash
curl -s http://127.0.0.1:8788/health     # → JSON snapshot
curl -s http://127.0.0.1:8788/status     # → "running"
```

On start the relay prints the served domain, the owner RBAC anchor, the store path,
and a redacted admin-token fingerprint (the real bearer token is written to
`CITRATE_COMMS_ADMIN_TOKEN_FILE` if set, 0600 — never logged).

**Web client (optional track):**

```bash
cd webapp
cp .env.example .env.local
pnpm install
pnpm dev -p 3004            # citrate-comms-web on :3004 (APP_ORIGIN default)
```

## Connect it locally  ← the differentiator

1. **Run the relay** on `ws://127.0.0.1:8787` with `CITRATE_COMMS_OWNER` set
   (above). Clients dial this address; the relay is otherwise standalone (no chain
   node required for the local loop — chain 40204 anchoring of the audit log is
   optional/roadmap).
2. **Point clients at the relay.** Native `comms-client` and the agent bridge dial
   `ws://127.0.0.1:8787`; set `CITRATE_COMMS_DOMAIN` on the relay to match the
   domain your clients bind in the SIWE handshake (default `relay.citrate.ai`).
3. **Wire the web client to identity.** Run
   [citrate-identity](https://github.com/CitrateNetwork/citrate-identity) on
   `:3000`, then in `webapp/.env.local`:
   ```bash
   NEXT_PUBLIC_AUTH_MODE=oidc
   NEXT_PUBLIC_OIDC_ISSUER=http://localhost:3000
   NEXT_PUBLIC_OIDC_CLIENT_ID=citrate-comms-web
   OIDC_ISSUER=http://localhost:3000
   OIDC_JWKS_URL=http://localhost:3000/jwks
   OIDC_AUDIENCE=citrate-comms-web
   APP_ORIGIN=http://localhost:3004
   ```
   The authority must register `citrate-comms-web` with redirect
   `http://localhost:3004/auth/callback`.
4. **End-to-end check:** relay `GET /health` returns 200; a client can create a
   workspace owned by `CITRATE_COMMS_OWNER` and exchange an MLS message that the
   relay forwards without ever holding plaintext.

For the full chain → identity → apps bring-up see https://docs.citrate.ai/local-stack.

## Configuration

Relay env (all read at startup, see `crates/comms-relay/src/main.rs`):

| Var | Default | Purpose |
|-----|---------|---------|
| `CITRATE_COMMS_OWNER` | **required** | Workspace owner wallet (`0x` + 40 hex); RBAC trust anchor. |
| `CITRATE_COMMS_BIND` | `127.0.0.1:8787` | WebSocket listen address. |
| `CITRATE_COMMS_ADMIN_BIND` | `127.0.0.1:8788` | Loopback-only admin surface. |
| `CITRATE_COMMS_DATA` | `./data` | RocksDB store path (AES-256-GCM-SIV at rest). |
| `CITRATE_COMMS_DOMAIN` | `relay.citrate.ai` | Logical relay domain bound in the SIWE handshake. |
| `CITRATE_COMMS_MASTER_KEY` | OS keyring | Optional explicit at-rest key (64 hex); else keyring, created on first run. |
| `CITRATE_COMMS_ADMIN_TOKEN_FILE` | unset | Path to export the admin bearer token (0600); it is never logged. |

Web client env vars are annotated in `webapp/.env.example`
(`NEXT_PUBLIC_OIDC_*`, `DATABASE_URL`, `RESEND_API_KEY`, `COMMS_ENC_KEY`, …).

## Links

- Docs: https://docs.citrate.ai/comms
- Depends on: [citrate-identity](https://github.com/CitrateNetwork/citrate-identity) (login; optional chain 40204 audit anchoring)
- Consumed by: Citrate teams self-hosting the workspace; the native client and web client
- Contributing (DCO): CONTRIBUTING.md · Security: SECURITY.md · License: LICENSE

## License

Source-available (BUSL-1.1) — free for personal/non-commercial; commercial = membership.
