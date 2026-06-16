# Deploying the citrate-comms relay (DigitalOcean + Caddy)

A one-page runbook to stand up `wss://comms.<yourdomain>` so two teammates can chat
across the internet. The relay is **server-blind** (ciphertext + routing metadata only),
binds **loopback**, and is fronted by **Caddy** with automatic HTTPS. Total time ~15 min
(plus a one-time rocksdb build on the droplet).

```
[ teammate A ] ──wss──┐
                      ▼
          comms.<domain>  (DO droplet)
          ┌─────────────────────────┐
          │ Caddy :443  (auto-TLS)   │
          │   └─ proxy → 127.0.0.1   │
          │ comms-relay :8787 (ws)   │  ← loopback, server-blind, AES-256-GCM at rest
          └─────────────────────────┘
                      ▲
[ teammate B ] ──wss──┘
```

## 0. Prerequisites
- A DigitalOcean **droplet**: Ubuntu 22.04/24.04, **2 GB RAM** (1 GB works — the script
  adds swap for the rocksdb build), your SSH key added.
- A **domain** you control, with a DNS **A record** `comms.<yourdomain> → <droplet IP>`
  created **before** you start (Caddy needs it to issue the TLS cert).
- Your **workspace owner wallet** address (`0x…`, 40 hex) — the RBAC trust anchor and the
  teammate who runs the client in "create channel" mode.

## 1. One-command deploy (from your laptop)
```bash
DROPLET=root@<droplet-ip> \
DOMAIN=comms.<yourdomain> \
OWNER=0x<your-wallet> \
deploy/push.sh
```
`push.sh` rsyncs the source to `/opt/citrate-comms/src` and runs `bootstrap-droplet.sh`,
which installs build deps + Caddy + Rust, builds the relay, generates an at-rest master
key, installs the `.env` / systemd unit / Caddyfile, and starts everything.

## 2. Verify
```bash
ssh root@<droplet-ip> 'systemctl status comms-relay --no-pager'
ssh root@<droplet-ip> 'journalctl -u comms-relay -n 30 --no-pager'
# From your laptop, the TLS endpoint should answer (a WebSocket upgrade is expected):
curl -sI https://comms.<yourdomain> | head -1
```
The relay log prints the owner, store path, and `server-blind: …` banner. The **admin
surface** (`127.0.0.1:8788`) is loopback-only and never proxied.

## 3. Run the two-person test
Both teammates install the `citrate-comms` desktop client (a single binary — see
`deploy/../README` / WP-4.7 release artifacts). **Order matters:** the joiner signs in
first so their KeyPackage is published, then the owner invites them.

**Teammate B (joiner) — signs in first:**
```bash
CITRATE_COMMS_RELAY=wss://comms.<yourdomain> \
CITRATE_COMMS_DOMAIN=comms.<yourdomain> \
citrate-comms
# The app prints B's address: 0x<bob>. Share it with A.
```

**Teammate A (owner / creator):**
```bash
CITRATE_COMMS_RELAY=wss://comms.<yourdomain> \
CITRATE_COMMS_DOMAIN=comms.<yourdomain> \
CITRATE_COMMS_PEER=0x<bob> \
citrate-comms
# A must sign in with the SAME wallet as CITRATE_COMMS_OWNER on the relay.
```
A creates a channel and invites B; B joins automatically; the header pill goes
**● live**; messages are MLS-encrypted end to end. The relay never sees plaintext.

> Wallet identity is stored in the OS keyring per account
> (`CITRATE_COMMS_WALLET_ACCOUNT`, default `client:default:wallet`). To run two identities
> on one machine for a smoke test, set a different account for each.

## 4. Updating the relay
Re-run `deploy/push.sh` — it rsyncs the new source and rebuilds. The `.env` (and its
master key) and the RocksDB store are preserved across redeploys.

## Security notes
- **Back up the master key** (`/opt/citrate-comms/.env`, `CITRATE_COMMS_MASTER_KEY`).
  Losing it makes the at-rest store unreadable. It never leaves the droplet.
- The relay holds **no group secrets** — a compromised relay leaks metadata (who/when/
  sizes), never message content. See `PLANSET/07` §5 (threat model).
- Plaintext `ws://` to a remote host is refused by the client (WP-4.6); always use `wss://`.
- For a **LAN / airgap** test instead of the internet, point clients at the relay's
  private address and set `CITRATE_COMMS_ALLOW_INSECURE_WS=1` (plaintext ws on a trusted
  network) — or run everything on one box over loopback. See `docs/audit/AIRGAP_TEST.md`.
