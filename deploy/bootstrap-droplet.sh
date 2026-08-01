#!/usr/bin/env bash
# Bootstrap a fresh Ubuntu 22.04/24.04 droplet into a citrate-comms relay host.
# Run as root ON THE DROPLET, with the source tree already present at
# /opt/citrate-comms/src (push.sh rsyncs it there). Idempotent: safe to re-run.
#
#   DOMAIN=comms.example.com OWNER=0x<your-wallet> ./bootstrap-droplet.sh
#
# What it does: installs build deps + Caddy + Rust, creates the `comms` service user,
# builds the relay, installs the .env / systemd unit / Caddyfile (substituting your
# domain), generates an at-rest master key on first run, and starts everything.
set -euo pipefail

DOMAIN="${DOMAIN:?set DOMAIN=comms.example.com}"
OWNER="${OWNER:?set OWNER=0x<40-hex workspace owner wallet>}"
SRC="${SRC:-/opt/citrate-comms/src}"
PREFIX="/opt/citrate-comms"

log() { printf '\n\033[1;32m==>\033[0m %s\n' "$*"; }

[[ $EUID -eq 0 ]] || { echo "run as root"; exit 1; }
[[ -d "$SRC" ]] || { echo "source not found at $SRC — run deploy/push.sh from your laptop first"; exit 1; }
[[ "$OWNER" =~ ^0x[0-9a-fA-F]{40}$ ]] || { echo "OWNER must be 0x + 40 hex"; exit 1; }

log "Installing build dependencies + Caddy"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
# clang/libclang: rocksdb's bindgen needs them. The rest: build-essential + tooling.
apt-get install -y build-essential clang libclang-dev pkg-config libssl-dev \
	libdbus-1-dev \
	curl git ca-certificates debian-keyring debian-archive-keyring apt-transport-https

if ! command -v caddy >/dev/null 2>&1; then
	curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
	curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list >/dev/null
	apt-get update -y && apt-get install -y caddy
fi

log "Adding a low-memory swapfile if RAM < 2 GB (rocksdb build is memory-hungry)"
mem_kb=$(awk '/MemTotal/{print $2}' /proc/meminfo)
if [[ "$mem_kb" -lt 2000000 && ! -f /swapfile ]]; then
	fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile
	echo '/swapfile none swap sw 0 0' >>/etc/fstab
fi

log "Creating the comms service user + layout"
id -u comms >/dev/null 2>&1 || useradd --system --home "$PREFIX" --shell /usr/sbin/nologin comms
mkdir -p "$PREFIX/bin" "$PREFIX/data"

log "Installing Rust toolchain (rootless, into /opt/rust)"
export RUSTUP_HOME=/opt/rust/rustup CARGO_HOME=/opt/rust/cargo
if [[ ! -x "$CARGO_HOME/bin/cargo" ]]; then
	curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path --profile minimal
fi
export PATH="$CARGO_HOME/bin:$PATH"

log "Building comms-relay (release, locked)"
cd "$SRC"
# `-p comms-relay` is LOad-BEARING, not stylistic. comms-relay depends on comms-core
# with `default-features = false, features = ["store"]` so the MLS engine is not
# compiled in — that is how server-blindness is enforced (PLANSET/02 §1).
#
# But Cargo unifies features across a build. `cargo build --workspace` resolves
# comms-core to `mls + store` because comms-client asks for it, and the relay then
# links THAT artifact. Measured 2026-08-01: a workspace-built relay binary carries 39
# OpenMLS symbol references; this per-package build carries 0.
#
# So the guarantee depends on HOW the relay is built, and nothing used to check.
# Changing this line to `--workspace` would silently ship the MLS engine inside the
# server-blind relay.
cargo build --release --locked -p comms-relay

# Verify the artifact, not the intent. The dependency graph is the mechanism; this is
# the proof that the mechanism held for the binary about to be installed.
log "Verifying the relay binary links no MLS engine (server-blind invariant)"
if nm -a "$SRC/target/release/comms-relay" 2>/dev/null | grep -qi "openmls" \
	|| strings "$SRC/target/release/comms-relay" 2>/dev/null | grep -qi "openmls"; then
	echo "FATAL: the relay binary references OpenMLS." >&2
	echo "  The server-blind invariant is that the relay CANNOT decrypt, enforced by" >&2
	echo "  not compiling the MLS module into it. Something re-enabled comms-core's" >&2
	echo "  'mls' feature for this build — most likely a workspace-wide build command." >&2
	echo "  Refusing to install. Build with: cargo build --release --locked -p comms-relay" >&2
	exit 1
fi

install -m 0755 "$SRC/target/release/comms-relay" "$PREFIX/bin/comms-relay"

log "Installing .env (generating a master key on first run)"
if [[ ! -f "$PREFIX/.env" ]]; then
	MASTER_KEY=$(openssl rand -hex 32)
	sed -e "s|comms.example.com|$DOMAIN|g" \
		-e "s|^CITRATE_COMMS_OWNER=.*|CITRATE_COMMS_OWNER=$OWNER|" \
		-e "s|^CITRATE_COMMS_MASTER_KEY=.*|CITRATE_COMMS_MASTER_KEY=$MASTER_KEY|" \
		"$SRC/deploy/.env.example" >"$PREFIX/.env"
	echo "  generated a new at-rest master key — backed-up copy recommended"
else
	echo "  $PREFIX/.env exists; leaving it (and its master key) untouched"
fi
chmod 600 "$PREFIX/.env"
chown -R comms:comms "$PREFIX"

log "Installing the systemd unit"
install -m 0644 "$SRC/deploy/comms-relay.service" /etc/systemd/system/comms-relay.service
systemctl daemon-reload
systemctl enable --now comms-relay
systemctl restart comms-relay

log "Installing the Caddyfile for $DOMAIN (append-safe; co-located host)"
# Caddy runs as the `caddy` user; the Caddyfile's `log { output file ... }` directive
# needs a log dir it can write, or Caddy fails to (re)start with "permission denied".
mkdir -p /var/log/caddy
chown caddy:caddy /var/log/caddy 2>/dev/null || true
CADDYFILE=/etc/caddy/Caddyfile
if [[ -f "$CADDYFILE" ]] && grep -qE "^[[:space:]]*(https://)?$DOMAIN[[:space:]]*\{" "$CADDYFILE"; then
	echo "  $DOMAIN site block already present in $CADDYFILE — leaving it untouched"
else
	# This droplet co-locates other production domains. NEVER overwrite the
	# Caddyfile; back it up and APPEND the comms block instead.
	if [[ -f "$CADDYFILE" ]]; then
		cp -a "$CADDYFILE" "$CADDYFILE.bak-pre-comms-$(date +%Y%m%d-%H%M%S)"
		printf '\n' >>"$CADDYFILE"
	fi
	sed "s|comms.example.com|$DOMAIN|g" "$SRC/deploy/Caddyfile" >>"$CADDYFILE"
	echo "  appended $DOMAIN block to $CADDYFILE"
fi
caddy validate --config "$CADDYFILE" --adapter caddyfile
systemctl reload caddy || systemctl restart caddy

log "Done. Verify:"
echo "  systemctl status comms-relay --no-pager"
echo "  curl -s http://127.0.0.1:8788/health   # loopback admin (bearer-gated for mutations)"
echo "  Clients connect to:  wss://$DOMAIN"
echo "  Workspace owner:     $OWNER"
