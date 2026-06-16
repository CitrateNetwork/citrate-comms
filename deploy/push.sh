#!/usr/bin/env bash
# Push the source to the droplet and (re)bootstrap the relay. Run from your laptop,
# from the repo root or anywhere:
#
#   DROPLET=root@comms.example.com DOMAIN=comms.example.com OWNER=0x<wallet> deploy/push.sh
#
# It rsyncs the workspace (minus target/ and .git) to /opt/citrate-comms/src on the
# droplet, then runs bootstrap-droplet.sh there. Re-run any time to deploy a new build.
set -euo pipefail

DROPLET="${DROPLET:?set DROPLET=root@<droplet-ip-or-host>}"
DOMAIN="${DOMAIN:?set DOMAIN=comms.example.com}"
OWNER="${OWNER:?set OWNER=0x<40-hex workspace owner wallet>}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "==> Rsyncing $REPO_ROOT -> $DROPLET:/opt/citrate-comms/src"
ssh "$DROPLET" 'mkdir -p /opt/citrate-comms/src'
rsync -az --delete \
	--exclude target/ --exclude .git/ --exclude deploy/secrets/ \
	"$REPO_ROOT/" "$DROPLET:/opt/citrate-comms/src/"

echo "==> Running bootstrap on $DROPLET"
ssh "$DROPLET" "DOMAIN='$DOMAIN' OWNER='$OWNER' bash /opt/citrate-comms/src/deploy/bootstrap-droplet.sh"

echo "==> Done. Tail logs with:  ssh $DROPLET 'journalctl -u comms-relay -f'"
