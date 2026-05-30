#!/usr/bin/env bash
#
# Migrate tlsgate on this host from the local binary + systemd unit to a
# Docker Compose deployment under /opt/tlsgate, preserving the approval DB.
#
# Run on the mx host as root:
#   sudo ./migrate-to-docker.sh
#
# It is safe to re-run: it will not overwrite an existing /opt/tlsgate/data DB.
# Roll back at any time with:  cd /opt/tlsgate && docker compose down && systemctl start <old-service>
set -euo pipefail

# --- config (override via env if needed) ------------------------------------
IMAGE="${IMAGE:-ghcr.io/kilo666mj/tlsgate:latest}"
BASE="${BASE:-/opt/tlsgate}"
FINGERPRINT="${FINGERPRINT:-ja3}"   # keep ja3 so the migrated approvals stay valid
# Routes are LISTEN=BACKEND; defaults match the mail (mailcow) deployment.
ROUTE_IMAP="${ROUTE_IMAP:-[::]:993=127.0.0.1:10993}"
ROUTE_SMTP="${ROUTE_SMTP:-[::]:465=127.0.0.1:10465}"
ASSUME_YES="${ASSUME_YES:-0}"       # set to 1 to skip the disable-old-service prompt

DATA="$BASE/data"

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root (sudo $0)"
command -v docker >/dev/null              || die "docker not installed"
docker compose version >/dev/null 2>&1    || die "docker compose plugin not available"

# --- 1. detect the existing deployment --------------------------------------
OLD_SVC=""
for svc in tlsgate mail-fingerprint; do
	if systemctl list-unit-files "$svc.service" >/dev/null 2>&1 \
		&& systemctl cat "$svc.service" >/dev/null 2>&1; then
		OLD_SVC="$svc"
		break
	fi
done
[ -n "$OLD_SVC" ] && log "found existing service: $OLD_SVC.service" \
	|| warn "no existing tlsgate/mail-fingerprint service found; continuing (fresh install)"

OLD_DATA=""
for d in /var/lib/tlsgate /var/lib/mail-fingerprint; do
	if [ -f "$d/db.sqlite" ]; then OLD_DATA="$d"; break; fi
done
[ -n "$OLD_DATA" ] && log "found existing data: $OLD_DATA" \
	|| warn "no existing db.sqlite found; the new instance will start empty"

# --- 2. write the compose file ----------------------------------------------
log "creating $BASE"
mkdir -p "$DATA"

cat > "$BASE/docker-compose.yml" <<YAML
services:
  tlsgate:
    image: $IMAGE
    restart: unless-stopped
    # host networking: binds the privileged ports directly, reaches the
    # localhost backends, and preserves real client source IPs.
    network_mode: host
    command:
      - serve
      - --route=$ROUTE_IMAP
      - --route=$ROUTE_SMTP
      - --fingerprint=$FINGERPRINT
    volumes:
      # :Z relabels the bind mount for SELinux (container_file_t). Harmless on
      # hosts without SELinux. Required on RHEL/Fedora-family hosts or the
      # container cannot read its data even as root.
      - ./data:/var/lib/tlsgate:Z
    read_only: true
    tmpfs: ["/tmp"]
    cap_drop: ["ALL"]
    cap_add: ["NET_BIND_SERVICE"]
    security_opt: ["no-new-privileges:true"]
YAML
log "wrote $BASE/docker-compose.yml"

# --- 3. pull the image (no downtime yet) ------------------------------------
log "pulling $IMAGE"
( cd "$BASE" && docker compose pull )

# --- 4. stop old service, then copy the DB (clean, WAL flushed) -------------
if [ -n "$OLD_SVC" ] && systemctl is-active --quiet "$OLD_SVC"; then
	log "stopping $OLD_SVC (frees ports 993/465; brief mail downtime)"
	systemctl stop "$OLD_SVC"
fi

if [ -n "$OLD_DATA" ]; then
	if [ -f "$DATA/db.sqlite" ]; then
		warn "$DATA/db.sqlite already exists — NOT overwriting it"
	else
		log "migrating database from $OLD_DATA"
		cp -a "$OLD_DATA"/db.sqlite* "$DATA"/ 2>/dev/null || cp -a "$OLD_DATA"/db.sqlite "$DATA"/
		[ -f "$OLD_DATA/config.json" ] && cp -a "$OLD_DATA/config.json" "$DATA"/ && log "migrated config.json"
	fi
fi

# The container runs as root with all capabilities dropped, so it does NOT have
# CAP_DAC_OVERRIDE and must actually own its files. The migrated DB/config are
# still owned by the old system user, so hand them to root (uid 0).
log "setting ownership of $DATA to root (container runtime uid)"
chown -R 0:0 "$DATA"

# --- 5. start the container -------------------------------------------------
log "starting tlsgate container"
( cd "$BASE" && docker compose up -d )

sleep 2
if ( cd "$BASE" && docker compose ps --status running --quiet | grep -q .); then
	log "container is running. Recent logs:"
	( cd "$BASE" && docker compose logs --tail=15 )
else
	( cd "$BASE" && docker compose logs --tail=40 ) || true
	die "container is not running — check the logs above; the old service is stopped, start it to roll back"
fi

# --- 6. confirm, then disable the old unit ----------------------------------
if [ -n "$OLD_SVC" ]; then
	cat <<EOF

Verify a real mail client now connects (look for APPROVED in the logs above),
then disable the old unit so it does not grab ports 993/465 on next boot.
EOF
	if [ "$ASSUME_YES" = "1" ]; then
		REPLY=y
	else
		read -r -p "Disable $OLD_SVC.service now? [y/N] " REPLY || REPLY=n
	fi
	case "$REPLY" in
		[yY]*) systemctl disable "$OLD_SVC"; log "disabled $OLD_SVC.service" ;;
		*)     warn "left $OLD_SVC.service enabled — disable it yourself once verified: systemctl disable $OLD_SVC" ;;
	esac
fi

log "done. Manage with: cd $BASE && docker compose [logs|pull|up -d|down]"
