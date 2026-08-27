# Deployment

Ansible, graceful upgrades, Docker, and PROXY protocol deployment guidance.

Static Linux binaries are available from the
[GitHub releases page](https://github.com/kilo666mj/tlsgate/releases). Building
from source or with Ansible requires Go 1.26.5 or newer.

## Deploy

```bash
cd ansible
cp inventory.example inventory
cp group_vars/tlsgate.example.yml group_vars/tlsgate.yml
# Edit both files for your host, routes, and policy.
ansible-playbook --syntax-check playbook.yml
ansible-playbook playbook.yml --ask-become-pass
```

The real inventory and group variables are ignored; only sanitized examples are
committed. To temporarily allow unknown fingerprints during initial setup, set
`allow_unknown: true` in `group_vars/tlsgate.yml` and re-run.

To use JA4 instead of JA3, set `fingerprint: ja4` in the group variables.
Switching the method on an existing database refuses to start until you also set
`reset_fingerprints: true` for one deployment. This purges stored fingerprints;
set it back to false and re-approve clients afterward.

### Graceful upgrades

tlsgate sits in front of IMAPS and SMTPS on the mail host, so a hard restart
drops live mail sessions mid-transfer — a poor trade for updating a noise
filter. Deploys therefore hand off rather than restart, using
[tableflip](https://github.com/cloudflare/tableflip).

On `SIGHUP` the running process re-execs the newly installed binary and passes
it the listening sockets over an inherited control fd. The new process starts
serving immediately; **the old one keeps running its existing connections until
they finish**, up to `--drain-timeout` (default 1 hour). No connection is
refused in the gap, because the socket is inherited rather than rebound.

The hour matters: an IMAP IDLE session legitimately sits quiet for half an hour,
and a short drain would kill exactly the sessions this is meant to protect. A
`SIGTERM`/`SIGINT` stop is different — that drains for 10 seconds and exits,
since the operator asked for it to stop.

The unit is `Type=notify` with `NotifyAccess=all`, because after a handoff the
serving process is a child of the original main PID and has to tell systemd to
track it. The playbook uses `systemctl reload-or-restart`, which reloads a
running service and falls back to a start on first deploy.

> **First deploy of a tableflip build must be a hard restart.** A pre-tableflip
> tlsgate treats `SIGHUP` as a clean stop and never comes back — reloading one
> is how a deploy takes mail *down* instead of keeping it up. Confirm every host
> is running a tableflip build before relying on the graceful path.

## Docker

Prebuilt multi-arch images (`linux/amd64`, `linux/arm64`) are published to GHCR:

```bash
docker pull ghcr.io/kilo666mj/tlsgate:latest
```

Or build the static `FROM scratch` image yourself:

```bash
docker build -t tlsgate .
```

### docker compose

The repo ships an example [`docker-compose.yml`](../docker-compose.yml) that fronts
a mailcow backend on the standard ports. Adjust the routes/backends, then:

```bash
docker compose up -d
```

It uses host networking so the localhost backends are reachable and tlsgate sees
real client source IPs; a bridge-network variant is included as a comment.

### docker run

Run it with persistent state mounted at the default database/config directory:

```bash
docker run --rm \
  --network host \
  --cap-drop ALL \
  --cap-add NET_BIND_SERVICE \
  --security-opt no-new-privileges \
  -v tlsgate-data:/var/lib/tlsgate \
  ghcr.io/kilo666mj/tlsgate:latest serve \
    --route '[::]:993=127.0.0.1:10993' \
    --route '[::]:465=127.0.0.1:10465' \
    --allow-unknown
```

The published image runs as UID/GID 65532. Named volumes initialize with the
correct ownership. For a host bind mount, create the directory and run
`chown 65532:65532 <directory>`; add `:Z` on SELinux hosts. The capability is
needed only for listener ports below 1024.

Each `--route LISTEN=BACKEND` adds a proxied port; repeat it for as many
services as you need (host or container-network backend addresses):

```bash
docker run --rm \
  --network host \
  -v tlsgate-data:/var/lib/tlsgate \
  ghcr.io/kilo666mj/tlsgate:latest serve \
    --route '[::]:1993=127.0.0.1:10993'
```

This high-port form needs no bind capability and is suitable for enrollment
testing. With bridge networking, `127.0.0.1` is the container itself; use a
backend address reachable from that network (and expect Docker NAT to obscure
the original client address).

### Preserving client addresses with PROXY protocol

For a backend such as nginx that supports PROXY protocol, pass
`--proxy-protocol v2`. tlsgate then writes a binary PROXY v2 header before the
original, byte-identical TLS stream so the backend can recover the client's
address. The option applies to every configured route and is disabled by
default; do not enable it until every backend listener expects PROXY protocol.

For nginx, the corresponding listener and real-IP configuration is typically:

```nginx
listen 8443 ssl proxy_protocol;
set_real_ip_from 127.0.0.1;
real_ip_header proxy_protocol;
```

Keep the backend listener private and restrict `set_real_ip_from` to the
tlsgate address. A backend that does not expect the header will interpret it as
invalid TLS and reject the connection.

## Site-specific systemd-to-Docker migration

`migrate-to-docker.sh` is an example for the original mailcow deployment. It
assumes particular service names, database paths, ports, host networking, and
SELinux behavior. Inspect the plan without changing the host:

```bash
./migrate-to-docker.sh --dry-run
```

Override `IMAGE`, `BASE`, `FINGERPRINT`, `ROUTE_IMAP`, and `ROUTE_SMTP` as
needed. A real run stops the detected service briefly to copy a clean SQLite
database. Keep a recovery session open and verify a real client before agreeing
to disable the old unit.
