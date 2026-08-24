# Deployment

Ansible, graceful upgrades, Docker, and PROXY protocol deployment guidance.

## Deploy

```bash
cd ansible
ansible-playbook playbook.yml --ask-become-pass
```

To temporarily allow unknown fingerprints (e.g. during initial setup), set
`allow_unknown=true` in `ansible/inventory` and re-run.

To use JA4 instead of JA3, set `fingerprint=ja4` in `ansible/inventory` (default
`ja3`). Switching the method on an existing database refuses to start until you
also pass `--reset-fingerprints` (purges stored fingerprints); re-approve
clients after.

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
  -p 993:993 \
  -p 465:465 \
  -v tlsgate-data:/var/lib/tlsgate \
  tlsgate serve \
    --route [::]:993=127.0.0.1:10993 \
    --route [::]:465=127.0.0.1:10465 \
    --allow-unknown
```

Each `--route LISTEN=BACKEND` adds a proxied port; repeat it for as many
services as you need (host or container-network backend addresses):

```bash
docker run --rm \
  --network host \
  -v tlsgate-data:/var/lib/tlsgate \
  tlsgate serve \
    --route [::]:993=127.0.0.1:10993 \
    --route [::]:465=127.0.0.1:10465
```

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
