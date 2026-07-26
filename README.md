# iepl-node-agent

Private node-side runtime for the iepl-go control plane.

The Agent enrolls once with a short-lived token, pins the control-plane CA and
Ed25519 configuration key, then maintains one outbound mTLS WebSocket. Desired
Xray state, user revisions, heartbeats, host CPU/memory/network metrics, online
state and durable traffic batches all use that channel. There are no public
management ports on a node.

Supported inbound families:

- VLESS over TLS, WebSocket TLS, gRPC TLS, and TCP REALITY Vision
- Trojan over TLS, WebSocket TLS, and gRPC TLS
- Shadowsocks 2022 AES-128-GCM, AES-256-GCM, and ChaCha20-Poly1305
- TUIC v5 over TLS/QUIC
- Hysteria2 over TLS/QUIC, including Salamander obfuscation

Build and test:

```sh
go test ./...
go build ./cmd/iepl-agent
```

Production installation is performed by the checksummed release installer in
`scripts/install.sh`; runtime state belongs under `/var/lib/iepl-agent` and
identity material under `/etc/iepl-agent`. GitHub Actions publishes a
CycloneDX SBOM, in-toto/SLSA provenance, and a keyless Sigstore bundle that
signs the release checksum manifest.

Public GitHub release installation:

```sh
sh install.sh --version v0.1.21 \
  --enroll-url https://www.m7mt.com/api/v1/agent/enroll \
  --enroll-token '<one-time-token>'
```

The repository and release assets are public, so no GitHub token or Python
runtime is required. The installer accepts `curl` or BusyBox `wget`, verifies
the release checksum, creates the least-privilege `iepl-agent` user, and
automatically selects systemd or Alpine OpenRC. The one-time enrollment token
is kept only in the installer temporary directory and is not written to the
service environment or Agent logs. For an existing protected token file, use
`--token-file`; it must have mode `0600`.

On Alpine, the installer creates an OpenRC service and enables it with
`rc-update add iepl-agent default`. On systemd hosts it installs and enables
`iepl-agent.service` as before. Upgrades preserve the prior binary and service
unit and restore them automatically when enrollment, service reload, restart,
or the post-restart health check fails.

## Signed maintenance

Starting with `v0.1.15`, every installation also enables a root-owned
`iepl-agent-maintenance` service. The normal Agent continues to run as the
unprivileged `iepl-agent` account. The maintenance service accepts only three
Ed25519-signed operations from the pinned control-plane key:

- check the public GitHub release once per hour and report the result over WSS;
- install one exact `vX.Y.Z` release after verifying `checksums.txt`, with
  automatic binary rollback when the restarted service does not become healthy,
  then replace the root maintenance process in place with the verified release;
- remove both services, identity, runtime state, logs, installation directory,
  and the system account during a confirmed full uninstall.

There is no shell command, URL, path, or argument field in the maintenance
protocol. Replayed command IDs are stored in a root-only directory. Existing
installations older than `v0.1.15` need one regular installer upgrade; all later
checks, updates, and full uninstalls are available from the administrator
console.

## Host metrics

Starting with `v0.1.18`, the Agent samples Linux `/proc` on each heartbeat and
reports CPU utilization, memory utilization, aggregate receive/transmit rates
for non-loopback interfaces, and host uptime. The control plane stores one
rolling sample per server per minute and combines it with the existing online
user ledger. Metrics use the established outbound mTLS WebSocket and do not
open a monitoring port on the server.

Starting with `v0.1.19`, traffic batches preserve the real collection window
instead of measuring the local SQLite write duration. This keeps per-user and
server-wide realtime bandwidth aligned with the one-second Xray counter sample.

Starting with `v0.1.20`, the Agent reads its local runtime state before opening
the control WSS connection. Slow local storage therefore cannot consume the
server hello deadline and leave an otherwise healthy server offline.

Starting with `v0.1.21`, the first acknowledged heartbeat resets reconnect
backoff to one second. A node with an intermittent transport no longer remains
offline for the prior 60-second maximum after every healthy session, while
pre-health failures still retain exponential backoff.
