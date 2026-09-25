# iepl-node-agent

Private node-side runtime for the iepl-go control plane.

The Agent enrolls once with a short-lived token, pins the control-plane CA and
Ed25519 configuration key, then maintains one outbound mTLS WebSocket. Desired
Xray state, user revisions, heartbeats, host CPU/memory/network metrics, online
state and durable traffic batches all use that channel. There are no public
management ports on a node.

Supported inbound families:

- VLESS over TLS, WebSocket TLS, gRPC TLS, and TCP REALITY Vision
- VMess over TLS, WebSocket TLS, and gRPC TLS
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
sh install.sh --version v0.1.26 \
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
or the post-restart health check fails. If PID 1 does not have `CAP_SYS_ADMIN`,
the installer automatically removes only the namespace and execution filters
that a restricted container cannot apply. The Agent still runs as the
`iepl-agent` user with its capability boundary and managed runtime directories.

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

## Automatic BBR configuration (v0.1.52)

After installation, an upgrade, or a maintenance-service restart, the root
maintenance manager applies best-effort Linux TCP tuning. Selection uses actual
kernel capabilities, not distribution names or kernel-version guesses:

| Kernel / environment | Result |
| --- | --- |
| `bbr2` available or `tcp_bbr2` loadable | Select BBRv2 |
| Only `bbr` available or `tcp_bbr` loadable | Select kernel BBR and log the fallback; its generation is not inferred |
| `bbr3` already selected | Preserve it |
| No supported BBR implementation | Preserve current algorithm and remove stale Agent-owned tuning config |
| Restricted container / read-only procfs | Log the failure; keep Agent running |
| Read-only configuration filesystem | Apply runtime setting where possible and log missing persistence |

The Agent attempts `fq` as the default for future interfaces. Existing interface
queue disciplines, shaping rules and open connections are not replaced. A TCP
default does not configure UDP/QUIC congestion control. The code does not install
a kernel, reboot the server or claim that a generic `bbr` implementation is v2.
Module loading is skipped in detected containers because modules are host-global.

Verified settings are saved atomically in
`/etc/sysctl.d/99-zz-iepl-agent-bbr.conf`. A conflicting unmanaged file at this path
is left intact and reported. Startup rechecks capabilities after a kernel change.
Other software can still override host settings later; this is not a continuous
enforcement loop.

On systemd, a fixed root oneshot (`iepl-agent-network-tuning.service`) performs
the work outside the old maintenance unit's read-only kernel sandbox. The normal
Agent keeps its existing privileges. On OpenRC, the root maintenance process
performs tuning directly. Unsupported permissions, missing tools and failed
readback never make the upgrade fail. A failed readback triggers an attempt to
restore the previous algorithm. Each external helper has a five-second timeout.

Inspect the result on systemd:

```sh
journalctl -u iepl-agent-network-tuning.service --no-pager -n 20
sysctl net.ipv4.tcp_congestion_control net.ipv4.tcp_available_congestion_control
```

On OpenRC, inspect the maintenance-service log. Root can manually retry using
`/opt/iepl-agent/bin/iepl-agent tune-network`. Full uninstall removes only the
Agent-owned tuning files and leaves the current runtime TCP default intact.

## REALITY SNI guard (v0.1.53)

Every REALITY inbound is fronted by a TCP listener that filters the TLS
ClientHello by SNI before Xray sees the connection. Only the inbound's declared
`server_names` are allowed through; everything else is dropped without dialing
the dest.

This closes the traffic-theft path documented in the official Xray REALITY
guide: REALITY replays the client's SNI when it forwards an
authentication-failed connection to its dest, so if the dest is a CDN node that
routes by SNI instead of validating it, an attacker could proxy arbitrary
traffic through the node. With the guard in place, non-declared SNI never
reaches REALITY's fallback.

| Property | Behavior |
| --- | --- |
| Matching | Exact and case-sensitive, mirroring REALITY's own `server_names` lookup |
| Public port | Owned by the guard; Xray's REALITY inbound binds loopback behind it |
| Client address | Preserved via PROXY protocol on TCP/WebSocket/HTTPUpgrade; gRPC and XHTTP have no proxy-protocol support in this Xray fork and record loopback |
| Config changes | Guards follow `ApplyConfig`, roll back with the core, and release the public port when an inbound is disabled |
| Reporting | Heartbeat carries `guarded_inbounds` and `guard_rejected` |

The guard applies to every REALITY inbound, whether it existed before this
release or is added afterwards; no enrollment or client change is required.
`MNET_REALITY_SNI_GUARD=off` in the Agent environment disables it as an
operations escape hatch.

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

Starting with `v0.1.22`, the Agent aggregates per-user domain connection
sessions in memory, checkpoints them to a bounded local WAL, and reports
connect/disconnect time, duration, and transfer totals to the control plane.
