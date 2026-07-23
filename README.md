# iepl-node-agent

Private node-side runtime for the iepl-go control plane.

The Agent enrolls once with a short-lived token, pins the control-plane CA and
Ed25519 configuration key, then maintains one outbound mTLS WebSocket. Desired
Xray state, user revisions, heartbeats, online state and durable traffic
batches all use that channel. There are no public management ports on a node.

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
sh install.sh --version v0.1.10 \
  --enroll-url https://test-vpn-agent-ss.mtmt.top/api/v1/agent/enroll \
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
