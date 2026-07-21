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
identity material under `/etc/iepl-agent`. GitHub Actions attaches build
provenance to the release assets and publishes a CycloneDX SBOM.

Private GitHub release installation:

```sh
export IEPL_AGENT_GITHUB_TOKEN='a short-lived token with read access'
sh install.sh --version v0.1.5 \
  --enroll-url https://test-vpn-agent-ss.mtmt.top/api/v1/agent/enroll \
  --token-file /root/iepl-agent-enroll-token
unset IEPL_AGENT_GITHUB_TOKEN
```

The enrollment token file must have mode `0600`. Neither token is installed in
the service environment or written to Agent logs. Upgrades preserve the prior
binary and systemd unit and restore them automatically when enrollment,
service reload, restart, or the post-restart health check fails.
