#!/bin/sh
set -eu

repo="guanzihao166/iepl-node-agent"
version="${IEPL_AGENT_VERSION:-}"
enroll_url=""
token_file=""

usage() {
  echo "usage: IEPL_AGENT_GITHUB_TOKEN=... $0 --version vX.Y.Z [--enroll-url https://...] [--token-file /root/token]" >&2
  exit 2
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --version) version="${2:-}"; shift 2 ;;
    --enroll-url) enroll_url="${2:-}"; shift 2 ;;
    --token-file) token_file="${2:-}"; shift 2 ;;
    *) usage ;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "installer must run as root" >&2; exit 1; }
[ -n "$version" ] || usage
[ -n "${IEPL_AGENT_GITHUB_TOKEN:-}" ] || { echo "IEPL_AGENT_GITHUB_TOKEN is required for the private repository" >&2; exit 1; }

case "$(uname -m)" in
  x86_64|amd64) arch="amd64" ;;
  aarch64|arm64) arch="arm64" ;;
  *) echo "unsupported architecture" >&2; exit 1 ;;
esac

asset="iepl-agent-linux-${arch}"
base="https://github.com/${repo}/releases/download/${version}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

auth="Authorization: Bearer ${IEPL_AGENT_GITHUB_TOKEN}"
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
  -H "$auth" -H "Accept: application/octet-stream" -o "$tmp/$asset" "$base/$asset"
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
  -H "$auth" -H "Accept: application/octet-stream" -o "$tmp/checksums.txt" "$base/checksums.txt"
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
  -H "$auth" -H "Accept: application/octet-stream" -o "$tmp/iepl-agent.service" "$base/iepl-agent.service"

(cd "$tmp" && awk -v asset="$asset" '$2 == asset || $2 == "iepl-agent.service" { print }' checksums.txt | sha256sum -c -)
unset auth IEPL_AGENT_GITHUB_TOKEN

if ! id iepl-agent >/dev/null 2>&1; then
  useradd --system --home-dir /var/lib/iepl-agent --shell /usr/sbin/nologin iepl-agent
fi
install -d -o root -g root -m 0755 /opt/iepl-agent/bin
install -d -o iepl-agent -g iepl-agent -m 0700 /etc/iepl-agent /var/lib/iepl-agent
install -o root -g root -m 0755 "$tmp/$asset" /opt/iepl-agent/bin/iepl-agent.new
/opt/iepl-agent/bin/iepl-agent.new version >/dev/null
mv -f /opt/iepl-agent/bin/iepl-agent.new /opt/iepl-agent/bin/iepl-agent

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
if [ -f "$script_dir/../packaging/systemd/iepl-agent.service" ]; then
  install -o root -g root -m 0644 "$script_dir/../packaging/systemd/iepl-agent.service" /etc/systemd/system/iepl-agent.service
else
  install -o root -g root -m 0644 "$tmp/iepl-agent.service" /etc/systemd/system/iepl-agent.service
fi
systemctl daemon-reload

if [ -n "$enroll_url" ] || [ -n "$token_file" ]; then
  [ -n "$enroll_url" ] && [ -n "$token_file" ] || usage
  [ -f "$token_file" ] || { echo "enrollment token file does not exist" >&2; exit 1; }
  mode="$(stat -c '%a' "$token_file")"
  [ "$mode" = "600" ] || { echo "enrollment token file must have mode 600" >&2; exit 1; }
  /opt/iepl-agent/bin/iepl-agent enroll --url "$enroll_url" --token-file "$token_file"
  chown -R iepl-agent:iepl-agent /etc/iepl-agent /var/lib/iepl-agent
fi

systemctl enable iepl-agent.service
if [ -f /etc/iepl-agent/identity.json ]; then
  systemctl restart iepl-agent.service
else
  echo "Agent installed but not started: enrollment identity is absent."
fi
