#!/bin/sh
set -eu

repo="guanzihao166/iepl-node-agent"
version="${IEPL_AGENT_VERSION:-}"
enroll_url=""
token_file=""
enroll_token=""

usage() {
  echo "usage: sh install.sh --version vX.Y.Z --enroll-url https://... --enroll-token TOKEN" >&2
  echo "   or: sh install.sh --version vX.Y.Z --enroll-url https://... --token-file /root/token" >&2
  exit 2
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --version) version="${2:-}"; shift 2 ;;
    --enroll-url) enroll_url="${2:-}"; shift 2 ;;
    --token-file) token_file="${2:-}"; shift 2 ;;
    --enroll-token) enroll_token="${2:-}"; shift 2 ;;
    *) usage ;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "installer must run as root" >&2; exit 1; }
[ -n "$version" ] || usage
[ -z "$token_file" ] || [ -z "$enroll_token" ] || { echo "use either --token-file or --enroll-token, not both" >&2; exit 1; }

has_identity=0
[ -f /etc/iepl-agent/identity.json ] && has_identity=1
if [ "$has_identity" -eq 0 ]; then
  [ -n "$enroll_url" ] || usage
  [ -n "$token_file" ] || [ -n "$enroll_token" ] || usage
elif [ -n "$token_file" ] || [ -n "$enroll_token" ]; then
  [ -n "$enroll_url" ] || usage
fi

if [ -n "$enroll_url" ]; then
  case "$enroll_url" in
    https://*) ;;
    *) echo "enrollment URL must use https://" >&2; exit 1 ;;
  esac
fi

case "$(uname -m)" in
  x86_64|amd64) arch="amd64" ;;
  aarch64|arm64) arch="arm64" ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

fetch() {
  source_url=$1
  destination=$2
  if command -v curl >/dev/null 2>&1; then
    curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 -o "$destination" "$source_url"
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O "$destination" "$source_url"
  else
    echo "curl or wget is required" >&2
    exit 1
  fi
}

if [ "$version" = "latest" ]; then
  release_base="https://github.com/${repo}/releases/latest/download"
  expected_version=""
else
  release_base="https://github.com/${repo}/releases/download/${version}"
  expected_version="$version"
fi

asset="iepl-agent-linux-${arch}"
tmp="$(mktemp -d /tmp/iepl-agent-install.XXXXXX)"
trap 'rm -rf "$tmp"' EXIT INT TERM

fetch "${release_base}/${asset}" "$tmp/$asset"
fetch "${release_base}/checksums.txt" "$tmp/checksums.txt"

checksum_line="$(awk -v asset="$asset" '$2 == asset { print; found = 1; exit } END { if (!found) exit 1 }' "$tmp/checksums.txt")" || {
  echo "release checksum is missing for $asset" >&2
  exit 1
}
printf '%s\n' "$checksum_line" | (cd "$tmp" && sha256sum -c -)

is_alpine=0
[ -f /etc/alpine-release ] && is_alpine=1
service_mode=""
service_path=""
service_source=""
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  service_mode="systemd"
  service_path="/etc/systemd/system/iepl-agent.service"
  service_source="$tmp/iepl-agent.service"
  fetch "${release_base}/iepl-agent.service" "$service_source"
elif command -v rc-service >/dev/null 2>&1 || [ "$is_alpine" -eq 1 ]; then
  service_mode="openrc"
  service_path="/etc/init.d/iepl-agent"
  service_source="$tmp/iepl-agent.openrc"
  fetch "${release_base}/iepl-agent.openrc" "$service_source"
else
  echo "no supported service manager found; systemd or OpenRC is required" >&2
  exit 1
fi

if ! id iepl-agent >/dev/null 2>&1; then
  if [ "$is_alpine" -eq 1 ]; then
    addgroup -S iepl-agent 2>/dev/null || true
    adduser -S -D -H -s /sbin/nologin -G iepl-agent iepl-agent
  elif command -v useradd >/dev/null 2>&1; then
    useradd --system --home-dir /var/lib/iepl-agent --shell /usr/sbin/nologin iepl-agent
  elif command -v adduser >/dev/null 2>&1; then
    adduser --system --home /var/lib/iepl-agent --shell /usr/sbin/nologin iepl-agent
  else
    echo "cannot create iepl-agent system user" >&2
    exit 1
  fi
fi

install -d -o root -g root -m 0755 /opt/iepl-agent/bin
install -d -o iepl-agent -g iepl-agent -m 0700 /etc/iepl-agent /var/lib/iepl-agent
if [ "$service_mode" = "openrc" ]; then
  install -d -o iepl-agent -g iepl-agent -m 0700 /run/iepl-agent /var/log/iepl-agent
fi

install -o root -g root -m 0755 "$tmp/$asset" /opt/iepl-agent/bin/iepl-agent.new
reported_version="$(/opt/iepl-agent/bin/iepl-agent.new version)"
if [ -n "$expected_version" ] && [ "$reported_version" != "$expected_version" ]; then
  echo "release binary version mismatch: expected $expected_version, got $reported_version" >&2
  exit 1
fi

had_binary=0
had_service=0
if [ -f /opt/iepl-agent/bin/iepl-agent ]; then
  install -o root -g root -m 0755 /opt/iepl-agent/bin/iepl-agent /opt/iepl-agent/bin/iepl-agent.previous
  had_binary=1
fi
if [ -f "$service_path" ]; then
  install -o root -g root -m 0644 "$service_path" "${service_path}.previous"
  had_service=1
fi

service_reload() {
  if [ "$service_mode" = "systemd" ]; then
    systemctl daemon-reload
  fi
}

service_enable() {
  if [ "$service_mode" = "systemd" ]; then
    systemctl enable iepl-agent.service
  else
    rc-update add iepl-agent default
  fi
}

service_restart() {
  if [ "$service_mode" = "systemd" ]; then
    systemctl restart iepl-agent.service
  else
    rc-service iepl-agent restart
  fi
}

service_active() {
  if [ "$service_mode" = "systemd" ]; then
    systemctl is-active --quiet iepl-agent.service
  else
    rc-service iepl-agent status >/dev/null 2>&1
  fi
}

rollback_install() {
  echo "Agent installation failed; restoring the previous release." >&2
  if [ "$had_binary" -eq 1 ]; then
    mv -f /opt/iepl-agent/bin/iepl-agent.previous /opt/iepl-agent/bin/iepl-agent
  else
    rm -f /opt/iepl-agent/bin/iepl-agent
  fi
  if [ "$had_service" -eq 1 ]; then
    mv -f "${service_path}.previous" "$service_path"
  else
    rm -f "$service_path"
  fi
  service_reload || true
  if [ "$had_binary" -eq 1 ] && [ -f /etc/iepl-agent/identity.json ]; then
    service_restart || true
  fi
  exit 1
}

mv -f /opt/iepl-agent/bin/iepl-agent.new /opt/iepl-agent/bin/iepl-agent
if [ "$service_mode" = "systemd" ]; then
  install -o root -g root -m 0644 "$service_source" "$service_path"
else
  install -o root -g root -m 0755 "$service_source" "$service_path"
fi
service_reload || rollback_install

if [ -n "$enroll_token" ]; then
  token_file="$tmp/enroll.token"
  (umask 077 && printf '%s' "$enroll_token" > "$token_file")
fi
if [ -n "$token_file" ]; then
  [ -f "$token_file" ] || { echo "enrollment token file does not exist" >&2; rollback_install; }
  mode="$(stat -c '%a' "$token_file" 2>/dev/null || stat -f '%Lp' "$token_file")"
  [ "$mode" = "600" ] || { echo "enrollment token file must have mode 600" >&2; rollback_install; }
  /opt/iepl-agent/bin/iepl-agent enroll --url "$enroll_url" --token-file "$token_file" || rollback_install
  chown -R iepl-agent:iepl-agent /etc/iepl-agent /var/lib/iepl-agent
fi

service_enable || rollback_install
if [ -f /etc/iepl-agent/identity.json ]; then
  service_restart || rollback_install
  healthy=0
  attempts=0
  while [ "$attempts" -lt 10 ]; do
    attempts=$((attempts + 1))
    if service_active && [ "$(/opt/iepl-agent/bin/iepl-agent version)" = "$reported_version" ]; then
      healthy=1
      break
    fi
    sleep 1
  done
  [ "$healthy" -eq 1 ] || rollback_install
else
  echo "Agent installed but not started: enrollment identity is absent."
fi

echo "Agent ${reported_version} installed successfully (${service_mode})."
