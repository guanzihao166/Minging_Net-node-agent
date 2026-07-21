#!/bin/sh
set -eu

version=${1:-}
output=${2:-}
[ -n "$version" ] && [ -n "$output" ] || {
  echo "usage: $0 VERSION OUTPUT" >&2
  exit 2
}
command -v go >/dev/null 2>&1 || { echo "go is required" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "jq is required" >&2; exit 1; }

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT INT TERM
go list -m -json all | jq -s . > "$tmp"
timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)

jq --arg version "$version" --arg timestamp "$timestamp" '
  {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    version: 1,
    metadata: {
      timestamp: $timestamp,
      component: {
        type: "application",
        name: "iepl-node-agent",
        version: $version
      },
      tools: {
        components: [{type: "application", name: "go", version: "go-list"}]
      }
    },
    components: [
      .[]
      | select(.Main != true)
      | {
          type: "library",
          name: .Path,
          version: (.Replace.Version // .Version // "unknown"),
          properties: (
            [{name: "go.module.path", value: .Path}]
            + (if .Sum then [{name: "go.module.sum", value: .Sum}] else [] end)
            + (if .Replace then [{name: "go.module.replace", value: .Replace.Path}] else [] end)
          )
        }
    ]
  }
' "$tmp" > "$output"

jq -e '.bomFormat == "CycloneDX" and .specVersion == "1.5" and (.components | length > 0)' "$output" >/dev/null
