#!/bin/sh
set -eu

output=${1:-}
shift || true
[ -n "$output" ] && [ "$#" -gt 0 ] || {
  echo "usage: $0 OUTPUT SUBJECT..." >&2
  exit 2
}
command -v jq >/dev/null 2>&1 || { echo "jq is required" >&2; exit 1; }
command -v sha256sum >/dev/null 2>&1 || { echo "sha256sum is required" >&2; exit 1; }

subjects=$(mktemp)
trap 'rm -f "$subjects"' EXIT INT TERM
: > "$subjects"
for file in "$@"; do
  [ -f "$file" ] || { echo "provenance subject is missing: $file" >&2; exit 1; }
  digest=$(sha256sum "$file" | cut -d' ' -f1)
  jq -n --arg name "$(basename "$file")" --arg digest "$digest" \
    '{name: $name, digest: {sha256: $digest}}' >> "$subjects"
done

repository=${GITHUB_REPOSITORY:-unknown/unknown}
server_url=${GITHUB_SERVER_URL:-https://github.com}
sha=${GITHUB_SHA:-unknown}
ref=${GITHUB_REF:-unknown}
workflow_ref=${GITHUB_WORKFLOW_REF:-unknown}
run_id=${GITHUB_RUN_ID:-unknown}
run_attempt=${GITHUB_RUN_ATTEMPT:-unknown}
generated_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)

jq -s \
  --arg repository "$repository" --arg server_url "$server_url" --arg sha "$sha" \
  --arg ref "$ref" --arg workflow_ref "$workflow_ref" --arg run_id "$run_id" \
  --arg run_attempt "$run_attempt" --arg generated_at "$generated_at" '
  {
    _type: "https://in-toto.io/Statement/v1",
    subject: .,
    predicateType: "https://slsa.dev/provenance/v1",
    predicate: {
      buildDefinition: {
        buildType: "https://github.com/Attestations/GitHubActionsWorkflow@v1",
        externalParameters: {repository: $repository, ref: $ref},
        internalParameters: {workflowRef: $workflow_ref},
        resolvedDependencies: [{
          uri: ($server_url + "/" + $repository + "/tree/" + $sha),
          digest: {gitCommit: $sha}
        }]
      },
      runDetails: {
        builder: {id: $workflow_ref},
        metadata: {
          invocationId: ($server_url + "/" + $repository + "/actions/runs/" + $run_id + "/attempts/" + $run_attempt),
          startedOn: $generated_at
        }
      }
    }
  }
' "$subjects" > "$output"

jq -e '._type == "https://in-toto.io/Statement/v1" and (.subject | length > 0)' "$output" >/dev/null
