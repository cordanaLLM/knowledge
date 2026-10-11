#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output_root="${ARCHEION_KNOWLEDGE_VERIFY_OUTPUT_ROOT:-}"
cleanup_output_root=false

if [[ -z "$output_root" ]]; then
  output_root="$(mktemp -d "${TMPDIR:-/tmp}/archeion-knowledge-verify.XXXXXX")"
  cleanup_output_root=true
fi

cleanup() {
  if [[ "$cleanup_output_root" == true ]]; then
    rm -rf -- "$output_root"
  fi
}
trap cleanup EXIT

mkdir -p "$output_root/pycache"
export PYTHONPYCACHEPREFIX="$output_root/pycache"

cd "$repo_root"

python3 -m py_compile mcp/*.py pipeline/*.py
for workflow in workflows/*.js; do
  node --check "$workflow"
done

request_file="$output_root/mcp-requests.jsonl"
cat >"$request_file" <<'EOF'
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"archeion-knowledge-verify","version":"1"}}}
{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}
EOF

verify_server() {
  local server="$1"
  local server_name="$2"
  local tool_name="$3"
  local response_file="$output_root/${server_name}.jsonl"

  timeout 10s python3 "$server" <"$request_file" >"$response_file"
  python3 - "$response_file" "$server_name" "$tool_name" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
server_name = sys.argv[2]
tool_name = sys.argv[3]
responses = [json.loads(line) for line in path.read_text().splitlines() if line]
if len(responses) != 2:
    raise SystemExit(f"expected 2 MCP responses from {server_name}, got {len(responses)}")
if responses[0].get("result", {}).get("serverInfo", {}).get("name") != server_name:
    raise SystemExit(f"unexpected server identity from {server_name}")
tools = responses[1].get("result", {}).get("tools", [])
if [tool.get("name") for tool in tools] != [tool_name]:
    raise SystemExit(f"unexpected tool inventory from {server_name}: {tools!r}")
PY
}

verify_server mcp/dogfood_mcp.py archeion-dogfood-registry search_cluster_docs
verify_server mcp/dogfood_dev_mcp.py archeion-dev-registry search_dev_docs

echo "archeion-knowledge verification passed"
