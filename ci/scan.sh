#!/usr/bin/env bash
# =============================================================================
# ci/scan.sh — Vulnerability Scanner CI Entrypoint
# =============================================================================
# Usage:
#   ./scan.sh <repo_path> [thread_id]
#
# Environment variables required (inject via CI secrets or Infisical):
#   ZAI_API_KEY          — z.ai GLM orchestrator key
#   FEATHERLESS_API_KEY  — Featherless VulnLLM-R-7B key
#   DEEPSEEK_API_KEY     — DeepSeek second-opinion key
#
# Optional:
#   ORCH_MODEL           — Override orchestrator model (default: glm-5.2)
#   ANTHROPIC_BASE_URL   — Override orchestrator base URL
#   FAIL_ON             — Severity threshold for CI failure: CRITICAL|HIGH|MEDIUM|LOW
#                         Default: HIGH (fail on HIGH or CRITICAL findings)
#   SCAN_WORKSPACE       — Path to scan workspace (default: ./scan)
#   FEATHERLESS_CONCURRENCY — Max concurrent specialist calls (default: 2)
#   LANGFUSE_HOST        — LangFuse observability host (optional)
#   LANGFUSE_PUBLIC_KEY  — LangFuse public key (optional)
#   LANGFUSE_SECRET_KEY  — LangFuse secret key (optional)
#
# Infisical injection (CI systems):
#   infisical run \
#     --projectId edd30857-23d4-4840-bf2f-2f31eaba2b83 \
#     --env prod \
#     -- ./scan.sh <repo_path>
#
# =============================================================================

set -euo pipefail

REPO_PATH="${1:?Usage: $0 <repo_path> [thread_id]}"
THREAD_ID="${2:-scan-$(date +%Y%m%d-%H%M%S)}"
FAIL_ON="${FAIL_ON:-HIGH}"
SCAN_WORKSPACE="${SCAN_WORKSPACE:-./scan}"

# Resolve absolute path
REPO_PATH="$(realpath "$REPO_PATH")"

echo "============================================================"
echo " vulnscan-agent"
echo "============================================================"
echo " Repo:        $REPO_PATH"
echo " Thread ID:   $THREAD_ID"
echo " Fail on:     $FAIL_ON+"
echo " Workspace:   $SCAN_WORKSPACE"
echo "============================================================"

# Verify required keys are present (fail fast before spinning up the agent)
if [[ -z "${ZAI_API_KEY:-}" && -z "${ORCH_API_KEY:-}" ]]; then
    echo "ERROR: ZAI_API_KEY (or ORCH_API_KEY) must be set" >&2
    exit 1
fi
if [[ -z "${FEATHERLESS_API_KEY:-}" ]]; then
    echo "ERROR: FEATHERLESS_API_KEY must be set" >&2
    exit 1
fi
if [[ -z "${DEEPSEEK_API_KEY:-}" ]]; then
    echo "ERROR: DEEPSEEK_API_KEY must be set" >&2
    exit 1
fi

# Export workspace path so Python tools can find it
export REPO_ROOT="$REPO_PATH"
export SCAN_WORKSPACE="$SCAN_WORKSPACE"

# Ensure workspace exists
mkdir -p "$SCAN_WORKSPACE/findings"

# Run the graph
echo ""
echo "Starting agent scan..."
python3 - <<EOF
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath('$0'))))
from graph import run_scan
result = run_scan(repo_root="$REPO_PATH", thread_id="$THREAD_ID")
EOF

echo ""
echo "Scan complete."

# Print SARIF output path (used by GitHub/Gitea upload steps)
SARIF_PATH="$SCAN_WORKSPACE/results.sarif"
if [[ -f "$SARIF_PATH" ]]; then
    echo "SARIF report: $SARIF_PATH"
else
    echo "NOTE: results.sarif not found — SARIF output was skipped or failed" >&2
fi

# Determine exit code based on finding severity
REPORT="$SCAN_WORKSPACE/report.md"
if [[ ! -f "$REPORT" ]]; then
    echo "WARNING: No report.md found — complete_scan may not have been called" >&2
    exit 0
fi

echo ""
echo "=== Finding Summary ==="
# Extract counts from report
python3 - <<'PYEOF'
import json
import os
import sys
from pathlib import Path

workspace = os.environ.get("SCAN_WORKSPACE", "./scan")
fail_on = os.environ.get("FAIL_ON", "HIGH")
findings_dir = Path(workspace) / "findings"

severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
fail_threshold = severity_order.get(fail_on.upper(), 1)

counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
for p in findings_dir.glob("*.json"):
    try:
        f = json.loads(p.read_text())
        sev = f.get("severity", "LOW")
        counts[sev] = counts.get(sev, 0) + 1
    except Exception:
        pass

for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
    print(f"  {sev}: {counts[sev]}")

total_failing = sum(
    count for sev, count in counts.items()
    if severity_order.get(sev, 99) <= fail_threshold
)

print(f"\nFAIL_ON={fail_on} — {total_failing} finding(s) at or above threshold")
if total_failing > 0:
    print("CI FAILED: resolve or suppress findings before merging")
    sys.exit(1)
else:
    print("CI PASSED: no findings at or above threshold")
PYEOF
