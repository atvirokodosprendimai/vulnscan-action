# vulnscan-agent

Agent-native vulnerability scanner using LangGraph + LangChain + LangFuse.

An orchestrator LLM (GLM-5.2 or any Anthropic-compatible provider) drives a
`create_react_agent` tool-calling loop. VulnLLM-R-7B acts as a *specialist
tool* — it is not the agent and cannot drive loops. The agent decides what to
examine and when.

## Architecture

```
init(load scan/context.md)
  -> react_agent_node (explore / scan / specialist / judge / record loop)
    -> approval_gate (interrupt mechanism — no-op in v1, wired for future external-writes)
      -> report
```

The graph uses `SqliteSaver` checkpointing to `scan/checkpoints.sqlite` so
scans survive CI runner suspension and can be resumed with the same thread_id.

## Running Locally

```bash
cd ops/tools/vulnscan-agent
pip install -e ".[dev]"

export ZAI_API_KEY="..."
export FEATHERLESS_API_KEY="..."
export DEEPSEEK_API_KEY="..."

python -c "from graph import run_scan; run_scan('/path/to/repo')"
```

## Running in CI

```bash
# Inject secrets via Infisical then run the scan script:
infisical run \
  --projectId edd30857-23d4-4840-bf2f-2f31eaba2b83 \
  --env prod \
  -- ./ci/scan.sh /path/to/repo
```

The script exits non-zero when findings at or above `FAIL_ON` severity exist
(default: `HIGH`).

## Environment Variables

### Required

| Variable | Purpose |
|----------|---------|
| `ZAI_API_KEY` | Orchestrator auth key (z.ai GLM-5.2, Anthropic-compatible) |
| `FEATHERLESS_API_KEY` | Specialist VulnLLM-R-7B key |
| `DEEPSEEK_API_KEY` | Second-opinion DeepSeek key |

### Orchestrator Overrides (swap providers without code changes)

| Variable | Default | Example override |
|----------|---------|-----------------|
| `ANTHROPIC_BASE_URL` | `https://api.z.ai/api/anthropic` | `https://api.minimax.io/anthropic` |
| `ORCH_MODEL` | `glm-5.2` | `MiniMax-M3` or `claude-opus-4-5` |
| `ORCH_API_KEY` | falls back to `ZAI_API_KEY` | set when key differs from ZAI |

### Scan Behaviour

| Variable | Default | Purpose |
|----------|---------|---------|
| `REPO_ROOT` | `.` | Repository root to scan |
| `SCAN_WORKSPACE` | `./scan` | Findings / checkpoints / report dir |
| `FEATHERLESS_CONCURRENCY` | `2` | Max simultaneous specialist calls |
| `FAIL_ON` | `HIGH` | CI failure threshold (`CRITICAL`/`HIGH`/`MEDIUM`/`LOW`) |

### LangFuse Observability (optional — no-op when unset)

| Variable | Purpose |
|----------|---------|
| `LANGFUSE_PUBLIC_KEY` | LangFuse public key |
| `LANGFUSE_SECRET_KEY` | LangFuse secret key |
| `LANGFUSE_BASE_URL` | Self-hosted LangFuse base URL (alias: `LANGFUSE_HOST`) |

## Verified Endpoints (do not "correct" these — live-verified 2026-06-24)

| Model | Provider | Base URL | Auth |
|-------|----------|----------|------|
| `glm-5.2` (default) | z.ai | `https://api.z.ai/api/anthropic` | `ZAI_API_KEY` |
| `MiniMax-M3` | MiniMax | `https://api.minimax.io/anthropic` | `ORCH_API_KEY` |
| `Virtue-AI-HUB/VulnLLM-R-7B` | Featherless | `https://api.featherless.ai/v1` | `FEATHERLESS_API_KEY` |
| `deepseek-v4-flash` | DeepSeek | `https://api.deepseek.com` | `DEEPSEEK_API_KEY` |

## Specialist Gotchas (load-bearing)

1. **Cloudflare User-Agent block**: Featherless sits behind CF which returns
   HTTP 403 "error code: 1010" on default Python/urllib User-Agents.
   Fix: always send `User-Agent: curl/8.4.0`.

2. **VulnLLM-R-7B hallucination**: The -R reasoning model emits analysis, then
   `</think>`, then hallucinates fake user/assistant turns to pad to max_tokens.
   Fix: send `stop` sequences AND post-process: keep only content before `</think>`.

3. **Featherless concurrency**: 429 with no server queue when over-limit.
   Fix: `asyncio.Semaphore` sized via `FEATHERLESS_CONCURRENCY` (default 2) +
   exponential backoff.

## Cost Tracking (LangFuse note)

`glm-5.2`, `Virtue-AI-HUB/VulnLLM-R-7B`, and `deepseek-v4-flash` are **not**
in LangFuse's default model-price table. Token counts are captured correctly, but
cost shows $0 until custom prices are defined:

1. LangFuse UI → Models → New Model → enter model name + price per 1K tokens.
2. Or use `langfuse-cli model create`.

This does not block trace collection.

## Tests

```bash
pip install -e ".[dev]"
pytest
```

All tests pass fully offline — no network, no API keys required.
Tests requiring live keys are guarded with `@pytest.mark.skipif`.

## Security

**This scanner is CLI/CI-only.** Never run `langgraph dev` or `langgraph serve`
or otherwise expose the graph's checkpoint/state endpoints over a network.

The LangDrained CVE class (discovered 2024) targets unauthenticated access to
`get_state_history` and the checkpointer API in LangGraph's built-in dev server.
When exposed, an attacker can read or overwrite arbitrary agent state and
checkpoints, enabling RCE-class impact depending on the agent's tool surface.

Mitigations applied in this project:

- `langgraph` and `langgraph-checkpoint-sqlite` are pinned to patched minimum
  versions in `pyproject.toml`.
- `checkpoints.sqlite` is gitignored and lives only on the local CI runner.
- No `langgraph dev` / `langgraph serve` usage — the graph is invoked directly
  via `run_scan()` in `graph.py`.

If you add a web UI or API wrapper over this scanner, treat the checkpoint
database as a privileged resource: authenticated access only, never public.

## Scan Workspace

```
scan/
  findings/<uuid>.json   — individual finding records
  context.md             — suppressions + accepted risks (persists across runs)
  checkpoints.sqlite     — LangGraph checkpoint db (resume support)
  report.md              — final report (written by complete_scan tool)
  results.sarif          — SARIF 2.1.0 output (written by complete_scan tool)
```

The `scan/` directory is gitignored except `.gitkeep`.
`checkpoints.sqlite` is also gitignored (node-local state).
