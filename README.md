# vulnscan-action

Reusable GitHub Actions workflow that runs the agent-native vulnerability
scanner (LangGraph orchestrator + VulnLLM-R-7B specialist + DeepSeek
second-opinion) against any repo, uploads SARIF to code scanning, and fails CI
on findings at or above a severity threshold.

The agent itself is vendored here (see [`AGENT.md`](AGENT.md) for its internals).
This repo packages it as a `workflow_call` reusable workflow so every repo
consumes one pinned version.

## Usage

Add a caller workflow to your repo (full version in
[`examples/caller.yml`](examples/caller.yml)):

```yaml
name: Vulnerability Scan
on: [pull_request, workflow_dispatch]

jobs:
  scan:
    uses: atvirokodosprendimai/vulnscan-action/.github/workflows/vulnscan.yml@v1
    permissions:
      contents: read
      security-events: write
    with:
      fail_on: HIGH
    secrets:
      ZAI_API_KEY: ${{ secrets.ZAI_API_KEY }}
      FEATHERLESS_API_KEY: ${{ secrets.FEATHERLESS_API_KEY }}
      DEEPSEEK_API_KEY: ${{ secrets.DEEPSEEK_API_KEY }}
```

## Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `scan_path` | `.` | Path within the caller repo to scan. |
| `fail_on` | `HIGH` | Fail CI on findings ≥ this severity (`CRITICAL`/`HIGH`/`MEDIUM`/`LOW`). |
| `orch_model` | _(agent default)_ | Override orchestrator model. |
| `python_version` | `3.11` | Python for the agent. |
| `action_ref` | `v1` | Ref of this repo to vendor — keep equal to the `@ref` you pin in `uses:`. |

## Secrets

| Secret | Required | Purpose |
|--------|----------|---------|
| `ZAI_API_KEY` | yes | z.ai GLM orchestrator. |
| `FEATHERLESS_API_KEY` | yes | Featherless VulnLLM-R-7B specialist. |
| `DEEPSEEK_API_KEY` | yes | DeepSeek second-opinion. |
| `LANGFUSE_HOST` / `LANGFUSE_PUBLIC_KEY` / `LANGFUSE_SECRET_KEY` | no | Tracing. |

**Recommended:** set the three keys as **organization-level** GitHub secrets so
every repo's caller inherits them without per-repo configuration.

## Cost & triggers

Every run calls three LLM APIs — there is a real per-run cost. The example
caller triggers on `pull_request` and manual `workflow_dispatch`. Add `push:`
only if you accept scanning every push. For large or low-risk repos, prefer
`workflow_dispatch` / scheduled runs.

## Outputs

- **Code scanning** — `results.sarif` uploaded to the Security tab (needs
  `security-events: write`, already in the example caller).
- **Artifacts** — `results.sarif` + `report.md` attached to the run
  (`vulnscan-results-<sha>`), retained 30 days.
- **CI gate** — the job exits non-zero when findings meet `fail_on`.

## Versioning

Pin a major tag (`@v1`). Breaking changes bump the major; `v1` tracks the latest
compatible release. Keep `action_ref` equal to the `@ref` in `uses:`.
