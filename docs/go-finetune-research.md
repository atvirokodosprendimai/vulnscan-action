# Extending VulnLLM-R-7B to Go — Research Notes

> Source: DeerFlow ultra-research run, 2026-06-24 (cited from `github.com/ucsb-mlsec/VulnLLM-R`,
> CVEfixes, CodeQL/gosec docs). Numbers marked *(est.)* are research estimates — verify before committing budget.
> Full DeerFlow artifact: thread `c01b0b6b-96d7-44b7-9153-5440f6290e27` on the local DeerFlow instance.

## TL;DR
A Go fine-tune of VulnLLM-R-7B is a **~$20–30, 2–3 day** QLoRA project on a single 24 GB GPU.
Cheaper interim (already shipped): **gosec + govulncheck** in the scanner allowlist cover Go without training.

## 1. Base model / reproducibility
- Repo `ucsb-mlsec/VulnLLM-R` (337★) — Qwen2.5-7B-Instruct, **SFT + SimPO** on reasoning chains distilled from DeepSeek-R1 + QwQ-32B. Supports **C/C++ + Python**; Java was zero-shot only. Go = out-of-distribution.
- Pipeline: **LLaMA-Factory + DeepSpeed ZeRO-3**. Scripts/configs released; **training data must be re-downloaded**; reasoning distillation needs Together AI / OpenAI API. ~1–2 days to reproduce from scratch. Reproducibility ~6/10.
- Released SFT config (`qwen2_7B_full_sft.yaml`): lr 1e-5, cosine, warmup 0.1, 3 epochs, batch 2/device × grad-accum 8. LoRA config (`qwen2_lora_sft.yaml`): rank 8, alpha 16, dropout 0.1, targets q/k/v/o.

## 2. Go datasets (~1–2k usable samples total)
| Dataset | Format | Go yield | Notes |
|---|---|---|---|
| **CVEfixes v1.0.8** | SQLite (~12.7k commits, 4249 projects, 272 CWEs, MIT) | ~500–1500 fn-level before/after pairs *(est.)* | Primary. Filter `language = 'Go'` |
| **go-vulnfixes-db** | commit diffs | ~700 *(est.)* | Best Go-specific |
| **CrossVul** | SQLite, 40+ langs, ~9k file-level | ~300–500 *(est.)* | Supplement, file-level (coarser) |
| **OSV.dev (Go)** | REST/JSON | metadata only, **no source** | Severity/version enrichment, not training |
| ❌ DiverseVul / BigVul / PrimeVul / SVEN / Juliet / CleanVul | — | **no Go** | — |

Reasoning-chain labels: distill from a strong teacher (DeepSeek-R1 / Claude) per dataset sample — CWE + explanation + fix reasoning → SFT targets (same recipe as the base model).

## 3. Fine-tune method (single GPU)
QLoRA on `Virtue-AI-HUB/VulnLLM-R-7B`:
- 4-bit NF4, **LoRA rank 16 / alpha 16**, targets q/k/v/o
- lr 1e-5 cosine, warmup 0.1, **2 epochs**, 16K context, DeepSpeed ZeRO-3 (CPU offload if needed)
- **Anti-forgetting: 2:1 → 3:1 old:new replay** (co-train original C/C++/Python samples), proportional sampling
- Go loss expected to drop fast (~500 steps); eval F1 on held-out Go set each epoch
- Then **SimPO/DPO** on Go preference pairs (correct vs over-flagging) for false-positive reduction

## 4. Evaluation (you'd set the Go baseline — none published)
Compare against: **gosec** (~50 rules, no published F1), **govulncheck** (package-level), **CodeQL-Go** (~50+ dataflow queries, updated Dec 2025), **semgrep-go** (~100+ rules), and VulnLLM-R zero-shot. **Target F1 ≥ 0.75 = Go SOTA.**

## 5. Cost (QLoRA path)
| Component | HW | Hrs | $ |
|---|---|---|---|
| Data prep | CPU | 1–2 | ~0 |
| SFT (Go + replay) | 1× A10G/4090 | 2–4 | ~2–4 |
| DPO/SimPO | 1× A10G/4090 | 2–4 | ~2–4 |
| Eval | 1× A10G/4090 | 1–2 | ~1–2 |
| Inference (vLLM) | 1× A10G/4090 | 2–4 | ~2–4 |
| Together AI (distillation) | — | — | ~5–10 |
| **Total** | | | **~$10–40** |

Cheapest proof-of-concept path: Day 1 extract+format (CPU, $0) → Day 2 QLoRA SFT on a Vast.ai A10G ~6h (~$4) → Day 2–3 DPO ~6h (~$4) → **~$20–30 total**. Full fine-tune (2× A100 80GB) ~$120–480.

## Decision
Train only if gosec + govulncheck + the GLM/DeepSeek orchestrator prove insufficient on real Go. The interim Go scanners are live now; this fine-tune is the upgrade path if Go detection quality demands it.
