# Phase 1 Verification

Complete local verification:

```powershell
python -m governance_eval verify --artifacts-dir artifacts/phase1
```

The same command runs on GitHub-hosted Ubuntu runners from the shadow workflow. It exits nonzero if tests fail, if a defective control is not blocked, if a clean control is blocked, if repeated decisions are unstable, if deterministic flake rate is nonzero, or if the benchmark artifact is not schema-valid JSON.

The command writes `artifacts/phase1/governance-benchmark-latest.json` plus a timestamped benchmark JSON file.

The aggregate benchmark result is `phase1_decision=BENCHMARK_PASS|BENCHMARK_FAIL`.
Per-case simulated governance decisions remain `MERGE|BLOCK_TECHNICAL|ASK_BUSINESS`.

Metrics include both ratios and counts:

- `critical_defects_blocked / critical_defect_count`
- `negative_controls_blocked / negative_control_count`
- `false_blocks / verified_safe_count`

Delivery readiness requires the benchmark JSON result, not only a green GitHub status context. The accepted result must contain `phase1_decision=BENCHMARK_PASS`, empty `acceptance_errors`, a valid `artifact_content_hash`, case counts, and the required metric numerators and denominators. When readiness is evaluated against GitHub artifact evidence, the GitHub artifact digest must also be supplied.

The final review gate is recorded as `review_gate=GITHUB_CODEX_FINAL_REVIEW|FALLBACK_CLEAN_ROOM_QUORUM` with `github_review_state=CLEAN|STALE|UNAVAILABLE|BLOCKING_FINDINGS_PRESENT`. If GitHub Codex review is stale or unavailable, a fallback clean-room quorum can be supplied as schema-valid JSON under `artifacts/review-quorum/`; the shadow workflow uploads that directory as `governance-review-quorum-json` when it exists.
