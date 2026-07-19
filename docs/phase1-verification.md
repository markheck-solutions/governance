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

Phase 1 is shadow benchmark evidence. Its result must validate against the benchmark schema, contain `phase1_decision=BENCHMARK_PASS`, have no acceptance errors, and retain the recomputable content hash, metrics, provenance, target revision, exact-command, runner, and interpreter fields. It does not replace protected-path delivery evidence.

Protected merge readiness is computed by the pinned delivery-receipt workflow and its schema-validated receipt. The final AI review path is the GitHub Codex connector. Exact-head, in-window P0-P2 findings block; missing, late, quota-limited, or unavailable Codex evidence records `AI_REVIEW_UNAVAILABLE` and is neither approval nor a deterministic merge blocker after final reconciliation. There is no manual review-quorum fallback.
