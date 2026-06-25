# Phase 1 Verification

Complete local verification:

```powershell
python -m governance_eval verify --artifacts-dir artifacts/phase1
```

The same command runs on GitHub-hosted Ubuntu runners from the shadow workflow. It exits nonzero if tests fail, if a defective control is not blocked, if a clean control is blocked, if repeated decisions are unstable, if deterministic flake rate is nonzero, or if the benchmark artifact is not schema-valid JSON.

The command writes `artifacts/phase1/governance-benchmark-latest.json` plus a timestamped benchmark JSON file.
