# GitHub supportability enforcement

This repository provides repo-agnostic, reusable GitHub Actions. Application repositories supply a typed supportability configuration and pin reusable workflows to an exact Governance commit SHA.

## Merge decision

GREEN requires:

- configured deterministic gates pass;
- architecture implementation and behavior proof pass;
- the Codex connector evidence snapshot is complete, fully paginated, exact-head bound, and collected after the five-minute review window;
- every in-window Codex P0-P2 finding is resolved;
- the delivery receipt binds the PR head, workflow run, and uploaded evidence artifact.

Codex is evidence, not approval. A valid post-cutoff reconciliation with no exact-head Codex response records `AI_REVIEW_UNAVAILABLE` and does not block. Missing, malformed, incomplete, stale, or digest-invalid collection evidence is RED. Copilot is not a required reviewer, gate, receipt input, or dependency.

## Target configuration

```yaml
ai_review:
  provider: codex_connector
  adapter: codex_connector_pr_signal_v2
  review_window_seconds: 300
  unavailable_after_cutoff: non_blocking
  unresolved_p0_p1_p2_blocks: true
```

These values are fixed by schema. Target repositories cannot substitute reviewer identities, shorten the window, or turn blocking findings into advisory output.

## Event model

`supportability-enforcement.yml` uses `pull_request_target` so GitHub loads the caller from the protected base branch, not from candidate code. It runs only for pull-request head transitions:

- `opened`
- `reopened`
- `synchronize`
- `ready_for_review`

The workflow attempts one `@codex review` request bound to the exact new head, then starts the evidence window. GitHub may reject a GitHub Actions bot-to-bot trigger with `403 Resource not accessible by integration`; the request job records that transport failure as a warning and continues into deterministic reconciliation. No PAT or Copilot fallback is required. That bounded request job has `issues: write`; evaluator and receipt jobs remain read-only. Candidate code is checked out with `persist-credentials: false`, and configured commands receive an empty `GH_TOKEN`. There is no comment-triggered rerun loop and no `actions: write` permission. The protected baseline and delivery workflows are pinned to an exact publication commit; the candidate evaluator is separately exercised against the PR head. Each reusable workflow has a hard ten-minute timeout. The Codex collector performs at most one bounded sleep and one final recollection after the five-minute deadline.

## Required checks

Protect `main` with the existing four check contexts produced by the enforcement workflow. Do not rename or delete required contexts during bootstrap. Apply protection changes only through the controlled procedure in `TASK.md`.

## Evidence artifacts

The supportability artifact contains:

- `supportability-gate-result.json`
- `architecture-gate-result.json`
- `architecture-gate-result.md`
- `codex-connector-snapshot.json`
- `codex-connector-evidence-result.json`
- `ai-review-gate-result.json`

The delivery workflow rejects missing artifacts, mismatched artifact digests, invalid nested status, claimed AI approval, and GitHub run or PR identity mismatches.

## Adoption boundary

Do not roll this framework into target repositories until Governance passes its own protected checks and positive/negative canaries. Target repositories remain read-only during Governance Phase 1 evaluation.

After self-enforcement passes, generate a reviewable bundle outside the target repository:

```powershell
python -m governance_eval adoption-bundle `
  --repository owner/repository `
  --governance-sha <exact-40-character-governance-sha> `
  --config-source <typed-supportability-config> `
  --output-dir <new-empty-bundle-path>
```

The command does not edit the target repository or GitHub settings. It emits the typed config, canonical supportability standard, exact-pinned protected caller, protection instructions, and a schema-valid manifest with file hashes and the three target-repository required contexts. Review and apply that bundle through a separate target-repository pull request.

Prove generator behavior without touching a target repository:

```powershell
python -m governance_eval prove-adoption `
  --governance-sha <exact-40-character-governance-sha> `
  --artifacts-dir <new-artifact-path>
```

Success requires a clean disposable bundle to validate and a caller-pin-substituted defective bundle to fail closed.
