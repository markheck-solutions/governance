# GitHub supportability enforcement

This repository publishes repo-agnostic Governance components. Adopter repositories supply typed configuration and pin an exact certified Governance SHA. Governance source uses separate source qualification; every Governance product workflow on Governance source is diagnostic.

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

The standard adopter profile accepts only `pull_request_target` request evidence for these pull-request head transitions:

- `opened`
- `reopened`
- `synchronize`
- `ready_for_review`

Candidate execution belongs in a separate `pull_request` workflow with no secrets, no write token, and no authoritative check identity. It may upload only untrusted evidence. The external verifier never checks out or executes candidate code; it validates hostile artifacts and exact identities before its dedicated GitHub App publishes the adopter's required result. Merge-group support is a later optional profile and requires live eligibility proof.

## Required checks

On Governance source, require only `Governance Source Qualification`; product contexts are diagnostic. On an adopter, require the one stable context published by the dedicated external verifier App. Apply protection only through the evidence-backed procedure in `TASK.md`.

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

Do not roll this framework into application repositories until exact publication qualification, verifier-App binding, rollback proof, and every disposable positive/negative canary pass. Target repositories remain read-only until an explicit installation.
