# GitHub-Enforced Supportability Governance

This repo provides reusable GitHub workflows and Python validators that convert the Supportability Standard into objective GitHub evidence.

The owner-facing rule is simple:

```text
GREEN: required gates passed, Copilot reviewed the latest head, no unresolved P0-P2 findings, and GitHub evidence can be verified.
RED: any required gate, review, artifact, SHA, or remote proof is missing or failed.
YELLOW: reserved for future non-blocking advisory receipts; current enforcement fails closed to RED.
```

## Target Repo Opt-In

Each target repo must add `.github/governance/supportability.yml` and copy the standard text into the path named by `standard.source`.

The `standard.hash` value must be the SHA-256 of the adopted standard file. The workflow fails closed if the file is missing or the hash does not match.

```yaml
standard:
  name: supportability-standard
  source: docs/reference/supportability-standard.md
  hash: "<sha256 of adopted standard text>"

required_gates:
  lint:
    - "..."
  format_check:
    - "..."
  typecheck:
    - "..."
  complexity:
    - "..."
  architecture:
    - "..."
  tests:
    - "..."
  compile_or_build:
    - "..."
  package_audit: []
  sql_supportability: auto

coverage:
  changed_files: required
  high_risk_files: required
  forbid_gate_scope_narrowing: true
  forbid_threshold_weakening: true

ai_review:
  copilot_required: true
  latest_head_required: true
  unresolved_p0_p1_p2_blocks: true
  reviewer_login_patterns:
    - "*copilot*"
    - "chatgpt-codex-connector*"

receipt:
  artifact_name: supportability-delivery-receipt
  retention_days: 90
```

If a repo contains SQL files and `sql_supportability` is `auto`, the gate returns RED until explicit SQL validation commands are configured.

Config changes are protected. A PR that changes `.github/governance/supportability.yml` returns RED. Bootstrap the first config as a separate owner-approved PR, then require the supportability checks for later code changes.

The `receipt` block is validated as the target repo's declared contract. Reusable workflow inputs/defaults enforce the actual artifact names and 90-day retention during upload.

## Caller Workflow

Target repos should pin the governance reusable workflow to an exact commit SHA, not to floating `main`.

The governance repo also includes `.github/workflows/supportability-enforcement.yml` as its own caller. This proves the same reusable workflow wiring GitHub will enforce in opted-in target repos.

```yaml
name: Governed PR

on:
  pull_request:

permissions:
  actions: read
  contents: read
  pull-requests: read

jobs:
  supportability:
    uses: markheck-solutions/governance/.github/workflows/supportability-gate.yml@<governance-commit-sha>
    with:
      target-repository: ${{ github.repository }}
      target-repository-url: https://github.com/${{ github.repository }}.git
      target-base-sha: ${{ github.event.pull_request.base.sha }}
      target-head-sha: ${{ github.event.pull_request.head.sha }}
      target-pr-number: ${{ github.event.pull_request.number }}
      target-pr-url: ${{ github.event.pull_request.html_url }}
      governance-ref: <governance-commit-sha>

  delivery-receipt:
    needs: supportability
    if: ${{ always() }}
    uses: markheck-solutions/governance/.github/workflows/delivery-receipt.yml@<governance-commit-sha>
    with:
      target-repository: ${{ github.repository }}
      target-repository-url: https://github.com/${{ github.repository }}.git
      target-base-sha: ${{ github.event.pull_request.base.sha }}
      target-head-sha: ${{ github.event.pull_request.head.sha }}
      target-pr-number: ${{ github.event.pull_request.number }}
      target-pr-url: ${{ github.event.pull_request.html_url }}
      governance-ref: <governance-commit-sha>
      supportability-artifact-id: ${{ needs.supportability.outputs['artifact-id'] }}
      supportability-artifact-digest: ${{ needs.supportability.outputs['artifact-digest'] }}
```

## Required Repository Rules

The target repo ruleset should require:

- Pull requests before merge to `main`.
- Status check `Supportability Gate`.
- Status check `Delivery Receipt`.
- Stale check dismissal after new commits.
- No bypass except explicit owner emergency.

Copilot review is required input to the receipt, not the only merge authority.

## What GitHub Enforces

The workflows enforce objective proof:

- Required commands exist and return success.
- Required commands are not marked non-blocking.
- Configured command strings do not contain known scope-narrowing or threshold-weakening markers.
- Changed files and deterministic high-risk production files receive gate coverage.
- The adopted standard file exists and matches the pinned hash.
- Copilot or an allowed AI reviewer reviewed the latest head SHA.
- Unresolved `P0`, `P1`, or `P2` AI review evidence blocks GREEN.
- Artifacts are retained for 90 days.
- Delivery receipts can be re-checked against GitHub PR, run, artifact, `git ls-remote`, and fresh-clone evidence.

GitHub cannot guarantee perfect engineering judgment. It can block unsupported delivery claims when objective evidence is missing.
