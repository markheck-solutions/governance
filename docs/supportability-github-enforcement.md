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

architecture_policy:
  version: 1
  enforcement_mode: block_all
  governed_roots:
    - path: governance_eval
      kind: production_python
      owner: governance
      purpose: executable governance evaluator
  runtime_relevance:
    production_globs:
      - "**/*.py"
      - "**/*.sql"
    non_runtime_globs:
      - "docs/**"
      - "schemas/**"
      - "artifacts/**"
      - "**/*.md"
      - "**/*.json"
  vague_names:
    forbidden:
      - utils
      - helpers
      - common
      - misc
      - stuff
      - shared
  modules:
    governance_eval:
      path: governance_eval
      owner: governance
      purpose: evaluator runtime and CLI implementation
      classification: application
      domain: governance-evaluation
      allowed_dependencies: []
      forbidden_dependencies:
        - tests
      test_strategy: unittest coverage through tests/
      limits:
        max_file_lines: 700
        max_function_lines: 120
        max_class_lines: 240
        max_functions_per_file: 45
        max_classes_per_file: 12
  known_debt: []
```

If a repo contains SQL files and `sql_supportability` is `auto`, the gate returns RED until explicit SQL validation commands are configured.

Config changes are protected. A PR that weakens `.github/governance/supportability.yml` returns RED. Weakening includes changing away from `block_all`, removing governed roots, narrowing runtime production globs, broadening non-runtime globs, narrowing vague-name controls, broadening allowed dependencies, narrowing forbidden dependencies, increasing size limits, or adding/extending `known_debt`.

The `receipt` block is validated as the target repo's declared contract. Reusable workflow inputs/defaults enforce the actual artifact names and 90-day retention during upload.

The `architecture_policy` block is the repo-specific module/package boundary registry. The reusable workflow directly invokes `python -m governance_eval architecture-gate`; `required_gates.architecture` may add repo-specific checks, but it cannot replace the approved checker.

Architecture enforcement is hard-stop only:

- `block_all` is the only CI-valid mode.
- `report_only` and `block_new` are rejected by schema/config validation.
- `architecture_behavior_proof` is `PASS` only when positive, negative, and theater fixtures run and pass.
- `known_debt` documents debt only. It does not suppress findings, lower violation count, or convert architecture supportability to GREEN.

Architecture evidence is written as both `architecture-gate-result.json` and `architecture-gate-result.md`.

## Protected Baseline State

Protected baseline reusable workflows now exist on `main`. Missing proof is still RED: missing baseline artifact ID, missing baseline artifact digest, missing baseline evidence, missing candidate evidence, missing receipt verification, or failed receipt verification cannot produce GREEN.

## Caller Workflow

Target repos should pin the governance reusable workflow to an exact commit SHA, not to floating `main`.

The governance repo also includes `.github/workflows/supportability-enforcement.yml` as its own caller. Governance PRs run two judges:

- Baseline protected judge from an immutable known-good workflow ref, with `governance-ref` set to the PR base SHA. This must block merge.
- Candidate judge from the PR head. This reports candidate behavior but cannot be the only authority.

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
- Status check `Baseline Protected Supportability Gate`.
- Status check `Baseline Protected Delivery Receipt`.
- Branches up to date before merge.
- Conversation resolution.
- Auto-merge disabled until strict hard-stop checks are proven.
- No bypass for AI or bot actors.

Copilot review is required input to the receipt, not the only merge authority.

## What GitHub Enforces

The workflows enforce objective proof:

- Required commands exist and return success.
- Required commands are not marked non-blocking.
- Configured command strings do not contain known scope-narrowing or threshold-weakening markers.
- Changed files and deterministic high-risk production files receive gate coverage.
- The approved architecture checker runs directly and emits JSON plus Markdown evidence.
- Workflow GREEN requires architecture owner status GREEN, gate implementation PASS, repo architecture supportability PASS, behavior proof PASS, no violations, no new violations, no known debt, no expired known debt, protected baseline judge evidence, candidate judge evidence, baseline and candidate receipts, and no errors.
- Architecture policy covers runtime/production-relevant files with registered module ownership, allowed dependencies, forbidden dependencies, strict fingerprinted known debt records, and deterministic Python size/import checks. Known debt never forgives a violation.
- The adopted standard file exists and matches the pinned hash.
- Copilot or an allowed AI reviewer reviewed the latest head SHA.
- Unresolved `P0`, `P1`, or `P2` AI review evidence blocks GREEN.
- Artifacts are retained for 90 days.
- Delivery receipts can be re-checked against GitHub PR, run, artifact, `git ls-remote`, and fresh-clone evidence.

GitHub cannot guarantee perfect engineering judgment. It can block unsupported delivery claims when objective evidence is missing.
