# Governance Evaluator

Governance is a repository-agnostic control plane for solo, AI-directed software development. It evaluates a target repository without modifying it and produces machine-readable evidence for one deterministic outcome:

- `MERGE` / `SHADOW_MERGE`
- `BLOCK_TECHNICAL` / `SHADOW_BLOCK_TECHNICAL`
- `ASK_BUSINESS` / `SHADOW_ASK_BUSINESS`

AI reviewers may produce structured findings. Only deterministic evaluator code computes the outcome.

## What is generic and what is repository-specific

The evaluator core, schemas, evidence rules, workflow isolation, supportability checks, architecture checks, review gates, and decision logic are generic.

A target pack is the adapter for one repository. It declares immutable revisions, language/runtime adapter, behavior reproducers, structural detectors, required commands, and documented exclusions. Spaghetti is one registered real-target pack and benchmark control; it is not embedded in the evaluator core and is not the framework's default identity.

Supported command adapters are `raw`, `python`, `node`, `dotnet`, `go`, `rust`, `java`, and `powershell`. An unsupported required capability becomes `UNKNOWN` and blocks. It never silently passes.

## Trust model

Reusable workflows use three isolated jobs:

1. A trusted planner checks out the evaluator at the reusable workflow's own repository and SHA, validates bounded inputs, and emits a hash-bound plan.
2. Fresh ephemeral jobs execute target commands. They do not contain the evaluator, expected decisions, benchmark labels, or merge logic.
3. A fresh trusted judge validates plan identity and evidence, scans source without executing it, and computes the deterministic result.

The caller cannot select an arbitrary evaluator revision. Target repositories remain read-only. Local plain subprocess execution cannot claim isolated `GREEN` supportability evidence.

## Apply governance to a repository

1. Add a versioned target pack and register it. Use immutable 40-character commit SHAs for historical or safe controls.
2. Add the repository's supportability configuration. Commands must be real semantic checks for lint, formatting, types, complexity, architecture, tests, build, package health, and SQL when SQL-like production sources exist.
3. Add both positive and negative controls. A required case that is missing, malformed, unsupported, or unreproduced blocks.
4. Validate locally:

   ```powershell
   python -m unittest discover -s tests -p test_*.py
   python -m ruff check governance_eval tests
   python -m ruff format --check governance_eval tests
   python -m mypy governance_eval
   python -m build
   ```

5. Run the deterministic calibration benchmark:

   ```powershell
   python -m governance_eval benchmark --repeat 3 --artifacts-dir artifacts/calibration
   ```

6. Run complete deterministic verification:

   ```powershell
   python -m governance_eval verify --repeat 3 --artifacts-dir artifacts/complete
   ```

   Verification runs the evaluator tests, every registered real-target control at exact immutable revisions, and the deterministic benchmark.

7. Call the reusable supportability or target-evaluation workflow from the target repository. Start in `SHADOW`; promote to `BLOCKING` only after protected required-check and clean/defective canary proof.

The target repository owns its commands and configuration. Governance owns the evaluator, schemas, target-pack policy, and decision computation.

## Evidence and failure behavior

Evidence binds the evaluator SHA, target SHA, target-pack hash, schema hashes, command plan, execution identity, artifact content hash, and deterministic evidence hash. Registered target mirrors support exact offline checkout; a missing repository, missing commit, origin mismatch, or SHA mismatch fails closed.

`GREEN` means the configured checks actually ran in the required isolated execution mode. Command names, `compileall`, echo commands, empty package checks, and duplicated commands cannot impersonate semantic gates.

## GitHub AI review

GitHub Copilot supplies the supportability review evidence. Codex supplies the final delivery-readiness review evidence. Review evidence must come from an exact approved GitHub bot identity, use the structured evidence contract, bind to the latest commit SHA, and contain no unresolved P0-P2 finding.

AI review is evidence, not authority. Reviewers find and explain risks. GitHub Actions collect that evidence. Only deterministic evaluator code computes `GREEN`/`RED`, `MERGE`, `BLOCK_TECHNICAL`, or `ASK_BUSINESS`.

## Rollout boundary

The framework does not auto-merge, alter branch protection, refactor target production code, or run an autonomous repair loop. Publishing changes, configuring secrets, and changing protected checks are separate owner-authorized operations. Local proof and live GitHub enforcement are reported separately.

See the supportability enforcement guide for GitHub installation, required checks, receipts, and canary proof. `TASK.md` defines the current implementation mission; reference documents preserve prior reasoning but do not override executable requirements.
