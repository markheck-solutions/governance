# Task: Governance Evaluation Phase 1

Implement Phase 1 completely in this repository.

## Goal

Create an offline-first benchmark that tests whether a governance system detects known software-development failures. The first deliverable is the test rig, not the autonomous coding factory.

## Inputs

Read:

- `docs/spec/resolve_failure.md`
- `docs/reference/supportability-standard.md`
- `docs/reference/current-governance-skill.md`
- `targets/spaghetti.toml`

The Spaghetti repository is an evaluated target and must remain read-only.

## Required implementation

1. Create a maintainable Python package and command-line interface for governance evaluation.
2. Define versioned JSON Schemas for:
   - evaluation cases;
   - detector evidence;
   - review findings;
   - benchmark run results;
   - final decisions.
3. Implement deterministic final outcomes:
   - `MERGE`
   - `BLOCK_TECHNICAL`
   - `ASK_BUSINESS`
4. The decision engine must fail closed for missing, malformed, unresolved, or unverifiable required evidence.
5. Resolve and record exact immutable commit SHAs for the Spaghetti historical case in a generated lock file. Do not rely on floating branches.
6. Reproduce PR #141's partial-metadata route-interleaving defect as an executable historical behavior case. A review comment alone is not sufficient evidence.
7. Add paired clean and defective fixtures for:
   - private helper re-export;
   - test dependency on private production internals;
   - import cycle;
   - untyped public dictionary boundary;
   - narrowed validation-gate scope;
   - weakened validation threshold.
8. Each defective fixture must be blocked. Each clean fixture must pass.
9. Produce a machine-readable benchmark artifact containing at least:
   - critical-defect recall;
   - negative-control recall;
   - false-block rate;
   - repeated-run decision stability;
   - deterministic flake rate;
   - execution duration.
10. Add automated tests for the evaluator, schemas, detectors, decision engine, historical case, clean controls, and defective controls.
11. Add a non-blocking GitHub Actions shadow workflow that runs the tests and benchmark and uploads the JSON artifact.
12. Document one local command that performs the complete Phase 1 verification on Windows and on a GitHub-hosted runner.

## Explicitly out of scope

- Modifying Spaghetti production code.
- Enabling auto-merge.
- Changing branch protection or repository rulesets.
- Building planner/builder/repair-agent orchestration.
- Calling an AI model to make the final decision.
- Claiming that human transferability or full autonomous governance has been established.

## Required controls

Before editing, explicitly spawn a read-only specification-analysis subagent to derive a proposed case matrix and identify ambiguities. The primary agent resolves technical ambiguities conservatively; use `ASK_BUSINESS` only for genuine business-behavior ambiguity.

After implementation and tests, explicitly spawn a fresh read-only adversarial-review subagent against the exact final diff. It must inspect for false positives, false negatives, self-modifying judge risks, floating references, fabricated evidence, and tests that merely assert fixtures rather than exercise detectors. Repair every reproduced P0-P2 finding and rerun all verification.

## Acceptance criteria

Completion is `FAIL` unless all are true:

- The PR #141 behavior defect is executable and is blocked.
- Every defective synthetic control is blocked.
- Every clean control passes.
- Critical-defect recall is 100% for the reproduced critical set.
- Negative-control recall is 100%.
- False-block rate is 0% for the initial verified-safe control set.
- Repeated deterministic runs produce identical decisions.
- Deterministic flake rate is 0% in the configured repetition test.
- Benchmark results are written as schema-valid JSON.
- The full local verification command exits nonzero on any failed criterion.
- No evaluated target code was modified.
- The final report lists exact commands, exit codes, generated artifacts, commit SHAs, unresolved unknowns, and the machine-computed decision.

Do not weaken these criteria to finish. If the historical defect cannot be reproduced from available evidence, implement the remaining harness, return `BLOCK_TECHNICAL`, and state exactly what evidence is missing.
