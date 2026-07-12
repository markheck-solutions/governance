# Task: Repository-Agnostic Governance Framework Hardening

## Goal

Build and prove a reusable governance framework for any repository that adopts a
versioned target pack and the adapters required by that repository's technology
stack. Spaghetti is one historical target pack. It is not a framework default,
special case, or required runtime dependency.

## Framework contract

```text
target-neutral deterministic core
  + versioned target pack
  + declared command/language adapters
  + isolated target execution
  + GitHub Actions and SHA-bound AI review evidence
  = governed target decision
```

Unsupported, missing, malformed, stale, or unverifiable required capability is
`UNKNOWN` and deterministically produces `BLOCK_TECHNICAL`.

GitHub Copilot and Codex may produce structured findings and evidence.
Only deterministic code computes `MERGE`, `BLOCK_TECHNICAL`, or `ASK_BUSINESS`.

## Required implementation

1. Remove target-specific assumptions from core CLI, benchmark, locks, schemas,
   artifacts, and detector orchestration. Keep target specifics inside packs and
   adapters.
2. Provide at least two target-neutral controls: a Python repository adapter and
   a command-only non-Python repository adapter.
3. Isolate untrusted target commands from the trusted judge. Candidate execution
   must not share a writable judge checkout. Record and verify evaluator identity
   and tree hashes across trust transitions.
4. Validate gate semantics, applicability, and coverage. Placeholder commands,
   compile-only substitutes, duplicated capabilities, non-blocking commands,
   narrowed scopes, weakened thresholds, and missing package/SQL proof fail
   closed.
5. Require every applicable gate to cover every changed and high-risk production
   file.
6. Fix all reproduced detector false positives and false negatives, including:
   private imports versus public re-exports, async raw-dictionary boundaries,
   cycles through package initializers, and partial gate coverage.
7. Complete verification must execute every registered required real-target pack
   at exact immutable revisions. Fixture-only success cannot produce framework
   success. Verified immutable caches may support explicit offline execution.
8. Require structured GitHub AI review evidence from exact approved bot identities.
   Copilot supplies supportability review evidence; Codex supplies final
   delivery-readiness review evidence. Both bind to the latest target commit SHA
   and fail closed on unresolved P0-P2 findings. Review evidence cannot compute
   the governed decision.
9. Keep AI review separate from deterministic enforcement. GitHub Actions collect
   evidence; deterministic evaluator code alone computes the outcome.
10. Support explicit `SHADOW` and `BLOCKING` enforcement modes. Blocking mode must
    exit nonzero on technical blocks or missing required evidence. Do not add
    auto-merge.
11. Decompose oversized modules along real responsibilities. New and touched
    production functions must satisfy C901 <= 10. Tighten repository limits; do
    not raise or bypass them.
12. Replace bootstrap documentation with an operator guide covering the threat
    model, trust seams, target-pack/adapters, onboarding, commands, artifacts,
    enforcement, and honest limitations.

## Required controls

- Every blocking detector has clean, defective, and evasion/mutation controls.
- A hostile target attempting judge mutation is blocked.
- A target covered by only one of several applicable gates is blocked.
- Internal use of a private module without public export passes.
- Public export of a private helper blocks.
- Async raw-dictionary public interfaces block.
- Cycles through `__init__.py` block.
- Removing the Spaghetti pack does not break generic-core tests.
- A command-only non-Python pack evaluates through the same public interface.
- Missing real-target, AI-review, or integrity evidence blocks the corresponding
  configured claim.

## Explicit boundaries

- Evaluated target repositories remain read-only except disposable isolated
  checkouts and scratch output.
- No application production refactoring.
- No auto-merge.
- No weakening, waiver, allowlist, baseline debt, or human approval converts RED
  to GREEN.
- Do not claim universal semantic support. A repo is governable when its required
  capabilities have declared, versioned adapters; unsupported capabilities fail
  closed.

## Completion

Completion is `FAIL` unless all confirmed P0-P2 findings are fixed, all controls
run, the complete verification command exits zero, machine-readable evidence is
schema-valid, target repos remain unchanged, and a fresh read-only adversarial
review finds no unresolved P0-P2 issue.

GitHub enforcement status must be reported separately for repo config, caller
workflow, protected branch/ruleset, required checks, clean canary, defective
canary, and overall governance.
