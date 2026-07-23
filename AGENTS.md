# Repository contract

## Purpose

Build and publish Practical Tamper-Resistant Governance v1 for solo, AI-directed software development. Governance source development and Governance adopter enforcement are separate trust boundaries; this repository does not modify the application repositories it evaluates.

## Authority order

1. `AGENTS.md`
2. The active root task file, currently `TASK.md`
3. `docs/spec/resolve_failure.md`
4. Files under `docs/reference/`

Reference documents describe the current system and prior reasoning. They are inputs, not proof and not executable requirements unless adopted by `TASK.md`.

## Non-negotiable rules

- Work autonomously from the root task. Do not stop after planning.
- Keep evaluated target repositories read-only.
- Pin external repository evidence to exact commit SHAs; never evaluate floating `main` as historical proof.
- Never invent a reproduction, expected result, command result, metric, or commit identity.
- A missing or unreproduced deterministic case or capability is a blocking failure, not a pass.
- AI agents may produce evidence and findings. Only deterministic code computes `MERGE`, `BLOCK_TECHNICAL`, or `ASK_BUSINESS`.
- Deterministic GitHub Actions are the merge authority. An external AI service is never an availability prerequisite for deterministic governance.
- Attempt to request Codex review automatically for every new head SHA. A GitHub-blocked bot-to-bot request is transport unavailability, not evaluator failure; do not require a PAT or Copilot fallback. Use GitHub server time. Evidence with an authoritative GitHub creation or submission timestamp at or before that head's cutoff is in-window even when observed later. Do not finalize until a fully paginated collection begins after the cutoff and reconciles the unchanged head. Exact-head in-window Codex P0-P2 findings block. Missing, late, quota-limited, or unavailable Codex evidence records `AI_REVIEW_UNAVAILABLE`; it is neither approval nor a merge blocker after final reconciliation.
- Copilot is not a required reviewer, gate, receipt dependency, or availability dependency.
- Do not implement auto-merge, production refactoring, or an autonomous repair loop.
- Do not modify the global governance skill during Phase 1.
- Prefer cross-platform Python 3.12+ and commands runnable on Windows and GitHub-hosted runners.
- Keep dependencies minimal and pinned.
- Tests for the evaluator must include positive and negative controls.
- Treat candidate-controlled repository content as malicious. Protect base-branch evaluator and verifier code, workflows, action and dependency pins, configuration and standard hashes, toolchain and image identities, authoritative result artifacts, required-check identity, branch protection, and rulesets from candidate control.
- Classify every adapter with an evaluator-owned assurance class: `EVALUATOR_AUTHORITATIVE`, `CONTAINED_BUILD`, or `COOPERATIVE_DYNAMIC`. `EXTERNAL_ORACLE` is reserved and is not implemented in Governance v1.
- `python.unittest.v1` is `COOPERATIVE_DYNAMIC`. Protect its command, scope, containment, resource bounds, host-owned result, and evidence bindings, but do not claim that arbitrary malicious code loaded into the same interpreter truthfully executed assertions.
- This narrow dynamic-test non-guarantee does not weaken command, filesystem, credential, artifact, scope, threshold, workflow, replay, process, or resource-abuse controls.
- Governance application checks on the Governance source repository are diagnostic, never required. Source changes use independent source qualification.
- Source candidate lint, type, test, and build work runs only in the exact-hash `pull_request` workflow with read-only contents access. Its result is non-authoritative.
- The base-controlled source qualifier never executes candidate code. It validates both source workflow hashes and the unique required-context producer, then reconciles the exact repository, PR, head, first-attempt workflow run, and complete job set before emitting `Governance Source Qualification`.
- Source qualifier modules, its workflow pair, the pinned lock, and package contract are byte-frozen to the trusted base. Updating that authority requires the explicit pull-request-only maintainer lane.
- Governance application checks become authoritative only in adopter repositories that explicitly install an exact certified Governance SHA and bind their required decision to the dedicated verifier GitHub App.

## Source and release authority

- Governance source changes merge through protected pull requests with independent source qualification. Direct push, force push, and branch deletion remain forbidden.
- A permanent, auditable, pull-request-only maintainer editing lane may bypass the source ruleset. It never authorizes direct push, force push, deletion, adopter verification, or a false-green result.
- Source-control settings changes require an owner-authorized transaction, exact target checks, before-and-after snapshots, hashes, fresh verification, and a tested restore path for incomplete transactions. The prior self-referential four-check profile is not the desired baseline.
- Keep one active implementation pull request at a time. Code may be repaired through multiple finite local iterations until the frozen acceptance suite passes; a failed live PR follows the bounded replacement rule below.
- Publish the complete evaluator without changing live adopter pins or configuration. Qualify the exact publication merge, then use a pin-only activation pull request followed by a config-only migration pull request.
- Candidate execution is untrusted and non-authoritative. Only the external verifier validates hostile evidence and writes the adopter's stable required check through a dedicated verifier GitHub App.
- Merge queue is an optional adopter profile and may be enabled only after live GitHub eligibility and event authority are proved. The standard profile is pull-request-only.
- AI transport or quota unavailability records `AI_REVIEW_UNAVAILABLE` and never blocks deterministic execution after the bounded cutoff. Valid exact-head, in-window P0-P2 findings remain blocking.
- Use merge-commit strategy for publication so candidate ancestry and tree equality remain auditable. A source-boundary merge is not product readiness; completion still requires implementation, exact-merge qualification, activation, migration, rollback, release, and live canaries.

## Execution bounds

- Every subprocess uses an enforced hard timeout and records command, start/end time, timeout state, and exit code in schema-valid evidence.
- Focused verification command: 2 minutes maximum.
- Complete local verification: 5 minutes maximum; all local verification for one slice: 10 minutes maximum.
- Codex evidence wait: 5 minutes maximum.
- GitHub workflows set `timeout-minutes` at or below 10. Protected pull-request deadlines use GitHub server time.
- GitHub deterministic workflow: 10 minutes maximum; protected pull request: 15 minutes maximum.
- Local development may use multiple finite, bounded repair attempts until the acceptance suite passes. Do not create an autonomous repair loop.
- After a qualified head opens a pull request, permit at most one repair push for a live-only finding. A failed pull request ends that pull request, not the assignment; close or replace it from the last qualified checkpoint. Do not repeat the same pull request, polling, or verification loop.
- A timeout is a failure signal, never a reason to extend the same scope or claim partial success.

## Agent separation

Use subagents only for bounded, read-only analysis:

- Threat-model or specification review.
- GitHub Actions trust-boundary review.
- Cumulative release-delta review.
- Final adversarial review of the exact diff and test evidence.
- The primary agent implements and repairs. Reviewer agents must not edit files.

No agent may certify its own output merely by narrative assertion.

## Completion

Completion requires implementation, automated tests, exact commands and results, generated machine-readable benchmark evidence, live protected-path canaries, and resolution of every reproduced P0-P2 finding. Report a blocked result rather than weakening deterministic scope or fabricating proof. External AI availability is reported separately from deterministic governance status.
