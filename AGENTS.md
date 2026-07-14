# Repository contract

## Purpose

Build and test an executable governance evaluator for solo, AI-directed software development. This repository judges governance mechanisms; it does not modify the application repositories it evaluates.

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
- Request Codex review automatically for every new head SHA. Use GitHub server time. Evidence with an authoritative GitHub creation or submission timestamp at or before that head's cutoff is in-window even when observed later. Do not finalize until a fully paginated collection begins after the cutoff and reconciles the unchanged head. Exact-head in-window Codex P0-P2 findings block. Missing, late, quota-limited, or unavailable Codex evidence records `AI_REVIEW_UNAVAILABLE`; it is neither approval nor a merge blocker after final reconciliation.
- Copilot is not a required reviewer, gate, receipt dependency, or availability dependency.
- Do not implement auto-merge, production refactoring, or an autonomous repair loop.
- Do not modify the global governance skill during Phase 1.
- Prefer cross-platform Python 3.12+ and commands runnable on Windows and GitHub-hosted runners.
- Keep dependencies minimal and pinned.
- Tests for the evaluator must include positive and negative controls.

## Authorized self-bootstrap

The owner authorized one controlled bootstrap because the installed Copilot-dependent gate cannot authorize its own replacement.

- One bootstrap pull request may combine evaluator, configuration, reusable workflow, caller, and receipt changes. Existing required context names remain unchanged. This is the only exception to normal transition separation.
- Before any live mutation, bind the candidate to an exact commit SHA; pass complete local verification; obtain a read-only adversarial review with zero unresolved P0-P2 findings; persist the current branch-protection/ruleset snapshot plus digest; and prepare an independently reviewed exact rollback commit whose tree restores the pre-bootstrap base.
- Live mutations may target only `markheck-solutions/governance`. Evaluated application repositories remain read-only.
- The only permitted live protection mutation is toggling `enforce_admins` for `main` from `true` to `false`, then back to `true`. Direct push, required-context deletion or rename, ruleset deletion, default-branch change, force push, permission change, and every other live mutation are forbidden.
- Merge the bootstrap through an auditable pull request using merge-commit strategy so candidate ancestry is preserved. Squash and rebase merge are forbidden. Do not exploit a spoofed context, false-green result, stale artifact, or unrelated admin change.
- Immediately restore admin enforcement. Verify live protection equality against the saved snapshot before canaries.
- A repository-owned deterministic bootstrap command must produce a schema-valid receipt binding resource URLs, ETags when supplied, actor, GitHub server timestamps, mutation requests and responses, candidate SHA, PR head before merge, merge SHA, rollback SHA, pre/post protection digests, and transaction expiry.
- On failure, first compare the live `main` tree to the saved pre-bootstrap base tree. If equal, skip code rollback and restore/verify protection only. If different, the same exception authorizes one emergency rollback pull request and one rollback-only `enforce_admins` `true` to `false` to `true` cycle. Admin-merge only the exact reviewed rollback SHA, verify its resulting tree equals the saved base tree, and restore the saved protection snapshot before reporting `BLOCK_TECHNICAL`. The audit receipt records both protection cycles. Direct push remains forbidden.
- Rollback authority remains active until code/protection restoration succeeds. The bootstrap exception expires only after restored protection equality, a valid audit receipt, and canary readiness are verified. All later changes use the protected pull-request path normally.

## Execution bounds

- Every subprocess uses an enforced hard timeout and records command, start/end time, timeout state, and exit code in schema-valid evidence.
- Focused verification command: 2 minutes maximum.
- Complete local verification: 5 minutes maximum; all local verification for one slice: 10 minutes maximum.
- Codex evidence wait: 5 minutes maximum.
- GitHub workflows set `timeout-minutes` at or below 10. Protected pull-request and bootstrap deadlines use GitHub server time.
- GitHub deterministic workflow: 10 minutes maximum; protected pull request: 15 minutes maximum.
- Controlled bootstrap transaction: 60 minutes maximum with deterministic abort and rollback when exceeded.
- One repair loop per slice. If it fails, inspect the design once and either produce a qualified checkpoint or emit deterministic `BLOCK_TECHNICAL` evidence. Do not repeat the same PR, polling, or verification loop.
- A timeout is a failure signal, never a reason to extend the same scope or claim partial success.

## Agent separation

Explicitly use bounded subagents when available:

- A read-only specification analyst derives acceptance cases before implementation.
- A read-only adversarial reviewer inspects the final diff and test evidence.
- The primary agent implements and repairs. Reviewer agents must not edit files.

No agent may certify its own output merely by narrative assertion.

## Completion

Completion requires implementation, automated tests, exact commands and results, generated machine-readable benchmark evidence, live protected-path canaries, and resolution of every reproduced P0-P2 finding. Report a blocked result rather than weakening deterministic scope or fabricating proof. External AI availability is reported separately from deterministic governance status.
