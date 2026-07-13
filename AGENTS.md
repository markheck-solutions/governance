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
- A missing or unreproduced required case is a blocking failure, not a pass.
- AI agents may produce evidence and findings. Only deterministic code computes `MERGE`, `BLOCK_TECHNICAL`, or `ASK_BUSINESS`.
- Do not implement auto-merge, branch protection changes, production refactoring, or an autonomous repair loop during Phase 1.
- Do not modify the global governance skill during Phase 1.
- Prefer cross-platform Python 3.12+ and commands runnable on Windows and GitHub-hosted runners.
- Keep dependencies minimal and pinned.
- Tests for the evaluator must include positive and negative controls.

## Agent separation

Explicitly use bounded subagents when available:

- A read-only specification analyst derives acceptance cases before implementation.
- A read-only adversarial reviewer inspects the final diff and test evidence.
- The primary agent implements and repairs. Reviewer agents must not edit files.

No agent may certify its own output merely by narrative assertion.

## Delivery discipline

These controls limit wasted execution without weakening `TASK.md` or its completion criteria.

- Work one dependency-complete implementation slice at a time. Do not begin another slice until the current slice has a qualified checkpoint commit. A blocker stops work; it does not unlock another slice.
- A qualified checkpoint commit is an exact commit SHA whose committed tree—not an uncommitted worktree—passes formatting, `git diff --check`, every focused positive and negative control for the slice, changed-file and highest-risk-file coverage, and a read-only exact-diff review with zero unresolved P0-P2 findings.
- A plan, status message, test invocation, elapsed effort, arbitrary commit, or unbound artifact is not a deliverable. Progress reports must identify a qualified checkpoint commit SHA, protected-path pull request URL, exact-SHA-bound machine-readable artifact digest, or exact newly reproduced failing assertion.
- Run focused positive and negative controls before an aggregate suite. Do not use an aggregate suite to discover failures that a bounded focused command can expose.
- Every command must have a declared hard timeout. After the first timeout, do not rerun the same scope with a larger timeout. Isolate the slow file or case, identify the cause, and set the next bound from measured evidence.
- Permit at most two consecutive repair or verification loops without a qualified checkpoint commit. At that point, stop, inspect the design and diff, and either produce the qualified checkpoint or stop work on the slice.
- A blocker artifact is valid only when produced by a repository-owned deterministic evaluator command present in the recorded head SHA and validated against a schema present in that same commit. It must record the base SHA, head SHA, exact command, hard timeout, exit code or timeout state, failing assertion or missing external prerequisite, evidence digest, and code-computed `BLOCK_TECHNICAL` decision. Hand-authored or schema-invalid artifacts and narrative blocker claims are invalid. A blocker artifact never resets the two-loop limit or authorizes work on another slice.
- Run formatting and `git diff --check` before expensive verification.
- Reusable-workflow publication, caller-pin activation, typed-configuration migration, and protected-surface activation always use separate pull requests. Do not combine any two of these transition classes, even when they appear compatible.
- Do not start target-repository rollout while Governance self-enforcement remains unproven.
- Never convert a timeout, skipped test, partial batch, narrative review, or locally green subset into a completion claim.

## Completion

Completion requires implementation, automated tests, exact commands and results, generated machine-readable benchmark evidence, and resolution of every reproduced P0-P2 finding. Report a blocked result rather than weakening scope or fabricating proof.
