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

## Completion

Completion requires implementation, automated tests, exact commands and results, generated machine-readable benchmark evidence, and resolution of every reproduced P0-P2 finding. Report a blocked result rather than weakening scope or fabricating proof.
