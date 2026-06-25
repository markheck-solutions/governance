---
name: governance
description: >
  Use when the user starts a prompt with "$governance" or asks to enforce
  governance, supportability, machine-wide AI control-plane cleanup, proof-first
  coding, greenfield setup, brownfield refactoring, or strict completion gates.
---

# Governance

Primary code-work router for this PC.

## Voice

Use Caveman `ultra`.

Keep exact:
- commands
- paths
- code
- error text
- validation output
- pass/fail evidence

Relax compression only when terse wording would make order, risk, or meaning unclear.

## Router

Use only these process skills when relevant:
- `improve-codebase-architecture`
- `decompose-into-slices`
- `tdd`
- `debug-like-expert`
- `ai-regression-testing`
- `verify-before-complete`
- `review`
- `security-review`
- `observability`
- `handoff`
- `find-skills`

No other process router outranks this skill. Repo `AGENTS.md` files add local constraints; they do not replace governance.

## Work Rules

- Read applicable repo contracts before editing.
- For supportability, refactor, package/runtime, architecture cleanup, test hardening, repo maintainability, release/package proof, or completion-gate work, read `C:\Users\mheck\Documents\AI\HOW-TO\HOW-TO_supportability_standard.md` from disk before planning, editing, validating, or claiming completion.
- Treat every required item in `C:\Users\mheck\Documents\AI\HOW-TO\HOW-TO_supportability_standard.md` as pass/fail unless the owner explicitly scopes that item out in the current prompt.
- Do not rely on this skill's summary as a substitute for the canonical supportability standard file.
- If the canonical supportability standard cannot be read, stop and report the blocker. Do not proceed as if governance has been applied.
- No completion claim without fresh proof from the current turn.
- No supportability pass from narrowed gates, non-blocking gates, exception ledgers, ratchets, docs-only edits, or tests-only edits.
- For brownfield repos, map changed files plus highest-risk production files to gates before claiming supportability.
- For greenfield repos, create gates before feature work.
- Preserve approved local infrastructure unless the owner explicitly asks to change it.

## SQL Supportability Gate

For any `$governance` supportability, refactor, maintainability, completion-gate, package/runtime, or architecture work in a repo with SQL-like sources, require a fail-closed SQL supportability gate.

This rule applies to every repository. The SQL supportability gate must use the current repository's validation system, dependency model, database engine, file layout, runtime entry points, and CI or local proof commands. A repository with SQL-like sources and no blocking SQL supportability gate is `Repo SQL supportability: FAIL` until a repository-local gate exists and runs.

SQL-like sources must be discovered by content, runtime use, and execution sinks, not file path alone. Discovery must cover tracked files, untracked non-ignored files, ignored SQL candidates, ignored files referenced by production runtime reads, embedded Python SQL, embedded PowerShell SQL, templates, generated SQL inputs, env/path-loaded SQL sources, and execution-sink call sites.

Status must be reported separately:

```text
Gate implementation: PASS|FAIL
Repo SQL supportability: PASS|FAIL
SQL behavior proof: PASS|FAIL|NOT_REQUIRED
```

Do not merge these statuses into "done".

Fail closed:
- Missing SQL gate = `Repo SQL supportability: FAIL`.
- Non-blocking SQL gate = `Repo SQL supportability: FAIL`.
- SQL gate missing from local validation = `Repo SQL supportability: FAIL`.
- SQL gate missing from CI/workflow proof = `Repo SQL supportability: FAIL`.
- Unknown, dynamic, unscanned, unparsed, unclassified, unavailable, or unverifiable SQL = `Repo SQL supportability: FAIL`.
- SQL execution sink with statically unresolved SQL = `SQL gate FAIL` and `Repo SQL supportability: FAIL`.
- Production SQL parse failure = `SQL gate FAIL` and `Repo SQL supportability: FAIL`.
- Required live database proof unavailable = `SQL behavior proof: FAIL` and `Repo SQL supportability: FAIL`.

`SQL behavior proof: NOT_REQUIRED` is allowed only when current evidence proves extracted executable SQL, canonical SQL, execution-sink hash, role metadata hash, and dependency graph hash match the prior baseline.

For SQL gate or governance-skill edits, final proof must include current file hashes, exact commands, pass/fail results, and gate coverage for changed files plus highest-risk production SQL files.

## Output

Use short sections:
- `Action`
- `Proof`
- `Risk`
- `Next`

For completion reports, include exact commands and pass/fail results.
