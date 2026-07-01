# Supportability Review Instructions

When reviewing pull requests in this repository, review against the Supportability Standard in `docs/reference/supportability-standard.md`.

Use these severity labels exactly:

- `P0`: fake delivery, security or data-loss risk, wrong repository, wrong branch, wrong commit proof, forged or missing GitHub evidence.
- `P1`: missing required gate, missing behavior proof, missing SQL gate, missing artifact, missing remote proof, stale review, or failed supportability receipt.
- `P2`: supportability boundary, complexity, testability, architecture, or gate-coverage issue that should block merge until resolved.
- `P3`: non-blocking cleanup, clarity, naming, or documentation improvement.

Blocking rule:

- Any unresolved `P0`, `P1`, or `P2` finding must block a GREEN delivery receipt.
- Include the reviewed head commit SHA in the review body.
- When the review is clean, end the response with this hidden evidence block using the exact reviewed head commit SHA:

```text
<!-- governance-review-evidence:v1
{"schema_version":"governance-review-evidence.v1","reviewed_commit_sha":"<HEAD_SHA>","verdict":"clean","open_findings":[]}
-->
```

- When the review is blocked, end with the same hidden evidence block using verdict `blocked` and list each open finding with `severity`, `title`, and `path`.
- Call out any changed file or high-risk production file that is outside lint, format, typecheck, complexity, architecture, tests, compile/build, package audit, or SQL supportability gate coverage.
- Call out any gate scope narrowing, threshold weakening, skipped required command, non-blocking required command, or missing artifact proof.

Do not approve by narrative confidence. Require GitHub-visible proof.
