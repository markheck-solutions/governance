# Task: Repository-Agnostic Governance Self-Enforcement

Implement and prove a reusable GitHub governance framework that can govern this repository before it is adopted by another repository.

## Goal

Governance is a target-neutral evaluator and GitHub enforcement framework for solo, AI-directed software development. It must:

- preserve the completed Phase 1 offline benchmark as a mandatory regression suite;
- judge changes with deterministic code, not narrative approval;
- execute target-specific capabilities through typed, versioned adapters;
- keep the trusted judge separate from candidate-controlled code and commands;
- replace its currently deadlocked Copilot-dependent path through the authorized controlled bootstrap, then pass its restored protected pull-request path;
- prove clean, defective, and stale-evidence canaries before any target rollout.

Spaghetti remains one registered historical target pack and benchmark source. It is not the framework identity, default target, or special case in the core evaluator. TWMN and all other application repositories remain out of scope until Governance self-enforcement is proven.

## Authority and evidence

- `AGENTS.md` remains the repository contract.
- External repository evidence must use exact immutable commit SHAs.
- Evaluated target remotes are never mutated. Declared untrusted execution may write only to disposable target copies; those mutations may never be pushed, persisted, or represented as target-repository changes. Historical source evidence is pinned to exact SHAs and digests. Generated evidence artifacts may be persisted only with required identity and digest bindings. Live GitHub state is freshly queried and treated as mutable evidence.
- Missing, malformed, stale, unsupported, unresolved, or unverifiable required evidence or capability is `BLOCK_TECHNICAL`.
- Only deterministic code computes `MERGE`, `BLOCK_TECHNICAL`, or `ASK_BUSINESS`.
- `ASK_BUSINESS` is reserved for genuine owner-scoped behavior ambiguity.
- Human approval, AI approval, waiver, allowlist, CODEOWNER approval, baseline debt, or known-debt metadata never converts RED to GREEN.
- Deterministic GitHub Actions own merge decisions. External AI evidence can add blocking findings but cannot be the availability dependency that authorizes deterministic checks.

## Preserved Phase 1 benchmark

The Phase 1 benchmark remains mandatory and must continue to provide:

1. Versioned schemas for cases, detector evidence, review findings, benchmark results, and decisions.
2. The executable Spaghetti PR #141 partial-metadata interleaving reproducer. Review prose alone is not evidence.
3. Paired clean and defective controls for:
   - private helper re-export;
   - test dependency on private production internals;
   - import cycle;
   - untyped public dictionary boundary;
   - narrowed validation-gate scope;
   - weakened validation threshold.
4. Clean, defective, and evasion or mutation controls for every blocking rule.
5. Machine-readable benchmark artifacts.
6. A complete local verification command:

   ```text
   python -m governance_eval verify --artifacts-dir artifacts/phase1
   ```

Phase 1 acceptance remains:

- critical-defect recall: 100%;
- negative-control recall: 100%;
- false-block rate: 0% for the verified-safe controls;
- repeated deterministic decisions: identical;
- deterministic flake rate: 0%;
- benchmark JSON: schema-valid;
- execution duration: recorded;
- complete verification: nonzero exit on any failed criterion.

These thresholds may not be weakened, narrowed, waived, or replaced by narrative evidence.

## Framework contract

### Deterministic core

The core owns schemas, target-pack validation, typed execution-plan generation, evidence validation, deterministic decisions, and delivery-receipt verification. Core behavior must not depend on a named target repository.

### Target packs

Repository-specific cases, fixtures, typed capability declarations, bounded adapter inputs, expected capabilities, and immutable evidence belong in versioned target packs. Target packs may not provide executable names, shell text, or arbitrary argument vectors. Evaluator-owned adapters generate every executable argument vector. Removing a target pack must not break the target-neutral core; removing a required registered pack must make complete verification RED.

### Typed capabilities and adapters

- Configuration selects supported typed capability and adapter identifiers, not arbitrary shell commands.
- Each adapter is versioned, has positive and negative controls, and generates an immutable execution plan.
- Unsupported adapters, capability versions, or options fail closed.
- The framework does not claim universal language support. A repository is governable only when all required capabilities have supported adapters.
- Candidate configuration cannot choose, replace, or modify the protected baseline judge or delivery-receipt verifier.

### Isolated execution

- Untrusted target execution receives no secrets or persisted credentials.
- Trusted judge files and target files do not share a writable execution boundary.
- Execution plans bind repository, pull request, base SHA, head SHA, evaluator identity, adapter version, configuration hash, working directory, and bounded commands or steps.
- Result artifacts bind the executed plan, exit status, output limits, artifact identity, and digest.

### GitHub enforcement

The framework must produce and verify this status split:

```text
Repo config: PASS|FAIL
Caller workflow: PASS|FAIL
Protected branch/ruleset: PASS|FAIL
Required checks: PASS|FAIL
Canary PR: PASS|FAIL
Repo GitHub governance: PASS|FAIL
```

`Repo GitHub governance: PASS` requires current live evidence for all fields. Offline benchmark success is necessary but not sufficient.

Required enforcement properties:

- reusable workflows pinned to exact immutable SHAs;
- protected baseline and delivery receipt independent from candidate judgment;
- stable final required-check names with no ghost or skipped-success path;
- artifacts bound to exact repository, pull request, base, head, run, ID, name, and digest;
- exact approved AI reviewer identities and latest-head binding for any AI evidence that is received before the bounded cutoff;
- unresolved reproduced P0-P2 findings block;
- A Codex request is attempted automatically for every new head SHA. GitHub-blocked bot-to-bot request transport is recorded but does not skip deterministic evaluation and does not require a PAT or Copilot fallback. Each head gets a five-minute cutoff derived from GitHub server time. Evidence whose authoritative GitHub creation or submission timestamp is at or before the cutoff is in-window even if observed later. GREEN is prohibited until a fully paginated collection begins after the cutoff and reconciles an unchanged head. Missing, late, quota-limited, or unavailable evidence then records `AI_REVIEW_UNAVAILABLE`, never approval, and does not block deterministic governance;
- Copilot is not a required gate, reviewer, receipt dependency, or fallback;
- manual Actions approval, manual API rerun, or owner-copied review evidence can never satisfy a required check, receipt, canary, or completion proof; automatic exact-head reconciliation is allowed.

Outside the controlled bootstrap below, existing branch protection and required checks may only be inspected and proven. The bootstrap may temporarily modify Governance protection only as narrowly as required to merge the exact independently reviewed bootstrap SHA, then must restore enforcement before canaries.

### Authorized controlled bootstrap

The installed gate requires Copilot to approve the change that removes Copilot. That circular dependency is not a valid product requirement. The owner authorized one bounded replacement transaction:

1. One bootstrap pull request may combine evaluator, configuration, reusable workflow, caller, and receipt changes. Existing four required context names remain unchanged.
   If the first live self-enforcement canary proves the protected `pull_request_target` caller cannot execute its own corrective PR, the still-open transaction permits one corrective bootstrap PR limited to reproduced bootstrap defects. It must satisfy the same exact-SHA verification, exact rollback, protection snapshot, mutation, restoration, and receipt controls. Produce one schema-valid audit receipt per merge cycle so each receipt binds its own candidate, pull request, merge, rollback, mutation pair, and protection snapshots; final proof lists both content hashes. This authority expires with the bootstrap transaction and cannot authorize later maintenance.
2. Before live mutation, the exact candidate SHA must pass complete local verification and a fresh read-only adversarial review with zero unresolved P0-P2 findings.
3. Snapshot and digest current branch protection, rulesets, required contexts, and default-branch identity. Prepare and independently review an exact rollback commit whose tree restores the pre-bootstrap base.
4. The only permitted live protection mutation is toggling `enforce_admins` for `main` from `true` to `false`, then back to `true`. Direct push, context deletion or rename, ruleset deletion, default-branch change, force push, permission change, and every unlisted mutation are forbidden.
5. Admin-merge only the exact reviewed bootstrap SHA through its pull request using merge-commit strategy so candidate ancestry is preserved. Squash and rebase merge are forbidden.
6. Immediately restore admin enforcement and verify live protection equality against the saved snapshot before running canaries.
7. A repository-owned deterministic bootstrap command must emit a schema-valid receipt binding resource URLs, ETags when supplied, actor, GitHub server timestamps, mutation request/response digests, candidate SHA, PR head immediately before merge, merge SHA, rollback SHA, pre/post protection digests, and transaction expiry.
8. On failed merge, restoration, receipt validation, deadline, or canary readiness, first compare the live `main` tree to the saved pre-bootstrap base tree. If equal, skip code rollback and restore/verify protection only. If different, the same exception authorizes one emergency rollback pull request and one rollback-only `enforce_admins` `true` to `false` to `true` cycle. Admin-merge only the exact reviewed rollback SHA, verify its resulting tree equals the saved base tree, and restore the saved protection snapshot before producing `BLOCK_TECHNICAL`. Produce one schema-valid receipt for each protection cycle and list both content hashes in final proof. Direct push remains forbidden.
9. Rollback authority remains active until restoration succeeds. The exception expires only after restored protection equality, valid audit receipt, and canary readiness. All later work must pass the restored protected pull-request path.

### Execution service levels

- Every subprocess uses an enforced hard timeout and records command, start/end time, timeout state, and exit code in schema-valid evidence.
- Focused verification command: at most 2 minutes.
- Complete local verification: at most 5 minutes; all local verification for the slice: at most 10 minutes.
- Codex evidence cutoff: 5 minutes from GitHub server time.
- GitHub workflows set `timeout-minutes` at or below 10. Protected-pull-request and transaction deadlines use GitHub server time.
- GitHub deterministic workflow: at most 10 minutes; protected pull request: at most 15 minutes.
- Entire controlled bootstrap: at most 60 minutes with deterministic abort and rollback when exceeded.
- Permit one repair loop. Then produce a qualified checkpoint or deterministic `BLOCK_TECHNICAL`; never repeat the same PR, polling, or verification loop.

## Required implementation

1. Preserve every Phase 1 acceptance criterion and registered benchmark case.
2. Remove target-specific assumptions from the evaluator core while retaining named target packs.
3. Replace arbitrary command configuration with typed, versioned capability adapters and bounded execution plans.
4. Provide a safe, deterministic, replay-resistant process for updating protected evaluator and workflow surfaces without same-PR self-authorization.
5. Validate both protected baseline evidence and candidate evidence contents before issuing a GREEN receipt.
6. Replace placeholder or duplicated gates with real lint, format, type, complexity, architecture, test, build, and package-audit capabilities. Applicability is computed deterministically from registered source and runtime evidence; a required capability without a supported adapter or executable evidence is `BLOCK_TECHNICAL`, never omitted.
7. Prove changed-file and highest-risk-file gate coverage without exclusions, threshold weakening, or scope narrowing.
8. Normalize received Codex review evidence from exact approved bot identities, bind it to the latest head SHA, and remove Copilot as a required provider.
9. Make received-review reconciliation deterministic and automatic without bot-comment approval deadlocks or manual rescue. Record bounded unavailability without converting it to approval or blocking deterministic governance indefinitely.
10. Keep required final contexts stable and fail closed on missing, skipped, malformed, or stale dependencies.
11. Produce machine-readable baseline, candidate, architecture, review, benchmark, and delivery-receipt artifacts.
12. Prove the framework through clean, defective, stale-review, and protected-context-spoof canaries.

## Required controls

Positive, negative, and evasion controls must cover at least:

- clean target evaluation;
- every preserved Phase 1 defect;
- hostile target attempt to modify or replace its judge;
- config plus companion-file migration;
- missing or unsupported adapter;
- arbitrary command or shell syntax;
- execution-plan mutation or artifact replay;
- narrowed gate scope or weakened threshold;
- duplicate command used as multiple semantic capabilities;
- missing or malformed candidate artifact;
- candidate-only GREEN with protected baseline RED;
- wildcard, similar-looking, or stale-head AI reviewer evidence;
- workflow pin substitution, floating ref, disabled job, changed condition, removed dependency, broadened permissions, or renamed required context;
- protected-context spoof attempt from candidate-controlled workflow;
- replay or mutation of a previously authorized protected-workflow update.

## Required workflow

Before each implementation slice:

1. A read-only specification analyst defines acceptance and ambiguity.
2. The primary agent implements the smallest dependency-complete slice.
3. Local verification runs with changed-file and high-risk-file gate coverage.
4. A fresh read-only adversarial reviewer inspects the exact final diff and evidence.
5. Every reproduced P0-P2 finding is repaired before push.
6. The pull request requests Codex automatically, records its bounded evidence status, and receives all deterministic required checks.
7. Merge occurs only through the protected pull-request path, except for the one exact-SHA controlled bootstrap defined above.

## Explicitly out of scope

- Modifying evaluated application repositories.
- TWMN or other target-repository adoption before Governance self-canaries pass.
- Auto-merge.
- Autonomous repair loops or planner/builder factories.
- Production application refactoring.
- Global governance-skill modification.
- Branch-protection, ruleset, or required-context mutation outside the one controlled Governance bootstrap.
- Claiming support for an adapter or ecosystem without executable positive, negative, and evasion controls.

## Completion

Completion is `FAIL` unless all are true:

- Phase 1 complete verification exits 0 and writes schema-valid artifacts.
- Every registered historical, clean, defective, and evasion control produces its expected deterministic result.
- All reproduced P0-P2 findings are resolved.
- Real lint, format, type, C901, architecture, tests, build, package audit, and benchmark gates pass for their complete registered scope.
- No changed or highest-risk production file is excluded from applicable gates.
- No gate threshold or scope was weakened.
- No evaluated target repository was modified.
- Governance configuration validates and uses supported typed adapters only.
- Protected baseline and candidate artifacts are independently schema-valid and bound to the exact pull-request head.
- Delivery receipt validates both evidence chains and remote GitHub state.
- These existing four required contexts are GREEN on the exact current head and base:
  - `Phase 1 shadow run`;
  - `Baseline Protected Supportability Gate / Supportability Gate`;
  - `Candidate Supportability Gate / Supportability Gate`;
  - `Baseline Protected Delivery Receipt / Delivery Receipt`.
- Clean canary merges through the protected path.
- Defective canary remains RED and closes unmerged.
- Stale-review canary proves stale AI evidence cannot block or authorize the current head; a current exact-head received P0-P2 finding remains RED until resolved.
- Protected-context-spoof canary cannot bypass the real protected result.
- Codex request transport is attempted automatically and cannot skip deterministic evaluation; exact-head received evidence is classified; missing or unavailable evidence records `AI_REVIEW_UNAVAILABLE`; no PAT or Copilot evidence is required.
- A deterministic adoption command generates repo config and a caller pinned to the exact Governance SHA, validates config hash and required-context mapping, documents protection setup, and proves disposable clean and defective adoption canaries without modifying any target repository.
- Fresh adversarial review reports zero unresolved P0-P2 findings.
- Final report lists exact commands, exit codes, artifacts, hashes, commit SHAs, live GitHub proof, and unresolved unknowns.

Do not weaken any criterion to finish. Report `BLOCK_TECHNICAL` when required proof is unavailable.
