# Task: Practical Tamper-Resistant Governance v1

Implement, activate, and prove a reusable GitHub governance framework that can govern this repository before on-demand adoption by another repository.

## Goal

Governance is a target-neutral evaluator and GitHub enforcement framework for solo, AI-directed software development. It must:

- preserve the completed Phase 1 offline benchmark as a mandatory regression suite;
- judge changes with deterministic code, not narrative approval;
- execute target-specific capabilities through typed, versioned adapters;
- separate candidate execution from the trusted verifier and authoritative merge decision;
- protect evaluator authority, credentials, evidence, scope, thresholds, and required-check identity from candidate control;
- release through normal protected pull requests without weakening branch protection or rulesets;
- prove clean, defective, and stale-evidence canaries before any target rollout.

Governance v1 supports the Python 3.12 ecosystem only.

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

## Revised threat model

Governance v1 protects these assets from candidate control:

- base-branch evaluator and verifier code;
- reusable and caller workflows;
- action and dependency pins;
- configuration and Supportability Standard hashes;
- toolchain and image identities;
- the authoritative result artifact directory and its evidence bindings;
- the GitHub required-check app and workflow identity;
- branch protection and rulesets.

Candidate-controlled repository content may be malicious. It may attempt command injection, arbitrary configuration, file writes, network or secret access, result replacement, artifact replay, workflow spoofing, evaluator modification, process escape, or resource exhaustion.

Governance prevents candidate control of protected assets and authoritative merge decisions. It does not claim Byzantine proof that arbitrary malicious code loaded into an in-process dynamic test runner truthfully executed assertions. That narrow non-guarantee does not weaken command, filesystem, credential, artifact, scope, threshold, workflow, replay, process, or resource-abuse controls. `docs/adr/0001-governance-v1-threat-model.md` records the complete decision.

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
- The evaluator assigns and the trusted verifier recomputes each adapter's assurance class. Candidate configuration cannot select or alter assurance.
- `EVALUATOR_AUTHORITATIVE`: Ruff lint, Ruff format, Ruff C901 at threshold 10, mypy, architecture, Phase 1 benchmark, Git diff integrity, and evaluator-owned package and artifact verification.
- `CONTAINED_BUILD`: candidate wheel build and other candidate build processes whose effects are contained and whose outputs are host-captured.
- `COOPERATIVE_DYNAMIC`: `python.unittest.v1` and any dynamic runner that imports candidate code. Its fixed command, scope, nonzero and not-all-skipped test requirements, timeout, output bounds, cleanup, host-owned result, and exact bindings remain enforced; assertion truth is not independently attributable.
- `EXTERNAL_ORACLE`: reserved for a future repository-specific stable external interface; not implemented or required for Governance v1.
- Unsupported adapters, capability versions, or options fail closed.
- The framework does not claim universal language support. A repository is governable only when all required capabilities have supported adapters.
- Candidate configuration cannot choose, replace, or modify the protected baseline judge or delivery-receipt verifier.

Practical Tamper-Resistant Governance v1 is the product release. Its typed configuration remains the separately versioned `schema_version: "2.0"` contract.

### Untrusted execution and trusted verification

- Candidate execution runs only in a `pull_request` workflow with `contents: read`, every unnecessary permission set to `none`, no secrets, no write token, exact action and evaluator pins, and no authoritative check identity.
- Provisioning is separate from offline gate execution. Candidate processes run non-root with a read-only root filesystem, dropped capabilities, no privilege escalation, bounded CPU, memory, PIDs, output, step time, and total time, and only a disposable target copy writable.
- Candidate code cannot access the Docker socket, evaluator checkout, toolchain source, or authoritative artifact directory.
- A host wrapper outside the target checkout owns result paths and records exact identities, timing, timeout and termination, exit status, bounded stream counts and digests, truncation, cleanup, and artifact name and content digest.
- The base-branch `pull_request_target` workflow performs only trusted verification and GitHub reconciliation. It never checks out candidate code for execution, imports candidate Python, runs candidate scripts, tests, builds, package hooks, or configuration, or executes artifact contents.
- The trusted verifier downloads artifacts as hostile data, safely inspects archive structure and bounds, validates schemas, recomputes digests and decisions, rejects identity mismatch or replay, reconciles the unchanged exact head and current protection, and alone emits the authoritative required context.
- Execution plans bind repository, pull request, base SHA and tree, head SHA and tree, evaluator and workflow identities, adapter version and assurance, configuration and standard hashes, toolchain and image identities, working directory, and bounded steps.

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

Branch protection, rulesets, required contexts, and permissions may only be inspected and proven. Weakening or bypassing them is out of scope.

### Protected three-PR release

1. **Publication:** merge the complete evaluator, adapters, schemas, workflows, evidence contracts, and adoption tooling without changing live pins, live config, required contexts, or protection. Use merge-commit strategy and record publication merge `M`; require `tree(M) == tree(C)` for the frozen qualified candidate `C`.
2. **Exact-`M` qualification:** rerun complete qualification against the publication merge while the old evaluator remains active. A failure requires a replacement publication pull request, not weakened criteria.
3. **Pin-only activation:** change only exact reusable workflow or action pins, `governance-ref` values, and literal pin fixtures. The old evaluator judges the transition. Verify every live pin equals `M` after merge.
4. **Config-only migration:** change only `.github/governance/supportability.yml` and exact migration fixtures from known v1 to typed v2. Require the protected baseline, candidate, and delivery checks GREEN.
5. Keep `main` frozen from publication-candidate freeze through activation and config migration. Preserve required-context names and protection throughout.

### Execution service levels

- Every subprocess uses an enforced hard timeout and records command, start/end time, timeout state, and exit code in schema-valid evidence.
- Focused verification command: at most 2 minutes.
- Complete local verification: at most 5 minutes; all local verification for the slice: at most 10 minutes.
- Codex evidence cutoff: 5 minutes from GitHub server time.
- GitHub workflows set `timeout-minutes` at or below 10. Protected-pull-request deadlines use GitHub server time.
- GitHub deterministic workflow: at most 10 minutes; protected pull request: at most 15 minutes.
- Local development may use multiple finite, bounded repair attempts until the acceptance suite passes. This does not authorize an autonomous repair loop.
- After a qualified head opens a pull request, permit at most one repair push for a live-only finding. A failed pull request ends that pull request, not the assignment; close or replace it from the last qualified checkpoint. Never repeat the same pull request, polling, or verification loop.

## Required implementation

1. Preserve every Phase 1 acceptance criterion and registered benchmark case.
2. Remove target-specific assumptions from the evaluator core while retaining named target packs.
3. Replace arbitrary command configuration with typed, versioned capability adapters and bounded execution plans.
4. Provide separate untrusted execution and trusted verification planes with a safe, deterministic, replay-resistant process for updating protected evaluator and workflow surfaces without same-PR self-authorization.
5. Validate both protected baseline evidence and candidate evidence contents before issuing a GREEN receipt.
6. Replace placeholder or duplicated gates with real lint, format, type, complexity, architecture, test, build, and package-audit capabilities. Applicability is computed deterministically from registered source and runtime evidence; a required capability without a supported adapter or executable evidence is `BLOCK_TECHNICAL`, never omitted.
7. Prove changed-file and highest-risk-file gate coverage without exclusions, threshold weakening, or scope narrowing.
8. Normalize received Codex review evidence from exact approved bot identities, bind it to the latest head SHA, and remove Copilot as a required provider.
9. Make received-review reconciliation deterministic and automatic without bot-comment approval deadlocks or manual rescue. Record bounded unavailability without converting it to approval or blocking deterministic governance indefinitely.
10. Keep required final contexts stable and fail closed on missing, skipped, malformed, or stale dependencies.
11. Produce machine-readable baseline, candidate, architecture, review, benchmark, and delivery-receipt artifacts.
12. Replace manual protected-path filename lists with structural protection for all evaluator Python, schemas, workflows, actions, dependency locks, package metadata, architecture and supportability configuration, adapter command logic, evidence validation, and final decisions.
13. Generate byte-stable, read-only adoption bundles and proofs without applying changes, opening pull requests, mutating protection, enumerating repositories, or modifying targets.
14. Prove the framework through clean, defective, replay, stale-review, protected-context-spoof, hostile-artifact, and AI-unavailable canaries.

## Required controls

Positive, negative, and evasion controls must cover at least:

- clean target evaluation;
- every preserved Phase 1 defect;
- hostile target attempt to modify or replace its judge;
- config plus companion-file migration;
- missing or unsupported adapter;
- arbitrary command or shell syntax;
- execution-plan mutation or artifact replay;
- candidate writes or races the result path, reads secrets, reaches the network during offline execution, writes outside the disposable target, accesses the Docker socket, leaves child processes, exhausts PIDs, times out, or floods output;
- archive traversal, links, duplicate entries, unexpected entries, decompression abuse, oversized content, malformed JSON, or digest and identity mismatch;
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
7. Merge occurs only through the normal protected pull-request path. No protection weakening or administrative bypass is authorized.

## Explicitly out of scope

- Modifying evaluated application repositories.
- TWMN or other target-repository adoption before Governance self-canaries pass.
- Auto-merge.
- Autonomous repair loops or planner/builder factories.
- Production application refactoring.
- Global governance-skill modification.
- Branch-protection, ruleset, required-context, default-branch, permission, or administrative-bypass mutation.
- Node, PowerShell, SQL, or additional language adapters in Governance v1.
- A custom hosted execution service, black-box assertion RPC framework, or `EXTERNAL_ORACLE` implementation in Governance v1.
- Universal hostile-code truth proof for in-process dynamic assertions.
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
- `python.unittest.v1` is documented and evidenced as `COOPERATIVE_DYNAMIC`; no completion document claims otherwise.
- The trusted verifier never executes or imports candidate code or executes artifact contents.
- Untrusted execution has no secrets or write token; authoritative artifacts are host-owned and exact-identity bound.
- Replay, mutation, malformed archives, scope narrowing, threshold weakening, and required-check spoofing deterministically block.
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
- The active evaluator and adoption pin equal publication merge `M`; live typed config is v2; arbitrary v1 command execution is unreachable; `main` contains no unactivated evaluator backlog.
- Protection, rulesets, and required contexts equal the saved snapshot.
- A schema-valid `governance_completion_receipt.v1` binds every release pull request, SHA, run, artifact, digest, command, exit, canary, live-protection proof, and remaining unknown.
- Fresh adversarial review reports zero unresolved P0-P2 findings.
- Final report lists exact commands, exit codes, artifacts, hashes, commit SHAs, live GitHub proof, and unresolved unknowns.

Do not weaken any criterion to finish. Report `BLOCK_TECHNICAL` when required proof is unavailable.
