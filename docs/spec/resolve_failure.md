Almost none of it is more Markdown. The data-driven approach is to treat the **governance system itself as software under test**.

```text
Known cases
    ↓
Current governance vs proposed governance
    ↓
Measured detection, false blocks, stability, cost
    ↓
Shadow operation
    ↓
Blocking enforcement
    ↓
Auto-repair and auto-merge
```

Do not build the autonomous factory first. Build the test rig that proves the factory can detect the exact failures that already escaped.

## 1. Define three outcomes

Every governed change must end in exactly one machine-computed state:

```text
MERGE
BLOCK_TECHNICAL
ASK_BUSINESS
```

`ASK_BUSINESS` is only for genuine questions such as:

> Should partially ranked routes preserve the old interleaving or adopt the new order?

It is not for interpreting Python, moving review comments, or choosing architecture.

The AI agents do **not** set the final result. They produce evidence. A deterministic function computes the result:

```python
merge_eligible = (
    required_behavior_cases_pass
    and deterministic_gates_pass
    and structural_debt_did_not_increase
    and no_unresolved_blocking_findings
    and rollback_proof_exists
)
```

Do not create one weighted “supportability score.” A severe behavior defect must not be offset by high test coverage or low complexity.

## 2. Build a governance benchmark from existing history

Spaghetti already has enough material: 205 commits, 111 closed pull requests, 13 releases, extensive tests, and numerous validation gates. ([GitHub][1])

Create three classes of evaluation cases.

### Behavior cases

These contain sanitized inputs and exact expected outputs:

```text
route order
ticket order
warning output
SQL payload shape
HTML/report output
packaged-runtime behavior
```

For a refactor, the current approved release is usually the behavior oracle. Explicit owner-scoped behavior changes need separate proof.

### Historical failure cases

PR #141 becomes a mandatory benchmark case. But it is not marked bad merely because Codex wrote a P2 comment. The reported scenario must be reproduced:

```text
Input:
Partially ranked route with an unranked A-B OL01 trunk

Expected:
A1, B1, A3, B3

Defective result:
A1, A3, B1, B3
```

The new governance system must detect that behavior difference and return `BLOCK_TECHNICAL`. PR #141 passed four checks, 855 tests, 95.09% coverage, SQL validation, and live-runtime proof despite the specific P2 finding, making it an essential negative control. ([GitHub][2])

### Synthetic structural violations

Generate small fixture repositories containing deliberate problems:

```text
private helper re-export
test importing a private production function
new import cycle
untyped public dict contract
new cross-layer dependency
gate scope narrowed to exclude changed code
quality threshold weakened
review finding ignored
```

Each mutation must cause the governance evaluator to fail. Include matching clean fixtures that must pass.

A governance rule without both a **failing negative control** and a **passing positive control** is prose, not enforcement.

## 3. Use strict data labels

Do not treat these as equivalent:

```text
merged = good
green CI = safe
review comment = real defect
```

Use three evidence labels:

```text
REPRODUCED_BAD
VERIFIED_SAFE
UNKNOWN
```

A case becomes `REPRODUCED_BAD` only when a test or deterministic detector demonstrates the problem.

A case becomes `VERIFIED_SAFE` only when its required behavior is demonstrated and the expected structural rules pass.

Everything else remains `UNKNOWN` and is excluded from benchmark accuracy calculations.

This prevents the evaluator from learning from unreliable labels.

## 4. Measure the governance system

Track a vector of metrics, not a single score.

| Measurement              | Meaning                                                                    |
| ------------------------ | -------------------------------------------------------------------------- |
| Critical-defect recall   | Percentage of reproduced critical defects correctly blocked                |
| Negative-control recall  | Percentage of injected violations correctly blocked                        |
| False-block rate         | Percentage of verified-safe changes incorrectly blocked                    |
| Decision stability       | Frequency with which repeated AI runs reach the same conclusion            |
| Deterministic flake rate | Frequency with which ordinary gates change result without a code change    |
| Repair convergence       | Percentage of defects repaired within the permitted attempts               |
| Escaped regression rate  | Auto-merged changes later requiring rollback or corrective repair          |
| Structural debt delta    | Whether measurable coupling and boundary violations increased or decreased |
| Runtime cost             | Tokens, execution time, and infrastructure cost per governed change        |

For architecture, record measurable counts such as:

```text
cross-module private references
private re-exports
tests coupled to private production internals
untyped boundary contracts
import cycles
module dependency fan-out
files repeatedly changed together
churn concentrated in complex modules
```

Git history is especially useful. If `sorting.py`, `tickets.py`, models, SQL, and rendering repeatedly change together, that co-change frequency is evidence of coupling. After a successful boundary refactor, unrelated changes should require fewer coordinated file modifications.

A hotspot ranking can help select work:

```text
hotspot priority =
    change frequency
    × complexity
    × dependency fan-out
    × association with defects
```

That formula selects refactoring targets. It does not determine merge eligibility.

## 5. Compare systems on the same cases

Run an actual controlled comparison:

```text
A: current supportability standard + current skill
B: current system + one reviewer
C: current system + two isolated reviewers
D: reviewer findings converted into reproducible tests before decision
E: full proposed orchestrator
```

Run every variant against the same calibration and holdout cases.

Record:

```text
known defects detected
safe cases blocked
run-to-run disagreement
repair success
cost
duration
```

Do not assume GPT-5.5 xhigh, two agents, or a longer skill is better. Require the benchmark to prove it.

Keep approximately 20% of cases as a holdout set. The agents receive the code and requirements but not the expected decision. This reduces prompt-fitting and compliance theater.

## 6. Promote automation in stages

### Stage 1: Offline historical replay

No branch protection changes. No production edits. No auto-merge.

Required starting results:

```text
100% of reproduced critical defects blocked
100% of synthetic negative controls blocked
all clean control fixtures passed
0 deterministic gate flakes
benchmark results emitted as JSON
```

### Stage 2: Shadow mode

The workflow runs on every new pull request but does not control merging.

Compare its recommendation with:

```text
test outcomes
review findings
follow-up repairs
rollbacks
production or package proof
```

A reasonable initial graduation target is:

```text
20 consecutive shadow runs
0 missed reproduced P2-or-higher defects
≤10% false-block rate on verified-safe changes
stable decisions on high-risk cases
```

These are starting thresholds, not universal laws. Adjust them only from observed results.

### Stage 3: Blocking objective failures

Make only these merge-blocking initially:

```text
behavior case failure
existing deterministic gate failure
new structural violation
weakened or narrowed validation
unresolved reproduced defect
malformed or missing evidence
```

AI architectural opinions remain advisory until converted into a reproducer or deterministic rule.

### Stage 4: Automated repair

The orchestrator sends reproducible failures directly to the repair agent, reruns validation, and repeats review.

```text
maximum repair attempts: 2 or 3
```

After that:

```text
BLOCK_TECHNICAL
```

You receive one plain-English reason, not a review packet.

### Stage 5: Low-risk auto-merge

Start with narrow classes:

```text
documentation
tests
internal cleanup with complete behavior parity
non-runtime tooling
```

Only later allow automatic merge for:

```text
sorting behavior
SQL
ticket generation
runtime packaging
authentication
release workflows
```

Each risk class should have its own performance history.

## 7. Keep the skill and standard small

Your supportability standard already establishes behavior proof, boundary improvement, and gate coverage. 

Your governance skill already acts as a router and requires the canonical standard. 

Add one principle to the standard:

```markdown
Every blocking governance rule must have:

- a machine-readable detector or executable behavior case
- at least one negative control that must fail
- at least one positive control that must pass
- benchmark results against historical and holdout cases
- measured false-negative and false-block rates
```

Add one small rule to the skill:

```markdown
Do not claim or enforce governed completion before the repository's
governance benchmark passes. Invoke the executable governance engine;
do not substitute narrative review for benchmark evidence.
```

The earlier conclusion that executable orchestration—not more prose—is missing remains correct. 

## 8. Put the evaluator outside the code it judges

A candidate pull request should not be able to modify its own judge.

Use a central protected governance repository or immutable action containing:

```text
decision engine
schemas
common structural detectors
holdout cases
benchmark runner
reusable GitHub workflow
```

Each application repository contains only:

```text
.governance/config.toml
.governance/cases/
.github/workflows/governed-change.yml
```

Reference the central reusable workflow by a full commit SHA. GitHub supports reusable workflows, and pinning to a commit SHA keeps the referenced workflow immutable for that invocation. ([GitHub Docs][3])

That matters because an AI-generated PR must not be able to:

```text
delete a failing case
weaken the decision rule
change BLOCK into PASS
exclude the touched file
replace the evaluator
```

Governance-system changes require running the complete benchmark before the new evaluator version is accepted.

## 9. Make agent output structured data

Codex can run non-interactively and validate final output against a JSON Schema using `codex exec --output-schema`. That is the correct interface for planner and reviewer results—not free-form Markdown. ([OpenAI Developers][4])

A review result should resemble:

```json
{
  "reviewed_base_sha": "abc123",
  "reviewed_head_sha": "def456",
  "findings": [
    {
      "id": "REV-001",
      "severity": "P2",
      "category": "behavior_regression",
      "file": "src/inca_sorter/sorting.py",
      "line": 813,
      "scenario": "partial metadata coverage",
      "expected": "preserve unranked trunk interleaving",
      "actual": "unranked rows remain grouped by endpoint",
      "reproducer_status": "REPRODUCED",
      "test_command": "python -m pytest ..."
    }
  ]
}
```

The reviewer cannot emit:

```json
{"merge_eligible": true}
```

That field belongs exclusively to the deterministic decision engine.

Codex subagents can handle bounded planner, builder, and reviewer jobs, but they must be explicitly assigned and given strict return formats. ([OpenAI Developers][5])

## 10. Record every governed run

Store an artifact for every attempt:

```json
{
  "run_id": "2026-06-25T...",
  "task_id": "TASK-123",
  "base_sha": "...",
  "candidate_sha": "...",
  "risk_class": "high",
  "builder_model": "...",
  "reviewer_model": "...",
  "prompt_hashes": {},
  "behavior_results": {},
  "gate_results": {},
  "structural_metrics_before": {},
  "structural_metrics_after": {},
  "review_findings": [],
  "repair_attempts": 1,
  "decision": "BLOCK_TECHNICAL",
  "duration_seconds": 0,
  "token_usage": {},
  "post_merge_outcome": null
}
```

After merge, update the outcome automatically when possible:

```text
release succeeded
package proof passed
corrective PR required
rollback occurred
new regression case created
```

Every escaped defect becomes a permanent benchmark case. The governance system should become harder to fool after each failure.

## 11. GitHub performs enforcement after calibration

Once the evaluator proves itself:

```text
Pull request
    ↓
Governance workflow
    ↓
Required status check
    ↓
GitHub auto-merge
```

GitHub required checks can prevent merging until the designated check passes, and auto-merge can merge once configured requirements are satisfied. ([GitHub Docs][6])

GitHub is not deciding whether the architecture is good. It enforces the decision produced by the benchmarked evaluator.

## The first implementation task

The first autonomous governance mission should be narrowly scoped:

```markdown
Implement Governance Evaluation Phase 1 only.

Do not modify production application behavior.
Do not enable auto-merge.
Do not modify branch protection.
Do not refactor production modules.

Build an offline governance benchmark that:

1. Defines machine-readable evaluation-case and result schemas.
2. Replays selected historical pull requests.
3. Includes PR #141's partial-metadata interleaving defect as a
   reproduced behavior case.
4. Includes synthetic negative and positive controls for:
   - private helper re-exports
   - private test dependencies
   - import cycles
   - untyped public boundaries
   - narrowed gate scope
   - weakened thresholds
5. Runs the current governance process and proposed evaluator against
   the same cases.
6. Reports:
   - critical-defect recall
   - negative-control recall
   - false-block rate
   - decision stability
   - deterministic flake rate
   - execution cost and duration
7. Stores immutable JSON artifacts for every run.
8. Adds a non-blocking GitHub shadow workflow.
9. Proves the benchmark itself with automated tests.

Completion is FAIL until every reproduced defect and negative control
is blocked and every clean control passes.
```

That is the correct starting point. The first deliverable is not an autonomous refactorer. It is evidence that the proposed governance system would have stopped the exact failure that caused this problem.

[1]: https://github.com/markheck-solutions/Spaghetti "GitHub - markheck-solutions/Spaghetti · GitHub"
[2]: https://github.com/markheck-solutions/Spaghetti/pull/141 "[codex] Refactor metadata route sorting by markheck-solutions · Pull Request #141 · markheck-solutions/Spaghetti · GitHub"
[3]: https://docs.github.com/en/actions/reference/security/secure-use?utm_source=chatgpt.com "Secure use reference - GitHub Docs"
[4]: https://developers.openai.com/codex/noninteractive "Non-interactive mode – Codex | OpenAI Developers"
[5]: https://developers.openai.com/codex/subagents?utm_source=chatgpt.com "Subagents – Codex"
[6]: https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/incorporating-changes-from-a-pull-request/automatically-merging-a-pull-request?utm_source=chatgpt.com "Automatically merging a pull request"
