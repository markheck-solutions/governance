# ADR 0001: Practical Tamper-Resistant Governance v1 threat model

- Status: Accepted
- Date: 2026-07-20
- Decision owner: Repository owner

## Context

The previous contract required a universal proof that hostile code could not forge the outcome of a dynamic test runner that imported that same code. Standard in-process Python testing cannot provide that attribution boundary. Requiring it deadlocked the release without improving the controls that protect GitHub merge authority.

Governance v1 therefore separates two questions:

1. Can candidate content control protected governance assets or the authoritative merge decision?
2. Can an in-process test runner independently prove that arbitrary hostile candidate code truthfully executed assertions?

Governance v1 guarantees the first. It does not claim the second.

Practical Tamper-Resistant Governance v1 is the product release name. Its typed configuration uses the independently versioned `schema_version: "2.0"` contract.

## Decision

Build Practical Tamper-Resistant Governance v1 with an untrusted candidate execution plane and a separate trusted verification plane. Adapter assurance is evaluator-owned, recorded in evidence, and recomputed by the trusted verifier. Candidate configuration cannot select or modify assurance.

No black-box assertion RPC service or external assertion platform is part of this release.

## Protected assets

Candidate content cannot create, replace, modify, select, or bypass:

- base-branch evaluator and verifier code;
- reusable and caller workflows;
- action and dependency pins;
- configuration and Supportability Standard hashes;
- toolchain and image identities;
- the authoritative result artifact directory and its evidence bindings;
- the GitHub required-check app and workflow identity;
- branch protection and rulesets.

## Adversary

Candidate-controlled repository content may be malicious. It may attempt:

- command or argument injection and arbitrary configuration;
- writes to evaluator, workflow, toolchain, result, or external filesystem paths;
- network, secret, credential, token, or Docker-socket access;
- result replacement, artifact mutation, replay, or identity swapping;
- workflow or required-check spoofing;
- evaluator, verifier, scope, threshold, or dependency modification;
- child-process persistence, process escape, or incomplete cleanup;
- resource exhaustion through CPU, memory, PIDs, time, disk, archives, or output.

## Guarantees

Governance prevents candidate control of protected assets and authoritative merge decisions through executable controls:

- candidate execution occurs only in a non-authoritative `pull_request` workflow with `contents: read`, unnecessary permissions set to `none`, no secrets, and no write token;
- exact certified evaluator, action, dependency, toolchain, and image identities are pinned and evidence-bound;
- evaluator-owned adapters compile commands and fixed thresholds from typed IDs; candidate configuration supplies no command, executable, arguments, environment, roots, patterns, thresholds, plugins, or arbitrary options;
- candidate processes receive only a disposable target copy and cannot access the evaluator checkout, toolchain source, Docker socket, or authoritative artifact directory;
- containment is non-root, read-only-root, capability-dropped, no-new-privileges, offline during gate execution, and bounded for CPU, memory, PIDs, output, step time, total time, and cleanup;
- a host wrapper outside the target checkout owns result paths and records exact identities, timing, termination, exit, bounded stream digests, truncation, cleanup, and artifact digests;
- the trusted verifier authenticates the `pull_request` workflow path and file hash against the previously published version; a head that changes the caller, pinned wrapper, permissions, conditions, dependencies, or result-upload path makes every artifact from that run non-authoritative for that change;
- a base-branch `pull_request_target` workflow performs trusted verification and GitHub reconciliation only; it never executes or imports candidate code, runs candidate configuration or package hooks, or executes artifact contents;
- hostile archives are rejected for traversal, links, duplicate or unexpected entries, decompression abuse, oversize content, malformed schemas, digest mismatch, replay, mutation, stale head, wrong repository, wrong workflow, wrong evaluator, wrong config, wrong standard, wrong toolchain, or wrong artifact;
- deterministic trusted code recomputes the final decision and alone emits the authoritative required context;
- current branch protection, rulesets, head identity, workflow/app identity, and required contexts are reconciled before authorization.

## Assurance classes

| Class | Governance v1 adapters and meaning |
|---|---|
| `EVALUATOR_AUTHORITATIVE` | Ruff lint, Ruff format check, Ruff C901 at fixed threshold 10, mypy with evaluator-owned configuration, architecture, Phase 1 benchmark, Git diff integrity, isolated package audit over the exact captured wheel, and artifact verification. Evaluator-owned logic computes the finding from authenticated inputs. |
| `CONTAINED_BUILD` | Wheel build and another candidate build process whose effects are contained and whose outputs are host-captured. Successful containment and capture are authoritative; semantic honesty of candidate build code is not implied. |
| `COOPERATIVE_DYNAMIC` | `python.unittest.v1` or another dynamic runner that imports candidate code. The runner command, scope, containment, resource controls, result ownership, and bindings are protected; assertion truth is cooperative evidence. |
| `EXTERNAL_ORACLE` | Reserved for a future repository-specific adapter with a stable external interface. It is not implemented or required for Governance v1. |

The trusted verifier rejects a missing, unknown, candidate-selected, or adapter-inconsistent assurance class.

## Dynamic-test non-guarantee

Governance v1 does not claim cryptographic or Byzantine attribution that arbitrary malicious code loaded into the same Python interpreter truthfully executed test assertions.

`python.unittest.v1` still requires:

- an evaluator-owned command and complete protected scope;
- a nonzero test count and a result that is not all skipped;
- timeout, output, process, containment, and cleanup controls;
- a host-owned result outside the candidate checkout;
- exact repository, pull request, base, head, evaluator, workflow, config, standard, toolchain, plan, run, and artifact bindings.

This non-guarantee is narrow. It does not weaken command, filesystem, credential, artifact, scope, threshold, workflow, replay, process, or resource-abuse controls. It also does not make dynamic test evidence an external availability prerequisite.

## Evidence ownership

The candidate may influence tool inputs and process behavior. It may not create, edit, or select the authoritative result path.

The host records the exact adapter and assurance class; repository and pull-request identities; base and head commits and trees; evaluator, workflow, configuration, standard, toolchain, and image identities; start and end; timeout and termination; exit code; stdout and stderr byte counts and SHA-256 digests; truncation; cleanup; and artifact name and content digest.

## Release and transition consequence

The former controlled-bootstrap and branch-protection-mutation authority is revoked. Publication, pin activation, and config migration use separate normal protected pull requests. No direct push, administrative bypass, protection weakening, ruleset mutation, required-context mutation, or permission mutation is authorized.

The publication pull request does not change the live execution caller or pins. The previously active protected evaluator judges it; candidate-changed workflow artifacts are not authorization evidence. After the exact publication merge is qualified, the previously active evaluator authorizes the bounded pin-only activation from static transition evidence and the exact-merge qualification receipt, not from artifacts emitted by the candidate-modified caller. Any other caller or wrapper change fails closed.

The current transitional workflow is not certified by this ADR. A docs-only contract reset may traverse the existing protected path, but Governance readiness remains `FAIL` until the split execution/verifier design is implemented, qualified at the publication merge, activated, migrated, and proven by live canaries.

## Future mode

A selected repository may later add an `EXTERNAL_ORACLE` adapter when it has a stable external interface and repository-specific executable controls. That future mode requires its own threat model, schemas, clean/defective/evasion controls, and protected release. It is not a Governance v1 readiness dependency.
