# ADR 0002: Separate source qualification from adopter authority

Status: accepted

## Context

Governance source was protected by the Governance application workflows being edited. A base-branch `pull_request_target` startup failure could therefore suppress its own required contexts and prevent a repair. Candidate execution and trusted verification also shared writable runner state, while the required contexts were bound only to the generic GitHub Actions App.

## Decision

1. Governance source development and Governance adopter enforcement are different trust boundaries.
2. Governance application checks are diagnostic, never required on Governance source. They are required only in adopter repositories that explicitly install Governance.
3. Governance source requires independent `Governance Source Qualification`, not a Governance product decision.
4. Source candidate commands run only in a frozen `pull_request` workflow with no secrets or write authority. The base-controlled source qualifier executes no candidate code; it validates the frozen workflow pair and unique context producer, then reconciles the exact repository, PR, head, first-attempt run, and complete job set.
5. Source qualifier modules, the workflow pair, pinned lock, and package contract remain byte-identical to the trusted base during ordinary qualification. Their intentional update uses the pull-request-only maintainer lane.
6. The exact owner has a permanent, auditable, pull-request-only maintainer editing lane. It cannot authorize direct push, force push, deletion, or adopter verification.
7. Source-control settings changes require exact target guards, before-and-after snapshots and hashes, fresh verification, and rollback only for an incomplete transaction. The previous self-referential required-check profile is not the desired baseline.
8. Adopters pin an exact certified Governance SHA. Candidate execution is untrusted, has no privileged credentials, and produces only non-authoritative evidence.
9. An external verifier controlled outside the adopter validates hostile artifacts and exact repository, PR, base, head, run, artifact, evaluator, configuration, and workflow identities. Only its dedicated verifier GitHub App publishes the stable required check.
10. `AI_REVIEW_UNAVAILABLE` does not block deterministic execution after the bounded cutoff. Valid exact-head, in-window findings at configured blocking severity remain blocking.
11. The standard profile is pull-request-only. Merge queue is optional and enabled only after current GitHub eligibility and event authority are proved.
12. Code may use multiple finite local repair iterations until the frozen acceptance suite passes. One active implementation pull request at a time remains the operational rule.

## Consequences

Governance can repair its source even when a Governance product workflow is broken. Source checks remain ordinary software qualification; they do not claim adopter-grade hostile-candidate authority. Adopter authority moves to a dedicated external verifier and App-bound context, preventing a same-name candidate check from satisfying protection.

This ADR supersedes ADR 0001 lines 62-66, which assigned trusted verification to an adopter-controlled base-branch `pull_request_target` workflow, and lines 99-105, which made Governance product checks authoritative over Governance source and prohibited the evidence-backed settings migration. ADR 0001's remaining threat controls and immutable transition-history fixtures remain in force until specifically replaced by a later ADR.
