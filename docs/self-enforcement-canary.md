# Source-edit canary

Governance source changes use independent source qualification. Governance application checks may run diagnostically, but they are not required and cannot veto repair of their own workflow.

The exact-hash `pull_request` source-candidate workflow has no secrets or write authority. The base-controlled qualifier executes no candidate code and emits the required source context only after exact PR/head/run/job reconciliation.

A clean canary changes a nonfunctional workflow or test-fixture line. It proves `Governance Source Qualification` runs, pull-request review and conversation rules remain active, direct push remains blocked, and the owner can merge only through the normal path or the permanent pull-request-only maintainer lane even when a Governance product check is absent or RED.

Adopter canaries are separate. Their authoritative result comes only from the external verifier and dedicated verifier GitHub App. No AI response within the bounded window records `AI_REVIEW_UNAVAILABLE`; valid exact-head P0-P2 findings remain blocking.
