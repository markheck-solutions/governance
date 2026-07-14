# Self-enforcement canary

Governance changes must pass the same protected pull-request path that this repository provides to other repositories.

A clean canary is successful only when all four required contexts are GREEN on the exact pull-request head and protected base, the delivery receipt validates both evidence chains, branch protection remains unchanged, and GitHub accepts a normal non-admin merge. A failed, skipped, spoofed, stale, or manually copied result is not proof.
