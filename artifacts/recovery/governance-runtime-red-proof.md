# Governance Runtime RED Proof

Status: `RED` — collected `2026-07-21T20:42:13Z`.

Frozen architecture SHA-256:

- `governance-self-maintenance-architecture.json`: `1b6a3aa1b3836de4572c4a2fb4a52b361fea680d44657e4125c765b61e74f9bd`
- `governance-self-maintenance-architecture.md`: `feaac1c3732d61cd677aafb3d610eb35bfb8e8ba64abefc8f882a0ddebfd2fd7`

`C-03` source PR [#4](https://github.com/markheck-solutions/governance-runtime-disposable-20260721/pull/4) and replay PR [#8](https://github.com/markheck-solutions/governance-runtime-disposable-20260721/pull/8) shared head `1fc32e21132d2c7a4987eff0d456dac85309c2ef` and base `3a601871593b13a16ae90d3ccbb2497d006458ec`.

PR #4 had successful run `29865142166`, with required check runs `88751380687`, `88751380753`, and `88752568492`; PR #8 later ran `29865574265` and closed unmerged. Required contexts were reusable by candidate SHA, not a unique merge-group plus PR identity.

Live state: `main` `1af18ded746ef97c6af49ae10e8e1bde1d660a94`; four required contexts bound to GitHub Actions app `15368`; admin enforcement true; zero rulesets; no `merge_group` workflow reference. Full machine-readable evidence: `governance-runtime-red-proof.json`.
