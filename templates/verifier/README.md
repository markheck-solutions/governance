# Governance Verifier

External authority for `Governance / Authoritative Decision`.

The workflow reads GitHub API metadata and one untrusted candidate artifact. It does not
checkout or execute adopter code. It creates an in-progress check with the dedicated App,
confirms the server-reported App ID and exact head, then completes that same check.

Required repository configuration:

- variable `GOVERNANCE_VERIFIER_CLIENT_ID`
- variable `GOVERNANCE_VERIFIER_APP_ID`
- secret `GOVERNANCE_VERIFIER_APP_PRIVATE_KEY`

The App installation must use selected repositories and only `Actions: read`,
`Checks: write`, `Contents: read`, `Metadata: read`, and `Pull requests: read`.
