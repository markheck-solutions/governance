from __future__ import annotations

import json
import unittest
from copy import deepcopy
from hashlib import sha256

from governance_eval.ai_review_gate import evaluate_ai_review_gate
from governance_eval.codex_connector_evidence import (
    TrustedCodexConnectorContext,
    TrustedWorkflowRequestReceipt,
    _classify_review_state,
    evaluate_codex_connector_evidence,
    serialize_codex_connector_evidence_result,
    validate_codex_connector_evidence_result,
)
from governance_eval.hashing import sha256_json
from governance_eval.schemas import load_schema, validate_named


REPOSITORY_ID = 1280677092
REPOSITORY = "markheck-solutions/governance"
PR_NUMBER = 31
PR_NODE_ID = "PR_kwDOTFWU5M8AAAAB"
BASE_SHA = "a" * 40
HEAD_SHA = "b" * 40
EVALUATOR_SHA = "e" * 40
ANCHOR = "2026-07-13T18:00:00Z"
DEADLINE = "2026-07-13T18:05:00Z"
WORKFLOW_SHA = "f" * 40
WORKFLOW_REF = (
    f"{REPOSITORY}/.github/workflows/supportability-enforcement.yml@refs/heads/main"
)
CONNECTOR_USER = {
    "login": "chatgpt-codex-connector[bot]",
    "id": 199175422,
    "node_id": "BOT_kgDOC98s_g",
    "type": "Bot",
}
CONNECTOR_APP = {
    "id": 1144995,
    "node_id": "A_kwHOAOQ6Gs4AEXij",
    "slug": "chatgpt-codex-connector",
}
CONNECTOR_REACTION_USER = {
    "login": "chatgpt-codex-connector[bot]",
    "id": 199175422,
    "node_id": "BOT_kgDOC98s_g",
    "type": "User",
}
COLLECTION_FIELDS = (
    "issue_comments",
    "issue_reactions",
    "pull_request_reviews",
    "review_comments",
    "pull_request_events",
)
PRODUCT_DETAILS = """<details> <summary>ℹ️ About Codex in GitHub</summary>
<br/>

[Your team has set up Codex to review pull requests in this repo](https://chatgpt.com/codex/cloud/settings/general). Reviews are triggered when you
- Open a pull request for review
- Mark a draft as ready
- Comment "@codex review".

If Codex has suggestions, it will comment; otherwise it will react with 👍.

Codex can also answer questions or update the PR. Try commenting "@codex address that feedback".
</details>"""


def clean_body(suffix: str = " Bravo.", prefix: str | None = None) -> str:
    reviewed = prefix or HEAD_SHA[:10]
    return (
        f"Codex Review: Didn't find any major issues.{suffix}\n\n"
        f"**Reviewed commit:** `{reviewed}`\n\n{PRODUCT_DETAILS}"
    )


def codex_review_body(prefix: str | None = None) -> str:
    reviewed = prefix or HEAD_SHA[:10]
    return (
        "\n### 💡 Codex Review\n\n"
        "Here are some automated review suggestions for this pull request.\n\n"
        f"**Reviewed commit:** `{reviewed}`\n    \n\n{PRODUCT_DETAILS}"
    )


def automatic_summary_body(head_sha: str = HEAD_SHA) -> str:
    return f"""### Summary

* Verified the PR head is exactly `{head_sha}`, matching the supplied `head_ref`.
* Confirmed the native Codex connector evaluator is present and deterministic: it binds snapshot digests, repository/PR identity, base/head SHAs, evaluator SHA, review window, connector identity, reviewed head, response metadata, reasons, and a result content hash before schema validation. [governance_eval/codex_connector_evidence.pyL126-L177](https://github.com/markheck-solutions/governance/blob/{head_sha}/governance_eval/codex_connector_evidence.py#L126-L177)
* Confirmed the evaluator fails closed for malformed or stale evidence, digest mismatch, non-head review evidence, unrecognized connector responses, manual `@codex review` requests, and unresolved blocking findings. [governance_eval/codex_connector_evidence.pyL180-L254](https://github.com/markheck-solutions/governance/blob/{head_sha}/governance_eval/codex_connector_evidence.py#L180-L254)
* Confirmed the machine-readable result schema requires exact connector identity, exact PR/head bindings, status, response metadata, reasons, and content hash. [schemas/v1/codex_connector_evidence_result.schema.jsonL7-L68](https://github.com/markheck-solutions/governance/blob/{head_sha}/schemas/v1/codex_connector_evidence_result.schema.json#L7-L68)
* Confirmed positive and negative controls cover deterministic clean connector evidence, quota/noise comments, missing/incomplete/stale snapshots, manual review requests, identity mismatches, and trusted full-SHA resolution. [tests/test_codex_connector_evidence.pyL158-L271](https://github.com/markheck-solutions/governance/blob/{head_sha}/tests/test_codex_connector_evidence.py#L158-L271)
* No code changes were needed, so I did **not** create a commit or open a new PR.

**Testing**

* ✅ `git rev-parse HEAD` — returned `{head_sha}`.
* ✅ `git status --porcelain=v1` — clean working tree.
* ✅ `python -m pytest tests/test_codex_connector_evidence.py` — 14 passed.
* ✅ `python -m governance_eval verify --artifacts-dir artifacts/phase1` — 315 tests passed; `phase1_decision` was `BENCHMARK_PASS`; generated `artifacts/phase1/governance-benchmark-20260713T212251Z.json`.

 [View task →](https://chatgpt.com/s/example)"""


def comment(
    body: str,
    *,
    comment_id: int = 200,
    created_at: str = "2026-07-13T18:01:00Z",
    user: dict | None = None,
    app: dict | None = None,
) -> dict:
    return {
        "id": comment_id,
        "created_at": created_at,
        "body": body,
        "user": deepcopy(CONNECTOR_USER if user is None else user),
        "performed_via_github_app": deepcopy(CONNECTOR_APP if app is None else app),
    }


def human_comment(
    body: str,
    *,
    comment_id: int = 100,
    created_at: str = "2026-07-13T18:01:00Z",
) -> dict:
    result = comment(
        body,
        comment_id=comment_id,
        created_at=created_at,
        user={
            "login": "markheck-solutions",
            "id": 12345,
            "node_id": "U_owner",
            "type": "User",
        },
    )
    result["performed_via_github_app"] = None
    return result


def connector_review(*, review_id: int = 300, commit_id: str = HEAD_SHA) -> dict:
    return {
        "id": review_id,
        "submitted_at": "2026-07-13T18:01:00Z",
        "state": "COMMENTED",
        "commit_id": commit_id,
        "body": "\n### 💡 Codex Review\n\nAutomated review suggestions.",
        "user": deepcopy(CONNECTOR_USER),
    }


def connector_review_comment(*, review_id: int = 300, severity: str = "P1") -> dict:
    return {
        "id": 400,
        "pull_request_review_id": review_id,
        "created_at": "2026-07-13T18:01:00Z",
        "commit_id": HEAD_SHA,
        "original_commit_id": HEAD_SHA,
        "path": "governance_eval/example.py",
        "line": 10,
        "body": f"![{severity} Badge] {severity}: unsafe evidence boundary",
        "user": deepcopy(CONNECTOR_USER),
    }


def connector_reaction(
    *,
    reaction_id: int = 407803693,
    node_id: str = "REA_lAHOTFWU5M8AAAABIsCXZM4YTpct",
    content: str = "+1",
    created_at: str = "2026-07-13T18:04:10Z",
    user: dict | None = None,
) -> dict:
    return {
        "id": reaction_id,
        "node_id": node_id,
        "created_at": created_at,
        "content": content,
        "user": deepcopy(CONNECTOR_REACTION_USER if user is None else user),
    }


def pull_request_event(
    event: str,
    *,
    event_id: int = 500,
    created_at: str = "2026-07-13T18:02:00Z",
) -> dict:
    return {
        "id": event_id,
        "node_id": f"EV_{event_id}",
        "event": event,
        "created_at": created_at,
    }


def snapshot() -> dict:
    return {
        "schema_version": "2.0",
        "collector": {
            "id": "github_rest_codex_connector_v1",
            "governance_evaluator_sha": EVALUATOR_SHA,
        },
        "collection_complete": True,
        "captured_at": DEADLINE,
        "collection_receipts": {},
        "repository": {"id": REPOSITORY_ID, "full_name": REPOSITORY},
        "pull_request": {
            "number": PR_NUMBER,
            "node_id": PR_NODE_ID,
            "created_at": ANCHOR,
            "state": "open",
            "draft": False,
            "base_sha": BASE_SHA,
            "head_sha": HEAD_SHA,
        },
        "issue_comments": [comment(clean_body())],
        "issue_reactions": [],
        "pull_request_reviews": [],
        "review_comments": [],
        "pull_request_events": [],
    }


def reaction_snapshot() -> dict:
    result = snapshot()
    result["captured_at"] = DEADLINE
    result["issue_comments"] = []
    result["issue_reactions"] = [connector_reaction()]
    result["pull_request_events"] = []
    return result


def raw_bytes(value: dict, *, refresh_receipts: bool = True) -> bytes:
    if refresh_receipts and value.get("schema_version") == "2.0":
        _refresh_collection_receipts(value)
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _refresh_collection_receipts(value: dict) -> None:
    repository = value["repository"]["full_name"]
    pull_request_number = value["pull_request"]["number"]
    endpoints = {
        "issue_comments": f"issues/{pull_request_number}/comments",
        "issue_reactions": f"issues/{pull_request_number}/reactions",
        "pull_request_reviews": f"pulls/{pull_request_number}/reviews",
        "review_comments": f"pulls/{pull_request_number}/comments",
        "pull_request_events": f"issues/{pull_request_number}/events",
    }
    receipts = {}
    for field in COLLECTION_FIELDS:
        items = value.setdefault(field, [])
        timestamp_field = (
            "submitted_at" if field == "pull_request_reviews" else "created_at"
        )
        ordered = sorted(
            items,
            key=lambda item: (str(item[timestamp_field]), int(item["id"])),
        )
        chunks = [ordered[index : index + 100] for index in range(0, len(ordered), 100)]
        if not chunks:
            chunks = [[]]
        pages = []
        for index, chunk in enumerate(chunks, start=1):
            terminal = index == len(chunks)
            next_url = None
            if not terminal:
                next_url = (
                    f"https://api.github.com/repos/{repository}/"
                    f"{endpoints[field]}?per_page=100&page={index + 1}"
                )
            pages.append(
                {
                    "page": index,
                    "item_count": len(chunk),
                    "page_sha256": sha256_json(chunk),
                    "next_url": next_url,
                    "terminal": terminal,
                }
            )
        receipts[field] = {
            "complete": True,
            "item_count": len(ordered),
            "items_sha256": sha256_json(ordered),
            "pages": pages,
        }
    value["collection_receipts"] = receipts


def trusted(raw: bytes, **changes: object) -> TrustedCodexConnectorContext:
    values = {
        "snapshot_file_sha256": "sha256:" + sha256(raw).hexdigest(),
        "repository_id": REPOSITORY_ID,
        "repository_full_name": REPOSITORY,
        "pull_request_number": PR_NUMBER,
        "pull_request_node_id": PR_NODE_ID,
        "pull_request_created_at": ANCHOR,
        "base_sha": BASE_SHA,
        "head_sha": HEAD_SHA,
        "governance_evaluator_sha": EVALUATOR_SHA,
        "review_window_started_at": ANCHOR,
        "review_deadline_at": DEADLINE,
        "resolved_clean_commit_sha": HEAD_SHA,
    }
    values.update(changes)
    if "workflow_request_receipt" not in changes:
        values["workflow_request_receipt"] = workflow_request_receipt(
            "TRANSPORT_UNAVAILABLE",
            repository_id=values["repository_id"],
            repository_full_name=values["repository_full_name"],
            pull_request_number=values["pull_request_number"],
            head_sha=values["head_sha"],
            review_window_started_at=values["review_window_started_at"],
        )
    return TrustedCodexConnectorContext(**values)  # type: ignore[arg-type]


def workflow_request_receipt(
    outcome: str = "POSTED",
    **changes: object,
) -> TrustedWorkflowRequestReceipt:
    repository = str(changes.get("repository_full_name", REPOSITORY))
    pull_request_number = int(changes.get("pull_request_number", PR_NUMBER))
    head_sha = str(changes.get("head_sha", HEAD_SHA))
    body = f"@codex review\n\nGovernance review request for exact head `{head_sha}`."
    endpoint = f"repos/{repository}/issues/{pull_request_number}/comments"
    command = [
        "gh",
        "api",
        "--method",
        "POST",
        endpoint,
        "-f",
        f"body={body}",
    ]
    values = {
        "workflow_ref": (
            f"{repository}/.github/workflows/"
            "supportability-enforcement.yml@refs/heads/main"
        ),
        "workflow_sha": WORKFLOW_SHA,
        "event_name": "pull_request_target",
        "event_action": "opened",
        "run_id": 123456,
        "run_attempt": 1,
        "repository_id": REPOSITORY_ID,
        "repository_full_name": repository,
        "pull_request_number": pull_request_number,
        "head_sha": head_sha,
        "review_window_started_at": ANCHOR,
        "job_id": "request-codex-review",
        "request_endpoint": endpoint,
        "request_body_sha256": "sha256:" + sha256(body.encode("utf-8")).hexdigest(),
        "outcome": outcome,
        "transport_command": command,
        "transport_started_at": "2026-07-13T18:00:30Z",
        "transport_completed_at": "2026-07-13T18:00:31Z",
        "transport_timeout_seconds": 30,
        "transport_timed_out": False,
        "transport_exit_code": (0 if outcome in {"POSTED", "RESPONSE_INVALID"} else 1),
        "transport_error_sha256": (
            "sha256:" + sha256(b"transport unavailable").hexdigest()
            if outcome == "TRANSPORT_UNAVAILABLE"
            else None
        ),
        "response_validation_error_sha256": (
            "sha256:" + sha256(b"INVALID_JSON\0{").hexdigest()
            if outcome == "RESPONSE_INVALID"
            else None
        ),
        "comment_id": 201 if outcome == "POSTED" else None,
        "comment_created_at": ("2026-07-13T18:01:00Z" if outcome == "POSTED" else None),
    }
    values.update(changes)
    return TrustedWorkflowRequestReceipt(**values)  # type: ignore[arg-type]


def evaluate(value: dict) -> dict:
    raw = raw_bytes(value)
    resolved = None if value.get("issue_reactions") else HEAD_SHA
    return evaluate_codex_connector_evidence(
        raw,
        trusted(raw, resolved_clean_commit_sha=resolved),
    )


def evaluate_with_workflow_request(
    value: dict, receipt: TrustedWorkflowRequestReceipt
) -> dict:
    raw = raw_bytes(value)
    resolved = None if value.get("issue_reactions") else HEAD_SHA
    return evaluate_codex_connector_evidence(
        raw,
        trusted(
            raw,
            resolved_clean_commit_sha=resolved,
            workflow_request_receipt=receipt,
        ),
    )


class CodexConnectorEvidenceTests(unittest.TestCase):
    def test_connector_failure_with_unrecognized_body_is_nonblocking_at_owner_gate(
        self,
    ) -> None:
        value = snapshot()
        value["issue_comments"].insert(
            0,
            comment(
                "You have reached your Codex usage limits for code reviews.",
                comment_id=201,
                created_at="2026-07-13T18:02:00Z",
            ),
        )
        raw = raw_bytes(value)
        context = trusted(raw)

        connector_result = evaluate_codex_connector_evidence(raw, context)
        owner_result = evaluate_ai_review_gate(
            HEAD_SHA,
            codex_result=connector_result,
            raw_snapshot_bytes=raw,
            trusted_context=context,
        )

        self.assertEqual(
            connector_result["reasons"],
            ["CONNECTOR_FAILURE_PRESENT", "RESPONSE_BODY_UNRECOGNIZED"],
        )
        self.assertEqual(connector_result["review_state"], "AI_REVIEW_UNAVAILABLE")
        self.assertEqual(owner_result["owner_status"], "GREEN")
        self.assertEqual(owner_result["evidence_status"], "AI_REVIEW_UNAVAILABLE")
        self.assertFalse(owner_result["approval_provided"])

    def test_connector_reaction_without_exact_head_review_blocks_technical(
        self,
    ) -> None:
        value = reaction_snapshot()

        result = evaluate(value)

        self.assertEqual(result["capability_status"], "BLOCK_TECHNICAL")
        self.assertEqual(result["review_state"], "AI_REVIEW_UNAVAILABLE")
        self.assertIsNone(result["reviewed_head_sha"])
        self.assertEqual(result["evidence_cutoff_at"], DEADLINE)
        self.assertIsNone(result["response"])
        self.assertEqual(result["adapter_id"], "codex_connector_pr_signal_v2")
        self.assertIn("NO_IN_WINDOW_RESPONSE", result["reasons"])

    def test_reaction_snapshot_pull_request_node_mismatch_blocks(self) -> None:
        value = reaction_snapshot()
        value["pull_request"]["node_id"] = "PR_replayed"

        result = evaluate(value)

        self.assertEqual(result["capability_status"], "BLOCK_TECHNICAL")
        self.assertIn("PULL_REQUEST_MISMATCH", result["reasons"])

    def test_connector_failure_around_clean_reaction_is_reconciled_unavailable(
        self,
    ) -> None:
        for created_at in (
            "2026-07-13T18:02:00Z",
            "2026-07-13T18:04:30Z",
        ):
            with self.subTest(created_at=created_at):
                value = reaction_snapshot()
                value["issue_comments"] = [
                    comment(
                        "Codex couldn't complete this request. Try again later.",
                        created_at=created_at,
                    )
                ]

                result = evaluate(value)

                self.assertEqual(result["capability_status"], "BLOCK_TECHNICAL")
                self.assertEqual(result["review_state"], "AI_REVIEW_UNAVAILABLE")
                self.assertIsNone(result["reviewed_head_sha"])
                self.assertIn("CONNECTOR_FAILURE_PRESENT", result["reasons"])

    def test_valid_post_cutoff_missing_response_is_nonblocking_unavailable(
        self,
    ) -> None:
        value = snapshot()
        value["issue_comments"] = []

        result = evaluate(value)

        self.assertEqual(result["capability_status"], "BLOCK_TECHNICAL")
        self.assertEqual(result["review_state"], "AI_REVIEW_UNAVAILABLE")
        self.assertEqual(result["reconciled_head_sha"], HEAD_SHA)
        self.assertIsNone(result["reviewed_head_sha"])
        self.assertIn("NO_IN_WINDOW_RESPONSE", result["reasons"])

    def test_multiple_connector_reactions_are_ambiguous(self) -> None:
        value = reaction_snapshot()
        value["issue_reactions"] = [
            connector_reaction(),
            connector_reaction(
                reaction_id=407803694,
                node_id="REA_lAHOTFWU5M8AAAABIsCXZM4YTpcy",
            ),
        ]

        result = evaluate(value)

        self.assertEqual(result["capability_status"], "BLOCK_TECHNICAL")
        self.assertIn("CONNECTOR_REACTION_AMBIGUOUS", result["reasons"])

    def test_connector_reaction_identity_lookalike_blocks_explicitly(self) -> None:
        value = reaction_snapshot()
        lookalike = deepcopy(CONNECTOR_REACTION_USER)
        lookalike["id"] = 1
        value["issue_reactions"] = [connector_reaction(user=lookalike)]

        result = evaluate(value)

        self.assertEqual(result["capability_status"], "BLOCK_TECHNICAL")
        self.assertIn("CONNECTOR_IDENTITY_MISMATCH", result["reasons"])

    def test_reaction_snapshot_rejects_event_after_capture(self) -> None:
        value = reaction_snapshot()
        value["pull_request_events"] = [
            {
                "id": 1,
                "node_id": "EV_future",
                "event": "review_requested",
                "created_at": "2026-07-13T18:05:01Z",
            }
        ]

        result = evaluate(value)

        self.assertEqual(result["capability_status"], "BLOCK_TECHNICAL")
        self.assertIn("SNAPSHOT_ITEM_AFTER_CAPTURE", result["reasons"])

    def test_reaction_snapshot_rejects_duplicate_reaction_node_ids(self) -> None:
        value = reaction_snapshot()
        owner = {
            "login": "markheck-solutions",
            "id": 12345,
            "node_id": "U_owner",
            "type": "User",
        }
        value["issue_reactions"].extend(
            [
                connector_reaction(
                    reaction_id=10,
                    node_id="REA_duplicate",
                    user=owner,
                ),
                connector_reaction(
                    reaction_id=11,
                    node_id="REA_duplicate",
                    user=owner,
                ),
            ]
        )

        result = evaluate(value)

        self.assertEqual(result["capability_status"], "BLOCK_TECHNICAL")
        self.assertIn("DUPLICATE_RESPONSE_NODE_ID", result["reasons"])

    def test_pagination_receipt_and_collector_mutations_block(self) -> None:
        mutations = (
            lambda value: value["collection_receipts"]["issue_reactions"].update(
                item_count=99
            ),
            lambda value: value["collection_receipts"]["issue_reactions"]["pages"][
                0
            ].update(page_sha256="0" * 64),
            lambda value: value["collection_receipts"]["issue_reactions"]["pages"][
                0
            ].update(
                terminal=False,
                next_url=(
                    f"https://api.github.com/repos/{REPOSITORY}/issues/"
                    f"{PR_NUMBER}/reactions?per_page=100&page=2"
                ),
            ),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                value = reaction_snapshot()
                _refresh_collection_receipts(value)
                mutate(value)
                raw = raw_bytes(value, refresh_receipts=False)
                result = evaluate_codex_connector_evidence(
                    raw,
                    trusted(raw, resolved_clean_commit_sha=None),
                )
                self.assertEqual(result["capability_status"], "BLOCK_TECHNICAL")
                self.assertIn("COLLECTION_RECEIPT_INVALID", result["reasons"])

        wrong_collector = reaction_snapshot()
        _refresh_collection_receipts(wrong_collector)
        wrong_collector["collector"]["governance_evaluator_sha"] = "c" * 40
        raw = raw_bytes(wrong_collector, refresh_receipts=False)
        result = evaluate_codex_connector_evidence(
            raw,
            trusted(raw, resolved_clean_commit_sha=None),
        )
        self.assertEqual(result["capability_status"], "BLOCK_TECHNICAL")
        self.assertIn("COLLECTOR_IDENTITY_MISMATCH", result["reasons"])

    def test_reaction_window_timing_and_finalization_controls(self) -> None:
        at_deadline = reaction_snapshot()
        at_deadline["issue_reactions"][0]["created_at"] = DEADLINE
        self.assertEqual(evaluate(at_deadline)["capability_status"], "BLOCK_TECHNICAL")

        unavailable_cases = []
        for created_at in (ANCHOR, "2026-07-13T17:59:59Z"):
            value = reaction_snapshot()
            value["issue_reactions"][0]["created_at"] = created_at
            unavailable_cases.append(
                ("not_after_start", value, "NO_IN_WINDOW_RESPONSE")
            )
        late = reaction_snapshot()
        late["issue_reactions"][0]["created_at"] = "2026-07-13T18:05:01Z"
        late["captured_at"] = "2026-07-13T18:05:02Z"
        unavailable_cases.append(("after_deadline", late, "NO_IN_WINDOW_RESPONSE"))
        for name, value, reason in unavailable_cases:
            with self.subTest(name=name):
                result = evaluate(value)
                self.assertEqual(result["capability_status"], "BLOCK_TECHNICAL")
                self.assertEqual(result["review_state"], "AI_REVIEW_UNAVAILABLE")
                self.assertIn(reason, result["reasons"])

        early_capture = reaction_snapshot()
        early_capture["captured_at"] = "2026-07-13T18:04:59Z"
        result = evaluate(early_capture)
        self.assertEqual(result["capability_status"], "BLOCK_TECHNICAL")
        self.assertEqual(result["review_state"], "INVALID_EVIDENCE")
        self.assertIn("EVIDENCE_CUTOFF_BEFORE_DEADLINE", result["reasons"])

        missing_events = reaction_snapshot()
        _refresh_collection_receipts(missing_events)
        del missing_events["pull_request_events"]
        raw = raw_bytes(missing_events, refresh_receipts=False)
        result = evaluate_codex_connector_evidence(
            raw,
            trusted(raw, resolved_clean_commit_sha=None),
        )
        self.assertEqual(result["capability_status"], "BLOCK_TECHNICAL")
        self.assertIn("SNAPSHOT_SCHEMA_INVALID", result["reasons"])

    def test_reaction_route_never_authorizes_lifecycle_events(self) -> None:
        disqualifying = (
            "closed",
            "reopened",
            "merged",
            "head_ref_force_pushed",
            "head_ref_deleted",
            "head_ref_restored",
            "base_ref_changed",
            "base_ref_force_pushed",
            "converted_to_draft",
            "ready_for_review",
        )
        for index, event in enumerate(disqualifying):
            with self.subTest(event=event):
                value = reaction_snapshot()
                value["pull_request_events"] = [
                    pull_request_event(event, event_id=500 + index)
                ]
                result = evaluate(value)
                self.assertEqual(result["capability_status"], "BLOCK_TECHNICAL")
                self.assertEqual(result["review_state"], "AI_REVIEW_UNAVAILABLE")
                self.assertIsNone(result["reviewed_head_sha"])

        wrong_head = reaction_snapshot()
        wrong_head["pull_request"]["head_sha"] = "c" * 40
        self.assertIn("PULL_REQUEST_MISMATCH", evaluate(wrong_head)["reasons"])

        reopened_window = reaction_snapshot()
        reopened_window["pull_request"]["created_at"] = "2026-07-13T17:00:00Z"
        result = evaluate(reopened_window)
        self.assertEqual(result["capability_status"], "BLOCK_TECHNICAL")
        self.assertIn("PULL_REQUEST_MISMATCH", result["reasons"])

    def test_reaction_signal_spoof_noise_and_content_controls(self) -> None:
        owner = {
            "login": "markheck-solutions",
            "id": 12345,
            "node_id": "U_owner",
            "type": "User",
        }
        copilot = {
            "login": "copilot-pull-request-reviewer[bot]",
            "id": 175728472,
            "node_id": "BOT_kgDOCnlnWA",
            "type": "Bot",
        }
        noise = reaction_snapshot()
        noise["issue_reactions"].extend(
            [
                connector_reaction(
                    reaction_id=10,
                    node_id="REA_owner",
                    user=owner,
                ),
                connector_reaction(
                    reaction_id=11,
                    node_id="REA_copilot",
                    content="eyes",
                    user=copilot,
                ),
            ]
        )
        self.assertEqual(evaluate(noise)["capability_status"], "BLOCK_TECHNICAL")

        eyes = reaction_snapshot()
        eyes["issue_reactions"] = [connector_reaction(content="eyes")]
        result = evaluate(eyes)
        self.assertEqual(result["capability_status"], "BLOCK_TECHNICAL")
        self.assertEqual(result["review_state"], "AI_REVIEW_UNAVAILABLE")
        self.assertEqual(result["reasons"], ["NO_IN_WINDOW_RESPONSE"])

        for content in ("rocket", "-1"):
            with self.subTest(content=content):
                value = reaction_snapshot()
                value["issue_reactions"] = [connector_reaction(content=content)]
                result = evaluate(value)
                self.assertEqual(result["capability_status"], "BLOCK_TECHNICAL")
                self.assertIn("CONNECTOR_REACTION_UNRECOGNIZED", result["reasons"])

        manual = reaction_snapshot()
        manual["issue_comments"] = [human_comment("@codex review")]
        result = evaluate(manual)
        self.assertEqual(result["capability_status"], "BLOCK_TECHNICAL")
        self.assertEqual(result["review_state"], "AI_REVIEW_UNAVAILABLE")
        self.assertIn("MANUAL_REVIEW_REQUEST_PRESENT", result["reasons"])

        historical = reaction_snapshot()
        historical["issue_comments"] = [
            human_comment("@codex review", created_at="2026-07-13T17:59:59Z")
        ]
        result = evaluate(historical)
        self.assertEqual(result["review_state"], "AI_REVIEW_UNAVAILABLE")
        self.assertEqual(result["reasons"], ["NO_IN_WINDOW_RESPONSE"])

        for created_at, expected_manual in ((ANCHOR, True), (DEADLINE, True)):
            with self.subTest(created_at=created_at):
                boundary = reaction_snapshot()
                boundary["issue_comments"] = [
                    human_comment("@codex review", created_at=created_at)
                ]
                result = evaluate(boundary)
                self.assertEqual(
                    "MANUAL_REVIEW_REQUEST_PRESENT" in result["reasons"],
                    expected_manual,
                )


class CodexConnectorReviewReconciliationTests(unittest.TestCase):
    def test_manual_request_never_authorizes_clean_or_suppresses_blocking(self) -> None:
        for created_at in (ANCHOR, "2026-07-13T18:01:00Z"):
            with self.subTest(created_at=created_at):
                clean = snapshot()
                clean["issue_comments"].append(
                    human_comment("@codex review", created_at=created_at)
                )
                result = evaluate(clean)
                self.assertEqual(result["review_state"], "AI_REVIEW_UNAVAILABLE")
                self.assertIsNone(result["reviewed_head_sha"])
                self.assertIsNone(result["response"])

        for severity in ("P0", "P1", "P2"):
            with self.subTest(severity=severity):
                blocking = snapshot()
                blocking["issue_comments"].append(human_comment("@codex review"))
                blocking["issue_comments"][0]["body"] = (
                    f"{severity}: unsafe exact-head evidence\n\n"
                    f"**Reviewed commit:** `{HEAD_SHA[:10]}`"
                )
                result = evaluate(blocking)
                self.assertEqual(result["review_state"], "BLOCKING_FINDINGS_PRESENT")
                self.assertIn("MANUAL_REVIEW_REQUEST_PRESENT", result["reasons"])
                self.assertIn("BLOCKING_FINDINGS_PRESENT", result["reasons"])

    def test_prior_activity_preserves_manual_taint_and_exact_head_findings(
        self,
    ) -> None:
        pull_request_created_at = "2026-07-13T17:00:00Z"

        manual = snapshot()
        manual["pull_request"]["created_at"] = pull_request_created_at
        manual["issue_comments"].append(
            human_comment("@codex review", created_at="2026-07-13T17:59:59Z")
        )
        raw = raw_bytes(manual)
        result = evaluate_codex_connector_evidence(
            raw,
            trusted(
                raw,
                pull_request_created_at=pull_request_created_at,
            ),
        )
        self.assertEqual(result["review_state"], "AI_REVIEW_UNAVAILABLE")
        self.assertIn("MANUAL_REVIEW_REQUEST_PRESENT", result["reasons"])

        finding = snapshot()
        finding["pull_request"]["created_at"] = pull_request_created_at
        review = connector_review()
        review["submitted_at"] = "2026-07-13T17:45:00Z"
        inline = connector_review_comment(severity="P2")
        inline["created_at"] = "2026-07-13T17:45:00Z"
        finding["pull_request_reviews"] = [review]
        finding["review_comments"] = [inline]
        raw = raw_bytes(finding)
        result = evaluate_codex_connector_evidence(
            raw,
            trusted(
                raw,
                pull_request_created_at=pull_request_created_at,
            ),
        )
        self.assertEqual(result["review_state"], "BLOCKING_FINDINGS_PRESENT")
        self.assertIn("BLOCKING_FINDINGS_PRESENT", result["reasons"])

        for severity in ("P0", "P1", "P2"):
            with self.subTest(severity=severity):
                issue_finding = snapshot()
                issue_finding["pull_request"]["created_at"] = pull_request_created_at
                issue_finding["issue_comments"].insert(
                    0,
                    comment(
                        f"{severity}: persistent same-head finding",
                        comment_id=199,
                        created_at="2026-07-13T17:45:00Z",
                    ),
                )
                raw = raw_bytes(issue_finding)
                result = evaluate_codex_connector_evidence(
                    raw,
                    trusted(
                        raw,
                        pull_request_created_at=pull_request_created_at,
                    ),
                )
                self.assertEqual(result["review_state"], "AI_REVIEW_UNAVAILABLE")
                self.assertIn("HEAD_ATTRIBUTION_AMBIGUOUS", result["reasons"])
                self.assertNotIn("BLOCKING_FINDINGS_PRESENT", result["reasons"])

    def test_prior_exact_head_finding_blocks_without_current_window_response(
        self,
    ) -> None:
        pull_request_created_at = "2026-07-13T17:00:00Z"
        value = reaction_snapshot()
        value["pull_request"]["created_at"] = pull_request_created_at
        review = connector_review()
        review["submitted_at"] = "2026-07-13T17:45:00Z"
        inline = connector_review_comment(severity="P2")
        inline["created_at"] = "2026-07-13T17:45:00Z"
        value["pull_request_reviews"] = [review]
        value["review_comments"] = [inline]

        raw = raw_bytes(value)
        result = evaluate_codex_connector_evidence(
            raw,
            trusted(
                raw,
                pull_request_created_at=pull_request_created_at,
                resolved_clean_commit_sha=None,
            ),
        )

        self.assertEqual(result["review_state"], "BLOCKING_FINDINGS_PRESENT")
        self.assertEqual(result["reviewed_head_sha"], HEAD_SHA)
        self.assertIsNone(result["response"])
        self.assertIn("BLOCKING_FINDINGS_PRESENT", result["reasons"])
        self.assertIn("NO_IN_WINDOW_RESPONSE", result["reasons"])

        value["issue_comments"] = [
            comment(
                "You have reached your Codex usage limits for code reviews.",
                created_at="2026-07-13T18:01:00Z",
            )
        ]
        raw = raw_bytes(value)
        result = evaluate_codex_connector_evidence(
            raw,
            trusted(
                raw,
                pull_request_created_at=pull_request_created_at,
                resolved_clean_commit_sha=None,
            ),
        )

        self.assertEqual(result["review_state"], "BLOCKING_FINDINGS_PRESENT")
        self.assertEqual(result["reviewed_head_sha"], HEAD_SHA)
        self.assertIn("BLOCKING_FINDINGS_PRESENT", result["reasons"])
        self.assertIn("CONNECTOR_FAILURE_PRESENT", result["reasons"])
        self.assertIn("RESPONSE_BODY_UNRECOGNIZED", result["reasons"])

    def test_exact_head_blocker_precedence_is_exhaustive_and_fail_closed(
        self,
    ) -> None:
        compatible_reasons = (
            "HEAD_ATTRIBUTION_AMBIGUOUS",
            "MANUAL_REVIEW_REQUEST_PRESENT",
            "NO_IN_WINDOW_RESPONSE",
            "ONLY_LATE_RESPONSE",
            "RESPONSE_BODY_UNRECOGNIZED",
            "CONNECTOR_FAILURE_PRESENT",
            "CONNECTOR_IDENTITY_MISMATCH",
            "CONNECTOR_REACTION_AMBIGUOUS",
            "CONNECTOR_REACTION_UNRECOGNIZED",
            "ORPHANED_REVIEW_COMMENT",
            "COMMIT_RESOLUTION_MISMATCH",
            "REVIEWED_COMMIT_NOT_HEAD",
        )
        source_or_binding_failures = (
            "SNAPSHOT_BYTES_INVALID",
            "SNAPSHOT_JSON_INVALID",
            "SNAPSHOT_BYTES_NONCANONICAL",
            "SNAPSHOT_FILE_DIGEST_MISMATCH",
            "SNAPSHOT_SCHEMA_INVALID",
            "REPOSITORY_MISMATCH",
            "PULL_REQUEST_MISMATCH",
            "PULL_REQUEST_NOT_REVIEWABLE",
            "COLLECTION_INCOMPLETE",
            "COLLECTOR_IDENTITY_MISMATCH",
            "COLLECTION_RECEIPT_INVALID",
            "SNAPSHOT_COMMIT_IDENTITY_INVALID",
            "SNAPSHOT_LIMIT_EXCEEDED",
            "DUPLICATE_RESPONSE_ID",
            "DUPLICATE_RESPONSE_NODE_ID",
            "SNAPSHOT_TIMESTAMP_INVALID",
            "EVIDENCE_CUTOFF_BEFORE_DEADLINE",
            "SNAPSHOT_ITEM_AFTER_CAPTURE",
        )

        for reason in compatible_reasons:
            with self.subTest(compatible_reason=reason):
                self.assertEqual(
                    _classify_review_state(
                        ["BLOCKING_FINDINGS_PRESENT", reason],
                        HEAD_SHA,
                        None,
                        HEAD_SHA,
                    ),
                    "BLOCKING_FINDINGS_PRESENT",
                )
        for reason in source_or_binding_failures:
            with self.subTest(source_or_binding_failure=reason):
                self.assertEqual(
                    _classify_review_state(
                        ["BLOCKING_FINDINGS_PRESENT", reason],
                        HEAD_SHA,
                        None,
                        HEAD_SHA,
                    ),
                    "INVALID_EVIDENCE",
                )

    def test_unattributed_prior_activity_is_unavailable_not_blocking(self) -> None:
        value = snapshot()
        value["pull_request"]["created_at"] = "2026-07-13T17:00:00Z"
        value["issue_comments"].append(
            human_comment("@codex review", created_at="2026-07-13T17:29:59Z")
        )
        value["issue_comments"].insert(
            0,
            comment(
                "P1: prior-head issue finding",
                comment_id=199,
                created_at="2026-07-13T17:29:59Z",
            ),
        )
        raw = raw_bytes(value)

        result = evaluate_codex_connector_evidence(
            raw,
            trusted(
                raw,
                pull_request_created_at="2026-07-13T17:00:00Z",
            ),
        )

        self.assertEqual(result["review_state"], "AI_REVIEW_UNAVAILABLE")
        self.assertIn("MANUAL_REVIEW_REQUEST_PRESENT", result["reasons"])
        self.assertIn("HEAD_ATTRIBUTION_AMBIGUOUS", result["reasons"])
        self.assertNotIn("BLOCKING_FINDINGS_PRESENT", result["reasons"])

    def test_human_claimed_sha_cannot_exempt_manual_request(self) -> None:
        value = snapshot()
        value["issue_comments"].append(
            human_comment(
                "@codex review\n\nGovernance review request for exact head "
                f"`{'c' * 40}`."
            )
        )

        result = evaluate(value)

        self.assertEqual(result["review_state"], "AI_REVIEW_UNAVAILABLE")
        self.assertIn("MANUAL_REVIEW_REQUEST_PRESENT", result["reasons"])

    def test_unbound_start_boundary_never_blocks_or_authorizes_clean(self) -> None:
        for body in (
            "P2: finding with ambiguous head attribution",
            "Codex couldn't complete this request. Try again later.",
        ):
            with self.subTest(body=body):
                value = snapshot()
                value["issue_comments"].insert(
                    0,
                    comment(body, comment_id=199, created_at=ANCHOR),
                )

                result = evaluate(value)

                self.assertEqual(result["review_state"], "AI_REVIEW_UNAVAILABLE")
                self.assertIn("HEAD_ATTRIBUTION_AMBIGUOUS", result["reasons"])
                self.assertNotIn("BLOCKING_FINDINGS_PRESENT", result["reasons"])
                self.assertIsNone(result["response"])

        lifecycle_boundary = snapshot()
        lifecycle_boundary["pull_request"]["created_at"] = "2026-07-13T17:00:00Z"
        lifecycle_boundary["issue_comments"].insert(
            0,
            comment(
                "P1: lifecycle-boundary finding",
                comment_id=199,
                created_at="2026-07-13T17:30:00Z",
            ),
        )
        raw = raw_bytes(lifecycle_boundary)
        result = evaluate_codex_connector_evidence(
            raw,
            trusted(
                raw,
                pull_request_created_at="2026-07-13T17:00:00Z",
            ),
        )
        self.assertEqual(result["review_state"], "AI_REVIEW_UNAVAILABLE")
        self.assertIn("HEAD_ATTRIBUTION_AMBIGUOUS", result["reasons"])
        self.assertNotIn("BLOCKING_FINDINGS_PRESENT", result["reasons"])

    def test_manual_taint_reconciles_unrecognized_review_as_unavailable(self) -> None:
        value = reaction_snapshot()
        value["issue_comments"] = [human_comment("@codex review")]
        value["pull_request_reviews"] = [connector_review()]

        result = evaluate(value)

        self.assertEqual(result["review_state"], "AI_REVIEW_UNAVAILABLE")
        self.assertEqual(
            result["reasons"],
            ["MANUAL_REVIEW_REQUEST_PRESENT", "RESPONSE_BODY_UNRECOGNIZED"],
        )

    def test_canonical_exact_head_review_can_be_clean(self) -> None:
        value = reaction_snapshot()
        review = connector_review()
        review["body"] = codex_review_body()
        value["pull_request_reviews"] = [review]

        result = evaluate(value)

        self.assertEqual(result["review_state"], "CLEAN")
        self.assertEqual(result["capability_status"], "PASS")
        self.assertEqual(result["reviewed_head_sha"], HEAD_SHA)
        self.assertEqual(result["response"]["response_type"], "pull_request_review")

        wrong_prefix = deepcopy(value)
        wrong_prefix["pull_request_reviews"][0]["body"] = codex_review_body("c" * 10)
        result = evaluate(wrong_prefix)
        self.assertEqual(result["review_state"], "INVALID_EVIDENCE")

    def test_stale_review_cannot_override_current_head_clean_response(self) -> None:
        value = snapshot()
        stale = connector_review(commit_id="c" * 40)
        stale["submitted_at"] = "2026-07-13T18:02:00Z"
        stale["body"] = codex_review_body("c" * 10)
        value["pull_request_reviews"] = [stale]

        result = evaluate(value)

        self.assertEqual(result["review_state"], "CLEAN")
        self.assertEqual(result["capability_status"], "PASS")
        self.assertEqual(result["response"]["response_type"], "issue_comment")
        self.assertEqual(result["reviewed_head_sha"], HEAD_SHA)

    def test_actions_request_requires_exact_first_attempt_receipt(self) -> None:
        request = comment(
            f"@codex review\n\nGovernance review request for exact head `{HEAD_SHA}`.",
            comment_id=201,
            user={
                "login": "github-actions[bot]",
                "id": 41898282,
                "node_id": "MDM6Qm90NDE4OTgyODI=",
                "type": "Bot",
            },
            app={
                "id": 15368,
                "node_id": "MDM6QXBwMTUzNjg=",
                "slug": "github-actions",
            },
        )
        request_only = reaction_snapshot()
        request_only["issue_comments"] = [request]

        result = evaluate(request_only)

        self.assertEqual(result["capability_status"], "BLOCK_TECHNICAL")
        self.assertEqual(result["review_state"], "AI_REVIEW_UNAVAILABLE")
        self.assertEqual(
            result["reasons"],
            ["MANUAL_REVIEW_REQUEST_PRESENT", "NO_IN_WINDOW_RESPONSE"],
        )
        self.assertIsNone(result["response"])
        self.assertEqual(
            result["workflow_request_receipt"]["outcome"],
            "TRANSPORT_UNAVAILABLE",
        )

        clean = snapshot()
        clean["issue_comments"].append(deepcopy(request))
        result = evaluate(clean)
        self.assertEqual(result["review_state"], "AI_REVIEW_UNAVAILABLE")
        self.assertIn("MANUAL_REVIEW_REQUEST_PRESENT", result["reasons"])

        receipt = workflow_request_receipt()
        result = evaluate_with_workflow_request(request_only, receipt)
        self.assertEqual(result["review_state"], "AI_REVIEW_UNAVAILABLE")
        self.assertEqual(result["reasons"], ["NO_IN_WINDOW_RESPONSE"])
        self.assertEqual(
            result["workflow_request_receipt"]["comment_id"],
            request["id"],
        )

        result = evaluate_with_workflow_request(clean, receipt)
        self.assertEqual(result["review_state"], "CLEAN")
        self.assertEqual(result["capability_status"], "PASS")

        unavailable_snapshot = reaction_snapshot()
        unavailable_snapshot["issue_comments"] = []
        unavailable_receipt = workflow_request_receipt("TRANSPORT_UNAVAILABLE")
        result = evaluate_with_workflow_request(
            unavailable_snapshot, unavailable_receipt
        )
        self.assertEqual(result["review_state"], "AI_REVIEW_UNAVAILABLE")
        self.assertEqual(result["reasons"], ["NO_IN_WINDOW_RESPONSE"])
        self.assertEqual(
            result["workflow_request_receipt"]["outcome"],
            "TRANSPORT_UNAVAILABLE",
        )
        timeout_receipt = workflow_request_receipt(
            "TRANSPORT_UNAVAILABLE",
            transport_exit_code=124,
            transport_timed_out=True,
        )
        result = evaluate_with_workflow_request(unavailable_snapshot, timeout_receipt)
        self.assertEqual(result["review_state"], "AI_REVIEW_UNAVAILABLE")
        self.assertTrue(result["workflow_request_receipt"]["transport_timed_out"])
        child_exit_124_receipt = workflow_request_receipt(
            "TRANSPORT_UNAVAILABLE",
            transport_exit_code=124,
            transport_timed_out=False,
        )
        result = evaluate_with_workflow_request(
            unavailable_snapshot, child_exit_124_receipt
        )
        self.assertEqual(result["review_state"], "AI_REVIEW_UNAVAILABLE")
        self.assertFalse(result["workflow_request_receipt"]["transport_timed_out"])
        old_head = deepcopy(request_only)
        old_head["issue_comments"][0]["body"] = (
            f"@codex review\n\nGovernance review request for exact head `{'c' * 40}`."
        )
        result = evaluate(old_head)
        self.assertIn("MANUAL_REVIEW_REQUEST_PRESENT", result["reasons"])

        for container, field, replacement in (
            ("user", "login", "github-actions-lookalike[bot]"),
            ("user", "id", 1),
            ("user", "node_id", "BOT_lookalike"),
            ("user", "type", "User"),
            ("performed_via_github_app", "id", 1),
            ("performed_via_github_app", "node_id", "APP_lookalike"),
            ("performed_via_github_app", "slug", "github-actions-lookalike"),
        ):
            with self.subTest(container=container, field=field):
                spoofed = deepcopy(request_only)
                spoofed["issue_comments"][0][container][field] = replacement
                result = evaluate(spoofed)
                self.assertIn("MANUAL_REVIEW_REQUEST_PRESENT", result["reasons"])

        owner_copy = deepcopy(request_only)
        owner_copy["issue_comments"] = [human_comment(request["body"])]
        result = evaluate(owner_copy)
        self.assertIn("MANUAL_REVIEW_REQUEST_PRESENT", result["reasons"])

        duplicate = deepcopy(clean)
        duplicate["issue_comments"].append(
            {**deepcopy(request), "id": request["id"] + 1}
        )
        result = evaluate_with_workflow_request(duplicate, receipt)
        self.assertEqual(result["review_state"], "AI_REVIEW_UNAVAILABLE")
        self.assertIn("MANUAL_REVIEW_REQUEST_PRESENT", result["reasons"])

        mismatched_comment = workflow_request_receipt(comment_id=999)
        result = evaluate_with_workflow_request(clean, mismatched_comment)
        self.assertEqual(result["review_state"], "INVALID_EVIDENCE")
        self.assertIn("WORKFLOW_REQUEST_RECEIPT_MISMATCH", result["reasons"])

        late = deepcopy(request_only)
        late["issue_comments"][0]["created_at"] = "2026-07-13T18:05:01Z"
        late["captured_at"] = "2026-07-13T18:05:02Z"
        late_receipt = workflow_request_receipt(
            comment_created_at="2026-07-13T18:05:01Z"
        )
        result = evaluate_with_workflow_request(late, late_receipt)
        self.assertEqual(result["review_state"], "AI_REVIEW_UNAVAILABLE")
        self.assertEqual(
            result["reasons"],
            [
                "NO_IN_WINDOW_RESPONSE",
                "WORKFLOW_REQUEST_POSTED_AFTER_DEADLINE",
            ],
        )

        late_failure = deepcopy(late)
        late_failure["issue_comments"].append(
            comment(
                "You have reached your Codex usage limits for code reviews.",
                comment_id=202,
                created_at="2026-07-13T18:02:00Z",
            )
        )
        raw = raw_bytes(late_failure)
        context = trusted(raw, workflow_request_receipt=late_receipt)
        result = evaluate_codex_connector_evidence(raw, context)
        owner = evaluate_ai_review_gate(
            HEAD_SHA,
            codex_result=result,
            raw_snapshot_bytes=raw,
            trusted_context=context,
        )
        self.assertEqual(result["review_state"], "AI_REVIEW_UNAVAILABLE")
        self.assertEqual(owner["owner_status"], "GREEN")
        self.assertIn("CONNECTOR_FAILURE_PRESENT", result["reasons"])
        self.assertIn("WORKFLOW_REQUEST_POSTED_AFTER_DEADLINE", result["reasons"])

        blocking_late = deepcopy(late)
        blocking_late["pull_request_reviews"] = [connector_review()]
        blocking_late["review_comments"] = [connector_review_comment(severity="P1")]
        result = evaluate_with_workflow_request(blocking_late, late_receipt)
        self.assertEqual(result["review_state"], "BLOCKING_FINDINGS_PRESENT")
        self.assertIn("WORKFLOW_REQUEST_POSTED_AFTER_DEADLINE", result["reasons"])

        result = evaluate_with_workflow_request(
            late,
            workflow_request_receipt(
                comment_id=999,
                comment_created_at="2026-07-13T18:05:01Z",
            ),
        )
        self.assertEqual(result["review_state"], "INVALID_EVIDENCE")
        self.assertIn("WORKFLOW_REQUEST_RECEIPT_MISMATCH", result["reasons"])

    def test_workflow_request_receipt_rejects_rerun_and_identity_evasions(
        self,
    ) -> None:
        invalid_receipts = (
            {"workflow_ref": WORKFLOW_REF.replace("supportability", "lookalike")},
            {"workflow_sha": "not-a-sha"},
            {"event_name": "workflow_dispatch"},
            {"event_action": "edited"},
            {"run_id": 0},
            {"run_attempt": 2},
            {"run_attempt": True},
            {"job_id": "other-job"},
            {"request_endpoint": "repos/other/repo/issues/31/comments"},
            {"request_body_sha256": "sha256:" + "0" * 64},
            {"outcome": "UNKNOWN"},
            {"transport_command": ["gh", "api"]},
            {"transport_started_at": "not-a-time"},
            {"transport_completed_at": "2026-07-13T18:00:29Z"},
            {"transport_timeout_seconds": 31},
            {"transport_timeout_seconds": True},
            {"transport_timed_out": "false"},
            {"transport_timed_out": True},
            {"transport_exit_code": None},
            {"transport_exit_code": 1},
            {"response_validation_error_sha256": "sha256:" + "0" * 64},
            {"comment_id": 0},
            {"comment_created_at": "not-a-time"},
        )
        for changes in invalid_receipts:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                workflow_request_receipt(**changes)

        with self.assertRaises(ValueError):
            workflow_request_receipt(
                "TRANSPORT_UNAVAILABLE",
                comment_id=201,
            )
        with self.assertRaises(ValueError):
            workflow_request_receipt(
                "TRANSPORT_UNAVAILABLE",
                transport_exit_code=1,
                transport_timed_out=True,
            )
        for changes in (
            {"response_validation_error_sha256": None},
            {"transport_exit_code": None},
            {"transport_exit_code": 1},
            {"comment_id": 201},
        ):
            with self.subTest(response_invalid=changes), self.assertRaises(ValueError):
                workflow_request_receipt("RESPONSE_INVALID", **changes)

        raw = raw_bytes(snapshot())
        context_mismatches = (
            {"repository_id": REPOSITORY_ID + 1},
            {"pull_request_number": PR_NUMBER + 1},
            {"head_sha": "c" * 40},
            {"review_window_started_at": "2026-07-13T18:00:01Z"},
            {"comment_created_at": "2026-07-13T17:59:59Z"},
        )
        for changes in context_mismatches:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                trusted(
                    raw,
                    workflow_request_receipt=workflow_request_receipt(**changes),
                )

    def test_p0_p1_p2_findings_block_reaction_before_or_after_signal(self) -> None:
        for severity in ("P0", "P1", "P2"):
            for submitted_at in (
                ANCHOR,
                "2026-07-13T18:02:00Z",
                "2026-07-13T18:04:30Z",
            ):
                with self.subTest(severity=severity, submitted_at=submitted_at):
                    value = reaction_snapshot()
                    review = connector_review()
                    review["submitted_at"] = submitted_at
                    value["pull_request_reviews"] = [review]
                    value["review_comments"] = [
                        connector_review_comment(severity=severity)
                    ]

                    result = evaluate(value)

                    self.assertEqual(result["capability_status"], "BLOCK_TECHNICAL")
                    self.assertIn("BLOCKING_FINDINGS_PRESENT", result["reasons"])

                    issue_comment = reaction_snapshot()
                    issue_comment["issue_comments"] = [
                        comment(
                            f"{severity}: unsafe exact-head evidence\n\n"
                            f"**Reviewed commit:** `{HEAD_SHA[:10]}`",
                            created_at=submitted_at,
                        )
                    ]
                    issue_result = evaluate(issue_comment)
                    self.assertEqual(
                        issue_result["capability_status"], "BLOCK_TECHNICAL"
                    )
                    self.assertEqual(
                        issue_result["review_state"], "BLOCKING_FINDINGS_PRESENT"
                    )
                    self.assertIn("BLOCKING_FINDINGS_PRESENT", issue_result["reasons"])

    def test_stale_issue_comment_finding_cannot_poison_current_clean_head(
        self,
    ) -> None:
        value = snapshot()
        value["issue_comments"][0]["created_at"] = "2026-07-13T18:03:00Z"
        value["issue_comments"].append(
            comment(
                f"P1: stale previous-head finding\n\n**Reviewed commit:** `{'c' * 10}`",
                comment_id=201,
                created_at="2026-07-13T18:04:00Z",
            )
        )

        result = evaluate(value)

        self.assertEqual(result["review_state"], "CLEAN")
        self.assertEqual(result["capability_status"], "PASS")
        self.assertNotIn("BLOCKING_FINDINGS_PRESENT", result["reasons"])

        unbound = deepcopy(value)
        unbound["issue_comments"][1]["body"] = "P1: unbound issue finding"
        result = evaluate(unbound)
        self.assertEqual(result["review_state"], "AI_REVIEW_UNAVAILABLE")
        self.assertIn("HEAD_ATTRIBUTION_AMBIGUOUS", result["reasons"])
        self.assertNotIn("BLOCKING_FINDINGS_PRESENT", result["reasons"])

    def test_exact_head_p3_feedback_is_nonblocking_without_supplying_approval(
        self,
    ) -> None:
        for marker, finding in (
            (HEAD_SHA[:10], "P3: simplify the local helper"),
            (
                HEAD_SHA,
                "**<sub><sub>![P3 Badge](https://img.shields.io/badge/"
                "P3-yellow?style=flat)</sub></sub> Simplify the local helper",
            ),
        ):
            with self.subTest(marker=marker):
                issue_feedback = snapshot()
                issue_feedback["issue_comments"][0]["body"] = (
                    f"{finding}\n\n**Reviewed commit:** `{marker}`"
                )
                raw = raw_bytes(issue_feedback)
                context = trusted(raw)

                result = evaluate_codex_connector_evidence(raw, context)

                self.assertEqual(result["review_state"], "CLEAN")
                self.assertEqual(result["capability_status"], "PASS")
                self.assertEqual(result["reviewed_head_sha"], HEAD_SHA)
                self.assertEqual(result["reasons"], [])
                owner = evaluate_ai_review_gate(
                    HEAD_SHA,
                    codex_result=result,
                    raw_snapshot_bytes=raw,
                    trusted_context=context,
                )
                self.assertEqual(owner["owner_status"], "GREEN")
                self.assertFalse(owner["approval_provided"])

        review_feedback = snapshot()
        review = connector_review()
        review["body"] = codex_review_body()
        review_feedback["issue_comments"] = []
        review_feedback["pull_request_reviews"] = [review]
        review_feedback["review_comments"] = [connector_review_comment(severity="P3")]
        result = evaluate(review_feedback)
        self.assertEqual(result["review_state"], "CLEAN")
        self.assertEqual(result["capability_status"], "PASS")
        self.assertEqual(result["reasons"], [])

    def test_p3_issue_feedback_still_requires_exact_head_attribution(self) -> None:
        cases = {
            "unbound": "P3: simplify the local helper",
            "multiple_markers": (
                "P3: simplify the local helper\n\n"
                f"**Reviewed commit:** `{HEAD_SHA[:10]}`\n"
                f"**Reviewed commit:** `{'c' * 10}`"
            ),
        }
        for name, body in cases.items():
            with self.subTest(name=name):
                value = snapshot()
                value["issue_comments"][0]["body"] = body
                result = evaluate(value)
                self.assertEqual(result["review_state"], "INVALID_EVIDENCE")
                self.assertEqual(result["capability_status"], "BLOCK_TECHNICAL")
                self.assertIn("RESPONSE_BODY_UNRECOGNIZED", result["reasons"])

        unresolved = snapshot()
        unresolved["issue_comments"][0]["body"] = (
            f"P3: simplify the local helper\n\n**Reviewed commit:** `{HEAD_SHA[:10]}`"
        )
        raw = raw_bytes(unresolved)
        result = evaluate_codex_connector_evidence(
            raw,
            trusted(raw, resolved_clean_commit_sha=None),
        )
        self.assertEqual(result["review_state"], "INVALID_EVIDENCE")
        self.assertIn("COMMIT_RESOLUTION_MISMATCH", result["reasons"])

    def test_exact_pr35_reaction_fixture_is_unavailable_without_head_attestation(
        self,
    ) -> None:
        value = reaction_snapshot()
        value["captured_at"] = "2026-07-13T22:12:10Z"
        value["pull_request"].update(
            number=35,
            node_id="PR_kwDOTFWU5M7xSZMq",
            created_at="2026-07-13T22:07:10Z",
            base_sha="f8a37f8d81d68290bac0b4c841c060a601e5fd8a",
            head_sha="dd4068034f9a4b9b3df19883445aa5df50d6e428",
        )
        value["issue_reactions"] = [
            connector_reaction(created_at="2026-07-13T22:11:20Z")
        ]
        value["pull_request_reviews"] = [
            {
                "id": 4689135932,
                "submitted_at": "2026-07-13T22:07:16Z",
                "state": "COMMENTED",
                "commit_id": "dd4068034f9a4b9b3df19883445aa5df50d6e428",
                "body": "Copilot was unable to review this pull request because the user who requested the review has reached their quota limit.",
                "user": {
                    "login": "copilot-pull-request-reviewer[bot]",
                    "id": 175728472,
                    "node_id": "BOT_kgDOCnlnWA",
                    "type": "Bot",
                },
            }
        ]
        value["pull_request_events"] = [
            {
                "id": 27933206579,
                "node_id": "RRE_lADOTFWU5M8AAAABIsCXZM8AAAAGgPLoMw",
                "event": "review_requested",
                "created_at": "2026-07-13T22:07:10Z",
            }
        ]
        raw = raw_bytes(value)
        context = trusted(
            raw,
            pull_request_number=35,
            pull_request_node_id="PR_kwDOTFWU5M7xSZMq",
            pull_request_created_at="2026-07-13T22:07:10Z",
            base_sha="f8a37f8d81d68290bac0b4c841c060a601e5fd8a",
            head_sha="dd4068034f9a4b9b3df19883445aa5df50d6e428",
            review_window_started_at="2026-07-13T22:07:10Z",
            review_deadline_at="2026-07-13T22:12:10Z",
            resolved_clean_commit_sha=None,
        )

        result = evaluate_codex_connector_evidence(raw, context)

        self.assertEqual(result["capability_status"], "BLOCK_TECHNICAL")
        self.assertEqual(result["review_state"], "AI_REVIEW_UNAVAILABLE")
        self.assertIsNone(result["response"])
        self.assertIsNone(result["reviewed_head_sha"])

    def test_reaction_result_contains_no_fabricated_app_provenance(self) -> None:
        value = reaction_snapshot()
        raw = raw_bytes(value)
        result = evaluate_codex_connector_evidence(
            raw,
            trusted(raw, resolved_clean_commit_sha=None),
        )
        self.assertIsNone(result["response"])
        self.assertIsNone(result["reviewed_head_sha"])
        self.assertEqual(result["review_state"], "AI_REVIEW_UNAVAILABLE")

    def test_reaction_commit_resolution_cannot_create_head_attestation(self) -> None:
        value = reaction_snapshot()
        raw = raw_bytes(value)
        clean = evaluate_codex_connector_evidence(
            raw,
            trusted(raw, resolved_clean_commit_sha=None),
        )
        self.assertEqual(clean["capability_status"], "BLOCK_TECHNICAL")

        wrong = evaluate_codex_connector_evidence(
            raw,
            trusted(raw, resolved_clean_commit_sha="c" * 40),
        )
        self.assertEqual(wrong["capability_status"], "BLOCK_TECHNICAL")
        self.assertEqual(wrong["review_state"], "AI_REVIEW_UNAVAILABLE")
        self.assertIsNone(wrong["reviewed_head_sha"])


class CodexConnectorCommentEvidenceTests(unittest.TestCase):
    def test_free_form_summary_never_authorizes_clean(self) -> None:
        bodies = (
            automatic_summary_body(),
            f"""### Summary

- The pull request head `{HEAD_SHA}` equals the supplied `head_ref`.
- Deterministic evidence collection and validation completed.
- No code changes were needed, so I did **not** create a commit or open a new PR.

### Testing

- ✅ Focused positive and negative controls passed.
""",
            automatic_summary_body().replace(
                "matching the supplied `head_ref`",
                "does not match the supplied `head_ref`",
            ),
            automatic_summary_body().replace(
                "* No code changes were needed",
                "* Found a critical authentication bypass requiring remediation.\n"
                "* No code changes were needed",
            ),
        )
        for body in bodies:
            with self.subTest(body=body[:80]):
                value = snapshot()
                value["issue_comments"][0]["body"] = body
                raw = raw_bytes(value)
                context = trusted(raw)

                first = evaluate_codex_connector_evidence(raw, context)
                second = evaluate_codex_connector_evidence(raw, context)

                self.assertEqual(first, second)
                self.assertEqual(first["capability_status"], "BLOCK_TECHNICAL")
                self.assertEqual(first["review_state"], "INVALID_EVIDENCE")
                self.assertIsNone(first["reviewed_head_sha"])
                self.assertIn("RESPONSE_BODY_UNRECOGNIZED", first["reasons"])

    def test_automatic_summary_fail_closed_controls(self) -> None:
        valid = automatic_summary_body()
        mutations = {
            "missing_testing": valid.split("\n**Testing**", 1)[0],
            "no_success": valid.replace("* ✅", "* completed"),
            "failed_test": valid.replace("14 passed.", "1 failed."),
            "test_error": valid.replace("14 passed.", "1 passed, 1 error."),
            "test_failures": valid.replace("14 passed.", "1 passed, 2 failures."),
            "test_failing": valid.replace("14 passed.", "2 tests are failing."),
            "unmarked_not_run_bullet": valid.replace(
                "* ✅ `python -m pytest tests/test_codex_connector_evidence.py` — 14 passed.",
                "* ✅ `python -m pytest tests/test_codex_connector_evidence.py` — 14 passed.\n* Required integration tests were not run.",
            ),
            "plain_not_run": valid.replace(
                "* ✅ `python -m pytest tests/test_codex_connector_evidence.py` — 14 passed.",
                "* ✅ `python -m pytest tests/test_codex_connector_evidence.py` — 14 passed.\nRequired integration tests were not run.",
            ),
            "plain_error": valid.replace(
                "* ✅ `python -m pytest tests/test_codex_connector_evidence.py` — 14 passed.",
                "* ✅ `python -m pytest tests/test_codex_connector_evidence.py` — 14 passed.\nIntegration suite ended with 1 error.",
            ),
            "fake_green_not_run": valid.replace(
                "14 passed.", "✅ required integration tests were not run."
            ),
            "timed_out_hyphen": valid.replace("14 passed.", "timed-out."),
            "time_out_hyphen": valid.replace("14 passed.", "time-out."),
            "exit_code": valid.replace("14 passed.", "exited with code 1."),
            "did_not_pass": valid.replace("14 passed.", "1 test did not pass."),
            "unsuccessful": valid.replace("14 passed.", "test run was unsuccessful."),
            "cancelled": valid.replace("14 passed.", "test run was cancelled."),
            "zero_passed": valid.replace("14 passed.", "0 passed."),
            "summary_timeout": valid.replace(
                "* No code changes were needed",
                "* The review timed out.\n* No code changes were needed",
            ),
            "summary_incomplete": valid.replace(
                "* No code changes were needed",
                "* Review incomplete.\n* No code changes were needed",
            ),
            "summary_cancelled": valid.replace(
                "* No code changes were needed",
                "* This review was cancelled.\n* No code changes were needed",
            ),
            "plain_summary_timeout": valid.replace(
                "* No code changes were needed",
                "The review timed out.\n* No code changes were needed",
            ),
            "timeout": valid.replace("14 passed.", "timed out."),
            "skipped": valid.replace("14 passed.", "required proof skipped."),
            "quota": valid.replace(
                "* No code changes were needed",
                "* You have reached your Codex usage limits.\n* No code changes were needed",
            ),
            "environment": valid.replace(
                "* No code changes were needed",
                "* To use Codex here, create an environment for this repo.\n* No code changes were needed",
            ),
            "unable": valid.replace(
                "* No code changes were needed",
                "* Codex was unable to complete the review.\n* No code changes were needed",
            ),
            "review_error": valid.replace(
                "* No code changes were needed",
                "* The review failed with an error.\n* No code changes were needed",
            ),
            "unavailable": valid.replace(
                "* No code changes were needed",
                "* The review service was unavailable.\n* No code changes were needed",
            ),
            "severity": valid.replace(
                "* No code changes were needed",
                "* P1 finding remains.\n* No code changes were needed",
            ),
            "wrong_head": valid.replace(HEAD_SHA, "c" * 40),
            "uppercase_head": valid.replace(HEAD_SHA, "B" * 40),
            "short_head": valid.replace(HEAD_SHA, HEAD_SHA[:10]),
            "mixed_head": valid.replace(
                f"returned `{HEAD_SHA}`", f"returned `{'c' * 40}`", 1
            ),
            "quoted": valid.replace("### Summary", "> ### Summary", 1),
            "fenced": "```markdown\n" + valid + "\n```",
            "linked_only": valid.replace(
                f"`{HEAD_SHA}`", f"[{HEAD_SHA}](https://example.invalid)", 1
            ),
            "competing": valid.replace(
                "* Confirmed the evaluator",
                f"* The PR head `{HEAD_SHA}` also matches `head_ref`.\n* Confirmed the evaluator",
            ),
        }
        for name, body in mutations.items():
            with self.subTest(name=name):
                value = snapshot()
                value["issue_comments"][0]["body"] = body
                result = evaluate(value)
                if name in {
                    "quota",
                    "environment",
                    "unable",
                    "review_error",
                    "unavailable",
                }:
                    self.assertEqual(result["capability_status"], "BLOCK_TECHNICAL")
                    self.assertEqual(result["review_state"], "AI_REVIEW_UNAVAILABLE")
                else:
                    self.assertEqual(result["capability_status"], "BLOCK_TECHNICAL")
                self.assertTrue(result["reasons"])

    def test_automatic_summary_identity_and_collection_controls(self) -> None:
        valid = automatic_summary_body()
        cases = []
        owner = snapshot()
        owner["issue_comments"] = [human_comment(valid)]
        cases.append(owner)
        wrong_app = snapshot()
        wrong_app["issue_comments"][0]["body"] = valid
        wrong_app["issue_comments"][0]["performed_via_github_app"]["id"] = 1
        cases.append(wrong_app)
        incomplete = snapshot()
        incomplete["issue_comments"][0]["body"] = valid
        incomplete["collection_complete"] = False
        cases.append(incomplete)
        manual = snapshot()
        manual["issue_comments"][0]["body"] = valid
        manual["issue_comments"].insert(0, human_comment("@codex review"))
        cases.append(manual)
        manual_other_task = snapshot()
        manual_other_task["issue_comments"][0]["body"] = valid
        manual_other_task["issue_comments"].insert(
            0, human_comment("@codex inspect this pull request and report findings")
        )
        cases.append(manual_other_task)
        finding = snapshot()
        finding["issue_comments"][0]["body"] = valid
        finding["pull_request_reviews"] = [connector_review()]
        finding["review_comments"] = [connector_review_comment(severity="P2")]
        cases.append(finding)

        for value in cases:
            with self.subTest(case=len(value["issue_comments"])):
                result = evaluate(value)
                self.assertEqual(result["capability_status"], "BLOCK_TECHNICAL")

    def test_live_clean_body_variants_pass_deterministically(self) -> None:
        for suffix in (
            " Bravo.",
            " Can't wait for the next one!",
            " Already looking forward to the next diff.",
            " Another round soon, please!",
            " :tada:",
        ):
            with self.subTest(suffix=suffix):
                value = snapshot()
                value["issue_comments"][0]["body"] = clean_body(suffix)
                raw = raw_bytes(value)
                context = trusted(raw)

                first = evaluate_codex_connector_evidence(raw, context)
                second = evaluate_codex_connector_evidence(raw, context)

                self.assertEqual(first, second)
                self.assertEqual(first["capability_status"], "PASS")
                self.assertEqual(first["reviewed_head_sha"], HEAD_SHA)
                self.assertEqual(first["reasons"], [])
                self.assertEqual(
                    serialize_codex_connector_evidence_result(first),
                    serialize_codex_connector_evidence_result(second),
                )
                validate_codex_connector_evidence_result(first, raw, context)

    def test_any_connector_failure_in_window_is_unavailable_despite_later_clean_signal(
        self,
    ) -> None:
        quota = comment(
            "You have reached your Codex usage limits for code reviews.",
            comment_id=199,
            created_at="2026-07-13T18:00:30Z",
        )
        value = snapshot()
        value["issue_comments"].insert(0, quota)
        first_result = evaluate(value)
        self.assertEqual(first_result["capability_status"], "BLOCK_TECHNICAL")
        self.assertEqual(first_result["review_state"], "AI_REVIEW_UNAVAILABLE")
        self.assertIn("CONNECTOR_FAILURE_PRESENT", first_result["reasons"])

        quota["id"] = 201
        quota["created_at"] = "2026-07-13T18:02:00Z"
        result = evaluate(value)
        self.assertEqual(result["capability_status"], "BLOCK_TECHNICAL")
        self.assertEqual(result["review_state"], "AI_REVIEW_UNAVAILABLE")
        self.assertIn("RESPONSE_BODY_UNRECOGNIZED", result["reasons"])

        quota["created_at"] = "2026-07-13T18:01:00Z"
        result = evaluate(value)
        self.assertEqual(result["capability_status"], "BLOCK_TECHNICAL")
        self.assertEqual(result["review_state"], "AI_REVIEW_UNAVAILABLE")
        self.assertIsNone(result["response"])

    def test_review_deadline_is_inclusive_and_only_late_evidence_is_unavailable(
        self,
    ) -> None:
        at_deadline = snapshot()
        at_deadline["issue_comments"][0]["created_at"] = DEADLINE
        self.assertEqual(evaluate(at_deadline)["capability_status"], "PASS")

        late_clean = snapshot()
        late_clean["issue_comments"][0]["created_at"] = "2026-07-13T18:05:01Z"
        late_clean["captured_at"] = "2026-07-13T18:05:02Z"
        late_result = evaluate(late_clean)
        self.assertEqual(late_result["capability_status"], "BLOCK_TECHNICAL")
        self.assertEqual(late_result["review_state"], "AI_REVIEW_UNAVAILABLE")
        self.assertIn("ONLY_LATE_RESPONSE", late_result["reasons"])
        self.assertIsNone(late_result["reviewed_head_sha"])

        late_failure = snapshot()
        late_failure["issue_comments"][0]["created_at"] = "2026-07-13T18:07:20Z"
        late_failure["captured_at"] = "2026-07-13T18:07:21Z"
        late_failure["issue_comments"][0]["body"] = (
            "Codex couldn't complete this request. Try again later."
        )
        failure_result = evaluate(late_failure)
        self.assertEqual(failure_result["capability_status"], "BLOCK_TECHNICAL")
        self.assertEqual(failure_result["review_state"], "AI_REVIEW_UNAVAILABLE")
        self.assertIn("ONLY_LATE_RESPONSE", failure_result["reasons"])

    def test_issue_comment_cutoff_before_deadline_blocks_without_crash(self) -> None:
        value = snapshot()
        value["captured_at"] = "2026-07-13T18:04:59Z"

        result = evaluate(value)

        self.assertEqual(result["capability_status"], "BLOCK_TECHNICAL")
        self.assertIn("EVIDENCE_CUTOFF_BEFORE_DEADLINE", result["reasons"])

    def test_snapshot_and_identity_fail_closed_controls(self) -> None:
        cases: list[tuple[str, dict]] = []
        missing = snapshot()
        missing["issue_comments"] = []
        cases.append(("missing", missing))
        closed = snapshot()
        closed["pull_request"]["state"] = "closed"
        cases.append(("closed", closed))
        draft = snapshot()
        draft["pull_request"]["draft"] = True
        cases.append(("draft", draft))
        incomplete = snapshot()
        incomplete["collection_complete"] = False
        cases.append(("incomplete", incomplete))
        duplicate_comment = snapshot()
        duplicate_comment["issue_comments"].append(
            comment(clean_body(), comment_id=200)
        )
        cases.append(("duplicate_comment", duplicate_comment))
        for name, value in cases:
            with self.subTest(name=name):
                result = evaluate(value)
                if name == "missing":
                    self.assertEqual(result["capability_status"], "BLOCK_TECHNICAL")
                    self.assertEqual(result["review_state"], "AI_REVIEW_UNAVAILABLE")
                else:
                    self.assertEqual(result["capability_status"], "BLOCK_TECHNICAL")
                self.assertTrue(result["reasons"])

        start_boundary = snapshot()
        start_boundary["issue_comments"][0]["created_at"] = ANCHOR
        result = evaluate(start_boundary)
        self.assertEqual(result["review_state"], "AI_REVIEW_UNAVAILABLE")
        self.assertEqual(
            result["reasons"],
            ["HEAD_ATTRIBUTION_AMBIGUOUS", "NO_IN_WINDOW_RESPONSE"],
        )

        historical_manual = snapshot()
        historical_manual["issue_comments"].insert(
            0,
            human_comment("@codex review", created_at="2026-07-13T17:59:59Z"),
        )
        result = evaluate(historical_manual)
        self.assertEqual(result["capability_status"], "PASS")
        self.assertEqual(result["reasons"], [])

        raw = raw_bytes(snapshot())
        mismatch_contexts = (
            trusted(raw, repository_id=999),
            trusted(raw, repository_full_name="evil/repo"),
            trusted(raw, pull_request_number=99),
            trusted(raw, base_sha="c" * 40),
            trusted(raw, head_sha="c" * 40),
            trusted(
                raw,
                review_window_started_at="2026-07-13T19:00:00Z",
                review_deadline_at="2026-07-13T19:05:00Z",
            ),
            trusted(raw, snapshot_file_sha256="sha256:" + "0" * 64),
            trusted(raw, resolved_clean_commit_sha="c" * 40),
        )
        for context in mismatch_contexts:
            with self.subTest(context=context):
                result = evaluate_codex_connector_evidence(raw, context)
                self.assertEqual(result["capability_status"], "BLOCK_TECHNICAL")

    def test_clean_prefix_requires_trusted_authoritative_full_sha_resolution(
        self,
    ) -> None:
        value = snapshot()
        raw = raw_bytes(value)
        for resolved in (None, HEAD_SHA[:10] + "c" * 30, "c" * 40):
            with self.subTest(resolved=resolved):
                result = evaluate_codex_connector_evidence(
                    raw, trusted(raw, resolved_clean_commit_sha=resolved)
                )
                self.assertEqual(result["capability_status"], "BLOCK_TECHNICAL")
                self.assertTrue(
                    {"COMMIT_RESOLUTION_MISMATCH", "REVIEWED_COMMIT_NOT_HEAD"}
                    & set(result["reasons"])
                )

    def test_malformed_noncanonical_and_duplicate_key_json_block(self) -> None:
        invalid_time = snapshot()
        invalid_time["issue_comments"][0]["created_at"] = "2026-99-99T99:99:99Z"
        raw_cases = (
            b"not-json",
            b"{}\n",
            raw_bytes(snapshot()) + b" ",
            b'{"schema_version":"1.0","schema_version":"1.0"}\n',
            b"[]\n",
            raw_bytes(invalid_time),
            b'{"nested":' + (b"[" * 5000) + b"0" + (b"]" * 5000) + b"}\n",
        )
        for raw in raw_cases:
            with self.subTest(raw=raw[:30]):
                result = evaluate_codex_connector_evidence(raw, trusted(raw))
                self.assertEqual(result["capability_status"], "BLOCK_TECHNICAL")
                self.assertTrue(result["reasons"])

    def test_orphaned_current_head_connector_review_comment_blocks(self) -> None:
        for severity in ("P0", "P1", "P2", "P3"):
            with self.subTest(severity=severity):
                value = snapshot()
                value["review_comments"] = [
                    connector_review_comment(review_id=999, severity=severity)
                ]

                result = evaluate(value)

                self.assertEqual(result["capability_status"], "BLOCK_TECHNICAL")
                self.assertIn("ORPHANED_REVIEW_COMMENT", result["reasons"])
                if severity in ("P0", "P1", "P2"):
                    self.assertEqual(
                        result["review_state"], "BLOCKING_FINDINGS_PRESENT"
                    )
                    self.assertIn("BLOCKING_FINDINGS_PRESENT", result["reasons"])

        stale = snapshot()
        stale["review_comments"] = [connector_review_comment(review_id=999)]
        stale["review_comments"][0]["commit_id"] = "c" * 40
        self.assertEqual(evaluate(stale)["capability_status"], "PASS")

        retargeted = reaction_snapshot()
        retargeted["review_comments"] = [
            connector_review_comment(review_id=999, severity="P1")
        ]
        retargeted["review_comments"][0]["original_commit_id"] = "c" * 40
        result = evaluate(retargeted)
        self.assertEqual(result["review_state"], "AI_REVIEW_UNAVAILABLE")
        self.assertNotIn("ORPHANED_REVIEW_COMMENT", result["reasons"])
        self.assertNotIn("BLOCKING_FINDINGS_PRESENT", result["reasons"])

        mutated = deepcopy(retargeted)
        mutated["review_comments"][0]["original_commit_id"] = HEAD_SHA
        result = evaluate(mutated)
        self.assertIn("ORPHANED_REVIEW_COMMENT", result["reasons"])
        self.assertIn("BLOCKING_FINDINGS_PRESENT", result["reasons"])

        for name, mutate in (
            (
                "retargeted",
                lambda comment: comment.update(original_commit_id="c" * 40),
            ),
            (
                "post_cutoff",
                lambda comment: comment.update(created_at="2026-07-13T18:05:30Z"),
            ),
        ):
            with self.subTest(name=name):
                linked = reaction_snapshot()
                linked["captured_at"] = "2026-07-13T18:06:00Z"
                linked["pull_request_reviews"] = [connector_review()]
                linked["review_comments"] = [connector_review_comment()]
                mutate(linked["review_comments"][0])
                result = evaluate(linked)
                self.assertNotIn("BLOCKING_FINDINGS_PRESENT", result["reasons"])

    def test_snapshot_commit_identities_require_semantic_full_match(self) -> None:
        cases = []

        base = snapshot()
        base["pull_request"]["base_sha"] += "\n"
        cases.append(("base", base))

        head = snapshot()
        head["pull_request"]["head_sha"] += "\n"
        cases.append(("head", head))

        parent = snapshot()
        parent_review = connector_review(commit_id=HEAD_SHA + "\n")
        parent_review["body"] = "P1: unsafe evidence boundary"
        parent["pull_request_reviews"] = [parent_review]
        cases.append(("parent", parent))

        inline_commit = snapshot()
        inline_commit["review_comments"] = [connector_review_comment(review_id=999)]
        inline_commit["review_comments"][0]["commit_id"] += "\n"
        cases.append(("inline_commit", inline_commit))

        inline_original = snapshot()
        inline_original["review_comments"] = [connector_review_comment(review_id=999)]
        inline_original["review_comments"][0]["original_commit_id"] += "\n"
        cases.append(("inline_original", inline_original))

        for name, value in cases:
            with self.subTest(name=name):
                result = evaluate(value)
                self.assertEqual(result["capability_status"], "BLOCK_TECHNICAL")
                self.assertIn("SNAPSHOT_COMMIT_IDENTITY_INVALID", result["reasons"])

    def test_current_head_connector_p0_p1_p2_findings_always_block(self) -> None:
        for severity in ("P0", "P1", "P2"):
            with self.subTest(severity=severity):
                value = snapshot()
                review = connector_review()
                review["submitted_at"] = "2026-07-13T18:00:30Z"
                value["pull_request_reviews"] = [review]
                value["review_comments"] = [connector_review_comment(severity=severity)]

                result = evaluate(value)

                self.assertEqual(result["capability_status"], "BLOCK_TECHNICAL")
                self.assertIn("BLOCKING_FINDINGS_PRESENT", result["reasons"])

        spoofed = snapshot()
        review = connector_review()
        review["user"]["id"] = 1
        spoofed["pull_request_reviews"] = [review]
        spoofed["review_comments"] = [connector_review_comment()]
        spoofed_result = evaluate(spoofed)
        self.assertEqual(spoofed_result["capability_status"], "BLOCK_TECHNICAL")
        self.assertIn("ORPHANED_REVIEW_COMMENT", spoofed_result["reasons"])
        self.assertIn("BLOCKING_FINDINGS_PRESENT", spoofed_result["reasons"])

    def test_parent_review_state_or_body_blocks_before_or_after_clean_comment(
        self,
    ) -> None:
        variants = (
            ("CHANGES_REQUESTED", "review state blocks"),
            ("COMMENTED", "P1: unsafe evidence boundary"),
        )
        for state, body in variants:
            for submitted_at in (
                "2026-07-13T18:00:30Z",
                "2026-07-13T18:02:00Z",
            ):
                with self.subTest(state=state, submitted_at=submitted_at):
                    value = snapshot()
                    review = connector_review()
                    review["state"] = state
                    review["body"] = body
                    review["submitted_at"] = submitted_at
                    value["pull_request_reviews"] = [review]

                    result = evaluate(value)

                    self.assertEqual(result["capability_status"], "BLOCK_TECHNICAL")
                    self.assertIn("BLOCKING_FINDINGS_PRESENT", result["reasons"])

    def test_connector_identity_and_owner_copy_cannot_spoof(self) -> None:
        identity_mutations = (
            ("user", "login", "chatgpt-codex-connector"),
            ("user", "id", 1),
            ("user", "node_id", "BOT_lookalike"),
            ("user", "type", "User"),
            ("performed_via_github_app", "id", 1),
            ("performed_via_github_app", "node_id", "A_lookalike"),
            ("performed_via_github_app", "slug", "chatgpt-codex-connect0r"),
        )
        for container, key, replacement in identity_mutations:
            with self.subTest(container=container, key=key):
                value = snapshot()
                value["issue_comments"][0][container][key] = replacement
                self.assertEqual(
                    evaluate(value)["capability_status"], "BLOCK_TECHNICAL"
                )

        copied = snapshot()
        copied["issue_comments"] = [human_comment(clean_body())]
        self.assertEqual(evaluate(copied)["capability_status"], "BLOCK_TECHNICAL")

        missing_app = snapshot()
        missing_app["issue_comments"][0]["performed_via_github_app"] = None
        self.assertEqual(evaluate(missing_app)["capability_status"], "BLOCK_TECHNICAL")

    def test_body_grammar_rejects_evasion_and_appended_findings(self) -> None:
        valid = clean_body()
        mutations = (
            valid.replace("Didn't", "Did not"),
            valid.replace(" Bravo.", " However P1 remains."),
            valid.replace(" Bravo.", " Please fix vulnerability."),
            valid.replace(" Bravo.", " Unknown celebration:"),
            valid + "\nP1: appended finding",
            "> " + valid,
            "```markdown\n" + valid + "\n```",
            valid.replace("</details>", "<details>nested</details></details>"),
            valid.replace("</details>", "Please fix vulnerability.\n</details>"),
            valid.replace("**Reviewed commit:**", "Reviewed commit:"),
        )
        for body in mutations:
            with self.subTest(body=body[:50]):
                value = snapshot()
                value["issue_comments"][0]["body"] = body
                result = evaluate(value)
                self.assertEqual(result["capability_status"], "BLOCK_TECHNICAL")
                self.assertIn("RESPONSE_BODY_UNRECOGNIZED", result["reasons"])

    def test_source_order_does_not_change_semantic_evidence(self) -> None:
        first = snapshot()
        first["issue_comments"].insert(
            0,
            comment(
                "You have reached your Codex usage limits for code reviews.",
                comment_id=199,
                created_at="2026-07-13T18:00:30Z",
            ),
        )
        first["pull_request_reviews"] = [connector_review(commit_id="c" * 40)]
        first["review_comments"] = [connector_review_comment()]
        first["pull_request_reviews"][0]["submitted_at"] = "2026-07-13T17:59:00Z"
        first["review_comments"][0]["created_at"] = "2026-07-13T17:59:00Z"
        first["review_comments"][0]["commit_id"] = "c" * 40
        second = deepcopy(first)
        second["issue_comments"].reverse()

        left = evaluate(first)
        right = evaluate(second)

        self.assertEqual(left["capability_status"], "BLOCK_TECHNICAL")
        self.assertEqual(right["capability_status"], "BLOCK_TECHNICAL")
        self.assertEqual(left["review_state"], "AI_REVIEW_UNAVAILABLE")
        self.assertEqual(
            left["normalized_snapshot_sha256"],
            right["normalized_snapshot_sha256"],
        )


class WorkflowRequestLaunchFailureTests(unittest.TestCase):
    def test_launch_failure_receipt_is_schema_valid_unavailable(self) -> None:
        unavailable_snapshot = reaction_snapshot()
        unavailable_snapshot["issue_comments"] = []
        receipt = workflow_request_receipt(
            "TRANSPORT_UNAVAILABLE",
            transport_exit_code=None,
        )

        result = evaluate_with_workflow_request(unavailable_snapshot, receipt)

        self.assertEqual(result["review_state"], "AI_REVIEW_UNAVAILABLE")
        self.assertIsNone(result["workflow_request_receipt"]["transport_exit_code"])

    def test_launch_failure_receipt_rejects_contradictions(self) -> None:
        for changes in (
            {"transport_timed_out": True},
            {"transport_error_sha256": None},
        ):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                workflow_request_receipt(
                    "TRANSPORT_UNAVAILABLE",
                    transport_exit_code=None,
                    **changes,
                )


class CodexConnectorResultValidationTests(unittest.TestCase):
    def test_context_and_v4_schema_reject_missing_request_receipt(self) -> None:
        raw = raw_bytes(snapshot())
        with self.assertRaisesRegex(
            ValueError, "automatic workflow request receipt is required"
        ):
            trusted(raw, workflow_request_receipt=None)

        context = trusted(raw)
        result = evaluate_codex_connector_evidence(raw, context)
        missing_receipt = deepcopy(result)
        missing_receipt["workflow_request_receipt"] = None
        missing_receipt["result_content_hash"] = sha256_json(
            {**missing_receipt, "result_content_hash": ""}
        )
        with self.assertRaises(ValueError):
            validate_named("codex_connector_evidence_result_v4", missing_receipt)
        with self.assertRaises(ValueError):
            validate_codex_connector_evidence_result(
                missing_receipt,
                raw,
                context,
            )

    def test_signal_normalized_transport_receipt_is_schema_valid(self) -> None:
        receipt = workflow_request_receipt(
            "TRANSPORT_UNAVAILABLE", transport_exit_code=143
        )
        self.assertEqual(receipt.transport_exit_code, 143)
        with self.assertRaises(ValueError):
            workflow_request_receipt("TRANSPORT_UNAVAILABLE", transport_exit_code=-15)

    def test_invalid_request_response_is_reconciled_unavailable(self) -> None:
        value = reaction_snapshot()
        value["issue_comments"] = []
        raw = raw_bytes(value)
        context = trusted(
            raw,
            resolved_clean_commit_sha=None,
            workflow_request_receipt=workflow_request_receipt("RESPONSE_INVALID"),
        )

        result = evaluate_codex_connector_evidence(raw, context)
        owner = evaluate_ai_review_gate(
            HEAD_SHA,
            codex_result=result,
            raw_snapshot_bytes=raw,
            trusted_context=context,
        )

        self.assertEqual(result["review_state"], "AI_REVIEW_UNAVAILABLE")
        self.assertEqual(
            result["reasons"],
            ["NO_IN_WINDOW_RESPONSE", "WORKFLOW_REQUEST_RESPONSE_INVALID"],
        )
        self.assertEqual(
            result["workflow_request_receipt"]["response_validation_error_sha256"],
            workflow_request_receipt(
                "RESPONSE_INVALID"
            ).response_validation_error_sha256,
        )
        self.assertEqual(owner["owner_status"], "GREEN")
        self.assertFalse(owner["approval_provided"])

        blocking = reaction_snapshot()
        blocking["issue_comments"] = []
        blocking["pull_request_reviews"] = [connector_review()]
        blocking["review_comments"] = [connector_review_comment(severity="P1")]
        blocking_raw = raw_bytes(blocking)
        blocking_result = evaluate_codex_connector_evidence(
            blocking_raw,
            trusted(
                blocking_raw,
                resolved_clean_commit_sha=None,
                workflow_request_receipt=workflow_request_receipt("RESPONSE_INVALID"),
            ),
        )
        self.assertEqual(blocking_result["review_state"], "BLOCKING_FINDINGS_PRESENT")
        self.assertIn("WORKFLOW_REQUEST_RESPONSE_INVALID", blocking_result["reasons"])

    def test_result_validation_replays_source_and_rejects_coherent_mutation(
        self,
    ) -> None:
        value = snapshot()
        raw = raw_bytes(value)
        context = trusted(raw)
        result = evaluate_codex_connector_evidence(raw, context)
        validate_named("codex_connector_evidence_result_v4", result)
        with self.assertRaises(ValueError):
            validate_named("codex_connector_evidence_result_v3", result)
        prior_v3 = deepcopy(result)
        prior_v3["schema_version"] = "3.0"
        for field in (
            "transport_command",
            "transport_started_at",
            "transport_completed_at",
            "transport_timeout_seconds",
            "transport_timed_out",
            "response_validation_error_sha256",
        ):
            prior_v3["workflow_request_receipt"].pop(field)
        prior_v3["result_content_hash"] = sha256_json(
            {**prior_v3, "result_content_hash": ""}
        )
        validate_named("codex_connector_evidence_result_v3", prior_v3)
        with self.assertRaises(ValueError):
            validate_named("codex_connector_evidence_result_v4", prior_v3)
        prior_v2 = deepcopy(prior_v3)
        prior_v2["schema_version"] = "2.0"
        prior_v2.pop("workflow_request_receipt")
        prior_v2["result_content_hash"] = sha256_json(
            {**prior_v2, "result_content_hash": ""}
        )
        validate_named("codex_connector_evidence_result_v2", prior_v2)
        with self.assertRaises(ValueError):
            validate_named("codex_connector_evidence_result_v3", prior_v2)

        impossible_reaction = deepcopy(result)
        impossible_reaction["response"].update(
            response_type="pull_request_reaction",
            response_node_id="REA_current",
            user_type="User",
            app_provenance="NOT_EXPOSED_BY_GITHUB_API",
            app_id=None,
            app_node_id=None,
            app_slug=None,
        )
        impossible_reaction["resolved_clean_commit_sha"] = None
        impossible_reaction["result_content_hash"] = sha256_json(
            {**impossible_reaction, "result_content_hash": ""}
        )
        with self.assertRaises(ValueError):
            serialize_codex_connector_evidence_result(impossible_reaction)

        mutations = (
            lambda item: item["response"].update(response_id=999),
            lambda item: item.update(reviewed_head_sha="c" * 40),
            lambda item: item["connector_identity"].update(user_id=1),
            lambda item: item.update(review_deadline_at="2026-07-13T18:04:59Z"),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                candidate = deepcopy(result)
                mutate(candidate)
                candidate["result_content_hash"] = sha256_json(
                    {**candidate, "result_content_hash": ""}
                )
                with self.assertRaises(ValueError):
                    validate_codex_connector_evidence_result(candidate, raw, context)

        requested = snapshot()
        requested["issue_comments"].append(
            comment(
                "@codex review\n\nGovernance review request for exact head "
                f"`{HEAD_SHA}`.",
                comment_id=201,
                user={
                    "login": "github-actions[bot]",
                    "id": 41898282,
                    "node_id": "MDM6Qm90NDE4OTgyODI=",
                    "type": "Bot",
                },
                app={
                    "id": 15368,
                    "node_id": "MDM6QXBwMTUzNjg=",
                    "slug": "github-actions",
                },
            )
        )
        requested_raw = raw_bytes(requested)
        requested_context = trusted(
            requested_raw,
            workflow_request_receipt=workflow_request_receipt(),
        )
        requested_result = evaluate_codex_connector_evidence(
            requested_raw, requested_context
        )
        substituted = deepcopy(requested_result)
        substituted["workflow_request_receipt"]["run_id"] += 1
        substituted["result_content_hash"] = sha256_json(
            {**substituted, "result_content_hash": ""}
        )
        with self.assertRaises(ValueError):
            validate_codex_connector_evidence_result(
                substituted, requested_raw, requested_context
            )

        rerun = deepcopy(requested_result)
        rerun["workflow_request_receipt"]["run_attempt"] = 2
        rerun["result_content_hash"] = sha256_json({**rerun, "result_content_hash": ""})
        with self.assertRaises(ValueError):
            serialize_codex_connector_evidence_result(rerun)

        quota = snapshot()
        quota["issue_comments"][0]["body"] = (
            "You have reached your Codex usage limits for code reviews."
        )
        quota_raw = raw_bytes(quota)
        quota_context = trusted(quota_raw)
        candidate = evaluate_codex_connector_evidence(quota_raw, quota_context)
        candidate["capability_status"] = "PASS"
        candidate["reasons"] = []
        candidate["reviewed_head_sha"] = HEAD_SHA
        candidate["result_content_hash"] = sha256_json(
            {**candidate, "result_content_hash": ""}
        )
        with self.assertRaises(ValueError):
            validate_codex_connector_evidence_result(
                candidate, quota_raw, quota_context
            )

    def test_schema_registry_and_trusted_input_validation(self) -> None:
        self.assertEqual(
            load_schema("codex_connector_snapshot")["title"],
            "Codex Connector Review Snapshot",
        )
        self.assertEqual(
            load_schema("codex_connector_evidence_result")["title"],
            "Codex Connector Evidence Result",
        )
        self.assertEqual(
            load_schema("codex_connector_snapshot_v2")["title"],
            "Codex Connector Review Snapshot v2",
        )
        self.assertEqual(
            load_schema("codex_connector_evidence_result_v2")["title"],
            "Codex Connector Evidence Result v2",
        )
        self.assertEqual(
            load_schema("codex_connector_evidence_result_v3")["title"],
            "Codex Connector Evidence Result v3",
        )
        self.assertEqual(
            load_schema("codex_connector_evidence_result_v4")["title"],
            "Codex Connector Evidence Result v4",
        )
        raw = raw_bytes(snapshot())
        with self.assertRaises(ValueError):
            trusted(raw, governance_evaluator_sha="not-a-sha")
        with self.assertRaises(ValueError):
            trusted(raw, review_window_started_at="not-a-time")
        for deadline in (
            "not-a-time",
            ANCHOR,
            "2026-07-13T17:59:59Z",
            "2026-07-13T18:05:01Z",
        ):
            with self.subTest(deadline=deadline), self.assertRaises(ValueError):
                trusted(raw, review_deadline_at=deadline)

    def test_v1_schemas_remain_immutable_and_accept_prior_artifacts(self) -> None:
        old_snapshot = {
            "schema_version": "1.0",
            "collection_complete": True,
            "repository": {"id": REPOSITORY_ID, "full_name": REPOSITORY},
            "pull_request": {
                "number": PR_NUMBER,
                "state": "open",
                "draft": False,
                "base_sha": BASE_SHA,
                "head_sha": HEAD_SHA,
            },
            "issue_comments": [comment(clean_body())],
            "pull_request_reviews": [],
            "review_comments": [],
        }
        validate_named("codex_connector_snapshot", old_snapshot)
        with self.assertRaises(ValueError):
            validate_named("codex_connector_snapshot_v2", old_snapshot)

        old_result = {
            "schema_version": "1.0",
            "capability": "CODEX_CONNECTOR_REVIEW_EVIDENCE",
            "adapter_id": "codex_connector_issue_comment_v1",
            "repository": {"id": REPOSITORY_ID, "full_name": REPOSITORY},
            "pull_request": {
                "number": PR_NUMBER,
                "base_sha": BASE_SHA,
                "head_sha": HEAD_SHA,
            },
            "governance_evaluator_sha": EVALUATOR_SHA,
            "review_window_started_at": ANCHOR,
            "review_deadline_at": DEADLINE,
            "snapshot_file_sha256": "sha256:" + "0" * 64,
            "normalized_snapshot_sha256": "1" * 64,
            "resolved_clean_commit_sha": HEAD_SHA,
            "connector_identity": {
                "login": CONNECTOR_USER["login"],
                "user_id": CONNECTOR_USER["id"],
                "user_node_id": CONNECTOR_USER["node_id"],
                "user_type": "Bot",
                "app_id": CONNECTOR_APP["id"],
                "app_node_id": CONNECTOR_APP["node_id"],
                "app_slug": CONNECTOR_APP["slug"],
            },
            "capability_status": "PASS",
            "reviewed_head_sha": HEAD_SHA,
            "response": {
                "response_type": "issue_comment",
                "response_id": 200,
                "created_at": "2026-07-13T18:01:00Z",
                "body_sha256": "2" * 64,
            },
            "reasons": [],
            "result_content_hash": "3" * 64,
        }
        validate_named("codex_connector_evidence_result", old_result)
        with self.assertRaises(ValueError):
            validate_named("codex_connector_evidence_result_v2", old_result)


if __name__ == "__main__":
    unittest.main()
