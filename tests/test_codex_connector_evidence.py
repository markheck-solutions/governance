from __future__ import annotations

import json
import unittest
from copy import deepcopy
from hashlib import sha256

from governance_eval.codex_connector_evidence import (
    TrustedCodexConnectorContext,
    evaluate_codex_connector_evidence,
    serialize_codex_connector_evidence_result,
    validate_codex_connector_evidence_result,
)
from governance_eval.hashing import sha256_json
from governance_eval.schemas import load_schema, validate_named


REPOSITORY_ID = 1280677092
REPOSITORY = "markheck-solutions/governance"
PR_NUMBER = 31
BASE_SHA = "a" * 40
HEAD_SHA = "b" * 40
EVALUATOR_SHA = "e" * 40
ANCHOR = "2026-07-13T18:00:00Z"
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


def human_comment(body: str, *, comment_id: int = 100) -> dict:
    result = comment(
        body,
        comment_id=comment_id,
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


def snapshot() -> dict:
    return {
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


def raw_bytes(value: dict) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def trusted(raw: bytes, **changes: object) -> TrustedCodexConnectorContext:
    values = {
        "snapshot_file_sha256": "sha256:" + sha256(raw).hexdigest(),
        "repository_id": REPOSITORY_ID,
        "repository_full_name": REPOSITORY,
        "pull_request_number": PR_NUMBER,
        "base_sha": BASE_SHA,
        "head_sha": HEAD_SHA,
        "governance_evaluator_sha": EVALUATOR_SHA,
        "review_window_started_at": ANCHOR,
        "resolved_clean_commit_sha": HEAD_SHA,
    }
    values.update(changes)
    return TrustedCodexConnectorContext(**values)  # type: ignore[arg-type]


def evaluate(value: dict) -> dict:
    raw = raw_bytes(value)
    return evaluate_codex_connector_evidence(raw, trusted(raw))


class CodexConnectorEvidenceTests(unittest.TestCase):
    def test_live_clean_body_variants_pass_deterministically(self) -> None:
        for suffix in (
            " Bravo.",
            " Can't wait for the next one!",
            " Already looking forward to the next diff.",
            " Another round soon, please!",
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

    def test_latest_signed_response_controls_result(self) -> None:
        quota = comment(
            "You have reached your Codex usage limits for code reviews.",
            comment_id=199,
            created_at="2026-07-13T18:00:30Z",
        )
        value = snapshot()
        value["issue_comments"].insert(0, quota)
        self.assertEqual(evaluate(value)["capability_status"], "PASS")

        quota["id"] = 201
        quota["created_at"] = "2026-07-13T18:02:00Z"
        result = evaluate(value)
        self.assertEqual(result["capability_status"], "BLOCK_TECHNICAL")
        self.assertIn("RESPONSE_BODY_UNRECOGNIZED", result["reasons"])

        quota["created_at"] = "2026-07-13T18:01:00Z"
        result = evaluate(value)
        self.assertEqual(result["capability_status"], "BLOCK_TECHNICAL")
        self.assertEqual(result["response"]["response_id"], 201)

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
        for index, created_at in enumerate((ANCHOR, "2026-07-13T17:59:59Z")):
            manual = snapshot()
            request = human_comment("@codex review", comment_id=100 + index)
            request["created_at"] = created_at
            manual["issue_comments"].insert(0, request)
            cases.append((f"manual_request_{index}", manual))
        stale = snapshot()
        stale["issue_comments"][0]["created_at"] = ANCHOR
        cases.append(("stale", stale))

        for name, value in cases:
            with self.subTest(name=name):
                result = evaluate(value)
                self.assertEqual(result["capability_status"], "BLOCK_TECHNICAL")
                self.assertTrue(result["reasons"])

        raw = raw_bytes(snapshot())
        mismatch_contexts = (
            trusted(raw, repository_id=999),
            trusted(raw, repository_full_name="evil/repo"),
            trusted(raw, pull_request_number=99),
            trusted(raw, base_sha="c" * 40),
            trusted(raw, head_sha="c" * 40),
            trusted(raw, review_window_started_at="2026-07-13T19:00:00Z"),
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
                    self.assertIn("BLOCKING_FINDINGS_PRESENT", result["reasons"])

        stale = snapshot()
        stale["review_comments"] = [connector_review_comment(review_id=999)]
        stale["review_comments"][0]["commit_id"] = "c" * 40
        self.assertEqual(evaluate(stale)["capability_status"], "PASS")

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

        self.assertEqual(left["capability_status"], "PASS")
        self.assertEqual(right["capability_status"], "PASS")
        self.assertEqual(
            left["normalized_snapshot_sha256"],
            right["normalized_snapshot_sha256"],
        )

    def test_result_validation_replays_source_and_rejects_coherent_mutation(
        self,
    ) -> None:
        value = snapshot()
        raw = raw_bytes(value)
        context = trusted(raw)
        result = evaluate_codex_connector_evidence(raw, context)
        validate_named("codex_connector_evidence_result", result)

        mutations = (
            lambda item: item["response"].update(response_id=999),
            lambda item: item.update(reviewed_head_sha="c" * 40),
            lambda item: item["connector_identity"].update(user_id=1),
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
        raw = raw_bytes(snapshot())
        with self.assertRaises(ValueError):
            trusted(raw, governance_evaluator_sha="not-a-sha")
        with self.assertRaises(ValueError):
            trusted(raw, review_window_started_at="not-a-time")


if __name__ == "__main__":
    unittest.main()
