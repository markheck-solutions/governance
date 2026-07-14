from __future__ import annotations

import unittest
from copy import deepcopy

from governance_eval.bootstrap_audit import generate_bootstrap_audit_receipt
from governance_eval.hashing import sha256_json


def record() -> dict:
    protection_url = "https://api.github.com/repos/owner/repo/branches/main/protection"
    endpoint = f"{protection_url}/enforce_admins"
    disable_request = {"method": "DELETE", "url": endpoint}
    disable_response = {"status": 204, "body": None}
    restore_request = {"method": "POST", "url": endpoint}
    restore_response = {
        "status": 200,
        "body": {"url": endpoint, "enabled": True},
    }
    return {
        "repository_url": "https://github.com/owner/repo",
        "protection_url": protection_url,
        "rulesets_url": "https://api.github.com/repos/owner/repo/rulesets",
        "actor": "owner",
        "started_at": "2026-07-14T00:00:00Z",
        "completed_at": "2026-07-14T00:05:00Z",
        "expires_at": "2026-07-14T01:00:00Z",
        "candidate_sha": "a" * 40,
        "pull_request_number": 37,
        "pr_head_before_merge": "a" * 40,
        "merge_sha": "b" * 40,
        "rollback_sha": "c" * 40,
        "resource_etags": {
            "pre_protection": "etag-1",
            "post_protection": "etag-2",
            "pre_rulesets": None,
            "post_rulesets": None,
        },
        "mutation_events": [
            {
                "action": "disable_enforce_admins",
                "server_timestamp": "2026-07-14T00:01:00Z",
                "resource_url": protection_url,
                "request": disable_request,
                "response": disable_response,
                "request_sha256": sha256_json(disable_request),
                "response_sha256": sha256_json(disable_response),
            },
            {
                "action": "restore_enforce_admins",
                "server_timestamp": "2026-07-14T00:04:00Z",
                "resource_url": protection_url,
                "request": restore_request,
                "response": restore_response,
                "request_sha256": sha256_json(restore_request),
                "response_sha256": sha256_json(restore_response),
            },
        ],
    }


class BootstrapAuditTests(unittest.TestCase):
    def test_restored_bounded_transaction_passes_deterministically(self) -> None:
        source = record()
        first = generate_bootstrap_audit_receipt(
            source,
            pre_protection={"enabled": True},
            post_protection={"enabled": True},
            pre_rulesets=[],
            post_rulesets=[],
        )
        second = generate_bootstrap_audit_receipt(
            source,
            pre_protection={"enabled": True},
            post_protection={"enabled": True},
            pre_rulesets=[],
            post_rulesets=[],
        )
        self.assertEqual(first, second)
        self.assertEqual(first["decision"], "PASS")
        self.assertTrue(all(first["checks"].values()))

    def test_drift_or_wrong_head_blocks(self) -> None:
        source = record()
        source["pr_head_before_merge"] = "d" * 40
        result = generate_bootstrap_audit_receipt(
            source,
            pre_protection={"enabled": True},
            post_protection={"enabled": False},
            pre_rulesets=[],
            post_rulesets=[],
        )
        self.assertEqual(result["decision"], "BLOCK_TECHNICAL")
        self.assertFalse(result["checks"]["candidate_matches_pr_head"])
        self.assertFalse(result["checks"]["protection_restored"])

    def test_mutation_digest_or_order_blocks(self) -> None:
        for mutate in (
            lambda value: value["mutation_events"][0].update(
                action="restore_enforce_admins"
            ),
            lambda value: value["mutation_events"][1].update(response_sha256="bad"),
        ):
            with self.subTest(mutate=mutate):
                source = deepcopy(record())
                mutate(source)
                result = generate_bootstrap_audit_receipt(
                    source,
                    pre_protection={},
                    post_protection={},
                    pre_rulesets=[],
                    post_rulesets=[],
                )
                self.assertEqual(result["decision"], "BLOCK_TECHNICAL")

    def test_unbounded_or_reversed_transaction_blocks(self) -> None:
        too_long = record()
        too_long["expires_at"] = "2026-07-14T03:00:00Z"
        reversed_events = record()
        reversed_events["mutation_events"][1]["server_timestamp"] = (
            "2026-07-14T00:00:30Z"
        )
        for source in (too_long, reversed_events):
            with self.subTest(source=source):
                result = generate_bootstrap_audit_receipt(
                    source,
                    pre_protection={},
                    post_protection={},
                    pre_rulesets=[],
                    post_rulesets=[],
                )
                self.assertEqual(result["decision"], "BLOCK_TECHNICAL")

    def test_missing_resource_or_unbound_payload_blocks(self) -> None:
        missing_url = record()
        del missing_url["mutation_events"][0]["resource_url"]
        mutated_payload = record()
        mutated_payload["mutation_events"][0]["response"] = {"enabled": True}
        cross_repo = record()
        cross_repo["rulesets_url"] = "https://api.github.com/repos/other/repo/rulesets"
        wrong_method = record()
        wrong_method["mutation_events"][0]["request"]["method"] = "POST"
        wrong_method["mutation_events"][0]["request_sha256"] = sha256_json(
            wrong_method["mutation_events"][0]["request"]
        )
        for source in (missing_url, mutated_payload, cross_repo, wrong_method):
            with self.subTest(source=source):
                result = generate_bootstrap_audit_receipt(
                    source,
                    pre_protection={},
                    post_protection={},
                    pre_rulesets=[],
                    post_rulesets=[],
                )
                self.assertEqual(result["decision"], "BLOCK_TECHNICAL")

    def test_malformed_required_fields_emit_schema_valid_block(self) -> None:
        source = record()
        source.update(
            candidate_sha="bad",
            started_at="bad",
            actor="",
            pull_request_number=0,
            repository_url="bad",
        )
        result = generate_bootstrap_audit_receipt(
            source,
            pre_protection={},
            post_protection={},
            pre_rulesets=[],
            post_rulesets=[],
        )
        self.assertEqual(result["decision"], "BLOCK_TECHNICAL")
        self.assertEqual(result["candidate_sha"], "0" * 40)
        self.assertEqual(result["pull_request_number"], 1)


if __name__ == "__main__":
    unittest.main()
