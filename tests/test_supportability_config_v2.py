from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from governance_eval.paths import repo_root
from governance_eval.supportability import parse_supportability_config_bytes
from governance_eval.supportability_config_v2 import (
    AUTHORIZED_GOVERNANCE_V1_SHA256,
    TYPED_CAPABILITIES,
    ExecutableConfigError,
    validate_config_transition,
    validate_executable_supportability_config_bytes,
)


REPOSITORY = "markheck-solutions/governance"
CONFIG_PATH = ".github/governance/supportability.yml"


class ExecutableSupportabilityConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = repo_root(Path(__file__).resolve())
        self.v1_bytes = (self.root / CONFIG_PATH).read_bytes()

    def test_only_exact_governance_v1_bytes_translate(self) -> None:
        envelope = self._validate(self.v1_bytes)
        self.assertEqual(envelope["mode"], "legacy_v1_exact")
        self.assertEqual(envelope["content_sha256"], AUTHORIZED_GOVERNANCE_V1_SHA256)
        self.assertEqual(envelope["effective"]["capabilities"], TYPED_CAPABILITIES)
        self.assertNotIn("required_gates", envelope["effective"])

        altered = self.v1_bytes + b"\n"
        for raw, repository, path in (
            (altered, REPOSITORY, CONFIG_PATH),
            (self.v1_bytes.replace(b"\n", b"\r\n"), REPOSITORY, CONFIG_PATH),
            (self.v1_bytes, "owner/other", CONFIG_PATH),
            (self.v1_bytes, REPOSITORY, "supportability.yml"),
        ):
            with self.subTest(repository=repository, path=path, size=len(raw)):
                with self.assertRaisesRegex(ExecutableConfigError, "validation-only"):
                    validate_executable_supportability_config_bytes(
                        raw, repository_full_name=repository, path=path
                    )

    def test_typed_profile_validates_without_aliasing_caller_data(self) -> None:
        config = self._typed_config()
        envelope = self._validate(self._json_bytes(config))
        self.assertEqual(envelope["mode"], "typed_v2")
        self.assertEqual(envelope["source"], config)
        envelope["source"]["capabilities"]["lint"] = "changed"
        self.assertEqual(
            envelope["effective"]["capabilities"]["lint"],
            "python.ruff-check.v1",
        )

    def test_typed_profile_rejects_commands_options_and_unknown_fields(self) -> None:
        mutations = {
            "shell text": lambda item: item["capabilities"].__setitem__(
                "lint", "python -m ruff check ."
            ),
            "adapter object": lambda item: item["capabilities"].__setitem__(
                "lint", {"adapter": "python.ruff-check.v1", "root": "."}
            ),
            "adapter array": lambda item: item["capabilities"].__setitem__(
                "lint", ["python.ruff-check.v1"]
            ),
            "threshold option": lambda item: item.__setitem__(
                "complexity_threshold", 11
            ),
            "root option": lambda item: item.__setitem__("root", "."),
            "environment option": lambda item: item.__setitem__("environment", {}),
            "unknown capability": lambda item: item["capabilities"].__setitem__(
                "extra", "python.other.v1"
            ),
            "missing capability": lambda item: item["capabilities"].pop("tests"),
            "unsupported implementation": lambda item: item.__setitem__(
                "unsupported_ecosystems", ["node"]
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                config = self._typed_config()
                mutate(config)
                with self.assertRaisesRegex(ExecutableConfigError, "invalid"):
                    self._validate(self._json_bytes(config))

    def test_duplicate_keys_and_nonfinite_values_fail_closed(self) -> None:
        valid = self._json_bytes(self._typed_config()).decode("utf-8")
        duplicate = valid.replace(
            '"schema_version":"2.0"',
            '"schema_version":"2.0","schema_version":"2.0"',
            1,
        ).encode("utf-8")
        nonfinite = valid.replace('"retention_days":90', '"retention_days":NaN').encode(
            "utf-8"
        )
        duplicate_yaml = b"schema_version: '2.0'\nschema_version: '2.0'\n"
        for raw in (duplicate, nonfinite, duplicate_yaml):
            with self.subTest(raw=raw[:80]):
                with self.assertRaisesRegex(ExecutableConfigError, "malformed"):
                    self._validate(raw)

    def test_numeric_boolean_confusion_and_malformed_architecture_block(self) -> None:
        mutations = (
            lambda item: item["coverage"].__setitem__("forbid_gate_scope_narrowing", 1),
            lambda item: item["ai_review"].__setitem__("review_window_seconds", 300.0),
            lambda item: item["receipt"].__setitem__("retention_days", 90.0),
            lambda item: item["architecture_policy"].__setitem__("version", True),
            lambda item: item["architecture_policy"].__setitem__(
                "governed_roots", ["x"]
            ),
            lambda item: item["architecture_policy"].__setitem__(
                "runtime_relevance", {}
            ),
            lambda item: item["architecture_policy"].__setitem__(
                "modules", {"x": None}
            ),
            lambda item: item["standard"].__setitem__("source", "../standard.md"),
        )
        for mutate in mutations:
            config = self._typed_config()
            mutate(config)
            with self.subTest(config=config):
                with self.assertRaises(ExecutableConfigError):
                    self._validate(self._json_bytes(config))

    def test_deep_config_and_forged_transition_envelopes_block(self) -> None:
        deep = b'{"schema_version":"2.0","x":' + (b"[" * 3000) + (b"]" * 3000) + b"}"
        with self.assertRaisesRegex(ExecutableConfigError, "malformed"):
            self._validate(deep)

        valid = self._validate(self._json_bytes(self._typed_config()))
        for baseline, candidate in (
            ({}, {}),
            ({**valid, "mode": "unknown"}, valid),
            ({**valid, "source": {}}, valid),
        ):
            with self.subTest(baseline=baseline):
                with self.assertRaises(ExecutableConfigError):
                    validate_config_transition(baseline, candidate)

        changed = self._validate(self._json_bytes(self._typed_config()))
        changed["content_sha256"] = "f" * 64
        with self.assertRaisesRegex(ExecutableConfigError, "same-version"):
            validate_config_transition(valid, changed)

    def test_transition_is_one_way_and_preserves_policy(self) -> None:
        baseline = self._validate(self.v1_bytes)
        candidate = self._validate(self._json_bytes(self._typed_config()))
        validate_config_transition(baseline, candidate)

        changed = self._typed_config()
        changed["receipt"]["retention_days"] = 91
        with self.assertRaises(ExecutableConfigError):
            changed_candidate = {
                **candidate,
                "source": changed,
            }
            validate_config_transition(baseline, changed_candidate)

        with self.assertRaisesRegex(ExecutableConfigError, "cannot downgrade"):
            validate_config_transition(candidate, baseline)

    def _typed_config(self) -> dict[str, object]:
        parsed = parse_supportability_config_bytes(self.v1_bytes, suffix=".yml")
        parsed = copy.deepcopy(parsed)
        parsed.pop("required_gates")
        parsed["schema_version"] = "2.0"
        parsed["capabilities"] = copy.deepcopy(TYPED_CAPABILITIES)
        return parsed

    def _validate(self, raw: bytes) -> dict[str, object]:
        return validate_executable_supportability_config_bytes(
            raw,
            repository_full_name=REPOSITORY,
            path=CONFIG_PATH,
        )

    @staticmethod
    def _json_bytes(value: dict[str, object]) -> bytes:
        return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


if __name__ == "__main__":
    unittest.main()
