"""Offline tests for Immunis security foundations."""

import json
import unittest

from immunis.policy import Action, PolicyGate
from immunis.provenance import ProvenanceStore
from immunis.quarantine import (
    ModelResponse,
    QuarantineEngine,
    QuarantineError,
)
from immunis.schemas import (
    ValidationError,
    parse_quarantine_json,
)


class FakeModel:
    """Deterministic fake model with no network calls or API costs."""

    def __init__(self, response_text: str) -> None:
        self.response_text = response_text
        self.calls = 0

    def analyze(self, source_id: str, content: str) -> ModelResponse:
        self.calls += 1
        return ModelResponse(self.response_text)


class QuarantineSchemaTests(unittest.TestCase):
    def setUp(self) -> None:
        self.valid_payload = {
            "source_id": "source_1",
            "content_type": "email",
            "summary": "A harmless test email.",
            "claims": [
                {
                    "text": "The meeting starts at noon.",
                    "kind": "fact",
                    "confidence": 0.95,
                }
            ],
        }

    def test_valid_result_is_accepted(self) -> None:
        result = parse_quarantine_json(
            json.dumps(self.valid_payload),
            expected_source_id="source_1",
        )

        self.assertEqual(result["source_id"], "source_1")
        self.assertEqual(len(result["claims"]), 1)

    def test_malformed_json_is_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            parse_quarantine_json(
                "{not valid json",
                expected_source_id="source_1",
            )

    def test_source_id_mismatch_is_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            parse_quarantine_json(
                json.dumps(self.valid_payload),
                expected_source_id="different_source",
            )

    def test_unexpected_field_is_rejected(self) -> None:
        payload = dict(self.valid_payload)
        payload["execute_instruction"] = True

        with self.assertRaises(ValidationError):
            parse_quarantine_json(
                json.dumps(payload),
                expected_source_id="source_1",
            )

    def test_invalid_confidence_is_rejected(self) -> None:
        payload = dict(self.valid_payload)
        payload["claims"] = [
            {
                "text": "A test claim.",
                "kind": "fact",
                "confidence": 4.5,
            }
        ]

        with self.assertRaises(ValidationError):
            parse_quarantine_json(
                json.dumps(payload),
                expected_source_id="source_1",
            )


class ProvenanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = ProvenanceStore()

        self.store.add_source(
            source_id="source_1",
            kind="webpage",
            uri="https://evil.test/fixture",
            trust="untrusted",
        )

        self.store.add_fact(
            fact_id="fact_1",
            text="A claim from the webpage.",
            kind="fact",
            trust="untrusted",
            parent_ids=["source_1"],
            parent_type="source",
        )

        self.store.add_fact(
            fact_id="fact_2",
            text="A derived claim.",
            kind="fact",
            trust="untrusted",
            parent_ids=["fact_1"],
            parent_type="fact",
        )

    def tearDown(self) -> None:
        self.store.close()

    def test_active_fact_is_retrievable(self) -> None:
        fact = self.store.get_fact("fact_1")

        self.assertIsNotNone(fact)
        self.assertEqual(fact["text"], "A claim from the webpage.")

    def test_revocation_cascades_to_derived_facts(self) -> None:
        revoked = self.store.revoke_source("source_1")

        self.assertEqual(set(revoked), {"fact_1", "fact_2"})
        self.assertIsNone(self.store.get_fact("fact_1"))
        self.assertIsNone(self.store.get_fact("fact_2"))
        self.assertEqual(self.store.list_active_facts(), [])

    def test_fact_without_parent_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.store.add_fact(
                fact_id="orphan",
                text="No source.",
                kind="fact",
                trust="trusted",
                parent_ids=[],
            )


class PolicyGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.gate = PolicyGate(
            allowed_external_recipients={"safe@example.test"}
        )

    def test_allowlisted_read_only_action_is_allowed(self) -> None:
        decision = self.gate.evaluate(
            Action(
                tool="read_email",
                args={"mailbox": "fixture"},
            ),
            fact_trust={},
        )

        self.assertEqual(decision.status, "allow")

    def test_unknown_tool_is_denied(self) -> None:
        decision = self.gate.evaluate(
            Action(
                tool="send_money",
                args={"amount": 10},
            ),
            fact_trust={},
        )

        self.assertEqual(decision.status, "deny")

    def test_tainted_fact_cannot_authorize_read_action(self) -> None:
        decision = self.gate.evaluate(
            Action(
                tool="web_search",
                args={"query": "weather"},
                based_on=("fact_bad",),
            ),
            fact_trust={"fact_bad": "untrusted"},
        )

        self.assertEqual(decision.status, "deny")

    def test_email_draft_requires_approval(self) -> None:
        decision = self.gate.evaluate(
            Action(
                tool="draft_email",
                args={
                    "to": "safe@example.test",
                    "body": "A harmless test draft.",
                },
            ),
            fact_trust={},
        )

        self.assertEqual(decision.status, "ask_user")
        self.assertTrue(decision.requires_approval)

    def test_unknown_fact_is_denied(self) -> None:
        decision = self.gate.evaluate(
            Action(
                tool="read_file",
                args={"path": "fixture.txt"},
                based_on=("missing_fact",),
            ),
            fact_trust={},
        )

        self.assertEqual(decision.status, "deny")


class QuarantineEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = ProvenanceStore()

        self.payload = {
            "source_id": "quarantine_source",
            "content_type": "webpage",
            "summary": "A test webpage.",
            "claims": [
                {
                    "text": "The page contains a test claim.",
                    "kind": "fact",
                    "confidence": 0.9,
                }
            ],
        }

        self.model = FakeModel(json.dumps(self.payload))
        self.engine = QuarantineEngine(self.model, self.store)

    def tearDown(self) -> None:
        self.store.close()

    def test_valid_content_is_processed_and_stored_as_untrusted(self) -> None:
        result = self.engine.process(
            source_id="quarantine_source",
            content="A harmless fixture page.",
        )

        self.assertEqual(result.claim_count, 1)

        fact = self.store.get_fact("quarantine_source_fact_1")

        self.assertIsNotNone(fact)
        self.assertEqual(fact["trust"], "untrusted")

    def test_invalid_model_json_stores_no_facts(self) -> None:
        model = FakeModel("not JSON")
        engine = QuarantineEngine(model, self.store)

        with self.assertRaises(QuarantineError):
            engine.process("bad_source", "Fixture content.")

        self.assertEqual(self.store.list_active_facts(), [])

    def test_empty_content_is_rejected(self) -> None:
        with self.assertRaises(QuarantineError):
            self.engine.process("empty_source", "  ")

        self.assertEqual(self.model.calls, 0)

    def test_content_limit_is_enforced(self) -> None:
        engine = QuarantineEngine(
            self.model,
            self.store,
            max_content_chars=5,
        )

        with self.assertRaises(QuarantineError):
            engine.process("large_source", "123456")

        self.assertEqual(self.model.calls, 0)

    def test_source_mismatch_fails_closed(self) -> None:
        payload = dict(self.payload)
        payload["source_id"] = "some_other_source"

        model = FakeModel(json.dumps(payload))
        engine = QuarantineEngine(model, self.store)

        with self.assertRaises(QuarantineError):
            engine.process("expected_source", "Fixture content.")

        self.assertEqual(self.store.list_active_facts(), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)