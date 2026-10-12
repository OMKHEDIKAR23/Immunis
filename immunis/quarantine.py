"""Quarantine untrusted content before it reaches the planner."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from immunis.provenance import ProvenanceStore
from immunis.schemas import ValidationError, parse_quarantine_json


@dataclass(frozen=True)
class ModelResponse:
    """Raw response returned by a quarantine model client."""

    text: str


class QuarantineModel(Protocol):
    """Interface implemented by real and fake model clients."""

    def analyze(self, source_id: str, content: str) -> ModelResponse:
        """Analyze untrusted content and return structured text."""
        ...


@dataclass(frozen=True)
class QuarantineResult:
    """Validated output from the quarantine pipeline."""

    source_id: str
    summary: str
    fact_ids: tuple[str, ...]
    claim_count: int


class QuarantineError(RuntimeError):
    """Raised when quarantine cannot safely process content."""


class QuarantineEngine:
    """Process untrusted content through a model and strict validation."""

    def __init__(
        self,
        model: QuarantineModel,
        store: ProvenanceStore,
        max_content_chars: int = 20_000,
    ) -> None:
        if max_content_chars <= 0:
            raise ValueError("max_content_chars must be positive.")

        self.model = model
        self.store = store
        self.max_content_chars = max_content_chars

    def process(
        self,
        source_id: str,
        content: str,
        source_kind: str = "document",
        source_uri: str = "fixture://untrusted-content",
    ) -> QuarantineResult:
        """Analyze, validate, and store untrusted content."""

        if not isinstance(source_id, str) or not source_id.strip():
            raise QuarantineError("A valid source ID is required.")

        if not isinstance(content, str) or not content.strip():
            raise QuarantineError("Content must be a non-empty string.")

        if len(content) > self.max_content_chars:
            raise QuarantineError("Content exceeds the configured limit.")

        # Register the original content as untrusted.
        self.store.add_source(
            source_id=source_id,
            kind=source_kind,
            uri=source_uri,
            trust="untrusted",
        )

        try:
            response = self.model.analyze(source_id, content)

            if not isinstance(response, ModelResponse):
                raise QuarantineError(
                    "The model client returned an invalid response type."
                )

            validated = parse_quarantine_json(
                response.text,
                expected_source_id=source_id,
            )

        except (ValidationError, ValueError, TypeError) as exc:
            raise QuarantineError(
                "Quarantine rejected the model response."
            ) from exc

        fact_ids: list[str] = []

        try:
            for index, claim in enumerate(validated["claims"], start=1):
                fact_id = f"{source_id}_fact_{index}"

                self.store.add_fact(
                    fact_id=fact_id,
                    text=claim["text"],
                    kind=claim["kind"],
                    trust="untrusted",
                    parent_ids=[source_id],
                    parent_type="source",
                )

                fact_ids.append(fact_id)

        except (ValueError, TypeError) as exc:
            # Revoke the source so any stored claims become unavailable.
            self.store.revoke_source(source_id)

            raise QuarantineError(
                "Quarantine could not safely store its claims."
            ) from exc

        return QuarantineResult(
            source_id=source_id,
            summary=validated["summary"],
            fact_ids=tuple(fact_ids),
            claim_count=len(fact_ids),
        )