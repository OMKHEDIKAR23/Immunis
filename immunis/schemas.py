"""Strict schemas and validation for Immunis quarantine output."""

from __future__ import annotations

import json
from typing import Any


MAX_JSON_CHARS = 20_000
MAX_SUMMARY_CHARS = 2_000
MAX_CLAIMS = 50
MAX_CLAIM_CHARS = 1_000

ALLOWED_TOP_LEVEL_KEYS = {
    "source_id",
    "content_type",
    "summary",
    "claims",
}

ALLOWED_CLAIM_KEYS = {
    "text",
    "kind",
    "confidence",
}

ALLOWED_CONTENT_TYPES = {
    "email",
    "webpage",
    "document",
    "file",
    "tool_result",
    "other",
}

ALLOWED_CLAIM_KINDS = {
    "fact",
    "instruction",
    "request",
    "opinion",
    "unknown",
}


class ValidationError(ValueError):
    """Raised when untrusted model output fails validation."""


def _require_string(
    value: Any,
    field_name: str,
    max_length: int,
) -> str:
    """Validate a non-empty string with a maximum length."""

    if not isinstance(value, str):
        raise ValidationError(f"{field_name} must be a string.")

    value = value.strip()

    if not value:
        raise ValidationError(f"{field_name} cannot be empty.")

    if len(value) > max_length:
        raise ValidationError(
            f"{field_name} exceeds {max_length} characters."
        )

    return value


def validate_quarantine_result(
    payload: Any,
    expected_source_id: str,
) -> dict[str, Any]:
    """
    Validate the structured output of the quarantine model.

    This function validates structure, not truth. A valid result may
    still contain false or malicious claims.
    """

    if not isinstance(payload, dict):
        raise ValidationError("The result must be a JSON object.")

    unexpected_keys = set(payload) - ALLOWED_TOP_LEVEL_KEYS
    missing_keys = ALLOWED_TOP_LEVEL_KEYS - set(payload)

    if unexpected_keys:
        raise ValidationError(
            f"Unexpected top-level keys: {sorted(unexpected_keys)}"
        )

    if missing_keys:
        raise ValidationError(
            f"Missing top-level keys: {sorted(missing_keys)}"
        )

    source_id = _require_string(
        payload["source_id"],
        "source_id",
        100,
    )

    if source_id != expected_source_id:
        raise ValidationError("The source ID does not match.")

    content_type = _require_string(
        payload["content_type"],
        "content_type",
        30,
    )

    if content_type not in ALLOWED_CONTENT_TYPES:
        raise ValidationError("Unsupported content_type.")

    summary = _require_string(
        payload["summary"],
        "summary",
        MAX_SUMMARY_CHARS,
    )

    claims = payload["claims"]

    if not isinstance(claims, list):
        raise ValidationError("claims must be a list.")

    if len(claims) > MAX_CLAIMS:
        raise ValidationError("Too many claims.")

    validated_claims: list[dict[str, Any]] = []

    for index, claim in enumerate(claims):
        if not isinstance(claim, dict):
            raise ValidationError(
                f"Claim {index} must be a JSON object."
            )

        unexpected_claim_keys = set(claim) - ALLOWED_CLAIM_KEYS
        missing_claim_keys = ALLOWED_CLAIM_KEYS - set(claim)

        if unexpected_claim_keys:
            raise ValidationError(
                f"Claim {index} has unexpected keys."
            )

        if missing_claim_keys:
            raise ValidationError(
                f"Claim {index} is missing required keys."
            )

        text = _require_string(
            claim["text"],
            f"claims[{index}].text",
            MAX_CLAIM_CHARS,
        )

        kind = _require_string(
            claim["kind"],
            f"claims[{index}].kind",
            30,
        )

        if kind not in ALLOWED_CLAIM_KINDS:
            raise ValidationError(
                f"Claim {index} has an unsupported kind."
            )

        confidence = claim["confidence"]

        # bool is a subclass of int in Python, so reject it explicitly.
        if isinstance(confidence, bool) or not isinstance(
            confidence, (int, float)
        ):
            raise ValidationError(
                f"Claim {index} confidence must be numeric."
            )

        if not 0.0 <= confidence <= 1.0:
            raise ValidationError(
                f"Claim {index} confidence must be between 0 and 1."
            )

        validated_claims.append(
            {
                "text": text,
                "kind": kind,
                "confidence": float(confidence),
            }
        )

    return {
        "source_id": source_id,
        "content_type": content_type,
        "summary": summary,
        "claims": validated_claims,
    }


def parse_quarantine_json(
    raw_text: str,
    expected_source_id: str,
) -> dict[str, Any]:
    """Parse JSON and reject malformed or structurally invalid output."""

    if not isinstance(raw_text, str):
        raise ValidationError("Model output must be text.")

    if not raw_text.strip():
        raise ValidationError("Model output is empty.")

    if len(raw_text) > MAX_JSON_CHARS:
        raise ValidationError("Model output is too large.")

    try:
        payload = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise ValidationError("Model output is not valid JSON.") from exc

    return validate_quarantine_result(
        payload,
        expected_source_id=expected_source_id,
    )