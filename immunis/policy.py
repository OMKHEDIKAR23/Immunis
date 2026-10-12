"""Deterministic action policy gate for Immunis."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


READ_ONLY_TOOLS = {
    "read_email",
    "web_search",
    "read_file",
    "calendar_lookup",
}

APPROVAL_REQUIRED_TOOLS = {
    "draft_email",
    "save_memory",
}


@dataclass(frozen=True)
class Action:
    """A proposed tool action from the planner."""

    tool: str
    args: dict[str, Any]
    based_on: tuple[str, ...] = ()


@dataclass(frozen=True)
class Decision:
    """A policy decision that must be logged by the caller."""

    status: str
    reason: str
    requires_approval: bool = False


class PolicyGate:
    """
    Evaluate proposed actions without relying on model judgment.

    This initial version deliberately uses a small tool allowlist.
    """

    def __init__(
        self,
        allowed_external_recipients: set[str] | None = None,
    ) -> None:
        self.allowed_external_recipients = (
            allowed_external_recipients or set()
        )

    def evaluate(
        self,
        action: Action,
        fact_trust: dict[str, str],
    ) -> Decision:
        """Return allow, deny, or ask_user."""

        if not isinstance(action.tool, str) or not action.tool:
            return Decision("deny", "Invalid tool name.")

        if not isinstance(action.args, dict):
            return Decision("deny", "Action arguments must be an object.")

        if not isinstance(action.based_on, tuple):
            return Decision(
                "deny",
                "based_on must be a tuple of fact IDs.",
            )

        known_tools = READ_ONLY_TOOLS | APPROVAL_REQUIRED_TOOLS

        if action.tool not in known_tools:
            return Decision(
                "deny",
                f"Tool {action.tool!r} is not allowlisted.",
            )

        for fact_id in action.based_on:
            if fact_id not in fact_trust:
                return Decision(
                    "deny",
                    f"Unknown provenance fact: {fact_id}.",
                )

        if action.tool == "draft_email":
            recipient = action.args.get("to")

            if not isinstance(recipient, str) or not recipient.strip():
                return Decision(
                    "deny",
                    "Email draft requires a valid recipient field.",
                )

            if recipient not in self.allowed_external_recipients:
                return Decision(
                    "ask_user",
                    "Recipient is not on the external-recipient allowlist.",
                    requires_approval=True,
                )

        tainted_facts = [
            fact_id
            for fact_id in action.based_on
            if fact_trust[fact_id] != "trusted"
        ]

        if tainted_facts:
            if action.tool in APPROVAL_REQUIRED_TOOLS:
                return Decision(
                    "ask_user",
                    "Action depends on untrusted information: "
                    + ", ".join(tainted_facts),
                    requires_approval=True,
                )

            return Decision(
                "deny",
                "Untrusted information cannot authorize this action.",
            )

        if action.tool in APPROVAL_REQUIRED_TOOLS:
            return Decision(
                "ask_user",
                "This action requires explicit user approval.",
                requires_approval=True,
            )

        return Decision("allow", "Read-only allowlisted action.")