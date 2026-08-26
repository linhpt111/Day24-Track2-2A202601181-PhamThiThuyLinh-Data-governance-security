"""Policy enforcement point for tool calls."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool


def check(context: PolicyContext) -> tuple[bool, str]:
    if context.data_classification == "restricted" and context.egress_enabled:
        return False, "restricted data cannot be used when egress is enabled"
    if context.delegation_depth > 1 and context.egress_enabled:
        return False, "delegated agent egress is not allowed"
    return (
        True,
        f"allowed {context.data_classification} data for {context.request_purpose} by {context.agent_owner}",
    )
