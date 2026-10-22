"""The gateway core, shared by every front-end.

One host identity, one audit log, one policy resolution path, one decision
engine. The CLI and the MCP server both come through here so a fix to the
boundary cannot land in one front-end and be missed in the other.

Nothing in this module prints or exits. Front-ends decide how a failure is
presented: the CLI renders a panel and exits 2, the MCP server returns an
error result. A security core that calls sys.exit() cannot be embedded.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from audit import AuditLogger
from approval import ApprovalStore
from evidence import EvidenceError, HostIdentity, load_or_create_identity
from policy import Policy, discover_policy, load_policy
from risk_engine import classify_command, classify_tool_call, inspect_prompt

PRODUCT_DIR = ".local/state/linux-ai-ssm"

__all__ = [
    "EvidenceError",
    "GatewayError",
    "GatewayState",
    "Policy",
    "approval_database_path",
    "audit_database_path",
    "decide_command",
    "decide_tool_call",
    "gateway_state",
    "reset_state_for_tests",
    "resolve_policy",
    "screen_prompt",
]


class GatewayError(Exception):
    """Any failure that must stop the front-end from deciding anything."""


@dataclass(frozen=True)
class GatewayState:
    identity: HostIdentity
    audit: AuditLogger
    # None on a hand-built state (tests, embedded use); the store is created
    # on first access so merely loading the CLI creates no ledger file.
    approvals: ApprovalStore | None = None


_STATE: GatewayState | None = None


def audit_database_path() -> Path:
    return Path.home() / PRODUCT_DIR / "audit.sqlite3"


def approval_database_path() -> Path:
    return Path.home() / PRODUCT_DIR / "approvals.sqlite3"


def gateway_state() -> GatewayState:
    """Load the host identity and open the audit log, once per process.

    Raises EvidenceError when the identity directory is half-present. Writing
    unsigned rows in that state would produce evidence that looks trustworthy
    and is not, so the caller must fail closed.
    """
    global _STATE

    if _STATE is None:
        identity = load_or_create_identity()
        _STATE = GatewayState(
            identity,
            AuditLogger(audit_database_path(), identity),
            ApprovalStore(approval_database_path()),
        )
    return _STATE


def reset_state_for_tests(state: GatewayState | None = None) -> None:
    """Swap or clear the singleton so tests never touch the real log."""
    global _STATE
    _STATE = state


def resolve_policy(explicit: str | Path | None = None) -> Policy:
    """Load the operator policy. Raises PolicyError if it cannot be trusted."""
    if explicit:
        return load_policy(explicit)

    found = discover_policy()
    if found is None:
        from policy import DEFAULT_POLICY

        return DEFAULT_POLICY

    return load_policy(found)


# ============================================================
# DECISIONS
# ============================================================

def screen_prompt(text: str, policy: Policy) -> dict:
    return inspect_prompt(text, policy)


def decide_command(command: str, policy: Policy) -> dict:
    return classify_command(command, policy=policy)


def decide_tool_call(name: str, arguments: dict[str, Any], policy: Policy) -> dict:
    return classify_tool_call(name, arguments, policy)


def rule_suffix(decision: dict) -> str:
    """Every refusal names the rule that produced it, everywhere."""
    rule_id = decision.get("rule_id") or ""
    return f" [rule {rule_id}]" if rule_id else ""
