"""Approval as a signed, single-use artifact instead of a transient "yes".

Before this module a human pressing Enter *was* the whole authorisation. The
CLI then wrote an audit row asserting that an approval had happened, but
nothing bound that assertion to the exact bytes that ran, nothing stopped a
second execution from claiming the same consent, and no other process could
check the claim without trusting the log.

Here an approval is an object with a lifecycle:

    request   the gateway classifies one exact command and opens a request
    mint      a human at this terminal re-confirms those bytes; the host
              Ed25519 key signs a token bound to them, to the policy
              fingerprint in force, to this host, to this actor, and to a
              deadline
    redeem    verification, then exactly one execution

Two rules make the token worth having, and neither is configurable:

* **Only a human mints.** ``mint_token`` takes a ``confirm`` callable and
  refuses without a true from it, and it needs the host *private* key. An
  agent-facing front-end can open a request and report its id; it cannot turn
  that into an approval. In strict mode nothing in the conversational path
  executes at all: a token has to be handed in from outside.
* **A token is one execution and no substitution.** Redemption re-hashes the
  command being run and compares it to the digest inside the signed core,
  re-classifies it against the policy loaded *now*, refuses an expired or
  already-consumed token, and refuses a token whose signature came from
  another host or was minted for another actor. Changing one character of the
  approved command invalidates it.

Nothing in this module prints, and nothing here writes an audit row: the
front-end that owns the log records the outcome, the same way it does for a
decision. Every refusal path in here is written so a caller can log it as a
signed row, which means "someone tried to reuse an approval" is provable
evidence rather than a log line nobody kept.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import secrets
import sqlite3
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from evidence import (
    canonical_json,
    policy_fingerprint,
    sha256_hex,
    sign_payload,
    verify_signature,
)
from risk_engine import classify_command

TOKEN_PREFIX = "ssm-approval-1-"
TOKEN_MAX_CHARS = 4096
SUBJECT_MAX_CHARS = 512

# An approval is short-lived and the ceiling is not negotiable. A policy may
# lower it; an agent that asks for a longer window is capped here instead of
# being refused in the middle of a task.
FLOOR_MAX_TTL_SECONDS = 900
DEFAULT_TTL_SECONDS = 120

# The built-in floor already requires human approval to leave a signed trace.
# "off" is deliberately absent: a policy file may tighten, never loosen.
APPROVAL_MODES = ("interactive", "strict")

STATES = ("open", "minted", "redeemed", "void", "expired")

# (subject, decision, ttl_seconds) -> True when the human consents.
Confirm = Callable[[str, dict, int], bool]

_CORE_KEYS = (
    "v", "request_id", "nonce", "subject_sha", "decision", "policy_sha",
    "key_id", "hostname", "actor", "requested_by", "issued_at", "expires_at",
)

_COLUMNS = (
    "request_id", "nonce", "subject", "subject_sha", "decision_json",
    "policy_sha", "key_id", "hostname", "actor", "requested_by", "issued_at",
    "expires_at", "state", "token_sha", "minted_at", "redeemed_at",
    "void_reason",
)


class ApprovalError(Exception):
    """Raised for any approval problem. Callers must not execute."""


def _utc(value: datetime | None) -> datetime:
    moment = value if value is not None else datetime.now(timezone.utc)
    if moment.tzinfo is None:
        return moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


def _iso(moment: datetime) -> str:
    return _utc(moment).isoformat()


def _parse(text: str, what: str) -> datetime:
    try:
        return _utc(datetime.fromisoformat(text))
    except (TypeError, ValueError) as exc:
        raise ApprovalError(f"{what} is not a valid timestamp: {text!r}") from exc


def _seconds_between(early: str, late: str) -> int:
    return int(round((_parse(late, "expires_at") - _parse(early, "issued_at")).total_seconds()))


def effective_ttl(policy: Any, requested: int | None = None) -> int:
    """The shortest of what was asked for, what the policy allows, and the floor."""
    base = getattr(policy, "approval_ttl", DEFAULT_TTL_SECONDS)
    candidates = [DEFAULT_TTL_SECONDS, int(base), FLOOR_MAX_TTL_SECONDS]
    if type(requested) is int and requested > 0:
        candidates.append(requested)
    return max(1, min(candidates))


def mode_for(policy: Any) -> str:
    return getattr(policy, "approval_mode", "interactive") or "interactive"


# ============================================================
# STORE
# ============================================================

class ApprovalStore:
    """The approval ledger: one row per request, transitions guarded by state.

    Deliberately a separate file from the audit log. The audit log is
    append-only evidence; this is operational state that legitimately changes,
    and mixing the two would let a state update look like an edit to history.
    """

    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path).expanduser().resolve()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
        if os.name != "nt":
            try:
                os.chmod(self.db_path, 0o600)
            except OSError:
                pass

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(str(self.db_path))
        db.execute("PRAGMA journal_mode = WAL")
        db.execute("PRAGMA busy_timeout = 5000")
        return db

    def _init_db(self) -> None:
        with closing(self._connect()) as db:
            with db:
                db.execute("""
                    CREATE TABLE IF NOT EXISTS approvals (
                        request_id TEXT PRIMARY KEY,
                        nonce TEXT NOT NULL UNIQUE,
                        subject TEXT NOT NULL,
                        subject_sha TEXT NOT NULL,
                        decision_json TEXT NOT NULL,
                        policy_sha TEXT NOT NULL,
                        key_id TEXT NOT NULL,
                        hostname TEXT NOT NULL,
                        actor TEXT NOT NULL,
                        requested_by TEXT NOT NULL,
                        issued_at TEXT NOT NULL,
                        expires_at TEXT NOT NULL,
                        state TEXT NOT NULL,
                        token_sha TEXT NOT NULL DEFAULT '',
                        minted_at TEXT NOT NULL DEFAULT '',
                        redeemed_at TEXT NOT NULL DEFAULT '',
                        void_reason TEXT NOT NULL DEFAULT ''
                    )
                """)

    def create(self, row: dict) -> None:
        with closing(self._connect()) as db:
            with db:
                db.execute(
                    f"INSERT INTO approvals ({', '.join(_COLUMNS)}) "
                    f"VALUES ({', '.join('?' for _ in _COLUMNS)})",
                    tuple(row[column] for column in _COLUMNS),
                )

    def get(self, *, request_id: str = "", nonce: str = "") -> dict | None:
        if request_id:
            clause, value = "request_id = ?", request_id
        elif nonce:
            clause, value = "nonce = ?", nonce
        else:
            raise ApprovalError("get() needs a request_id or a nonce")
        with closing(self._connect()) as db:
            db.row_factory = sqlite3.Row
            found = db.execute(
                f"SELECT {', '.join(_COLUMNS)} FROM approvals WHERE {clause}",
                (value,),
            ).fetchone()
        return dict(found) if found is not None else None

    def list(self, *, states: tuple[str, ...] | None = None, limit: int = 20) -> list[dict]:
        limit = max(1, min(int(limit), 200))
        with closing(self._connect()) as db:
            db.row_factory = sqlite3.Row
            if states:
                placeholders = ", ".join("?" for _ in states)
                rows = db.execute(
                    f"SELECT {', '.join(_COLUMNS)} FROM approvals "
                    f"WHERE state IN ({placeholders}) ORDER BY issued_at DESC LIMIT ?",
                    (*states, limit),
                ).fetchall()
            else:
                rows = db.execute(
                    f"SELECT {', '.join(_COLUMNS)} FROM approvals "
                    "ORDER BY issued_at DESC LIMIT ?",
                    (limit,),
                ).fetchall()
        return [dict(row) for row in rows]

    def transition(
        self,
        nonce: str,
        *,
        from_states: tuple[str, ...],
        to_state: str,
        now: datetime | None = None,
        token_sha: str = "",
        reason: str = "",
    ) -> bool:
        """Move one row forward, and report whether this call is the one that did it.

        The WHERE clause carries the previous state, so two simultaneous
        redeemers cannot both see a success: single-use is enforced by the
        database, not by an if-statement that read the state a moment before.
        """
        if to_state not in STATES:
            raise ApprovalError(f"unknown approval state {to_state!r}")
        moment = _iso(_utc(now))
        assignments = ["state = ?"]
        values: list[Any] = [to_state]
        if to_state == "minted":
            assignments.append("minted_at = ?")
            values.append(moment)
        if to_state == "redeemed":
            assignments.append("redeemed_at = ?")
            values.append(moment)
        if to_state == "void":
            assignments.append("void_reason = ?")
            values.append(reason[:300])
        if token_sha:
            assignments.append("token_sha = ?")
            values.append(token_sha)

        placeholders = ", ".join("?" for _ in from_states)
        values.extend([nonce, *from_states])
        with closing(self._connect()) as db:
            with db:
                cursor = db.execute(
                    f"UPDATE approvals SET {', '.join(assignments)} "
                    f"WHERE nonce = ? AND state IN ({placeholders})",
                    values,
                )
                return cursor.rowcount == 1

    def expire_stale(self, now: datetime | None = None) -> int:
        """Mark past-deadline rows expired so a listing cannot offer them back."""
        moment = _utc(now)
        moved = 0
        with closing(self._connect()) as db:
            with db:
                rows = db.execute(
                    "SELECT nonce, expires_at, state FROM approvals "
                    "WHERE state IN ('open', 'minted')"
                ).fetchall()
                for nonce, expires_at, _state in rows:
                    if _parse(expires_at, "expires_at") <= moment:
                        if self.transition(nonce, from_states=("open", "minted"),
                                           to_state="expired", now=moment):
                            moved += 1
        return moved

    def counts(self) -> dict[str, int]:
        with closing(self._connect()) as db:
            rows = db.execute(
                "SELECT state, COUNT(*) FROM approvals GROUP BY state"
            ).fetchall()
        found = dict(rows)
        return {state: int(found.get(state, 0)) for state in STATES}


# ============================================================
# REQUEST
# ============================================================

def _brief_decision(decision: dict) -> dict:
    return {
        "category": str(decision["category"]),
        "score": int(decision["score"]),
        "rule_id": str(decision.get("rule_id", "")),
        "reason": str(decision["reason"]),
    }


def _requester_kind(requested_by: str) -> str:
    """The plane a request arrived on, ignoring which client named itself.

    The MCP facade decorates this field with the connecting client ("mcp via
    Qoder") so the ledger says who asked, not merely how. Strict mode gates on
    the plane, so it reads the leading word; anything that is not ``cli`` or
    ``mcp`` stays unknown and stays refused.
    """
    return requested_by.split(maxsplit=1)[0].lower() if requested_by.strip() else ""


def request_approval(
    subject: str,
    policy: Any,
    identity: Any,
    store: ApprovalStore,
    *,
    ttl_seconds: int | None = None,
    requested_by: str = "cli",
    now: datetime | None = None,
) -> dict:
    """Open an approval for one exact command string.

    A command the gateway would never allow cannot even get a request opened,
    so an agent cannot queue up a destructive command and then shop for a
    human willing to approve it.
    """
    if not isinstance(subject, str) or not subject.strip():
        raise ApprovalError("an approval needs a non-empty command string")
    cleaned = subject.strip()
    if len(cleaned) > SUBJECT_MAX_CHARS:
        raise ApprovalError(
            f"command is longer than {SUBJECT_MAX_CHARS} characters; approvals "
            "cover one short, reviewable command"
        )
    if mode_for(policy) == "strict" and _requester_kind(requested_by) not in ("cli", "mcp"):
        raise ApprovalError(f"unknown requester {requested_by!r}")

    decision = classify_command(cleaned, policy=policy)
    if decision["blocked"]:
        raise ApprovalError(
            f"the gateway would block this command, so there is nothing to "
            f"approve: {decision['reason']} [rule {decision['rule_id']}]"
        )

    moment = _utc(now)
    ttl = effective_ttl(policy, ttl_seconds)
    row = {
        "request_id": "req-" + secrets.token_hex(4),
        "nonce": secrets.token_hex(16),
        "subject": cleaned,
        "subject_sha": sha256_hex(canonical_json({"command": cleaned})),
        "decision_json": canonical_json(_brief_decision(decision)),
        "policy_sha": policy_fingerprint(policy),
        "key_id": identity.key_id,
        "hostname": identity.hostname,
        "actor": identity.actor,
        "requested_by": requested_by,
        "issued_at": _iso(moment),
        "expires_at": _iso(moment + timedelta(seconds=ttl)),
        "state": "open",
        "token_sha": "",
        "minted_at": "",
        "redeemed_at": "",
        "void_reason": "",
    }
    store.create(row)
    return row


# ============================================================
# MINT
# ============================================================

def _encode(core: dict, signature: str) -> str:
    blob = canonical_json({"core": core, "signature": signature})
    body = base64.urlsafe_b64encode(blob.encode("utf-8")).decode("ascii")
    return TOKEN_PREFIX + body.rstrip("=")


def _decode(token: str) -> tuple[dict, str]:
    if not isinstance(token, str):
        raise ApprovalError("an approval token must be a string")
    text = token.strip()
    if not text.startswith(TOKEN_PREFIX):
        raise ApprovalError(
            "this is not an approval token; one starts with "
            f"{TOKEN_PREFIX!r}"
        )
    body = text[len(TOKEN_PREFIX):]
    if not body or len(body) > TOKEN_MAX_CHARS:
        raise ApprovalError("approval token is empty or oversized")
    try:
        raw = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
    except (binascii.Error, ValueError) as exc:
        raise ApprovalError(f"approval token is not valid base64: {exc}") from exc
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ApprovalError(f"approval token payload is not readable JSON: {exc}") from exc
    if not isinstance(parsed, dict) or not isinstance(parsed.get("core"), dict):
        raise ApprovalError("approval token payload has no core section")
    signature = parsed.get("signature")
    if not isinstance(signature, str) or not signature:
        raise ApprovalError("approval token carries no signature")
    return parsed["core"], signature


def _validate_core(core: dict) -> None:
    missing = [key for key in _CORE_KEYS if key not in core]
    if missing:
        raise ApprovalError(
            "approval token is missing signed field(s): " + ", ".join(missing)
        )
    if int(core["v"]) != 1:
        raise ApprovalError(
            f"approval token version {core['v']!r} is not understood by this build"
        )
    for key in ("request_id", "nonce", "subject_sha", "policy_sha", "key_id",
                "hostname", "actor", "requested_by", "issued_at", "expires_at"):
        if not isinstance(core[key], str) or not core[key]:
            raise ApprovalError(f"approval token field {key!r} is not a string")
    if not isinstance(core["decision"], dict):
        raise ApprovalError("approval token decision is not an object")


def mint_token(
    request_id: str,
    policy: Any,
    identity: Any,
    store: ApprovalStore,
    *,
    confirm: Confirm,
    now: datetime | None = None,
) -> dict:
    """Turn an open request into a signed token, or refuse without touching state.

    ``confirm`` is the human. It receives the exact command bytes, the
    decision that was made about them, and how long the approval will last,
    and minting stops the moment it does not return a true.
    """
    if not identity.has_private_key:
        raise ApprovalError(
            "this host has no private key, so an approval could not be signed. "
            "Install 'cryptography' or restore the identity directory; an "
            "unsigned approval is not evidence."
        )

    row = store.get(request_id=request_id)
    if row is None:
        raise ApprovalError(
            f"no approval request {request_id!r} on this host. Requests do not "
            "travel between machines; ask for one here."
        )

    moment = _utc(now)
    if row["state"] != "open":
        raise ApprovalError(
            f"approval {request_id} is {row['state']}, so it cannot be minted. "
            "Only a fresh, open request can become a token."
        )
    if _parse(row["expires_at"], "expires_at") <= moment:
        store.transition(row["nonce"], from_states=("open",), to_state="expired", now=moment)
        raise ApprovalError(
            f"approval {request_id} expired at {row['expires_at']} without being "
            "approved. Open a new request."
        )
    if row["policy_sha"] != policy_fingerprint(policy):
        raise ApprovalError(
            "the policy changed after this request was opened, so the decision "
            "printed on it may no longer be true. Open a new request."
        )

    decision = classify_command(row["subject"], policy=policy)
    if decision["blocked"]:
        raise ApprovalError(
            f"the gateway no longer clears this command: {decision['reason']} "
            f"[rule {decision['rule_id']}]"
        )

    ttl = _seconds_between(row["issued_at"], row["expires_at"])
    if not confirm(row["subject"], decision, ttl):
        store.transition(row["nonce"], from_states=("open",), to_state="void",
                         reason="declined by the human at the terminal", now=moment)
        raise ApprovalError("the human declined this approval")

    core = {
        "v": 1,
        "request_id": row["request_id"],
        "nonce": row["nonce"],
        "subject_sha": row["subject_sha"],
        "decision": json.loads(row["decision_json"]),
        "policy_sha": row["policy_sha"],
        "key_id": row["key_id"],
        "hostname": row["hostname"],
        "actor": row["actor"],
        "requested_by": row["requested_by"],
        "issued_at": row["issued_at"],
        "expires_at": row["expires_at"],
    }
    token = _encode(core, sign_payload(identity, core))
    if not store.transition(row["nonce"], from_states=("open",), to_state="minted",
                            now=moment, token_sha=sha256_hex(token)):
        raise ApprovalError(
            "this request was claimed by another process a moment ago; nothing "
            "was minted twice."
        )
    return {"token": token, "request": row, "expires_at": row["expires_at"]}


# ============================================================
# REDEEM
# ============================================================

def void_request(
    request_id: str,
    store: ApprovalStore,
    *,
    reason: str = "voided by the operator",
    now: datetime | None = None,
) -> dict:
    """Cancel an approval before it can be used, permanently."""
    row = store.get(request_id=request_id)
    if row is None:
        raise ApprovalError(f"no approval request {request_id!r} on this host")
    if row["state"] not in ("open", "minted"):
        raise ApprovalError(
            f"approval {request_id} is already {row['state']}; there is nothing "
            "to void"
        )
    if not store.transition(row["nonce"], from_states=("open", "minted"),
                            to_state="void", reason=reason, now=_utc(now)):
        raise ApprovalError(
            f"approval {request_id} changed state a moment ago; nothing was voided"
        )
    return store.get(request_id=request_id) or row


def inspect_token(
    token: str,
    policy: Any,
    identity: Any,
    store: ApprovalStore,
    *,
    now: datetime | None = None,
) -> dict:
    """Read a token without consuming it: signature, binding, deadline, state."""
    core, signature = _decode(token)
    _validate_core(core)
    moment = _utc(now)
    row = store.get(nonce=core["nonce"])
    return {
        "request_id": core["request_id"],
        "minted_by_host": core["hostname"],
        "key_id": core["key_id"],
        "actor": core["actor"],
        "requested_by": core["requested_by"],
        "issued_at": core["issued_at"],
        "expires_at": core["expires_at"],
        "decision": core["decision"],
        "policy_sha": core["policy_sha"],
        "subject_sha": core["subject_sha"],
        "signature_valid": bool(verify_signature(
            identity.public_key_pem, core, signature
        )),
        "this_host": core["key_id"] == identity.key_id and core["hostname"] == identity.hostname,
        "policy_matches_now": core["policy_sha"] == policy_fingerprint(policy),
        "expired": _parse(core["expires_at"], "expires_at") <= moment,
        "stored_state": row["state"] if row else "no record on this host",
        "command": row["subject"] if row else "",
    }


def redeem_token(
    token: str,
    subject: str,
    policy: Any,
    identity: Any,
    store: ApprovalStore,
    *,
    now: datetime | None = None,
) -> dict:
    """Spend a token on one exact command, once. Raises ApprovalError otherwise.

    The order is deliberate: everything cryptographic and policy-related is
    checked before the ledger is touched, and the ledger itself is the last
    gate, because it is the only one that can be raced.
    """
    moment = _utc(now)
    core, signature = _decode(token)
    _validate_core(core)

    if not verify_signature(identity.public_key_pem, core, signature):
        raise ApprovalError(
            "this token's signature does not validate against this host's key. "
            "Either it was not minted here or it was altered after minting."
        )
    if core["key_id"] != identity.key_id or core["hostname"] != identity.hostname:
        raise ApprovalError(
            f"this approval was minted on {core['hostname']} ({core['key_id']}) "
            f"and this host is {identity.hostname} ({identity.key_id}). A token "
            "is not portable between machines."
        )
    if core["actor"] != identity.actor:
        raise ApprovalError(
            f"this approval was minted for actor {core['actor']!r}, and the "
            f"actor running it is {identity.actor!r}."
        )
    if sha256_hex(canonical_json({"command": subject})) != core["subject_sha"]:
        raise ApprovalError(
            "the command being run is not the command that was approved, not by "
            "one character. The approval does not cover this."
        )
    if _parse(core["expires_at"], "expires_at") <= moment:
        raise ApprovalError(
            f"this approval expired at {core['expires_at']}; consent that ran "
            "out is not consent"
        )
    if core["policy_sha"] != policy_fingerprint(policy):
        raise ApprovalError(
            "the policy in force is not the policy this approval was minted "
            f"under ({core['policy_sha'][:18]}... differs). Re-approve."
        )

    decision = classify_command(subject, policy=policy)
    if decision["blocked"]:
        raise ApprovalError(
            f"the gateway now blocks this command: {decision['reason']} "
            f"[rule {decision['rule_id']}]"
        )
    recorded = json.loads(canonical_json(_brief_decision(decision)))
    stored = json.loads(canonical_json(core["decision"]))
    if recorded != stored:
        raise ApprovalError(
            "the gateway's decision about this command changed between mint and "
            f"redeem (was {stored.get('rule_id')!r} "
            f"score {stored.get('score')}, now {recorded['rule_id']!r} "
            f"score {recorded['score']}). That is not the approval the human signed."
        )

    row = store.get(nonce=core["nonce"])
    if row is None:
        raise ApprovalError(
            f"this token is signed and well-formed but the ledger on this host "
            f"has no request {core['request_id']}. Approvals are not issued "
            "twice; nothing ran."
        )
    if row["token_sha"] != sha256_hex(token):
        raise ApprovalError(
            "this token is not the one minted for that request, even though it "
            "carries the same binding fields. Nothing ran."
        )
    if row["state"] != "minted":
        outcome = (
            "A token buys one execution, and this one has already spent it."
            if row["state"] == "redeemed"
            else "Nothing was executed, and this token will not run anything now."
        )
        raise ApprovalError(
            f"this approval is {row['state']}, so it cannot be redeemed. "
            + outcome
        )
    if not store.transition(row["nonce"], from_states=("minted",),
                            to_state="redeemed", now=moment):
        raise ApprovalError(
            "another process redeemed this approval a moment ago. Nothing was "
            "executed twice."
        )
    return {
        "request_id": core["request_id"],
        "subject": subject,
        "decision": decision,
        "redeemed_at": _iso(moment),
        "expires_at": core["expires_at"],
    }


# ============================================================
# TEXT
# ============================================================

def read_token_argument(value: str) -> str:
    """Accept a token inline, from a file with @path, or from stdin with '-'.

    A token is not a credential, but it is one-shot consent, and a shell that
    keeps history or a host that shows /proc/PID/cmdline to other users would
    leak it into places nobody meant to write it.
    """
    text = (value or "").strip()
    if not text:
        raise ApprovalError("no approval token was supplied")
    if text == "-":
        import sys

        text = sys.stdin.read().strip()
        if not text:
            raise ApprovalError("stdin gave no approval token")
    if text.startswith("@"):
        path = Path(text[1:]).expanduser()
        try:
            text = path.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise ApprovalError(f"cannot read the approval token from {path}: {exc}") from exc
        if not text:
            raise ApprovalError(f"{path} is empty")
    return text


def approval_ladder(policy: Any) -> list[tuple[str, str]]:
    """Rows describing the approval regime, for --policy-show and evidence."""
    return [
        ("mode", mode_for(policy)),
        ("token lifetime", f"{effective_ttl(policy)}s (ceiling "
                           f"{FLOOR_MAX_TTL_SECONDS}s is not configurable)"),
        ("who can mint", "a human at this terminal, holding the host private key"),
        ("reuse", "impossible by construction: one token, one execution"),
    ]
