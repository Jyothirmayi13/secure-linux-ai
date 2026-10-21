"""Host identity and offline-verifiable evidence for the security gateway.

Phase 1 made every decision explainable. Phase 2 makes every decision
*provable*: a per-host Ed25519 key signs each audit row together with the
actor and the fingerprint of the policy that was in force, and the whole
log can be exported as a self-contained report that a third party verifies
without contacting the host that produced it.

Nothing here imports audit.py. audit.py imports this module, so the
dependency has one direction and no cycle.
"""

from __future__ import annotations

import base64
import getpass
import hashlib
import json
import os
import platform
import socket
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
except ImportError:  # pragma: no cover - reported, never silently skipped
    InvalidSignature = None  # type: ignore[assignment]
    serialization = None  # type: ignore[assignment]
    Ed25519PrivateKey = None  # type: ignore[assignment]
    Ed25519PublicKey = None  # type: ignore[assignment]

EVIDENCE_VERSION = 1
PRODUCT = "linux-ai-ssm"

PRIVATE_FILENAME = "ed25519.key"
PUBLIC_FILENAME = "ed25519.pub"
HOST_FILENAME = "host.json"

# The fields the signature covers. Keeping this list in one place means an
# audit row and a report row can never drift into signing different things.
SIGNATURE_FIELDS = ("event_hash", "actor", "policy_sha", "hostname")


class EvidenceError(Exception):
    """Raised when identity material exists but cannot be trusted."""


def cryptography_available() -> bool:
    return Ed25519PrivateKey is not None


def state_dir() -> Path:
    return (
        Path.home()
        / ".local"
        / "state"
        / "linux-ai-ssm"
    )


def identity_dir() -> Path:
    return state_dir() / "identity"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ============================================================
# CANONICAL SERIALIZATION
# ============================================================

def canonical_json(payload: dict | list) -> str:
    """The one JSON spelling used for hashing and signing, everywhere.

    ensure_ascii=True keeps a non-ASCII command from producing a different
    digest depending on the platform's locale.
    """
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ============================================================
# HOST IDENTITY
# ============================================================

@dataclass(frozen=True)
class HostIdentity:
    key_id: str
    hostname: str
    actor: str
    created_at: str
    public_key_pem: str
    dir_path: Path
    _private: Any = None

    @property
    def has_private_key(self) -> bool:
        return self._private is not None

    def describe(self) -> list[tuple[str, str]]:
        return [
            ("hostname", self.hostname),
            ("default actor", self.actor),
            ("key id", self.key_id),
            ("identity created", self.created_at),
            ("identity directory", str(self.dir_path)),
            ("private key present", "yes" if self.has_private_key else "no"),
            ("signing support", "yes" if cryptography_available() else "no"),
        ]


def _raw_bytes(public_key: Any) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _key_id(raw_public_key: bytes) -> str:
    digest = sha256_hex(raw_public_key.hex())
    return "sha256:" + digest[:32]


def _restrict(file_path: Path, mode: int) -> None:
    if os.name != "nt":
        try:
            os.chmod(file_path, mode)
        except OSError:
            pass


def _public_key_from_pem(pem: str) -> Any:
    try:
        return serialization.load_pem_public_key(pem.encode("utf-8"))
    except Exception as exc:  # corrupted or replaced public key
        raise EvidenceError(
            f"the host public key at {identity_dir() / PUBLIC_FILENAME} "
            f"cannot be read: {exc}"
        ) from exc


def load_or_create_identity(
    directory: str | Path | None = None,
) -> HostIdentity:
    """Load this host's signing key, creating it on first use.

    Returns an identity with ``_private=None`` when the ``cryptography``
    package is missing, so callers can degrade to unsigned rows and say so
    out loud instead of crashing a diagnostic session.
    """
    where = Path(directory) if directory else identity_dir()
    where.mkdir(parents=True, exist_ok=True)

    private_path = where / PRIVATE_FILENAME
    public_path = where / PUBLIC_FILENAME
    host_path = where / HOST_FILENAME

    hostname = socket.gethostname() or platform.node() or "unknown-host"
    try:
        actor = getpass.getuser()
    except Exception:
        actor = os.environ.get("USER") or os.environ.get("USERNAME") or "unknown"

    if not cryptography_available():
        pem = ""
        if public_path.is_file():
            pem = public_path.read_text(encoding="utf-8")
        created = "pre-existing"
        if host_path.is_file():
            try:
                created = json.loads(host_path.read_text(encoding="utf-8")).get(
                    "created_at", "pre-existing"
                )
            except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                pass
        return HostIdentity(
            key_id="(unavailable: cryptography not installed)",
            hostname=hostname,
            actor=actor,
            created_at=created,
            public_key_pem=pem,
            dir_path=where,
            _private=None,
        )

    if private_path.is_file():
        missing = [
            name
            for name, path in (
                (PUBLIC_FILENAME, public_path),
                (HOST_FILENAME, host_path),
            )
            if not path.is_file()
        ]
        if missing:
            raise EvidenceError(
                f"identity directory is incomplete: {where} has a private key "
                f"but no {' and no '.join(missing)}. Refusing to guess which "
                "files are correct. Restore them or remove the whole "
                "directory to start a new host identity."
            )

        private_key = serialization.load_pem_private_key(
            private_path.read_text(encoding="utf-8").encode("utf-8"),
            password=None,
        )
        pem = public_path.read_text(encoding="utf-8")
        meta = json.loads(host_path.read_text(encoding="utf-8"))
        return HostIdentity(
            key_id=meta.get("key_id", _key_id(_raw_bytes(private_key.public_key()))),
            hostname=meta.get("hostname", hostname),
            actor=meta.get("actor", actor),
            created_at=meta.get("created_at", now_iso()),
            public_key_pem=pem,
            dir_path=where,
            _private=private_key,
        )

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    created = now_iso()
    key_id = _key_id(_raw_bytes(public_key))

    private_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    _restrict(private_path, 0o600)

    public_path.write_text(pem, encoding="utf-8")
    _restrict(public_path, 0o644)

    host_path.write_text(
        canonical_json(
            {
                "product": PRODUCT,
                "key_id": key_id,
                "hostname": hostname,
                "actor": actor,
                "created_at": created,
                "algorithm": "Ed25519",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    _restrict(host_path, 0o600)

    return HostIdentity(
        key_id=key_id,
        hostname=hostname,
        actor=actor,
        created_at=created,
        public_key_pem=pem,
        dir_path=where,
        _private=private_key,
    )


def signature_payload(row: dict) -> dict:
    """The exact dict that gets signed for one audit row."""
    missing = [key for key in SIGNATURE_FIELDS if key not in row]
    if missing:
        raise EvidenceError(
            f"row is missing signed field(s): {', '.join(missing)}"
        )
    return {key: row[key] for key in SIGNATURE_FIELDS}


def sign_payload(identity: HostIdentity, payload: dict) -> str:
    if identity._private is None:
        raise EvidenceError("this identity has no private key; nothing to sign")
    signature = identity._private.sign(canonical_json(payload).encode("utf-8"))
    return base64.b64encode(signature).decode("ascii")


def verify_signature(
    public_key_pem: str,
    payload: dict,
    signature_b64: str,
) -> bool:
    """Verify against the public key carried inside the evidence itself."""
    if not cryptography_available():
        return False
    try:
        public_key = _public_key_from_pem(public_key_pem)
        public_key.verify(
            base64.b64decode(signature_b64),
            canonical_json(payload).encode("utf-8"),
        )
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True


# ============================================================
# POLICY FINGERPRINT
# ============================================================

def policy_fingerprint(policy: Any) -> str:
    """A digest of the decisions a policy makes, not of the file it lives in.

    ``source`` is deliberately excluded so the same policy.yaml produces the
    same fingerprint wherever it is installed.
    """
    material = {
        "name": policy.name,
        "allow_executables": sorted(policy.allow_executables),
        "deny_executables": sorted(policy.deny_executables),
        "deny_paths": list(policy.deny_paths),
        "deny_arguments": sorted(policy.deny_arguments),
        "rules": [
            {"id": r.rule_id, "pattern": r.pattern.pattern, "reason": r.reason}
            for r in policy.rules
        ],
        "injection_rules": [
            {"id": r.rule_id, "pattern": r.pattern.pattern, "reason": r.reason}
            for r in policy.injection_rules
        ],
        "max_score": policy.max_score,
        "block_sensitive": policy.block_sensitive,
        "read_roots": list(policy.read_roots),
        "tech_enabled": policy.tech_enabled,
        "max_suggestions": policy.max_suggestions,
        "ai_provider": policy.ai_provider,
        "ai_model": policy.ai_model,
        "ai_base_url": policy.ai_base_url,
        "ai_allow_cloud": policy.ai_allow_cloud,
        # Whether an execution has to carry a signed human approval is a policy
        # decision, so an approval minted under one regime cannot be presented
        # as evidence under another.
        "approval_mode": policy.approval_mode,
        "approval_ttl": policy.approval_ttl,
    }
    return "sha256:" + sha256_hex(canonical_json(material))


# ============================================================
# EXPORTED REPORT
# ============================================================

def build_report(
    rows: list[dict],
    identity: HostIdentity,
    policy: Any,
    *,
    hours: int | None = None,
    note: str = "",
) -> dict:
    """Assemble a self-contained, signed evidence document.

    ``rows`` must be oldest-first and carry every field needed to recompute
    the hash chain, so a verifier never has to trust a summary.
    """
    events = []
    for row in rows:
        events.append(
            {
                "id": row.get("id"),
                "timestamp": row["timestamp"],
                "command": row["command"],
                "category": row["category"],
                "score": int(row["score"]),
                "status": row["status"],
                "confirmed": bool(row["confirmed"]),
                "sensitive": bool(row["sensitive"]),
                "reason": row["reason"],
                "rule_id": row.get("rule_id", ""),
                "actor": row.get("actor", ""),
                "policy_sha": row.get("policy_sha", ""),
                "previous_hash": row["previous_hash"],
                "event_hash": row["event_hash"],
                "signature": row.get("signature", ""),
            }
        )

    signed = sum(1 for event in events if event["signature"])
    window = f"last {hours} hours" if hours else "all stored events"

    # A report that starts mid-log is a window, not the whole chain. Saying so
    # explicitly is what lets a verifier resume from the right hash instead of
    # wrongly reporting the first row as tampered.
    first_event = events[0] if events else None
    first_id = int(first_event["id"]) if first_event and first_event.get("id") else 1
    is_window = bool(events) and first_id > 1
    chain_start = {
        "kind": "window" if is_window else "full",
        "starts_at_event_id": first_id if events else None,
        "previous_hash": first_event["previous_hash"] if is_window else "GENESIS",
        "rows_excluded_before": first_id - 1,
    }

    return {
        "report_version": EVIDENCE_VERSION,
        "product": PRODUCT,
        "generated_at": now_iso(),
        "window": window,
        "note": note,
        "chain_start": chain_start,
        "host": {
            "hostname": identity.hostname,
            "key_id": identity.key_id,
            "public_key": identity.public_key_pem,
            "identity_created_at": identity.created_at,
            "default_actor": identity.actor,
        },
        "policy": {
            "name": policy.name,
            "source_label": policy.source_label,
            "fingerprint": policy_fingerprint(policy),
            "max_score": policy.max_score,
            "block_sensitive": policy.block_sensitive,
            # "Did host data leave this machine, by policy?" is part of the
            # evidence, so the egress rule travels with the report.
            "ai": {
                "provider": policy.ai_provider or "(from environment)",
                "model": policy.ai_model or "(from environment)",
                "base_url": policy.ai_base_url or "(provider default)",
                "allow_cloud": policy.ai_allow_cloud,
            },
            "approval": {
                "mode": policy.approval_mode,
                "ttl_seconds": policy.approval_ttl,
                "floor": "a signed, single-use human approval is required and "
                         "no policy file can turn it off",
            },
        },
        "summary": {
            "events": len(events),
            "signed_events": signed,
            "unsigned_events": len(events) - signed,
            "first_timestamp": events[0]["timestamp"] if events else None,
            "last_timestamp": events[-1]["timestamp"] if events else None,
        },
        "events": events,
    }


def sign_report(report: dict, identity: HostIdentity) -> dict:
    if not identity.has_private_key:
        raise EvidenceError(
            "cannot sign a report without the host private key. Install "
            "the 'cryptography' package or restore the identity directory."
        )
    signed = dict(report)
    signed["report_signature"] = {
        "algorithm": "Ed25519",
        "key_id": identity.key_id,
        "value": sign_payload(identity, _report_core(signed)),
    }
    return signed


def _report_core(report: dict) -> dict:
    return {
        key: value
        for key, value in report.items()
        if key not in ("report_signature",)
    }


def report_to_csv(report: dict) -> str:
    import csv
    import io

    buffer = io.StringIO()
    fields = (
        "id", "timestamp", "command", "category", "score", "status",
        "confirmed", "sensitive", "reason", "rule_id", "actor",
        "policy_sha", "previous_hash", "event_hash", "signature",
    )
    writer = csv.DictWriter(buffer, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    for event in report["events"]:
        writer.writerow({key: event.get(key, "") for key in fields})
    return buffer.getvalue()


def identity_exists() -> bool:
    return (identity_dir() / PUBLIC_FILENAME).is_file()


def recorded_key_id() -> str:
    """This host's key id, or '' when no identity has been created yet.

    Reading is deliberately side-effect free: verifying someone else's
    report must never generate a keypair on the verifier's machine.
    """
    host_path = identity_dir() / HOST_FILENAME
    if not host_path.is_file():
        return ""
    try:
        return json.loads(host_path.read_text(encoding="utf-8")).get("key_id", "")
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return ""


# The columns the chain recomputation reads from every row. A document that is
# missing one is a document that was edited, and must be reported as such.
_EVENT_FIELDS = (
    "timestamp", "command", "category", "score", "status", "confirmed",
    "sensitive", "reason", "previous_hash", "event_hash",
)


def verify_report(path: str | Path) -> dict:
    """Verify an exported report using nothing but the file itself.

    Checks the hash chain, every row signature, and the document signature.
    Rows written before signing existed are counted and reported as unsigned
    rather than quietly passed.
    """
    file_path = Path(path).expanduser()

    result = {
        "file": str(file_path),
        "ok": False,
        "loaded": False,
        "fully_signed": False,
        "chain_ok": False,
        "row_signatures_ok": True,
        "report_signature_ok": False,
        "summary_ok": True,
        "events": 0,
        "signed_events": 0,
        "unsigned_events": 0,
        "failures": [],
        "host": "",
        "policy": "",
        "scope": "",
        "report_note": "",
    }

    if not cryptography_available():
        result["failures"].append(
            "the 'cryptography' package is not installed, so signatures "
            "cannot be checked"
        )
        return result

    if not file_path.is_file():
        result["failures"].append(f"report not found: {file_path}")
        return result

    try:
        report = json.loads(file_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        result["failures"].append(f"report is not readable JSON: {exc}")
        return result

    if not isinstance(report, dict) or "events" not in report:
        result["failures"].append(
            "report has no 'events' array; it is not a gateway evidence file"
        )
        return result

    # A verifier that crashes on a malformed document gives an auditor no
    # verdict at all, so every section is shape-checked before it is read.
    for section in ("host", "policy", "chain_start", "summary"):
        value = report.get(section)
        if value is not None and not isinstance(value, dict):
            result["failures"].append(
                f"the '{section}' section is not an object; this document was "
                "edited outside the gateway"
            )
            return result

    events = report["events"]
    if not isinstance(events, list) or not all(
        isinstance(event, dict) for event in events
    ):
        result["failures"].append(
            "'events' is not a list of row objects; this document was edited "
            "outside the gateway"
        )
        return result
    result["events"] = len(events)

    result["loaded"] = True
    host = report.get("host") or {}
    result["host"] = f"{host.get('hostname', '?')} ({host.get('key_id', '?')})"
    policy = report.get("policy") or {}
    result["policy"] = f"{policy.get('name', '?')} {policy.get('fingerprint', '')}"
    # The note is inside the signed document core, so it is authenticated
    # evidence and safe to show an auditor.
    result["report_note"] = str(report.get("note") or "")

    public_key_pem = host.get("public_key", "")
    if not public_key_pem:
        result["failures"].append("report carries no host public key")
        return result

    if host.get("key_id") and host.get("key_id") == recorded_key_id():
        result["note"] = "verified against this host's own key"
    else:
        result["note"] = "verified with the key inside the report"

    # --- hash chain, recomputed from the stored components ---------------
    chain_start = report.get("chain_start") or {}
    start_hash = chain_start.get("previous_hash", "GENESIS")
    kind = chain_start.get("kind", "full")
    if kind not in ("full", "window"):
        result["failures"].append(f"unknown chain_start kind {kind!r}")
        return result
    if kind == "full" and start_hash != "GENESIS":
        result["failures"].append(
            "report claims to cover the whole log but its first row does not "
            "start at GENESIS"
        )
        return result

    first_id = events[0].get("id") if events else None
    previous_hash = start_hash
    for index, event in enumerate(events, start=1):
        missing = [key for key in _EVENT_FIELDS if key not in event]
        if missing:
            result["failures"].append(
                f"event {index}: has no {', '.join(missing)} field, so its "
                "place in the chain cannot be checked"
            )
            break
        if first_id is not None and event.get("id") != first_id + index - 1:
            result["failures"].append(
                f"event {index}: id {event.get('id')} does not follow the "
                f"previous id {first_id + index - 2} (a row was removed from "
                "the middle of the report)"
            )
            break

        if event["previous_hash"] != previous_hash:
            result["failures"].append(
                f"event {index}: previous_hash does not match the event "
                "before it (the log was reordered, edited, or a row was deleted)"
            )
            break

        payload = {
            "timestamp": event["timestamp"],
            "command": event["command"],
            "category": event["category"],
            "score": int(event["score"]),
            "status": event["status"],
            "confirmed": bool(event["confirmed"]),
            "sensitive": bool(event["sensitive"]),
            "reason": event["reason"],
            "previous_hash": previous_hash,
        }
        try:
            digest = sha256_hex(canonical_json(payload))
        except (TypeError, ValueError):
            result["failures"].append(
                f"event {index}: has a field that is not the type the gateway "
                f"writes (id {event.get('id')})"
            )
            break
        if digest != event["event_hash"]:
            result["failures"].append(
                f"event {index}: event_hash does not match its own contents "
                f"(edited row, id {event.get('id')})"
            )
            break
        previous_hash = event["event_hash"]
    else:
        result["chain_ok"] = True

    excluded = int(chain_start.get("rows_excluded_before", 0) or 0)
    result["scope"] = (
        f"{kind} chain, {len(events)} event(s)"
        + (f" ({excluded} earlier row(s) outside this window)" if kind == "window" else "")
    )

    # --- row signatures --------------------------------------------------
    hostname = host.get("hostname", "")
    for index, event in enumerate(events, start=1):
        signature = event.get("signature", "")
        if not signature:
            result["unsigned_events"] += 1
            continue
        result["signed_events"] += 1
        payload = {
            "event_hash": event.get("event_hash", ""),
            "actor": event.get("actor", ""),
            "policy_sha": event.get("policy_sha", ""),
            "hostname": hostname,
        }
        if not verify_signature(public_key_pem, payload, signature):
            result["row_signatures_ok"] = False
            result["failures"].append(
                f"event {index}: signature does not validate "
                f"(row forged or signed by a different key, id {event.get('id')})"
            )

    # --- summary cross-check --------------------------------------------
    # The chain only links forward, so dropping the newest rows would still
    # leave a valid chain. The stored summary makes that truncation visible
    # even before signature verification is considered.
    summary = report.get("summary") or {}
    claimed_events = summary.get("events")
    if claimed_events is not None and int(claimed_events) != len(events):
        result["summary_ok"] = False
        result["failures"].append(
            f"summary says {claimed_events} events but the file contains "
            f"{len(events)} (rows were added or removed after export)"
        )

    claimed_signed = summary.get("signed_events")
    if (
        result["summary_ok"]
        and claimed_signed is not None
        and int(claimed_signed) != result["signed_events"]
    ):
        result["summary_ok"] = False
        result["failures"].append(
            f"summary says {claimed_signed} signed events but "
            f"{result['signed_events']} signatures are present"
        )

    for key, position, which in (
        ("first_timestamp", 0, "first"),
        ("last_timestamp", -1, "last"),
    ):
        claimed = summary.get(key)
        if result["summary_ok"] and claimed and events:
            if claimed != events[position]["timestamp"]:
                result["summary_ok"] = False
                result["failures"].append(
                    f"summary {key} does not match the {which} event in the "
                    "file (the ends of the log were changed)"
                )

    # --- document signature ---------------------------------------------
    document_signature = report.get("report_signature")
    if not isinstance(document_signature, dict):
        result["failures"].append("report is unsigned")
    else:
        result["report_signature_ok"] = verify_signature(
            public_key_pem,
            _report_core(report),
            document_signature.get("value", ""),
        )
        if not result["report_signature_ok"]:
            result["failures"].append(
                "the document signature does not validate: this file was "
                "changed after it was exported"
            )
        elif document_signature.get("key_id") != host.get("key_id"):
            result["report_signature_ok"] = False
            result["failures"].append(
                "the document was signed by a key other than the one the "
                "report claims to come from"
            )

    result["ok"] = bool(
        result["chain_ok"]
        and result["row_signatures_ok"]
        and result["summary_ok"]
        and result["report_signature_ok"]
        and not result["failures"]
    )
    # "ok" means nobody altered this file. It does not mean every event in it
    # is provable: rows written before host signing existed carry no
    # signature, and an authentic report full of those must not claim more.
    result["fully_signed"] = bool(result["ok"] and result["unsigned_events"] == 0)
    return result
