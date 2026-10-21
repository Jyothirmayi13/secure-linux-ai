"""Tamper-evident local audit log for user-approved command execution."""

from __future__ import annotations

import os
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from evidence import (
    HostIdentity,
    canonical_json,
    policy_fingerprint,
    sha256_hex,
    sign_payload,
    verify_signature,
)

# Columns added by Phase 2. The hash payload is deliberately NOT among them,
# so rows written before signing existed still verify; they simply read as
# unsigned.
_ADDED_COLUMNS = (
    ("actor", "TEXT NOT NULL DEFAULT ''"),
    ("policy_sha", "TEXT NOT NULL DEFAULT ''"),
    ("rule_id", "TEXT NOT NULL DEFAULT ''"),
    ("signature", "TEXT NOT NULL DEFAULT ''"),
)


class AuditLogger:
    def __init__(self, db_path: str | Path, identity: HostIdentity | None = None):
        self.db_path = Path(db_path).expanduser().resolve()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.identity = identity
        self._init_db()
        self._restrict_permissions()

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(str(self.db_path))
        db.execute("PRAGMA journal_mode = WAL")
        db.execute("PRAGMA busy_timeout = 5000")
        db.execute("PRAGMA foreign_keys = ON")
        return db

    def _restrict_permissions(self) -> None:
        if os.name != "nt":
            os.chmod(self.db_path, 0o600)

    def _init_db(self) -> None:
        with closing(self._connect()) as db:
            with db:
                db.execute("""
                    CREATE TABLE IF NOT EXISTS audit_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL, command TEXT NOT NULL,
                        category TEXT NOT NULL, score INTEGER NOT NULL,
                        status TEXT NOT NULL, confirmed INTEGER NOT NULL,
                        sensitive INTEGER NOT NULL, reason TEXT NOT NULL,
                        previous_hash TEXT NOT NULL, event_hash TEXT NOT NULL UNIQUE
                    )
                """)
                existing = {
                    row[1] for row in db.execute("PRAGMA table_info(audit_events)")
                }
                for name, definition in _ADDED_COLUMNS:
                    if name not in existing:
                        db.execute(
                            f"ALTER TABLE audit_events ADD COLUMN {name} {definition}"
                        )

    @staticmethod
    def _hash(payload: dict) -> str:
        return sha256_hex(canonical_json(payload))

    def _last_hash(self, db: sqlite3.Connection) -> str:
        row = db.execute("SELECT event_hash FROM audit_events ORDER BY id DESC LIMIT 1").fetchone()
        return row[0] if row else "GENESIS"

    def log(
        self,
        command: str,
        risk: dict,
        status: str,
        confirmed: bool,
        reason: str | None = None,
        policy: Any = None,
    ) -> dict:
        """Persist an event. Call with ``status='approved'`` before execution.

        When a signing identity is attached the row is signed with the host
        key; without one the row is stored unsigned and reports say so.
        """
        timestamp = datetime.now(timezone.utc).isoformat()
        actor = self.identity.actor if self.identity else ""
        policy_sha = policy_fingerprint(policy) if policy is not None else ""
        rule_id = risk.get("rule_id", "")

        with closing(self._connect()) as db:
            with db:
                previous_hash = self._last_hash(db)
                payload = {
                    "timestamp": timestamp, "command": command,
                    "category": risk["category"], "score": int(risk["score"]),
                    "status": status, "confirmed": bool(confirmed),
                    "sensitive": bool(risk["sensitive"]), "reason": reason or risk["reason"],
                    "previous_hash": previous_hash,
                }
                event_hash = self._hash(payload)

                signature = ""
                if self.identity and self.identity.has_private_key:
                    signature = sign_payload(
                        self.identity,
                        {
                            "event_hash": event_hash,
                            "actor": actor,
                            "policy_sha": policy_sha,
                            "hostname": self.identity.hostname,
                        },
                    )

                db.execute("""
                    INSERT INTO audit_events
                    (timestamp, command, category, score, status, confirmed, sensitive,
                     reason, previous_hash, event_hash, actor, policy_sha, rule_id, signature)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (*payload.values(), event_hash, actor, policy_sha, rule_id, signature))

        return {
            **payload,
            "event_hash": event_hash,
            "actor": actor,
            "policy_sha": policy_sha,
            "rule_id": rule_id,
            "signature": signature,
        }

    _READ_COLUMNS = (
        "id", "timestamp", "command", "category", "score", "status",
        "confirmed", "sensitive", "reason", "previous_hash", "event_hash",
        "actor", "policy_sha", "rule_id", "signature",
    )

    def recent(self, limit: int = 50) -> list[dict]:
        limit = max(1, min(int(limit), 200))
        with closing(self._connect()) as db:
            rows = db.execute(
                f"SELECT {', '.join(self._READ_COLUMNS)} FROM audit_events "
                "ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(zip(self._READ_COLUMNS, row)) for row in rows]

    def export(
        self,
        hours: int | None = None,
        limit: int | None = None,
    ) -> list[dict]:
        """Oldest-first rows for an evidence report, so the chain reads forward.

        Both filters apply when both are given: the time window first, then
        the newest N rows inside it.
        """
        rows = self._all()

        if hours:
            cutoff = datetime.now(timezone.utc).timestamp() - hours * 3600
            rows = [
                row for row in rows
                if datetime.fromisoformat(row["timestamp"]).timestamp() >= cutoff
            ]

        if limit:
            rows = rows[-int(limit):]

        return rows

    def _all(self) -> list[dict]:
        with closing(self._connect()) as db:
            rows = db.execute(
                f"SELECT {', '.join(self._READ_COLUMNS)} FROM audit_events ORDER BY id"
            ).fetchall()
        return [dict(zip(self._READ_COLUMNS, row)) for row in rows]

    def count(self) -> int:
        with closing(self._connect()) as db:
            return db.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]

    def verify_chain(self) -> bool:
        return self.verify()["chain_ok"]

    def verify(self) -> dict:
        """Check the hash chain and every row signature.

        ``unsigned_rows`` are rows written before host signing existed. They
        are reported, not hidden, and they keep a report from claiming to be
        fully signed.
        """
        previous_hash = "GENESIS"
        chain_ok = True
        signed_ok = True
        unsigned = 0
        signed = 0
        failures: list[str] = []

        for index, row in enumerate(self._all(), start=1):
            payload = {key: row[key] for key in ("timestamp", "command", "category", "score", "status", "reason")}
            payload["confirmed"] = bool(row["confirmed"])
            payload["sensitive"] = bool(row["sensitive"])
            payload["previous_hash"] = previous_hash

            if row["previous_hash"] != previous_hash or self._hash(payload) != row["event_hash"]:
                failures.append(
                    f"row {index} (id {row['id']}): event_hash does not match "
                    "its contents or its predecessor"
                )
                chain_ok = False
                break

            previous_hash = row["event_hash"]

            if not row["signature"]:
                unsigned += 1
                continue

            signed += 1
            if self.identity is None:
                signed_ok = False
                failures.append(
                    f"row {index} carries a signature but no host identity is "
                    "loaded to check it"
                )
                continue

            if not verify_signature(
                self.identity.public_key_pem,
                {
                    "event_hash": row["event_hash"],
                    "actor": row["actor"],
                    "policy_sha": row["policy_sha"],
                    "hostname": self.identity.hostname,
                },
                row["signature"],
            ):
                signed_ok = False
                failures.append(
                    f"row {index} (id {row['id']}): signature does not validate "
                    "against this host's key"
                )

        if not chain_ok:
            signed_ok = False

        return {
            "chain_ok": chain_ok,
            "signed_ok": signed_ok,
            "signed_rows": signed,
            "unsigned_rows": unsigned,
            "rows": self.count(),
            "failures": failures,
            "signing": self.identity is not None and self.identity.has_private_key,
        }
