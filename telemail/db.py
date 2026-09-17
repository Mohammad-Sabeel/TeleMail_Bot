"""SQLite persistence.

Three design points worth defending:

1. `message_id` is the PRIMARY KEY on `emails`, so idempotency is a property of
   the schema rather than of application logic. Re-ingesting a message is a
   no-op no matter how the sync loop is interrupted.

2. The sync watermark advances only after the write commits (see sync.py), so a
   crash between fetch and write replays rather than skips.

3. `audit` is append-only, enforced by triggers. Code cannot quietly rewrite the
   record of what the model proposed and what the broker decided.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

from telemail.models import Email, SenderSignals, TriageResult

SCHEMA = """
CREATE TABLE IF NOT EXISTS emails (
    message_id            TEXT PRIMARY KEY,
    thread_id             TEXT NOT NULL,
    sender_email          TEXT NOT NULL,
    sender_name           TEXT,
    sender_domain         TEXT NOT NULL,
    subject               TEXT NOT NULL,
    snippet               TEXT NOT NULL,
    received_at           TEXT NOT NULL,
    labels                TEXT NOT NULL DEFAULT '[]',
    is_direct             INTEGER NOT NULL DEFAULT 0,
    has_list_unsubscribe  INTEGER NOT NULL DEFAULT 0,
    has_attachment        INTEGER NOT NULL DEFAULT 0,
    spf                   TEXT NOT NULL DEFAULT 'none',
    dkim                  TEXT NOT NULL DEFAULT 'none',
    dmarc                 TEXT NOT NULL DEFAULT 'none',
    auth_source           TEXT NOT NULL DEFAULT '',
    display_name_mismatch INTEGER NOT NULL DEFAULT 0,
    reply_to_differs      INTEGER NOT NULL DEFAULT 0,
    first_contact         INTEGER NOT NULL DEFAULT 1,
    sender_message_count  INTEGER NOT NULL DEFAULT 0,
    ingested_at           TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_emails_domain ON emails(sender_domain);
CREATE INDEX IF NOT EXISTS idx_emails_thread ON emails(thread_id);

CREATE TABLE IF NOT EXISTS triage (
    message_id      TEXT PRIMARY KEY REFERENCES emails(message_id),
    category        TEXT NOT NULL,
    urgency         INTEGER NOT NULL,
    requires_action INTEGER NOT NULL,
    reason          TEXT NOT NULL,
    confidence      REAL NOT NULL,
    source          TEXT NOT NULL,
    proposed_action TEXT NOT NULL DEFAULT 'none',
    decided_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_triage_source ON triage(source);

CREATE TABLE IF NOT EXISTS audit (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      TEXT NOT NULL,
    actor   TEXT NOT NULL,
    event   TEXT NOT NULL,
    payload TEXT NOT NULL,
    reason  TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_event ON audit(event);

-- Append-only. The audit log is evidence; nothing may revise it.
CREATE TRIGGER IF NOT EXISTS audit_no_update
    BEFORE UPDATE ON audit
    BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete
    BEFORE DELETE ON audit
    BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;

-- Ground truth. Deliberately separate from `triage`: a label is what YOU
-- decided, a verdict is what the system decided, and conflating them would make
-- the evaluation circular.
CREATE TABLE IF NOT EXISTS labels (
    message_id     TEXT PRIMARY KEY REFERENCES emails(message_id),
    important      INTEGER NOT NULL,
    rubric_version TEXT NOT NULL,
    labelled_at    TEXT NOT NULL
);

-- An approved action is bound to its target BEFORE the user sees the alert.
-- Single use: a consumed transaction cannot be replayed.
CREATE TABLE IF NOT EXISTS transactions (
    tid        TEXT PRIMARY KEY,
    message_id TEXT NOT NULL,
    action     TEXT NOT NULL,
    created_at TEXT NOT NULL,
    used_at    TEXT
);

CREATE TABLE IF NOT EXISTS state (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


def _now() -> str:
    return datetime.now().astimezone().isoformat()


class Database:
    def __init__(self, path: str | Path):
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        # The bot runs sync and triage via asyncio.to_thread. SQLite is built
        # serialized (sqlite3.threadsafety == 3), so one connection may be
        # shared across threads; /sync's lock keeps syncs from overlapping.
        # ponytail: shared connection; add a write lock if concurrent writers appear.
        self.con = sqlite3.connect(self.path, check_same_thread=False)
        self.con.row_factory = sqlite3.Row
        self.con.execute("PRAGMA foreign_keys = ON")
        self.con.executescript(SCHEMA)
        self.con.commit()

    def close(self) -> None:
        self.con.close()

    # ---------------------------------------------------------------- emails

    def insert_email(self, email: Email) -> bool:
        """Insert if new. Returns True if this was a new message.

        INSERT OR IGNORE against the primary key is what makes re-ingestion
        safe; no caller needs to check first.
        """
        s = email.signals
        cur = self.con.execute(
            """INSERT OR IGNORE INTO emails VALUES
               (:message_id,:thread_id,:sender_email,:sender_name,:sender_domain,
                :subject,:snippet,:received_at,:labels,:is_direct,
                :has_list_unsubscribe,:has_attachment,:spf,:dkim,:dmarc,
                :auth_source,:display_name_mismatch,:reply_to_differs,
                :first_contact,:sender_message_count,:ingested_at)""",
            {**email.model_dump(exclude={"labels", "signals", "received_at"}),
             "labels": json.dumps(email.labels),
             "received_at": email.received_at.isoformat(),
             "spf": s.spf, "dkim": s.dkim, "dmarc": s.dmarc,
             "auth_source": s.auth_source,
             "display_name_mismatch": int(s.display_name_mismatch),
             "reply_to_differs": int(s.reply_to_differs),
             "first_contact": int(s.first_contact),
             "sender_message_count": s.sender_message_count,
             "ingested_at": _now()})
        self.con.commit()
        return cur.rowcount == 1

    def get_email(self, message_id: str) -> Email | None:
        row = self.con.execute(
            "SELECT * FROM emails WHERE message_id = ?", (message_id,)).fetchone()
        if row is None:
            return None
        d = dict(row)
        return Email(
            **{k: d[k] for k in ("message_id", "thread_id", "sender_email",
                                 "sender_name", "sender_domain", "subject",
                                 "snippet")},
            received_at=datetime.fromisoformat(d["received_at"]),
            labels=json.loads(d["labels"]),
            is_direct=bool(d["is_direct"]),
            has_list_unsubscribe=bool(d["has_list_unsubscribe"]),
            has_attachment=bool(d["has_attachment"]),
            signals=SenderSignals(
                spf=d["spf"], dkim=d["dkim"], dmarc=d["dmarc"],
                auth_source=d["auth_source"],
                display_name_mismatch=bool(d["display_name_mismatch"]),
                reply_to_differs=bool(d["reply_to_differs"]),
                first_contact=bool(d["first_contact"]),
                sender_message_count=d["sender_message_count"]))

    def message_exists(self, message_id: str) -> bool:
        return self.con.execute("SELECT 1 FROM emails WHERE message_id = ?",
                                (message_id,)).fetchone() is not None

    def thread_exists(self, thread_id: str) -> bool:
        """The broker rejects hallucinated thread ids locally, before Google."""
        return self.con.execute("SELECT 1 FROM emails WHERE thread_id = ? LIMIT 1",
                                (thread_id,)).fetchone() is not None

    def sender_history(self, domain: str, *, exclude: str | None = None) -> int:
        """How many messages we have already seen from this domain.

        `exclude` omits the message being processed, so first_contact is
        computed against prior history rather than including itself.
        """
        if exclude:
            row = self.con.execute(
                "SELECT COUNT(*) c FROM emails WHERE sender_domain = ? "
                "AND message_id != ?", (domain, exclude)).fetchone()
        else:
            row = self.con.execute(
                "SELECT COUNT(*) c FROM emails WHERE sender_domain = ?",
                (domain,)).fetchone()
        return row["c"]

    def count_emails(self) -> int:
        return self.con.execute("SELECT COUNT(*) c FROM emails").fetchone()["c"]

    # ---------------------------------------------------------------- triage

    def upsert_triage(self, t: TriageResult) -> None:
        self.con.execute(
            """INSERT INTO triage VALUES
               (:message_id,:category,:urgency,:requires_action,:reason,
                :confidence,:source,:proposed_action,:decided_at)
               ON CONFLICT(message_id) DO UPDATE SET
                 category=excluded.category, urgency=excluded.urgency,
                 requires_action=excluded.requires_action, reason=excluded.reason,
                 confidence=excluded.confidence, source=excluded.source,
                 proposed_action=excluded.proposed_action,
                 decided_at=excluded.decided_at""",
            {**t.model_dump(), "requires_action": int(t.requires_action),
             "decided_at": _now()})
        self.con.commit()

    def get_triage(self, message_id: str) -> TriageResult | None:
        row = self.con.execute("SELECT * FROM triage WHERE message_id = ?",
                               (message_id,)).fetchone()
        if row is None:
            return None
        d = dict(row)
        d.pop("decided_at")
        d["requires_action"] = bool(d["requires_action"])
        return TriageResult(**d)

    def source_counts(self) -> dict[str, int]:
        """Prefilter vs model decision share — the ablation's headline number."""
        return {r["source"]: r["c"] for r in self.con.execute(
            "SELECT source, COUNT(*) c FROM triage GROUP BY source")}

    # ----------------------------------------------------------------- audit

    def log(self, *, actor: str, event: str, payload: Any,
            reason: str | None = None) -> None:
        self.con.execute(
            "INSERT INTO audit (ts, actor, event, payload, reason) "
            "VALUES (?,?,?,?,?)",
            (_now(), actor, event, json.dumps(payload, default=str), reason))
        self.con.commit()

    def audit_entries(self, event: str | None = None) -> list[dict]:
        sql = "SELECT * FROM audit"
        args: Iterable = ()
        if event:
            sql += " WHERE event = ?"
            args = (event,)
        return [{**dict(r), "payload": json.loads(r["payload"])}
                for r in self.con.execute(sql + " ORDER BY id", args)]

    # ---------------------------------------------------------------- labels

    def add_label(self, message_id: str, important: bool,
                  rubric_version: str = "v1") -> None:
        self.con.execute(
            "INSERT INTO labels VALUES (?,?,?,?) ON CONFLICT(message_id) "
            "DO UPDATE SET important=excluded.important, "
            "rubric_version=excluded.rubric_version, labelled_at=excluded.labelled_at",
            (message_id, int(important), rubric_version, _now()))
        self.con.commit()

    def label_count(self) -> int:
        return self.con.execute("SELECT COUNT(*) c FROM labels").fetchone()["c"]

    def label_balance(self) -> dict[str, int]:
        return {("important" if r["important"] else "not_important"): r["c"]
                for r in self.con.execute(
                    "SELECT important, COUNT(*) c FROM labels GROUP BY important")}

    def unlabelled(self, limit: int = 20) -> list[Email]:
        """Oldest-first so the sample is not biased toward whatever arrived today."""
        rows = self.con.execute(
            "SELECT e.message_id FROM emails e LEFT JOIN labels l "
            "USING (message_id) WHERE l.message_id IS NULL "
            "ORDER BY e.received_at ASC LIMIT ?", (limit,)).fetchall()
        return [self.get_email(r["message_id"]) for r in rows]

    def untriaged(self, limit: int = 40) -> list[Email]:
        """The triage queue. Distinct from `unlabelled` — labelling is a manual
        habit and triage is automatic; tying one to the other would stop triage
        the moment you caught up on labels."""
        rows = self.con.execute(
            "SELECT e.message_id FROM emails e LEFT JOIN triage t "
            "USING (message_id) WHERE t.message_id IS NULL "
            "ORDER BY e.received_at ASC LIMIT ?", (limit,)).fetchall()
        return [self.get_email(r["message_id"]) for r in rows]

    def alerted_message_ids(self) -> set[str]:
        return {e["payload"].get("message_id")
                for e in self.audit_entries(event="alert_sent")}

    def triaged_not_alerted(self, limit: int = 200) -> list[tuple[Email, TriageResult]]:
        """Everything judged but never announced — including messages deferred
        by quiet hours or the daily cap. This is what makes 'defer, never drop'
        true end to end rather than only inside policy.py."""
        alerted = self.alerted_message_ids()
        out = []
        for r in self.con.execute(
                "SELECT message_id FROM triage ORDER BY decided_at ASC LIMIT ?",
                (limit,)).fetchall():
            mid = r["message_id"]
            if mid in alerted:
                continue
            email, verdict = self.get_email(mid), self.get_triage(mid)
            if email and verdict:
                out.append((email, verdict))
        return out

    def labelled_dataset(self) -> list[dict]:
        """message_id, thread_id and the label — everything the metrics need."""
        return [dict(r) for r in self.con.execute(
            "SELECT l.message_id, e.thread_id, l.important, l.rubric_version "
            "FROM labels l JOIN emails e USING (message_id) "
            "ORDER BY e.received_at")]

    # ---------------------------------------------------------- transactions

    def create_transaction(self, tid: str, *, message_id: str, action: str) -> None:
        self.con.execute(
            "INSERT INTO transactions (tid, message_id, action, created_at) "
            "VALUES (?,?,?,?)", (tid, message_id, action, _now()))
        self.con.commit()

    def get_transaction(self, tid: str) -> dict | None:
        row = self.con.execute("SELECT * FROM transactions WHERE tid = ?",
                               (tid,)).fetchone()
        return dict(row) if row else None

    def consume_transaction(self, tid: str) -> bool:
        """Mark single-use. Returns False if it was already spent."""
        cur = self.con.execute(
            "UPDATE transactions SET used_at = ? WHERE tid = ? AND used_at IS NULL",
            (_now(), tid))
        self.con.commit()
        return cur.rowcount == 1

    # ----------------------------------------------------------------- state

    def set_state(self, key: str, value: str) -> None:
        self.con.execute(
            "INSERT INTO state VALUES (?,?) ON CONFLICT(key) "
            "DO UPDATE SET value=excluded.value", (key, value))
        self.con.commit()

    def get_state(self, key: str, default: str | None = None) -> str | None:
        row = self.con.execute("SELECT value FROM state WHERE key = ?",
                               (key,)).fetchone()
        return row["value"] if row else default
