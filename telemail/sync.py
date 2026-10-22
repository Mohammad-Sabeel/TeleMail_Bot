"""The watermark loop. Deterministic, unattended, and crash-safe.

Three properties, in the order they matter:

  idempotent      `message_id` is the PRIMARY KEY, so replay is a no-op. This is
                  a property of the schema, not of anything here.

  replay, never skip
                  the watermark advances only after every message in the cycle
                  has been committed AND no error occurred. A crash mid-cycle
                  therefore re-reads work already done rather than losing mail.
                  Given idempotency, re-reading is free; skipping is not.

  self-healing    Gmail expires a historyId after its retention window and
                  answers 404. That is not an error condition — it is a full
                  resync, handled and logged.

No model is involved and nothing here can write to the mailbox.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from telemail.gmail.adapter import MessageGone, WatermarkExpired
from telemail.gmail.normalise import from_gmail_payload

log = logging.getLogger(__name__)

WATERMARK_KEY = "history_id"
BOOTSTRAP_MESSAGES = 200
MAX_PAGES = 50


@dataclass
class SyncStats:
    fetched: int = 0
    inserted: int = 0
    duplicates: int = 0
    skipped: int = 0                 # deleted before we could fetch them
    inserted_ids: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    resynced: bool = False
    purged: int = 0                  # emails whose preview text aged out
    watermark: str | None = None

    @property
    def ok(self) -> bool:
        return not self.errors


class SyncEngine:
    def __init__(self, db, adapter, own_address: str = "", retention_days: int = 3,
                 now=None):
        self.db = db
        self.adapter = adapter
        self.own_address = own_address
        self.retention_days = retention_days
        self.now = now or (lambda: datetime.now().astimezone())

    def purge_old_content(self) -> int:
        """Retention: mail older than the window keeps its metadata but loses
        its preview text. Runs at the end of every cycle, so it needs no timer."""
        cutoff = self.now() - timedelta(days=self.retention_days)
        blanked = self.db.purge_content(cutoff)
        if blanked:
            log.info("retention: blanked preview text of %d email(s)", blanked)
        return blanked

    # ------------------------------------------------------------- ingest

    def _ingest(self, message_ids: list[str], stats: SyncStats) -> None:
        for mid in message_ids:
            try:
                payload = self.adapter.fetch_metadata(mid)
                email = from_gmail_payload(payload, own_address=self.own_address,
                                           db=self.db)
            except MessageGone:
                stats.skipped += 1
                continue
            except Exception as e:
                stats.errors.append(f"{mid}: {type(e).__name__}")
                log.warning("failed to ingest %s: %s", mid, e)
                continue

            stats.fetched += 1
            if self.db.insert_email(email):
                stats.inserted += 1
                stats.inserted_ids.append(email.message_id)
            else:
                stats.duplicates += 1

    # ---------------------------------------------------------- bootstrap

    def bootstrap(self) -> SyncStats:
        """First run. Read the watermark BEFORE listing, so anything that
        arrives during the listing is replayed on the next poll rather than
        falling into the gap between the two calls."""
        stats = SyncStats()
        watermark = str(self.adapter.profile().get("historyId", ""))

        listing = self.adapter.list_recent(max_results=BOOTSTRAP_MESSAGES)
        ids = [m["id"] for m in listing.get("messages", [])]
        self._ingest(ids, stats)

        if stats.ok and watermark:
            self.db.set_state(WATERMARK_KEY, watermark)
            stats.watermark = watermark
        self.db.log(actor="sync", event="bootstrap",
                    payload={"inserted": stats.inserted, "watermark": watermark})
        stats.purged = self.purge_old_content()
        return stats

    def resync(self) -> SyncStats:
        """Watermark expired. Re-read recent mail; duplicates are absorbed by
        the primary key, so this is safe to run at any time."""
        stats = self.bootstrap()
        stats.resynced = True
        self.db.log(actor="sync", event="resync",
                    payload={"inserted": stats.inserted,
                             "duplicates": stats.duplicates})
        return stats

    # --------------------------------------------------------------- poll

    def poll(self) -> SyncStats:
        watermark = self.db.get_state(WATERMARK_KEY)
        if not watermark:
            return self.bootstrap()

        stats = SyncStats()
        ids: list[str] = []
        new_watermark = watermark
        page_token = None

        for _ in range(MAX_PAGES):
            try:
                page = self.adapter.history(watermark, page_token=page_token)
            except WatermarkExpired:
                log.info("history %s expired; full resync", watermark)
                return self.resync()

            for record in page.get("history", []):
                for added in record.get("messagesAdded", []):
                    mid = added.get("message", {}).get("id")
                    if mid:
                        ids.append(mid)

            new_watermark = str(page.get("historyId", new_watermark))
            page_token = page.get("nextPageToken")
            if not page_token:
                break

        # de-duplicate within the cycle; the PK would absorb it anyway
        self._ingest(list(dict.fromkeys(ids)), stats)

        # The watermark advances only on a clean cycle. A partial failure
        # replays next time, which idempotency makes free.
        if stats.ok:
            self.db.set_state(WATERMARK_KEY, new_watermark)
            stats.watermark = new_watermark
        else:
            log.warning("holding watermark at %s after %d error(s)",
                        watermark, len(stats.errors))
        stats.purged = self.purge_old_content()
        return stats
