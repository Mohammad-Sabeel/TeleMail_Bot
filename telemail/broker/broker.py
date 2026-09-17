"""The enforcement boundary.

Every operation that touches the mailbox passes through `execute` or `approve`.
Both audit before they decide, and again after. Nothing else in the system holds
a mailbox client.

Three properties to defend in the viva:

  complete mediation  there is no second path; the adapter is imported here and
                      nowhere reachable from the planner (tests/test_boundary.py)
  fail-safe default   an unrecognised operation is a logged rejection, never a
                      pass-through
  economy of mechanism  dispatch is a static dict. Never `getattr(adapter, op)`,
                      which would turn a string from a model into a method name
                      — precisely the class of thing this project exists to stop
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Any, Protocol

from pydantic import TypeAdapter, ValidationError

from telemail.broker.intents import (ApprovedAction, BrokerRejection, Intent,
                                     validate_query)

_INTENT = TypeAdapter(Intent)
_ACTION = TypeAdapter(ApprovedAction)


@dataclass
class BrokerResult:
    ok: bool
    data: Any = None
    reason: str | None = None

    @classmethod
    def accepted(cls, data): return cls(True, data=data)

    @classmethod
    def rejected(cls, reason): return cls(False, reason=reason)


class ReadOnlyAdapter(Protocol):
    def search(self, query: str, max_results: int) -> list[dict]: ...
    def get_thread(self, thread_id: str) -> dict: ...
    def summarise(self, thread_id: str) -> dict: ...


class WriteService(Protocol):
    """A separate process holding its own narrow credential. Optional, absent
    by default, and unreachable from the planner in either case."""
    def mark_read(self, message_id: str) -> dict: ...
    def label_urgent(self, message_id: str) -> dict: ...


class Broker:
    def __init__(self, db, adapter: ReadOnlyAdapter,
                 write_service: WriteService | None = None):
        self.db = db
        self.adapter = adapter
        self.write_service = write_service

        # Static dispatch. The key space is fixed at import time and cannot be
        # widened by anything a model emits.
        self._read = {
            "search": lambda i: self.adapter.search(i.query, i.max_results),
            "get_thread": lambda i: self.adapter.get_thread(i.thread_id),
            "summarise": lambda i: self.adapter.summarise(i.thread_id),
        }
        self._write = {
            "mark_read": lambda a: self._writer().mark_read(a.message_id),
            "label_urgent": lambda a: self._writer().label_urgent(a.message_id),
        }

    def _writer(self) -> WriteService:
        if self.write_service is None:
            raise BrokerRejection("no write service configured")
        return self.write_service

    def _reject(self, raw, reason: str, actor: str) -> BrokerResult:
        self.db.log(actor="broker", event="rejected", payload=raw, reason=reason)
        return BrokerResult.rejected(reason)

    # ------------------------------------------------------- model-facing

    def execute(self, raw: dict, *, actor: str) -> BrokerResult:
        """The only path from model output to the mailbox. Read operations only."""
        self.db.log(actor=actor, event="proposed", payload=raw)

        if not isinstance(raw, dict):
            return self._reject(raw, "proposal is not an object", actor)

        try:
            intent = _INTENT.validate_python(raw)
        except ValidationError as e:
            return self._reject(raw, f"failed validation: {e.error_count()} error(s)",
                                actor)

        try:
            if intent.op == "search":
                validate_query(intent.query)
            elif not self.db.thread_exists(intent.thread_id):
                # A hallucinated id is refused locally, before it reaches Google.
                raise BrokerRejection("unknown thread_id")
        except BrokerRejection as e:
            return self._reject(raw, str(e), actor)

        self.db.log(actor="broker", event="accepted", payload=intent.model_dump())
        result = self._read[intent.op](intent)
        self.db.log(actor="broker", event="executed", payload={"op": intent.op})
        return BrokerResult.accepted(result)

    # -------------------------------------------------- human approval path

    def register_transaction(self, *, message_id: str, action: str) -> str:
        """Bind an action to a specific message BEFORE the user is shown it.

        Called by the alerting code, never by the planner. The returned token is
        the only way to reach a write, so an injected instruction cannot
        redirect an approved action onto a different message: the target was
        fixed when the transaction was created.
        """
        try:
            _ACTION.validate_python({"op": action, "message_id": message_id})
        except ValidationError:
            raise BrokerRejection(f"not an approvable action: {action}")

        tid = secrets.token_urlsafe(12)
        self.db.create_transaction(tid, message_id=message_id, action=action)
        self.db.log(actor="policy", event="transaction_registered",
                    payload={"tid": tid, "op": action, "message_id": message_id})
        return tid

    def approve(self, tid: str, *, actor: str) -> BrokerResult:
        self.db.log(actor=actor, event="approval_attempted", payload={"tid": tid})

        tx = self.db.get_transaction(tid)
        if tx is None:
            return self._reject({"tid": tid}, "unknown transaction", actor)
        if tx["used_at"] is not None:
            return self._reject({"tid": tid}, "transaction already used", actor)

        try:
            action = _ACTION.validate_python({"op": tx["action"],
                                              "message_id": tx["message_id"]})
            if not self.db.message_exists(action.message_id):
                raise BrokerRejection("unknown message_id")
            self.db.consume_transaction(tid)
            self.db.log(actor="broker", event="accepted",
                        payload=action.model_dump())
            result = self._write[action.op](action)
        except (ValidationError, BrokerRejection) as e:
            return self._reject({"tid": tid, "op": tx["action"]}, str(e), actor)

        self.db.log(actor="broker", event="executed",
                    payload={"op": action.op, "message_id": action.message_id})
        return BrokerResult.accepted(result)
