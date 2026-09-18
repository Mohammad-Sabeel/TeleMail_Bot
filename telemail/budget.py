"""A daily ceiling on model tokens (OWASP LLM10).

Kept in a small JSON file rather than the database: it must survive a restart,
and it must never be the reason a sync fails to record mail.
"""
from __future__ import annotations

import json
from pathlib import Path


class BudgetExceeded(RuntimeError):
    pass


class Budget:
    def __init__(self, path="data/budget.json", daily_tokens: int = 300_000, now=None):
        from datetime import datetime
        self.path = Path(path)
        self.daily_tokens = daily_tokens
        self.now = now or (lambda: datetime.now().astimezone())

    def _load(self) -> dict:
        try:
            return json.loads(self.path.read_text())
        except (OSError, ValueError):
            return {}

    def _today(self) -> str:
        return self.now().date().isoformat()

    def used_today(self) -> int:
        return int(self._load().get(self._today(), 0))

    @property
    def exhausted(self) -> bool:
        return self.used_today() >= self.daily_tokens

    def spend(self, prompt_tokens: int, completion_tokens: int) -> None:
        total = self.used_today() + int(prompt_tokens) + int(completion_tokens)
        if total > self.daily_tokens:
            raise BudgetExceeded(
                f"daily model budget reached: {self.used_today()} of "
                f"{self.daily_tokens} tokens used today")
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps({self._today(): total}))
        except OSError:
            pass
