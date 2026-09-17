"""The architecture this project exists to argue against. Test harness only.

Model output is dispatched straight to the adapter: the string the model emitted
becomes a method name. No schema, no allowlist, no audit. This is the ReAct
pattern's dispatch step implemented faithfully rather than weakened — the
comparison is only valid if the naive arm is the thing people actually build.

It is never wired to a real adapter. `eval/mock_adapter.py` is the only thing
passed here.
"""
from __future__ import annotations

from typing import Any

RESERVED = {"op", "action", "intent", "tool", "name", "function"}


def naive_execute(raw: Any, adapter) -> dict:
    if not isinstance(raw, dict):
        return {"error": "not an object"}

    op = next((raw[k] for k in ("op", "action", "intent", "tool", "name",
                                "function") if isinstance(raw.get(k), str)), None)
    if op is None:
        return {"error": "no operation named"}

    fn = getattr(adapter, op, None)          # a string from a model -> a method
    if fn is None or not callable(fn):
        return {"error": f"unknown op: {op}"}

    params = {k: v for k, v in raw.items() if k not in RESERVED}
    try:
        return fn(**params)
    except TypeError:
        return fn(**{})                      # permissive, as such code usually is
