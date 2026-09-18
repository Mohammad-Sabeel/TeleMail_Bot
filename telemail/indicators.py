"""A list of known-bad strings the user maintains: `data/indicators.txt`.

Deterministic and literal — no regex, so nothing typed into the list can change
how matching behaves. A hit is evidence in the rules layer, and by the existing
rule the model can raise a verdict but never lower one.

Signatures only catch what has already been seen; one changed word evades them.
They are a layer, never the control. Measured on and off in the evaluation.
"""
from __future__ import annotations

from pathlib import Path

MIN_LENGTH = 2


def load_indicators(path) -> list[str]:
    """Lower-cased entries, comments and blanks dropped, order kept, no duplicates."""
    path = Path(path)
    if not path.is_file():
        return []
    seen = {}
    for line in path.read_text(errors="replace").splitlines():
        entry = line.split("#", 1)[0].strip().lower()
        if len(entry) >= MIN_LENGTH:
            seen[entry] = None
    return list(seen)


def match_indicators(text: str, indicators: list[str]) -> list[str]:
    haystack = str(text or "").lower()
    return [i for i in indicators if i in haystack]


def add_indicator(path, entry: str) -> bool:
    """Append one entry. False if it is too short or already listed."""
    entry = str(entry or "").strip().lower()
    if len(entry) < MIN_LENGTH or entry in load_indicators(path):
        return False
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    existing = path.read_text(errors="replace") if path.is_file() else ""
    prefix = "" if not existing or existing.endswith("\n") else "\n"
    with path.open("a") as fh:
        fh.write(prefix + entry + "\n")
    return True
