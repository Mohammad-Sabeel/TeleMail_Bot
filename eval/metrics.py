"""Classification metrics, written out rather than imported.

Fifteen lines you can defend beats a library call you cannot. The confusion
matrix is the primary artefact; the headline figures are derived from it.
"""
from __future__ import annotations

import math
from dataclasses import dataclass


@dataclass(frozen=True)
class Confusion:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    @property
    def n(self) -> int:
        return self.tp + self.fp + self.fn + self.tn

    @property
    def precision(self) -> float:
        d = self.tp + self.fp
        return self.tp / d if d else 0.0

    @property
    def recall(self) -> float:
        d = self.tp + self.fn
        return self.tp / d if d else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def accuracy(self) -> float:
        return (self.tp + self.tn) / self.n if self.n else 0.0


def confusion(y_true: list[bool], y_pred: list[bool]) -> Confusion:
    if len(y_true) != len(y_pred):
        raise ValueError("length mismatch")
    tp = sum(t and p for t, p in zip(y_true, y_pred))
    fp = sum((not t) and p for t, p in zip(y_true, y_pred))
    fn = sum(t and (not p) for t, p in zip(y_true, y_pred))
    tn = sum((not t) and (not p) for t, p in zip(y_true, y_pred))
    return Confusion(tp, fp, fn, tn)


def split_by_thread(rows: list[dict], *, test_fraction: float = 0.25,
                    seed: int = 42) -> tuple[list[dict], list[dict]]:
    """Group-aware split.

    Two replies from one thread on opposite sides of the split leak the answer —
    same sender, same subject, same vocabulary. This is the error that silently
    inflates email classification results, so the split is by thread, never by
    message.
    """
    import random

    threads: dict[str, list[dict]] = {}
    for r in rows:
        threads.setdefault(r["thread_id"], []).append(r)

    keys = sorted(threads)
    random.Random(seed).shuffle(keys)

    target = int(len(rows) * test_fraction)
    test: list[dict] = []
    for k in keys:
        if len(test) >= target:
            break
        test.extend(threads[k])
    test_ids = {r["message_id"] for r in test}
    train = [r for r in rows if r["message_id"] not in test_ids]
    return train, test


def wilson(successes: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score interval. Correct at 0/n and n/n, where the normal
    approximation collapses to a zero-width interval and lies."""
    if successes < 0 or n < 0:
        raise ValueError("counts must not be negative")
    if successes > n:
        raise ValueError("successes exceed trials")
    if n == 0:
        return (0.0, 1.0)
    p = successes / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    margin = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - margin), min(1.0, centre + margin))


def rate_line(label: str, successes: int, n: int) -> str:
    low, high = wilson(successes, n)
    pct = 100 * successes / n if n else 0.0
    return (f"{label:<28}{successes:>3}/{n:<4}{pct:>6.1f}%  "
            f"[{100 * low:.1f}, {100 * high:.1f}]")
