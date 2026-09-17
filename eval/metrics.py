"""Classification metrics, written out rather than imported.

Fifteen lines you can defend beats a library call you cannot. The confusion
matrix is the primary artefact; the headline figures are derived from it.
"""
from __future__ import annotations

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
