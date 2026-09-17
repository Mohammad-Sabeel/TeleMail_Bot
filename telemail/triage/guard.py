"""Prompt Guard — an injection *signal*, never a gate.

Meta's Llama Prompt Guard classifies text as benign or containing an injection
attempt. It is probabilistic and incomplete, so it must not stand between
attacker-controlled content and the mailbox. That job belongs to the broker,
which is deterministic and complete.

This module therefore only ever produces evidence. It feeds the `suspicious`
category and the Telegram alert. Nothing here can permit or deny an operation.
See BUILD_PLAN Part 2 — defence in depth, not the control.

Model: https://www.kaggle.com/models/metaresearch/llama-3.1-prompt-guard
Download it, accept Meta's licence, and point GUARD_MODEL_PATH at the folder.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

# Threshold is calibrated against benign mail from your own inbox
# (scripts/calibrate_guard.py), never against the attack corpus.
GUARD_THRESHOLD = float(os.environ.get("GUARD_THRESHOLD", "0.5"))
GUARD_MODEL_PATH = os.environ.get("GUARD_MODEL_PATH", "data/prompt_guard")

# Prompt Guard's context window is short and T8 buries its instruction in ~400
# words of legitimate text. Scoring only the first window would miss it by
# construction — so we score overlapping chunks and take the maximum.
_CHUNK_WORDS = 180
_OVERLAP_WORDS = 60


@dataclass
class GuardVerdict:
    score: float              # max malicious probability across chunks
    flagged: bool             # score >= threshold
    label: str                # winning label as the model names it
    chunks_scored: int
    available: bool = True    # False when the model could not be loaded

    @classmethod
    def unavailable(cls) -> "GuardVerdict":
        """Absence of a verdict is not a clean bill of health."""
        return cls(score=0.0, flagged=False, label="unavailable",
                   chunks_scored=0, available=False)


def _chunks(text: str) -> list[str]:
    words = text.split()
    if len(words) <= _CHUNK_WORDS:
        return [text] if text.strip() else []
    step = _CHUNK_WORDS - _OVERLAP_WORDS
    return [" ".join(words[i:i + _CHUNK_WORDS])
            for i in range(0, len(words), step)
            if words[i:i + _CHUNK_WORDS]]


class PromptGuard:
    """Lazy-loading wrapper. Never raises into the pipeline."""

    def __init__(self, model_path: str = GUARD_MODEL_PATH,
                 threshold: float = GUARD_THRESHOLD):
        self.model_path = model_path
        self.threshold = threshold
        self._pipe = None
        self._benign_labels = {"benign", "label_0"}

    def _load(self):
        if self._pipe is not None:
            return self._pipe
        from transformers import pipeline          # imported late: torch is heavy
        self._pipe = pipeline("text-classification", model=self.model_path,
                              truncation=True, top_k=None)
        return self._pipe

    def score(self, text: str) -> GuardVerdict:
        parts = _chunks(text)
        if not parts:
            return GuardVerdict(0.0, False, "empty", 0)

        try:
            pipe = self._load()
        except Exception:
            # Model missing or unloadable. Report unavailable rather than
            # silently returning "benign" — a missing detector must never
            # look like a passed check.
            return GuardVerdict.unavailable()

        best_score, best_label = 0.0, "benign"
        for out in pipe(parts):
            for entry in out:
                label = str(entry["label"]).lower()
                if label in self._benign_labels:
                    continue
                if entry["score"] > best_score:
                    best_score, best_label = float(entry["score"]), label

        return GuardVerdict(score=best_score,
                            flagged=best_score >= self.threshold,
                            label=best_label,
                            chunks_scored=len(parts))
