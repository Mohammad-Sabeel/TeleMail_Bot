"""Calibrate the Prompt Guard threshold on YOUR benign mail.

This is the legitimate version of "train it on my Gmail". We do not fine-tune —
you have no labelled injections in your inbox, and your only injection examples
are the evaluation corpus, which must never be trained or tuned on.

Instead we measure the false-positive rate on genuinely benign mail and pick a
threshold. Development split only. Run before the attack corpus exists, so
there is no way for the corpus to influence the choice.

    python -m scripts.calibrate_guard --limit 300
"""
import argparse
import sqlite3

from telemail.config import get_settings
from telemail.triage.guard import PromptGuard

THRESHOLDS = [0.5, 0.7, 0.8, 0.9, 0.95, 0.99]


def benign_sample(limit: int) -> list[tuple[str, str]]:
    """Ordinary inbox mail. Assumes no injections — true today, and the
    reason this is a development split and not a test set."""
    con = sqlite3.connect(get_settings().db_path)
    rows = con.execute(
        "SELECT message_id, subject || ' ' || snippet FROM emails "
        "ORDER BY received_at DESC LIMIT ?", (limit,)).fetchall()
    con.close()
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=300)
    args = ap.parse_args()

    guard = PromptGuard(threshold=0.0)
    sample = benign_sample(args.limit)
    if not sample:
        raise SystemExit("No emails in the database yet — finish Phase 1 first.")

    scores = []
    for mid, text in sample:
        v = guard.score(text)
        if not v.available:
            raise SystemExit(
                "Prompt Guard could not be loaded. Download the model and set "
                "GUARD_MODEL_PATH. See telemail/triage/guard.py.")
        scores.append((v.score, mid, text[:80]))

    n = len(scores)
    print(f"\nScored {n} benign messages from your own inbox.\n")
    print(f"{'threshold':>10} {'false positives':>16} {'FPR':>8}")
    for t in THRESHOLDS:
        fp = sum(1 for s, _, _ in scores if s >= t)
        print(f"{t:>10.2f} {fp:>16d} {fp / n:>8.3f}")

    print("\nHighest-scoring benign messages — check these are genuinely benign:")
    for s, mid, preview in sorted(scores, reverse=True)[:5]:
        print(f"  {s:.3f}  {mid}  {preview}")

    print("\nPick the lowest threshold whose FPR you can live with, put it in "
          ".env as GUARD_THRESHOLD, and record the table in LOG.md.")
    print("Do NOT revisit this after seeing the attack corpus results.")


if __name__ == "__main__":
    main()
