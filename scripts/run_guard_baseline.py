"""Prompt Guard over the adversarial fixtures — the RQ2 detection baseline.

This measures what a purpose-built, production injection detector catches on
email-delivered indirect injection. Whatever it misses is what the broker has
to stop, and the broker's L3 rate is zero either way. That contrast is the
result; this script produces its left-hand column.

    python -m scripts.run_guard_baseline --fixtures data/fixtures
"""
import argparse
import csv
from collections import defaultdict
from email import policy
from email.parser import BytesParser
from pathlib import Path

from telemail.triage.guard import PromptGuard


def body_of(path: Path) -> str:
    msg = BytesParser(policy=policy.default).parse(path.open("rb"))
    parts = []
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() in ("text/plain", "text/html"):
                parts.append(part.get_content())
    else:
        parts.append(msg.get_content())
    subject = msg.get("Subject", "")
    return f"{subject}\n\n" + "\n".join(parts)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fixtures", default="data/fixtures")
    ap.add_argument("--out", default="data/guard_baseline.csv")
    args = ap.parse_args()

    guard = PromptGuard()
    files = sorted(Path(args.fixtures).glob("*.eml"))
    if not files:
        raise SystemExit(f"No .eml fixtures in {args.fixtures} — run harvest_corpus first.")

    rows, by_tech = [], defaultdict(lambda: [0, 0])
    for f in files:
        msg = BytesParser(policy=policy.default).parse(f.open("rb"))
        technique = msg.get("X-TeleMail-Technique", "?")
        v = guard.score(body_of(f))
        if not v.available:
            raise SystemExit(
                "Prompt Guard is not installed. Run: python -m scripts.download_guard")
        by_tech[technique][1] += 1
        by_tech[technique][0] += int(v.flagged)
        rows.append({"file": f.name, "technique": technique,
                     "score": round(v.score, 4), "flagged": v.flagged,
                     "chunks": v.chunks_scored})

    with open(args.out, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)

    total_hit = sum(h for h, _ in by_tech.values())
    total_n = sum(n for _, n in by_tech.values())

    print(f"\nPrompt Guard over {total_n} fixtures (threshold {guard.threshold})\n")
    print(f"{'technique':>10} {'detected':>10}")
    for t in sorted(by_tech):
        hit, n = by_tech[t]
        print(f"{t:>10} {f'{hit}/{n}':>10}")
    print(f"{'TOTAL':>10} {f'{total_hit}/{total_n}':>10}")
    print(f"\nwrote {args.out}")
    print("\nThe misses are the point: each one is an injection that reaches the "
          "planner, and that the broker must stop deterministically.")


if __name__ == "__main__":
    main()
