"""The daily labelling habit. Five minutes, ~20 messages.

This is the only input to the project that cannot be recovered late. Without it
there is no RQ1, no precision or recall, and no ablation.

One methodological rule, enforced here rather than trusted to discipline:
**the system's own verdict is never shown while labelling.** Seeing the model's
guess would contaminate the ground truth it is about to be measured against.

    python -m scripts.label            # 20 messages
    python -m scripts.label --n 40
    python -m scripts.label --stats
    python -m scripts.label --recheck-bulk   # re-judge bulk mail labelled important
"""
from __future__ import annotations

import argparse

from telemail.config import get_settings
from telemail.db import Database
from telemail.models import Email

RUBRIC_VERSION = "v1"

RUBRIC = """An email is IMPORTANT if ANY of:
  I1  Sender is on your priority list
  I2  You are a direct recipient AND it asks a question or requests an action
  I3  An explicit deadline or obligation falls within 7 days
  I4  It concerns account security, authentication, or a financial transaction
  I5  It is a reply in a thread you have previously participated in
Otherwise NOT IMPORTANT. In particular:
  X1  Bulk mail with List-Unsubscribe, unless it independently satisfies I4
  X2  Automated notifications from services you have not used in 30 days"""

TARGET = 150


def render(email: Email, index: int, total: int) -> str:
    """Facts only. No category, no urgency, no model output."""
    s = email.signals
    auth = f"spf={s.spf} dkim={s.dkim} dmarc={s.dmarc}"
    if not s.auth_source:
        auth += " (unverified)"
    flags = []
    if email.is_direct:
        flags.append("direct recipient")
    if email.has_list_unsubscribe:
        flags.append("bulk (List-Unsubscribe)")
    if s.first_contact:
        flags.append("first contact")
    else:
        flags.append(f"{s.sender_message_count} prior from this domain")

    return "\n".join([
        "", "─" * 70,
        f"[{index}/{total}]  {email.received_at:%Y-%m-%d %H:%M}",
        f"From:    {email.sender_name or ''} <{email.sender_email}>",
        f"Subject: {email.subject}",
        "",
        f"  {email.snippet}",
        "",
        f"  {auth}",
        f"  {' · '.join(flags)}",
        "─" * 70,
    ])


def progress(db: Database) -> str:
    n = db.label_count()
    balance = db.label_balance()
    bar = "█" * int(30 * min(n / TARGET, 1)) + "░" * (30 - int(30 * min(n / TARGET, 1)))
    return (f"\n{bar}  {n}/{TARGET} labels\n"
            f"important: {balance.get('important', 0)}   "
            f"not important: {balance.get('not_important', 0)}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=20)
    ap.add_argument("--stats", action="store_true")
    ap.add_argument("--recheck-bulk", action="store_true",
                    help="re-judge bulk mail labelled important against X1/I4")
    ap.add_argument("--db", default=None)
    args = ap.parse_args()

    db = Database(args.db or get_settings().db_path)

    if args.stats:
        print(progress(db))
        ds = db.labelled_dataset()
        print(f"distinct threads: {len({d['thread_id'] for d in ds})}")
        return

    batch = db.bulk_labelled_important() if args.recheck_bulk else db.unlabelled(args.n)
    if not batch:
        print("Nothing left to label. Run sync, or raise --n.")
        print(progress(db))
        return

    print(RUBRIC)
    print("\n  y = important    n = not important    s = skip    q = quit\n")

    done = 0
    for i, email in enumerate(batch, 1):
        print(render(email, i, len(batch)))
        while True:
            answer = input("  important? [y/n/s/q] ").strip().lower()
            if answer in ("y", "n", "s", "q"):
                break
            print("  y, n, s or q")

        if answer == "q":
            break
        if answer == "s":
            continue
        db.add_label(email.message_id, answer == "y", RUBRIC_VERSION)
        done += 1

    print(f"\nlabelled {done} this session.")
    print(progress(db))
    db.close()


if __name__ == "__main__":
    main()
