"""Operational reliability: schema validity, broker rejections, duplicates.

These are the numbers that show the system behaved, as distinct from the numbers
that show it was correct.

    python -m eval.reliability
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from telemail.db import Database


def collect(db: Database) -> dict:
    audit = db.audit_entries()
    events = Counter(e["event"] for e in audit)
    sources = db.source_counts()
    messages = db.count_emails()
    model_calls = sources.get("model", 0) + sources.get("fallback", 0)

    rejections = [e for e in audit if e["event"] == "rejected"]
    reasons = Counter((e["reason"] or "unknown").split(":")[0]
                      for e in rejections)

    duplicates = db.con.execute(
        "SELECT COUNT(*) - COUNT(DISTINCT message_id) d FROM emails").fetchone()["d"]

    return {
        "messages": messages,
        "triaged": sum(sources.values()),
        "by_source": sources,
        # Over model verdicts only. None when the model has not been asked
        # anything — a 100% computed over zero calls is not a result.
        "model_verdicts": model_calls,
        "schema_validity": (round(sources.get("model", 0) / model_calls, 4)
                            if model_calls else None),
        "fallback_rate": (round(sources.get("fallback", 0) / model_calls, 4)
                          if model_calls else None),
        # Over every ingested message, so mail deferred to a model that has not
        # run yet still counts as "not decided by the prefilter".
        "prefilter_share": (round(sources.get("prefilter", 0) / messages, 4)
                            if messages else None),
        "awaiting_model": len(db.untriaged(10_000)),
        "broker": {"proposed": events.get("proposed", 0),
                   "accepted": events.get("accepted", 0),
                   "rejected": events.get("rejected", 0),
                   "executed": events.get("executed", 0),
                   "by_reason": dict(reasons)},
        "unauthorised_updates": events.get("unauthorised_update", 0),
        "duplicates": duplicates,
        "resyncs": events.get("resync", 0),
        "alerts_sent": events.get("alert_sent", 0),
    }


def _pct(x) -> str:
    return "n/a (no model verdicts yet)" if x is None else f"{x:.1%}"


def render(r: dict) -> str:
    b = r["broker"]
    lines = ["", "Reliability", "",
             f"  messages ingested      {r['messages']}",
             f"  duplicates             {r['duplicates']}   (must be 0)",
             f"  history resyncs        {r['resyncs']}",
             "",
             f"  triaged                {r['triaged']}",
             f"  by source              {r['by_source'] or 'none'}",
             f"  prefilter share        {_pct(r['prefilter_share'])}   (of ingested; target 40-60%)",
             f"  awaiting model         {r['awaiting_model']}",
             f"  model verdicts         {r['model_verdicts']}",
             f"  schema validity        {_pct(r['schema_validity'])}",
             f"  fallback rate          {_pct(r['fallback_rate'])}",
             "",
             f"  proposals              {b['proposed']}",
             f"  accepted / rejected    {b['accepted']} / {b['rejected']}",
             f"  executed               {b['executed']}",
             f"  unauthorised updates   {r['unauthorised_updates']}   (dropped)"]
    if b["by_reason"]:
        lines.append("")
        lines.append("  rejections by reason")
        for reason, n in sorted(b["by_reason"].items(), key=lambda x: -x[1]):
            lines.append(f"    {n:>4}  {reason}")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=None)
    args = ap.parse_args()
    from telemail.config import get_settings
    db = Database(args.db or get_settings().db_path)
    r = collect(db)
    print(render(r))
    Path("data/reliability.json").write_text(json.dumps(r, indent=1))
    print("\nwrote data/reliability.json")


if __name__ == "__main__":
    main()
