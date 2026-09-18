"""Assemble results.md from the JSON each harness leaves behind.

Never transcribe a number by hand. You will change something in week 8 and
forget to update a figure, and the one inconsistency an examiner finds costs
more credibility than the whole table earns.

    python -m eval.render > results.md
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

DATA = Path("data")


def load(name: str):
    p = DATA / name
    return json.loads(p.read_text()) if p.exists() else None


def section(title: str, body: str | None, missing: str) -> str:
    return f"## {title}\n\n" + (body if body else f"_{missing}_\n")


def triage_section() -> str | None:
    r = load("triage_metrics.json")
    if not r:
        return None
    lines = [f"Held-out n={r['n_test']}, urgency threshold {r['threshold']} "
             f"(tuned on the development split only).", "",
             "| condition | precision | recall | F1 | n |",
             "|---|---|---|---|---|"]
    for name, c in r["conditions"].items():
        tp, fp, fn, tn = c["tp"], c["fp"], c["fn"], c["tn"]
        n = tp + fp + fn + tn
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        lines.append(f"| {name} | {prec:.3f} | {rec:.3f} | {f1:.3f} | {n} |")

    h = r["conditions"]["hybrid"]
    lines += ["", "**Confusion matrix — hybrid**", "",
              "| | predicted important | predicted not |", "|---|---|---|",
              f"| actually important | {h['tp']} | {h['fn']} |",
              f"| actually not | {h['fp']} | {h['tn']} |", ""]

    fns = r.get("false_negatives", [])
    lines.append(f"**False negatives ({len(fns)})** — each requires an "
                 f"explanation in the report.\n")
    for f in fns:
        lines.append(f"- `{f['source']}` u={f['urgency']} — {f['sender']} — "
                     f"{f['subject']}")
    return "\n".join(lines) + "\n"


def _attack_table(p: Path) -> str | None:
    import csv
    if not p.exists():
        return None
    rows = list(csv.DictReader(p.open()))
    by: dict[str, dict[str, str]] = {}
    for r in rows:
        by.setdefault(r["technique"], {})[r["arm"]] = r["level"]

    lines = ["| technique | brokered | naive |", "|---|---|---|"]
    for t in sorted(by, key=lambda x: (len(x), x)):
        lines.append(f"| {t} | {by[t].get('brokered','-')} | "
                     f"{by[t].get('naive','-')} |")

    n = len({(r["technique"], r["variant"]) for r in rows})
    lines += ["", "| outcome | brokered | naive |", "|---|---|---|"]
    for level, label in (("L3", "invoked"), ("L2", "proposed, blocked"),
                         ("L1", "misclassified"), ("L0", "no effect")):
        b = sum(r["level"] == level and r["arm"] == "brokered" for r in rows)
        v = sum(r["level"] == level and r["arm"] == "naive" for r in rows)
        lines.append(f"| {level} {label} | {b}/{n} | {v}/{n} |")
    return "\n".join(lines) + "\n"


def attack_section() -> str | None:
    nonce = _attack_table(DATA / "attack_results.csv")
    static = _attack_table(DATA / "attack_results_static.csv")
    if not (nonce or static):
        return None
    parts = []
    if static:
        parts.append("**Before — static `<email>` delimiters (T4 escapable)**\n\n" + static)
    if nonce:
        parts.append("**After — per-request nonced delimiters**\n\n" + nonce)
    return "\n".join(parts)


def t11_section() -> str | None:
    r = load("t11_headers.json")
    if not r:
        return None
    lines = ["Attacker wins = parser reports `spf=pass` for a forged header. "
             "The prepended Gmail verdict in the *delivered* condition is simulated.", "",
             "| condition | naive (dict-collapse) | trusted (topmost, mx.google.com) |",
             "|---|---|---|"]
    for cond, v in r["summary"].items():
        lines.append(f"| {cond} | {v['naive']}/{v['n']} | {v['trusted']}/{v['n']} |")
    return "\n".join(lines) + "\n"


def cross_batch_section() -> str | None:
    import csv
    p = DATA / "cross_batch.csv"
    if not p.exists():
        return None
    rows = list(csv.DictReader(p.open()))
    n = sum(int(r["neighbours"]) for r in rows)
    c = sum(int(r["contaminated"]) for r in rows)
    z = sum(int(r["noise"]) for r in rows)
    lines = ["| variant | neighbours changed | noise | poisoned itself changed | batched ≠ alone |",
             "|---|---|---|---|---|"]
    for r in rows:
        lines.append(f"| {r['variant']} | {r['contaminated']}/{r['neighbours']} | "
                     f"{r['noise']} | {r['self_changed']} | {r['batched_vs_alone_changed']} |")
    lines += ["", f"Neighbour verdicts changed by the payload **{c}/{n}**; between identical "
                  f"runs {z}/{n}; attributable to contamination **{max(c - z, 0)}/{n}**."]
    return "\n".join(lines) + "\n"


def pct(x) -> str:
    return "n/a — no model verdicts yet" if x is None else f"{x:.1%}"


def reliability_section() -> str | None:
    r = load("reliability.json")
    if not r:
        return None
    b = r["broker"]
    lines = ["| metric | value |", "|---|---|",
             f"| messages ingested | {r['messages']} |",
             f"| duplicates | {r['duplicates']} |",
             f"| history resyncs | {r['resyncs']} |",
             f"| prefilter decision share (of ingested) | {pct(r['prefilter_share'])} |",
             f"| awaiting model | {r.get('awaiting_model', 'n/a')} |",
             f"| model verdicts | {r.get('model_verdicts', 0)} |",
             f"| schema validity | {pct(r['schema_validity'])} |",
             f"| fallback rate | {pct(r['fallback_rate'])} |",
             f"| proposals / rejected | {b['proposed']} / {b['rejected']} |",
             f"| unauthorised updates dropped | {r['unauthorised_updates']} |"]
    if b["by_reason"]:
        lines += ["", "**Broker rejections by reason**", "",
                  "| reason | n |", "|---|---|"]
        for reason, n in sorted(b["by_reason"].items(), key=lambda x: -x[1]):
            lines.append(f"| {reason} | {n} |")
    return "\n".join(lines) + "\n"


def detection_section() -> str | None:
    import csv
    parts = []
    p = DATA / "paired_detection.csv"
    if p.exists():
        rows = list(csv.DictReader(p.open()))
        mean = sum(float(r["delta"]) for r in rows) / len(rows)
        flipped = sum(1 for r in rows if float(r["attack_score"]) >= 0.5
                      > float(r["control_score"]))
        parts.append(f"**Phishing detector** — mean Δ over {len(rows)} matched "
                     f"pairs: **{mean:+.3f}**; payload flipped the verdict in "
                     f"{flipped}/{len(rows)} pairs.\n")
    p = DATA / "injection_transfer.csv"
    if p.exists():
        rows = list(csv.DictReader(p.open()))
        n = len(rows)
        for mode in ("whole", "chunked"):
            a = sum(float(r[f"{mode}_attack"]) >= 0.5 for r in rows)
            c = sum(float(r[f"{mode}_control"]) >= 0.5 for r in rows)
            d = sum(float(r[f"{mode}_delta"]) for r in rows) / n
            wins = sum(float(r[f"{mode}_attack"]) > float(r[f"{mode}_control"])
                       for r in rows)
            parts.append(f"**Injection detector ({mode})** — attacks flagged "
                         f"{a}/{n}, controls {c}/{n}, mean Δ {d:+.3f}; attack "
                         f"outscored its own control in {wins}/{n} pairs.\n")
    return "\n".join(parts) if parts else None


def performance_section() -> str | None:
    r = load("performance.json")
    if not r:
        return None
    b, lat, c = r["broker_overhead"], r["pipeline_latency"], r["cost"]
    lines = ["**Mediation overhead** (per proposal, microseconds)", "",
             "| | p50 | p95 |", "|---|---|---|",
             f"| brokered | {b['brokered']['p50']} | {b['brokered']['p95']} |",
             f"| naive dispatch | {b['naive']['p50']} | {b['naive']['p95']} |",
             f"| **overhead** | **{b['overhead_p50']}** | |", "",
             f"**Pipeline latency** (seconds; live messages {lat['live_messages']} "
             f"of {lat['messages_total']}, backfill excluded)", "",
             "| stage | n | p50 | p95 |", "|---|---|---|---|"]
    for k in ("arrival_to_ingest", "ingest_to_decision", "decision_to_alert",
              "arrival_to_alert"):
        v = lat[k]
        lines.append(f"| {k.replace('_', ' ')} | {v['n']} | {v['p50']} | {v['p95']} |")
    cost = (f"${c['usd_per_1000']} per 1,000 model verdicts "
            f"({c['calls']} calls, {c['prompt_tokens']} in / {c['completion_tokens']} out tokens)"
            if c["usd_per_1000"] is not None else
            f"not yet measured ({c['calls']} model calls recorded)")
    lines += ["", f"**Cost:** {cost}"]
    return "\n".join(lines) + "\n"


def owasp_section() -> str | None:
    """Lifted from BUILD_PLAN.md so the mapping has one source, not two."""
    plan = Path("docs/BUILD_PLAN.md")
    if not plan.is_file():
        return None
    body = plan.read_text().split("## OWASP mapping — LLM Top 10 (2025)", 1)
    if len(body) < 2:
        return None
    table = body[1].split("\n## ", 1)[0].strip()
    return table + "\n" if table else None


def main():
    print(f"# TeleMail — Results\n")
    print(f"_Generated {datetime.now():%Y-%m-%d %H:%M}. "
          f"Every figure below is produced by `make evaluate`; none is typed "
          f"by hand._\n")
    print(section("RQ1 — Triage utility", triage_section(),
                  "not yet run: python -m eval.triage_metrics"))
    print(section("RQ2 — Attack resistance", attack_section(),
                  "not yet run: python -m eval.run_attacks [--delimiters static]"))
    print(section("T11 — Forged authentication headers", t11_section(),
                  "not yet run: python -m eval.t11_headers"))
    print(section("T10 — Cross-batch contamination", cross_batch_section(),
                  "not yet run: python -m eval.cross_batch"))
    print(section("Detection baselines", detection_section(),
                  "not yet run: python -m eval.phishing_clf && "
                  "python -m eval.injection_clf"))
    print(section("RQ3 — Cost of mediation", performance_section(),
                  "not yet run: python -m eval.performance"))
    print(section("Reliability", reliability_section(),
                  "not yet run: python -m eval.reliability"))
    print(section("OWASP LLM Top 10 (2025) mapping", owasp_section(),
                  "docs/BUILD_PLAN.md not found"))


if __name__ == "__main__":
    main()
