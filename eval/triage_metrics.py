"""RQ1 — does hybrid triage beat either component alone?

Three conditions over one labelled set, with the model called once per message
and cached so reruns are free and the numbers are stable:

  prefilter only   deterministic rules; deferred messages default to
                   not-important, which is what a rule-based system actually
                   does when its rules do not fire
  model only       the model's verdict for every message
  hybrid           prefilter where it is confident, model elsewhere

The decision threshold is swept on the DEVELOPMENT split only. The held-out set
is touched once, at the end, and never tuned against.

    python -m eval.triage_metrics
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from eval.metrics import Confusion, confusion, split_by_thread
from telemail.db import Database
from telemail.models import TriageResult
from telemail.triage.prefilter import PrefilterConfig, prefilter

CACHE_DIR = Path("data/model_verdicts")


def cache_path(model: str) -> Path:
    """One cache per model. A shared cache would silently reuse one model's
    answers after switching to another."""
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in model or "unknown")
    return CACHE_DIR / f"{safe}.json"
THRESHOLDS = [2, 3, 4, 5]
CONDITIONS = ("prefilter only", "model only", "hybrid")


def predicted_important(verdict: TriageResult | None, threshold: int) -> bool:
    """A deferred or missing verdict is 'not important' — the honest behaviour
    of a system that declined to decide."""
    return verdict is not None and verdict.urgency >= threshold


def model_verdicts(db: Database, rows: list[dict], planner,
                   cache: Path | None = None) -> dict[str, TriageResult]:
    cache = cache or cache_path(getattr(planner, "model", "unknown"))
    cached: dict[str, dict] = {}
    if cache.exists():
        cached = json.loads(cache.read_text())

    missing = [r["message_id"] for r in rows if r["message_id"] not in cached]
    if missing:
        emails = [db.get_email(mid) for mid in missing]
        for v in planner.triage([e for e in emails if e]):
            cached[v.message_id] = v.model_dump()
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text(json.dumps(cached, indent=1, default=str))

    return {k: TriageResult(**v) for k, v in cached.items()}


def evaluate(db: Database, rows: list[dict], models: dict[str, TriageResult],
             threshold: int, cfg: PrefilterConfig) -> dict[str, Confusion]:
    truth = [bool(r["important"]) for r in rows]
    preds: dict[str, list[bool]] = {c: [] for c in CONDITIONS}

    for r in rows:
        email = db.get_email(r["message_id"])
        pre = prefilter(email, cfg) if email else None
        mod = models.get(r["message_id"])

        preds["prefilter only"].append(predicted_important(pre, threshold))
        preds["model only"].append(predicted_important(mod, threshold))
        preds["hybrid"].append(predicted_important(pre or mod, threshold))

    return {c: confusion(truth, preds[c]) for c in CONDITIONS}


def sweep(db: Database, dev: list[dict], models, cfg) -> int:
    """Tuned on development data only. Recall is weighted above precision: a
    suppressed urgent message costs more than a spurious notification."""
    print(f"\nThreshold sweep on the development split (n={len(dev)})")
    print(f"{'thr':>4}{'precision':>11}{'recall':>9}{'F1':>8}")
    best, best_score = THRESHOLDS[0], -1.0
    for t in THRESHOLDS:
        c = evaluate(db, dev, models, t, cfg)["hybrid"]
        score = 0.7 * c.recall + 0.3 * c.precision
        print(f"{t:>4}{c.precision:>11.3f}{c.recall:>9.3f}{c.f1:>8.3f}"
              f"{'   <-' if score > best_score else ''}")
        if score > best_score:
            best, best_score = t, score
    return best


def render(results: dict[str, Confusion], threshold: int, n: int) -> str:
    lines = ["", f"Held-out results (n={n}, urgency threshold {threshold})", "",
             f"{'condition':<16}{'precision':>11}{'recall':>9}{'F1':>8}{'n':>6}"]
    for name in CONDITIONS:
        c = results[name]
        lines.append(f"{name:<16}{c.precision:>11.3f}{c.recall:>9.3f}"
                     f"{c.f1:>8.3f}{c.n:>6}")

    h = results["hybrid"]
    lines += ["", "Confusion matrix — hybrid", "",
              f"{'':>18}{'pred important':>16}{'pred not':>10}",
              f"{'actually important':>18}{h.tp:>16}{h.fn:>10}",
              f"{'actually not':>18}{h.fp:>16}{h.tn:>10}", ""]

    if n < 60:
        lines.append(f"NOTE: with n={n} a single flipped case moves F1 by "
                     f"roughly {100 / max(n, 1):.1f} points. Do not report more "
                     f"than two significant figures.")
    return "\n".join(lines)


def false_negatives(db: Database, rows: list[dict], models, threshold: int,
                    cfg: PrefilterConfig) -> list[dict]:
    """Every missed important message, listed. The plan requires an explanation
    for each; this produces the list to explain."""
    out = []
    for r in rows:
        if not r["important"]:
            continue
        email = db.get_email(r["message_id"])
        v = prefilter(email, cfg) or models.get(r["message_id"])
        if not predicted_important(v, threshold):
            out.append({"message_id": r["message_id"],
                        "subject": (email.subject if email else "")[:70],
                        "sender": email.sender_email if email else "",
                        "source": v.source if v else "no verdict",
                        "urgency": v.urgency if v else None,
                        "reason": v.reason if v else ""})
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=None)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--planner", choices=["openrouter", "ollama"],
                    default="openrouter")
    ap.add_argument("--model", default=None)
    args = ap.parse_args()

    from telemail.config import get_settings
    db = Database(args.db or get_settings().db_path)
    rows = db.labelled_dataset()
    if len(rows) < 20:
        raise SystemExit(f"only {len(rows)} labels — run `python -m scripts.label`")

    s = get_settings()
    model = args.model or s.model_name
    if args.planner == "openrouter":
        from telemail.triage.planner import OpenRouterPlanner
        planner = OpenRouterPlanner(s.openrouter_api_key, model)
    else:
        from telemail.triage.planner import OllamaPlanner
        planner = OllamaPlanner(model)
    if not planner.configured:
        raise SystemExit("set OPENROUTER_API_KEY and MODEL_NAME (or --model)")

    cfg = PrefilterConfig()
    models = model_verdicts(db, rows, planner)
    print(f"model {model}")
    dev, test = split_by_thread(rows, seed=args.seed)
    print(f"{len(rows)} labels over {len({r['thread_id'] for r in rows})} threads")
    print(f"development {len(dev)}   held-out {len(test)}")

    threshold = sweep(db, dev, models, cfg)
    results = evaluate(db, test, models, threshold, cfg)
    print(render(results, threshold, len(test)))

    fns = false_negatives(db, test, models, threshold, cfg)
    print(f"False negatives ({len(fns)}) — explain each in the report:")
    for f in fns:
        print(f"  [{f['source']:<9} u={f['urgency']}] {f['sender']:<28} "
              f"{f['subject']}")

    Path("data/triage_metrics.json").write_text(json.dumps(
        {"threshold": threshold, "n_test": len(test),
         "conditions": {k: vars(v) for k, v in results.items()},
         "false_negatives": fns}, indent=1))
    print("\nwrote data/triage_metrics.json")


if __name__ == "__main__":
    main()
