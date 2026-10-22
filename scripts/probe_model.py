"""The Phase 4 gate: can this model hold the output schema?

Run it before you depend on the model, not after. If it cannot keep the
contract, you want to know in week 1 when changing MODEL_NAME is free.

Below ~14/20, add one worked example and retry. Still low, try another model.
No model is assumed: pass candidates with --model, then put the one that passes
in .env as MODEL_NAME.

    python -m scripts.probe_model --model <openrouter-model-id>
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from telemail.db import Database
from telemail.models import Email

FAILURES = Path("data/probe_failures.json")


def probe(planner, emails: list[Email]) -> dict:
    results, failures = [], []
    for email in emails:
        verdicts = planner.triage([email])
        v = verdicts[0] if verdicts else None
        valid = v is not None and v.source == "model"
        results.append(valid)
        if not valid:
            failures.append({"message_id": email.message_id,
                             "subject": email.subject[:70],
                             "source": v.source if v else "none",
                             "reason": v.reason if v else "no verdict"})
    return {"valid": sum(results), "total": len(results), "failures": failures}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=20)
    ap.add_argument("--model", default=None,
                    help="model id to probe; defaults to MODEL_NAME from .env")
    ap.add_argument("--db", default=None)
    ap.add_argument("--planner", choices=["openrouter", "ollama"],
                    default="openrouter")
    args = ap.parse_args()

    from telemail.config import get_settings
    s = get_settings()
    db = Database(args.db or s.db_path)

    emails = db.unlabelled(args.n) or []
    if len(emails) < args.n:
        rows = db.con.execute("SELECT message_id FROM emails LIMIT ?",
                              (args.n,)).fetchall()
        emails = [db.get_email(r["message_id"]) for r in rows]
    if not emails:
        raise SystemExit("no messages in the database — run `python -m telemail sync`")

    if args.planner == "openrouter":
        from telemail.triage.planner import OpenRouterPlanner as P
        name = args.model or s.model_name
        if not name:
            raise SystemExit("No model chosen. Pass --model <id> (any OpenRouter "
                             "model supporting response_format), or set MODEL_NAME.")
        if not s.openrouter_api_key:
            raise SystemExit("OPENROUTER_API_KEY is empty in .env")
        planner = P(s.openrouter_api_key, name)
    else:
        from telemail.triage.planner import OllamaPlanner as P
        name = args.model or s.model_name
        if not name:
            raise SystemExit("No model chosen. Pass --model <ollama-model>.")
        planner = P(name)

    out = probe(planner, emails)
    print(f"\nmodel: {name}")
    print(f"valid / total: {out['valid']}/{out['total']}")

    if out["failures"]:
        FAILURES.parent.mkdir(parents=True, exist_ok=True)
        FAILURES.write_text(json.dumps(out["failures"], indent=1))
        print(f"{len(out['failures'])} failure(s) written to {FAILURES}")

    ratio = out["valid"] / max(out["total"], 1)
    print("\nGATE:", "pass — proceed" if ratio >= 0.7 else
          "below 70% — tighten the prompt with one worked example, then retry; "
          "if still low, probe a different --model")
    print("Record this number in notes/LOG.md. It goes in the report.")


if __name__ == "__main__":
    main()
