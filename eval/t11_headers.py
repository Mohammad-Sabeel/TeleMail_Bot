"""T11 — forged Authentication-Results, measured without a model.

Each T11 fixture carries a header the attacker wrote claiming spf/dkim/dmarc
pass. Two delivery conditions are evaluated:

  delivered      Gmail's own verdict prepended above the sender's headers, as
                 real delivery does. The prepended verdict is SIMULATED (fail,
                 since the harness sender cannot pass for the claimed domain).
  undelivered    the message as the attacker wrote it, with no Gmail header —
                 the residual-risk condition documented in headers.py.

"Attacker wins" means the parser reports spf=pass.

    python -m eval.t11_headers
"""
from __future__ import annotations

import json
from email import policy
from email.parser import BytesParser
from pathlib import Path

from telemail.gmail.headers import parse_auth_results, parse_auth_results_naive

FIXTURES = Path("data/fixtures")
OUT = Path("data/t11_headers.json")
GOOGLE_VERDICT = ("Authentication-Results",
                  "mx.google.com; spf=fail (google.com: domain of "
                  "harness@example.invalid does not designate sender) "
                  "smtp.mailfrom=harness@example.invalid; dkim=none; "
                  "dmarc=fail (p=REJECT) header.from=example.invalid")


def run(fixtures: Path = FIXTURES) -> dict:
    rows = []
    for f in sorted(fixtures.glob("T11_v*.eml")):
        if "control" in f.name:
            continue
        msg = BytesParser(policy=policy.default).parse(f.open("rb"))
        written = [(k, str(v)) for k, v in msg.items()]
        for condition, headers in (("delivered", [GOOGLE_VERDICT] + written),
                                   ("undelivered", written)):
            naive, trusted = parse_auth_results_naive(headers), parse_auth_results(headers)
            rows.append({"fixture": f.name, "condition": condition,
                         "naive": naive, "trusted": trusted,
                         "attacker_wins_naive": naive["spf"] == "pass",
                         "attacker_wins_trusted": trusted["spf"] == "pass"})

    summary = {}
    for cond in ("delivered", "undelivered"):
        rs = [r for r in rows if r["condition"] == cond]
        summary[cond] = {"n": len(rs),
                         "naive": sum(r["attacker_wins_naive"] for r in rs),
                         "trusted": sum(r["attacker_wins_trusted"] for r in rs)}
    return {"summary": summary, "rows": rows}


def main():
    result = run()
    s = result["summary"]
    print("\nT11 forged Authentication-Results — attacker wins (reported spf=pass)\n")
    print(f"{'condition':<13}{'naive (dict)':>14}{'trusted':>10}")
    for cond, v in s.items():
        print(f"{cond:<13}{v['naive']:>10}/{v['n']:<3}{v['trusted']:>7}/{v['n']}")
    OUT.write_text(json.dumps(result, indent=1))
    print(f"\nwrote {OUT}")


if __name__ == "__main__":
    main()
