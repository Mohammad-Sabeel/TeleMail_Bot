"""Held-out attacks from the LLMail-Inject challenge (Microsoft, MIT licence).

Real attacks written by real people against an email assistant, with the
challenge's own labels. We never tune against this data: half is reserved as
the test split and touched once. Uses the phase-2 submissions file (65MB)
rather than phase-1 (448MB) — phase-1 needs gigabytes of RAM to parse on this
machine and both files have the same record shape.
Cite as: LLMail-Inject challenge dataset, Microsoft, MIT licence.
"""
from __future__ import annotations

import csv
import json
import random
import re
from collections import defaultdict
from email import policy
from email.message import EmailMessage
from pathlib import Path

# Headers never fold: a folded X-TeleMail-Objectives breaks json.loads for a
# bare `email.message_from_bytes` parser (RFC-2822 folding inserts a literal
# newline inside the JSON string).
_NO_WRAP = policy.default.clone(max_line_length=None)

DATASET_URL = ("https://huggingface.co/datasets/microsoft/llmail-inject-challenge/"
               "resolve/main/data/labelled_unique_submissions_phase2.json")
DEFAULT_CACHE = Path("data/corpus/llmail/submissions_phase2.json")

# The real file is a dict keyed by "Subject of the email: <subject>.  Body:
# <body>" (the raw submission text) and valued by the challenge's outcome
# labels for that submission. Matched against the full 37303-key file with
# zero misses.
_KEY_PATTERN = re.compile(r"^Subject of the email:\s*(.*?)\.\s{2,3}Body:\s*(.*)$", re.S)


def fetch(dest: Path = DEFAULT_CACHE, get=None) -> Path:
    dest = Path(dest)
    if dest.exists():
        return dest
    if get is None:
        import httpx
        get = httpx.get
    dest.parent.mkdir(parents=True, exist_ok=True)
    response = get(DATASET_URL, timeout=120, follow_redirects=True)
    response.raise_for_status()
    dest.write_bytes(response.content)
    return dest


def load(path: Path = DEFAULT_CACHE) -> list[dict]:
    """Parse once; adapt the real shape (dict of text -> outcome) to records.

    There is no `level` field in this file. `judge_category` — the attack
    technique a judge model assigned (e.g. "social engineering") — stands in
    for it, falling back to `reason` ("api_triggered") for the submissions
    that triggered the tool call directly and so were never judged.
    """
    data = json.loads(Path(path).read_text())
    if isinstance(data, list):
        return data
    records = []
    for text, outcome in data.items():
        match = _KEY_PATTERN.match(text)
        subject, body = (match.group(1), match.group(2)) if match else ("(unparsed)", text)
        level = outcome.get("judge_category") or outcome.get("reason", "unknown")
        records.append({"subject": subject, "body": body, "level": level,
                         "objectives": outcome})
    return records


def sample(records: list[dict], n: int, seed: int = 20260918) -> list[dict]:
    """Round-robin across levels so no single difficulty dominates."""
    by_level = defaultdict(list)
    for r in records:
        by_level[str(r.get("level", "unknown"))].append(r)
    rng = random.Random(seed)
    for bucket in by_level.values():
        rng.shuffle(bucket)
    out, levels = [], sorted(by_level)
    while len(out) < n and any(by_level[l] for l in levels):
        for level in levels:
            if by_level[level] and len(out) < n:
                out.append(by_level[level].pop())
    return out


def split_for(index: int) -> str:
    return "dev" if index % 2 == 0 else "test"


# Only these three outcome fields are worth a header: judge_answer is a
# paragraph of judge reasoning we never use, and its length is what pushed
# the header past RFC-2822's fold threshold.
_OBJECTIVE_KEYS = ("attack_attempt", "reason", "judge_category")
_ATTACK_ATTEMPT_TRUE = (True, "True")
_ATTACK_ATTEMPT_FALSE = (False, "False")


def arm_for(record: dict) -> str:
    """The dataset's own attack_attempt label, not an assumption we write in."""
    value = (record.get("objectives") or {}).get("attack_attempt")
    if value in _ATTACK_ATTEMPT_TRUE:
        return "attack"
    if value in _ATTACK_ATTEMPT_FALSE:
        return "control"
    return "unclear"


def to_eml(record: dict, index: int, split: str | None = None) -> bytes:
    msg = EmailMessage(policy=_NO_WRAP)
    msg["Subject"] = str(record.get("subject") or "(no subject)")
    msg["From"] = "Attacker <attacker@llmail.invalid>"
    msg["To"] = "you@example.invalid"
    msg["X-TeleMail-Technique"] = "LLMAIL"
    msg["X-TeleMail-Variant"] = str(index)
    msg["X-TeleMail-Arm"] = arm_for(record)
    msg["X-TeleMail-Source"] = "llmail-inject"
    msg["X-TeleMail-Level"] = str(record.get("level", "unknown"))
    msg["X-TeleMail-Split"] = split if split is not None else split_for(index)
    objectives = record.get("objectives")
    if objectives:
        trimmed = {k: objectives[k] for k in _OBJECTIVE_KEYS if k in objectives}
        msg["X-TeleMail-Objectives"] = json.dumps(trimmed, separators=(",", ":"))
    msg.set_content(str(record.get("body") or ""))
    return msg.as_bytes()


def write_fixtures(records: list[dict], out_dir: Path) -> Path:
    """Split dev/test within each level so category mix can't skew the split."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    rows = []
    position_in_level = defaultdict(int)
    for index, record in enumerate(records):
        level = str(record.get("level", "unknown"))
        split = split_for(position_in_level[level])
        position_in_level[level] += 1
        name = f"LLMAIL_{index:03d}.eml"
        (out_dir / name).write_bytes(to_eml(record, index, split=split))
        rows.append({"file": name, "source": "llmail-inject", "level": level,
                     "split": split, "arm": arm_for(record)})
    manifest = out_dir / "manifest.csv"
    with manifest.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=["file", "source", "level", "split", "arm"])
        writer.writeheader()
        writer.writerows(rows)
    return manifest


def main():                                        # pragma: no cover
    path = fetch()
    records = sample(load(path), 200)
    manifest = write_fixtures(records, Path("data/fixtures_llmail"))
    print(f"wrote {len(records)} fixtures; manifest at {manifest}")


if __name__ == "__main__":                         # pragma: no cover
    main()
