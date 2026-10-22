"""An injection detector, and the transfer gap that matters.

Trained on 500 direct chat prompts (median 38 characters). Tested on injections
delivered through email, where the payload is one sentence inside several
hundred words of carrier text.

Two scoring modes are compared, because the difference is itself the result:

  whole      score the entire message at once. TF-IDF normalisation dilutes a
             one-sentence payload across a 500-word document.
  chunked    score overlapping 180-word windows, take the maximum. The same
             mitigation guard.py applies to Prompt Guard.

Paired controls (identical carrier, no payload) isolate the payload's effect
from the carrier's.

    python -m eval.injection_clf
"""
from __future__ import annotations

import csv
import json
from email import policy
from email.parser import BytesParser
from pathlib import Path

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline


# T8 buries its instruction in ~400 words of legitimate text. Scoring only the
# first window would miss it by construction, so long bodies are scored as
# overlapping chunks and the maximum is taken.
_CHUNK_WORDS = 180
_OVERLAP_WORDS = 60


def _chunks(text: str) -> list[str]:
    words = text.split()
    if len(words) <= _CHUNK_WORDS:
        return [text] if text.strip() else []
    step = _CHUNK_WORDS - _OVERLAP_WORDS
    return [" ".join(words[i:i + _CHUNK_WORDS])
            for i in range(0, len(words), step)
            if words[i:i + _CHUNK_WORDS]]

DATA = Path("data/corpus/Prompt_INJECTION_And_Benign_DATASET.jsonl")
FIXTURES = Path("fixtures/own")
MODEL_OUT = Path("data/injection_clf.joblib")
SEED = 42


def train():
    rows = [json.loads(l) for l in DATA.open(encoding="utf-8", errors="replace") if l.strip()]
    X = [r["prompt"] for r in rows]
    y = [1 if r["label"] == "malicious" else 0 for r in rows]
    lens = sorted(len(p.split()) for p in X)
    print(f"training on {len(X)} prompts, median {lens[len(lens)//2]} words "
          f"(balanced {sum(y)}/{len(y)-sum(y)})")

    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.25,
                                          random_state=SEED, stratify=y)
    clf = Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 2), min_df=1,
                                  sublinear_tf=True)),
        ("lr", LogisticRegression(max_iter=2000, class_weight="balanced",
                                  random_state=SEED)),
    ])
    clf.fit(Xtr, ytr)
    pred, prob = clf.predict(Xte), clf.predict_proba(Xte)[:, 1]
    print(f"\nHeld-out, in-distribution (n={len(yte)}):")
    print(classification_report(yte, pred, target_names=["benign", "injection"],
                                digits=3))
    print(f"ROC AUC: {roc_auc_score(yte, prob):.4f}")
    joblib.dump(clf, MODEL_OUT)
    return clf


def body_of(path: Path) -> str:
    msg = BytesParser(policy=policy.default).parse(path.open("rb"))
    parts = []
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() in ("text/plain", "text/html"):
                parts.append(part.get_content())
    else:
        parts.append(msg.get_content())
    return f"{msg.get('Subject', '')}\n" + "\n".join(parts)


def score(clf, text: str, chunked: bool) -> float:
    if not chunked:
        return float(clf.predict_proba([text])[0][1])
    parts = _chunks(text) or [text]
    return max(float(p[1]) for p in clf.predict_proba(parts))


def evaluate(clf):
    pairs = {}
    for f in sorted(FIXTURES.glob("*.eml")):
        msg = BytesParser(policy=policy.default).parse(f.open("rb"))
        key = (msg.get("X-TeleMail-Technique"), msg.get("X-TeleMail-Variant"))
        pairs.setdefault(key, {})[msg.get("X-TeleMail-Arm")] = body_of(f)

    rows = []
    for (tech, var), arms in pairs.items():
        if "attack" not in arms or "control" not in arms:
            continue
        r = {"technique": tech, "variant": var}
        for mode, chunked in (("whole", False), ("chunked", True)):
            a = score(clf, arms["attack"], chunked)
            c = score(clf, arms["control"], chunked)
            r[f"{mode}_attack"] = round(a, 4)
            r[f"{mode}_control"] = round(c, 4)
            r[f"{mode}_delta"] = round(a - c, 4)
            r[f"{mode}_detected"] = a >= 0.5
        rows.append(r)

    by_tech = {}
    for r in rows:
        by_tech.setdefault(r["technique"], []).append(r)

    print("\n" + "=" * 72)
    print("Transfer to email-delivered injection (paired against carrier controls)")
    print("=" * 72)
    print(f"{'technique':>10} | {'whole doc':>21} | {'chunked':>21}")
    print(f"{'':>10} | {'attack':>7}{'ctrl':>7}{'delta':>7} | "
          f"{'attack':>7}{'ctrl':>7}{'delta':>7}")
    print("-" * 72)
    for t in sorted(by_tech, key=lambda x: (len(x), x)):
        rs = by_tech[t]
        m = lambda k: sum(r[k] for r in rs) / len(rs)
        print(f"{t:>10} | {m('whole_attack'):>7.3f}{m('whole_control'):>7.3f}"
              f"{m('whole_delta'):>+7.3f} | {m('chunked_attack'):>7.3f}"
              f"{m('chunked_control'):>7.3f}{m('chunked_delta'):>+7.3f}")

    n = len(rows)
    wd = sum(r["whole_detected"] for r in rows)
    cd = sum(r["chunked_detected"] for r in rows)
    print("-" * 72)
    print(f"{'DETECTED':>10} | {f'{wd}/{n}':>21} | {f'{cd}/{n}':>21}")

    with open("results/injection_transfer.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    print("\nwrote results/injection_transfer.csv")


if __name__ == "__main__":
    evaluate(train())
