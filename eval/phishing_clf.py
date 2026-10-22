"""A phishing detector, trained by us, used as the RQ2 detection baseline.

The question it answers: does conventional phishing detection catch injected
instructions? If it does, the architecture is arguably unnecessary. If it does
not, detection cannot be the control and the broker has to be.

Two design constraints make the answer meaningful:

1. CARRIER EXCLUSION. The adversarial fixtures use Nazario and Nigerian_Fraud
   bodies as cover text. Training on those corpora would make the detector fire
   on the carrier and look like injection detection. They are held out entirely.

2. PAIRED CONTROLS. Every attack fixture has a control with identical cover and
   no payload. delta = score(attack) - score(control) isolates what the injected
   instruction contributes. A delta near zero means the detector is reading the
   phishing prose, not the injection.

    python -m eval.phishing_clf
"""
from __future__ import annotations

import csv
import sys
from email import policy
from email.parser import BytesParser
from pathlib import Path

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

csv.field_size_limit(sys.maxsize)

CORPUS = Path("data/corpus/archive")
FIXTURES = Path("data/fixtures")
MODEL_OUT = Path("data/phishing_clf.joblib")

# Held out: Nazario and Nigerian_Fraud supply the fixtures' carrier text.
TRAIN_FILES = ["CEAS_08.csv", "SpamAssasin.csv", "Enron.csv", "Ling.csv"]
SEED = 42


def load_training() -> tuple[list[str], list[int]]:
    X, y = [], []
    for name in TRAIN_FILES:
        path = CORPUS / name
        if not path.exists():
            continue
        with open(path, newline="", encoding="utf-8", errors="replace") as fh:
            for row in csv.DictReader(fh):
                body = (row.get("body") or "").strip()
                if not body:
                    continue
                X.append(f"{(row.get('subject') or '').strip()}\n{body}")
                y.append(int(row["label"]))
    return X, y


def train():
    X, y = load_training()
    print(f"training on {len(X)} messages from {', '.join(TRAIN_FILES)}")
    print("  (Nazario and Nigerian_Fraud held out — they are the fixture carriers)")

    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.25,
                                          random_state=SEED, stratify=y)
    clf = Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 2), min_df=3,
                                  max_features=50_000, sublinear_tf=True)),
        ("lr", LogisticRegression(max_iter=2000, C=1.0,
                                  class_weight="balanced", random_state=SEED)),
    ])
    clf.fit(Xtr, ytr)

    pred = clf.predict(Xte)
    prob = clf.predict_proba(Xte)[:, 1]
    print(f"\nHeld-out performance (n={len(yte)}):")
    print(classification_report(yte, pred, target_names=["legitimate", "phishing"],
                                digits=3))
    print(f"ROC AUC: {roc_auc_score(yte, prob):.4f}")

    MODEL_OUT.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(clf, MODEL_OUT)
    print(f"saved {MODEL_OUT}")
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


def evaluate(clf):
    pairs = {}
    for f in sorted(FIXTURES.glob("*.eml")):
        msg = BytesParser(policy=policy.default).parse(f.open("rb"))
        key = (msg.get("X-TeleMail-Technique"), msg.get("X-TeleMail-Variant"))
        arm = msg.get("X-TeleMail-Arm")
        pairs.setdefault(key, {})[arm] = body_of(f)

    rows = []
    for (tech, var), arms in sorted(pairs.items()):
        if "attack" not in arms or "control" not in arms:
            continue
        sa = clf.predict_proba([arms["attack"]])[0][1]
        sc = clf.predict_proba([arms["control"]])[0][1]
        rows.append({"technique": tech, "variant": var,
                     "attack_score": round(sa, 4),
                     "control_score": round(sc, 4),
                     "delta": round(sa - sc, 4)})

    by_tech = {}
    for r in rows:
        by_tech.setdefault(r["technique"], []).append(r)

    print("\n" + "=" * 62)
    print("Paired detection: does the payload change the verdict?")
    print("=" * 62)
    print(f"{'technique':>10} {'attack':>9} {'control':>9} {'delta':>9}")
    for t in sorted(by_tech, key=lambda x: (len(x), x)):
        rs = by_tech[t]
        a = sum(r["attack_score"] for r in rs) / len(rs)
        c = sum(r["control_score"] for r in rs) / len(rs)
        print(f"{t:>10} {a:>9.3f} {c:>9.3f} {a - c:>+9.3f}")

    mean_delta = sum(r["delta"] for r in rows) / len(rows)
    flipped = sum(1 for r in rows
                  if r["attack_score"] >= 0.5 > r["control_score"])
    print("-" * 62)
    print(f"{'MEAN':>10} {'':>9} {'':>9} {mean_delta:>+9.3f}")
    print(f"\npairs where the payload flipped the verdict to phishing: "
          f"{flipped}/{len(rows)}")

    with open("data/paired_detection.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    print("wrote data/paired_detection.csv")

    print("\nReading it: a delta near zero means the detector responds to the "
          "carrier text, not the injected instruction — injection is invisible "
          "to phishing detection, and the broker is what has to stop it.")


if __name__ == "__main__":
    evaluate(train())
