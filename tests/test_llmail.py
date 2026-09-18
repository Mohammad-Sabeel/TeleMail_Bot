import csv
import email
import json
from collections import Counter, defaultdict
from email import policy as email_policy
from email.parser import BytesParser

import pytest

from eval.llmail import DATASET_URL, fetch, sample, split_for, to_eml, write_fixtures

RECORDS = [{"level": f"L{i % 4}", "subject": f"Subject {i}",
            "body": f"Body {i} with instructions", "objectives": {"exfil.sent": i % 2 == 0}}
           for i in range(40)]


def test_sample_is_deterministic():
    assert [r["subject"] for r in sample(RECORDS, 8)] == \
           [r["subject"] for r in sample(RECORDS, 8)]


def test_sample_is_stratified_across_levels():
    levels = {r["level"] for r in sample(RECORDS, 8)}
    assert levels == {"L0", "L1", "L2", "L3"}


def test_sample_never_returns_more_than_asked():
    assert len(sample(RECORDS, 8)) == 8
    assert len(sample(RECORDS, 500)) == len(RECORDS)


def test_split_alternates_so_both_halves_are_balanced():
    assert [split_for(i) for i in range(4)] == ["dev", "test", "dev", "test"]


def test_eml_carries_our_headers_and_the_body():
    raw = to_eml(RECORDS[0], 3).decode()
    assert "X-TeleMail-Technique: LLMAIL" in raw
    assert "X-TeleMail-Variant: 3" in raw
    assert "X-TeleMail-Split: test" in raw
    assert "Body 0 with instructions" in raw


def test_write_fixtures_writes_files_and_a_manifest(tmp_path):
    # 8 across 4 levels gives 2 per level, so dev/test both appear under the
    # per-level split (see test_split_is_balanced_within_each_level).
    manifest = write_fixtures(sample(RECORDS, 8), tmp_path)
    rows = list(csv.DictReader(manifest.open()))
    assert len(rows) == 8
    assert {r["split"] for r in rows} == {"dev", "test"}
    assert all((tmp_path / r["file"]).exists() for r in rows)


def test_fetch_skips_the_download_when_the_file_exists(tmp_path):
    dest = tmp_path / "llmail.json"
    dest.write_text(json.dumps(RECORDS))

    def get(*a, **k):
        raise AssertionError("must not download an existing file")

    assert fetch(dest, get=get) == dest


def test_fetch_downloads_when_the_file_is_missing(tmp_path):
    dest = tmp_path / "llmail.json"
    calls = []

    class FakeResponse:
        content = b'{"a": 1}'

        def raise_for_status(self):
            pass

    def get(url, **kwargs):
        calls.append(url)
        return FakeResponse()

    assert fetch(dest, get=get) == dest
    assert dest.read_bytes() == b'{"a": 1}'
    assert calls == [DATASET_URL]


ARM_RECORDS = [
    {"level": "L0", "subject": "attack case", "body": "b0",
     "objectives": {"attack_attempt": "True", "reason": "judge",
                    "judge_category": "direct instructions"}},
    {"level": "L0", "subject": "control case", "body": "b1",
     "objectives": {"attack_attempt": "False", "reason": "judge",
                    "judge_category": "N/A"}},
    {"level": "L0", "subject": "unclear case", "body": "b2",
     "objectives": {"attack_attempt": "Unclear", "reason": "judge"}},
]


def test_arm_reflects_the_dataset_label_and_matches_the_manifest(tmp_path):
    manifest = write_fixtures(ARM_RECORDS, tmp_path)
    rows = list(csv.DictReader(manifest.open()))
    assert {r["arm"] for r in rows} == {"attack", "control", "unclear"}
    for row in rows:
        raw = (tmp_path / row["file"]).read_bytes().decode()
        assert f"X-TeleMail-Arm: {row['arm']}" in raw


def test_objectives_header_survives_both_eml_parsers(tmp_path):
    record = {"level": "L0", "subject": "s", "body": "b",
              "objectives": {"attack_attempt": "True", "reason": "judge",
                             "judge_category": "social engineering",
                             "judge_answer": "x" * 2000}}
    manifest = write_fixtures([record], tmp_path)
    name = list(csv.DictReader(manifest.open()))[0]["file"]
    raw = (tmp_path / name).read_bytes()

    compat_msg = email.message_from_bytes(raw)
    modern_msg = BytesParser(policy=email_policy.default).parsebytes(raw)

    for msg in (compat_msg, modern_msg):
        parsed = json.loads(msg["X-TeleMail-Objectives"])
        assert parsed == {"attack_attempt": "True", "reason": "judge",
                           "judge_category": "social engineering"}


def test_split_is_balanced_within_each_level(tmp_path):
    records = ([{"level": "L0", "subject": f"a{i}", "body": "b"} for i in range(7)] +
               [{"level": "L1", "subject": f"b{i}", "body": "b"} for i in range(3)])
    manifest = write_fixtures(records, tmp_path)
    rows = list(csv.DictReader(manifest.open()))
    per_level = defaultdict(Counter)
    for r in rows:
        per_level[r["level"]][r["split"]] += 1
    for level, counts in per_level.items():
        assert abs(counts["dev"] - counts["test"]) <= 1
