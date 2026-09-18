import csv
import json

import pytest

from eval.llmail import fetch, sample, split_for, to_eml, write_fixtures

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
    manifest = write_fixtures(sample(RECORDS, 4), tmp_path)
    rows = list(csv.DictReader(manifest.open()))
    assert len(rows) == 4
    assert {r["split"] for r in rows} == {"dev", "test"}
    assert all((tmp_path / r["file"]).exists() for r in rows)


def test_fetch_skips_the_download_when_the_file_exists(tmp_path):
    dest = tmp_path / "llmail.json"
    dest.write_text(json.dumps(RECORDS))

    def get(*a, **k):
        raise AssertionError("must not download an existing file")

    assert fetch(dest, get=get) == dest
