"""report.pdf: data first, then rendering."""
from datetime import datetime

from telemail.report import ReportEntry, build_report, caption, render_pdf
from telemail.triage.assess import Level


def entry(mid, level, urgency=3, day=16, subject=None):
    return ReportEntry(message_id=mid, sender="Registrar", subject=subject or f"S {mid}",
                       date=datetime(2026, 9, day, 10), urgency=urgency, level=level,
                       evidence=["e"], next_step="n", gist="g")


def test_entries_are_sorted_into_sections_most_urgent_first():
    r = build_report([entry("ok-low", Level.NONE, 2), entry("t", Level.THREAT),
                      entry("ok-high", Level.NONE, 5), entry("c", Level.CAUTION)],
                     [("News", "Sale")], datetime(2026, 9, 17, 9))
    assert [e.message_id for e in r.threats] == ["t"]
    assert [e.message_id for e in r.caution] == ["c"]
    assert [e.message_id for e in r.ok] == ["ok-high", "ok-low"]
    assert r.not_read == [("News", "Sale")]


def test_caption_counts_every_section():
    r = build_report([entry("t", Level.THREAT), entry("o", Level.NONE)],
                     [("a", "b"), ("c", "d")], datetime(2026, 9, 17))
    assert caption(r) == "1 threat · 0 caution · 1 no threat indicators · 2 bulk not read"


def test_renders_a_pdf_with_unicode_and_emoji(tmp_path):
    r = build_report([entry("t", Level.THREAT, subject="❗ Fee — naïve 日本 “quote”")],
                     [], datetime(2026, 9, 17))
    path = render_pdf(r, tmp_path / "reports" / "report.pdf")
    data = path.read_bytes()
    assert data.startswith(b"%PDF") and len(data) > 1000


def test_renders_with_the_builtin_font_fallback(tmp_path):
    r = build_report([entry("c", Level.CAUTION, subject="❗ naïve “quote” 日本")],
                     [("S — x", "y")], datetime(2026, 9, 17))
    path = render_pdf(r, tmp_path / "r.pdf", font_path="")
    assert path.read_bytes().startswith(b"%PDF")


def test_empty_report_still_renders(tmp_path):
    r = build_report([], [], datetime(2026, 9, 17))
    assert render_pdf(r, tmp_path / "e.pdf", font_path="").exists()
