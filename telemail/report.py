"""report.pdf — built as plain data, then rendered. Deterministic: no model here.

Holds verdicts, evidence, next steps and the model's one-line gist. No email body
text is copied in. The PDF is delivered through Telegram's servers.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from telemail.triage.assess import Level

FONT_CANDIDATES = ("/Library/Fonts/Arial Unicode.ttf",
                   "/System/Library/Fonts/Supplemental/Arial Unicode.ttf")
FOOTER = '"No threat indicators" is an automated assessment, not a guarantee.'
COLOURS = {Level.THREAT: (176, 32, 32), Level.CAUTION: (176, 110, 0),
           Level.NONE: (30, 120, 70)}
LABELS = {Level.THREAT: "THREAT", Level.CAUTION: "CAUTION",
          Level.NONE: "NO THREAT INDICATORS"}


@dataclass
class ReportEntry:
    message_id: str
    sender: str
    subject: str
    date: datetime
    urgency: int
    level: Level
    evidence: list[str]
    next_step: str
    gist: str | None


@dataclass
class SyncReport:
    created_at: datetime
    threats: list[ReportEntry]
    caution: list[ReportEntry]
    ok: list[ReportEntry]
    not_read: list[tuple[str, str]]


def build_report(entries: list[ReportEntry], not_read: list[tuple[str, str]],
                 created_at: datetime) -> SyncReport:
    def section(level):
        return sorted((e for e in entries if e.level == level),
                      key=lambda e: (-e.urgency, -e.date.timestamp()))
    return SyncReport(created_at, section(Level.THREAT), section(Level.CAUTION),
                      section(Level.NONE), list(not_read))


def caption(report: SyncReport) -> str:
    n = len(report.threats)
    return (f"{n} threat{'' if n == 1 else 's'} · {len(report.caution)} caution · "
            f"{len(report.ok)} no threat indicators · {len(report.not_read)} bulk not read")


def _clean(text: str, unicode_font: bool) -> str:
    """Drop emoji and symbols the fonts cannot draw; latin-1 only without a TTF."""
    kept = "".join(ch for ch in str(text or "")
                   if ord(ch) <= 0xFFFF and not 0xFE00 <= ord(ch) <= 0xFE0F
                   and not 0x2600 <= ord(ch) <= 0x27BF)
    if not unicode_font:
        kept = kept.encode("latin-1", "replace").decode("latin-1")
    return " ".join(kept.split())


def render_pdf(report: SyncReport, path: Path, font_path: str | None = None) -> Path:
    from fpdf import FPDF
    from fpdf.enums import XPos, YPos

    if font_path is None:
        font_path = next((f for f in FONT_CANDIDATES if Path(f).exists()), "")
    pdf = FPDF(format="A4")
    pdf.set_margins(18, 18, 18)
    pdf.set_auto_page_break(True, 18)
    pdf.add_page()
    if font_path:
        pdf.add_font("body", "", font_path)
        family, unicode_font = "body", True
    else:
        family, unicode_font = "Helvetica", False

    def line(text, size=10, colour=(25, 35, 40), gap=1.5):
        pdf.set_font(family, "", size)
        pdf.set_text_color(*colour)
        pdf.multi_cell(0, size * 0.5, _clean(text, unicode_font),
                       new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(gap)

    line("TeleMail sync report", 18, gap=1)
    line(f"{report.created_at:%d %b %Y, %H:%M}", 10, (110, 120, 125), gap=1)
    line(caption(report), 10, (110, 120, 125), gap=6)

    for title, level, entries in (("Threats", Level.THREAT, report.threats),
                                  ("Caution", Level.CAUTION, report.caution),
                                  ("No threat indicators — OK to respond", Level.NONE,
                                   report.ok)):
        line(title, 14, COLOURS[level], gap=2)
        if not entries:
            line("None.", 10, (110, 120, 125), gap=5)
            continue
        for e in entries:
            line(e.subject, 11, gap=0.5)
            line(f"From {e.sender} · {e.date:%d %b %Y %H:%M}", 9, (110, 120, 125), gap=1)
            line(f"Verdict: {LABELS[e.level]}", 9, COLOURS[e.level], gap=0.5)
            for item in e.evidence:
                line(f"- {item}", 9, gap=0.3)
            line(f"Next step: {e.next_step}", 9, gap=0.3)
            if e.gist:
                line(f"Gist: {e.gist}", 9, (70, 80, 85), gap=0.3)
            pdf.ln(4)
        pdf.ln(2)

    line("Not read: bulk", 14, (110, 120, 125), gap=2)
    if report.not_read:
        for sender, subject in report.not_read:
            line(f"{sender} — {subject}", 9, gap=0.3)
    else:
        line("None.", 10, (110, 120, 125))
    pdf.ln(6)
    line(FOOTER, 8, (110, 120, 125))

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    pdf.output(str(path))
    return path
