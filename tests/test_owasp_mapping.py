"""The OWASP mapping has one source: BUILD_PLAN.md. results.md reproduces it."""
from pathlib import Path

from eval.render import owasp_section

HEADING = "## OWASP mapping — LLM Top 10 (2025)"
RISKS = [f"LLM{n:02d}" for n in range(1, 11)]


def test_build_plan_covers_every_risk():
    plan = Path("docs/BUILD_PLAN.md").read_text()
    table = plan.split(HEADING, 1)[1].split("\n## ", 1)[0]
    for risk in RISKS:
        assert risk in table, f"{risk} missing from the mapping"


def test_render_reproduces_the_table():
    section = owasp_section()
    assert section is not None
    for risk in RISKS:
        assert risk in section
    assert HEADING not in section, "the heading is added by render, not duplicated"


def test_every_gap_names_a_stage_or_says_covered():
    table = owasp_section()
    rows = [r for r in table.splitlines() if r.startswith("| **LLM")]
    assert len(rows) == 10
    for row in rows:
        gap = row.rsplit("|", 2)[1].lower()
        assert "stage" in gap or "covered" in gap or "state it" in gap, row
