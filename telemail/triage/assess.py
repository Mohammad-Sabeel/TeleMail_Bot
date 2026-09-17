"""Feature C: layered verdict for one email.

Untrusted zone — it reads attacker-authored bodies and asks the model about them,
but cannot act. Three layers produce evidence; the verdict is the highest level
any layer reached, so no layer (least of all the model) can lower another.

  1. deterministic  header checks, links, attachments
  2. detector       the trained injection classifier (eval/injection_clf.py)
  3. model          a validated assessment; can raise to CAUTION, or to THREAT
                    only when layer 1 or 2 already found something
"""
from __future__ import annotations

import ipaddress
import re
from enum import IntEnum
from pathlib import Path
from urllib.parse import urlparse

from telemail.models import Email

DETECTOR_PATH = "data/injection_clf.joblib"
DETECTOR_THRESHOLD = 0.5
MAX_EVIDENCE = 8
RISKY_EXTENSIONS = {".html", ".htm", ".exe", ".js", ".vbs", ".scr", ".docm",
                    ".xlsm", ".iso", ".zip"}

_DOMAIN_RE = re.compile(r"\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b", re.I)
_detectors: dict[str, object] = {}


class Level(IntEnum):
    NONE = 0
    CAUTION = 1
    THREAT = 2


def _host(href: str) -> str:
    try:
        return (urlparse(href).hostname or "").lower()
    except ValueError:
        return ""


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def link_evidence(links: list[dict]) -> list[str]:
    out = []
    for link in links:
        host = _host(link.get("href") or "")
        if not host:
            continue
        if _is_ip(host):
            out.append(f"link to a raw IP address ({host})")
        elif "xn--" in host:
            out.append(f"link to a look-alike (punycode) domain ({host})")
        shown = _DOMAIN_RE.search(link.get("text") or "")
        if shown and "@" not in (link.get("text") or ""):
            text_domain = shown.group(1).lower().removeprefix("www.")
            real = host.removeprefix("www.")
            if (text_domain != real and not real.endswith("." + text_domain)
                    and not text_domain.endswith("." + real)):
                out.append(f"link text shows {text_domain} but goes to {real}")
    return list(dict.fromkeys(out))


def deterministic_evidence(email: Email, read: dict | None) -> tuple[Level, list[str]]:
    s = email.signals
    level, evidence = Level.NONE, []
    fails = [k.upper() for k in ("spf", "dkim", "dmarc") if getattr(s, k) == "fail"]
    if len(fails) >= 2:
        level = Level.THREAT
        evidence.append(f"{', '.join(fails)} failed")

    caution = []
    if s.display_name_mismatch:
        caution.append("display name claims a different domain")
    if s.reply_to_differs and s.first_contact:
        caution.append("first email from this sender, and replies go elsewhere")
    if read:
        caution += link_evidence(read.get("links", []))
        caution += [f"risky attachment: {name}" for name in read.get("attachments", [])
                    if Path(name.lower()).suffix in RISKY_EXTENSIONS]
    if caution:
        level = max(level, Level.CAUTION)
        evidence += caution
    return level, evidence[:MAX_EVIDENCE]


def detector_score(text: str, model_path: str = DETECTOR_PATH) -> float | None:
    """Maximum injection probability over overlapping chunks, so a payload buried
    in a long body is not diluted. None when the classifier file is missing."""
    if not Path(model_path).exists():
        return None
    if model_path not in _detectors:
        import joblib
        _detectors[model_path] = joblib.load(model_path)
    from telemail.triage.guard import _chunks
    parts = _chunks(text) or [text or ""]
    return float(max(p[1] for p in _detectors[model_path].predict_proba(parts)))
