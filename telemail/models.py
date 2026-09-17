"""The contracts. Written before any logic — everything else depends on these shapes."""
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

AuthResult = Literal["pass", "fail", "softfail", "neutral", "none", "permerror", "temperror"]


class SenderSignals(BaseModel):
    """Evidence about who sent this, never a verdict.

    Every field is computed by deterministic code from headers the receiving
    server asserted. The sender cannot write into this object.
    """
    spf: AuthResult = "none"
    dkim: AuthResult = "none"
    dmarc: AuthResult = "none"
    auth_source: str = ""          # which server asserted the above; "" means nobody we trust
    display_name_mismatch: bool = False
    reply_to_differs: bool = False
    first_contact: bool = True
    sender_message_count: int = 0

    def failed_checks(self) -> list[str]:
        """Named checks that failed. Absence of evidence is not a failure:
        spf=none is common for legitimate small senders and must not alarm."""
        out = []
        if self.spf == "fail":
            out.append("spf")
        if self.dkim == "fail":
            out.append("dkim")
        if self.dmarc == "fail":
            out.append("dmarc")
        if self.display_name_mismatch:
            out.append("display_name_mismatch")
        if self.reply_to_differs:
            out.append("reply_to_differs")
        return out


class Email(BaseModel):
    """Normalised message. The only shape the rest of the system sees.

    Bodies are never stored here (D4) — snippet only, fetched on demand.
    """
    message_id: str                # Gmail id — primary key everywhere
    thread_id: str
    sender_email: str
    sender_name: str | None = None
    sender_domain: str             # derived — cheap prefilter signal
    subject: str
    snippet: str
    received_at: datetime
    labels: list[str] = []
    is_direct: bool = False        # you are in To:, not just Cc:
    has_list_unsubscribe: bool = False
    has_attachment: bool = False
    signals: SenderSignals = SenderSignals()


class TriageResult(BaseModel):
    """One verdict per message. `source` is what makes the ablation possible."""
    message_id: str
    category: Literal["academic", "financial", "personal", "promotional",
                      "notification", "suspicious", "other", "uncertain"]
    urgency: int = Field(ge=1, le=5)
    requires_action: bool
    reason: str
    confidence: float = Field(ge=0.0, le=1.0)
    source: Literal["prefilter", "model", "fallback"]
    # The model's only operation-proposing path. Without this the broker has
    # nothing of the model's to mediate and RQ2 has no surface (see BUILD_PLAN 4).
    proposed_action: Literal["mark_read", "label_urgent", "none"] = "none"
