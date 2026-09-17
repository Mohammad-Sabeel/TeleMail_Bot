"""The allowlist, expressed as a type.

Anything not in these unions is not merely rejected — it is unrepresentable.
`extra="forbid"` means a model that invents a `recipient` field gets a
validation error rather than a silently ignored parameter.

Two separate unions, because they have different authorities:

  Intent          what the MODEL may propose. Read-only, without exception.
  ApprovedAction  what a HUMAN may authorise. Reachable only through a
                  pre-registered transaction the model cannot mint.
"""
from __future__ import annotations

import re
from typing import Annotated, Literal, Union

from pydantic import BaseModel, ConfigDict, Field

THREAD_ID = r"^[A-Za-z0-9_.@-]{1,128}$"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


# --------------------------------------------------------- model-proposable

class SearchIntent(_Strict):
    op: Literal["search"]
    query: str = Field(max_length=200)
    max_results: int = Field(default=10, ge=1, le=20)


class GetThreadIntent(_Strict):
    op: Literal["get_thread"]
    thread_id: str = Field(pattern=THREAD_ID)


class SummariseIntent(_Strict):
    op: Literal["summarise"]
    thread_id: str = Field(pattern=THREAD_ID)


class ReadMessageIntent(_Strict):
    op: Literal["read_message"]
    message_id: str = Field(pattern=THREAD_ID)


Intent = Annotated[Union[SearchIntent, GetThreadIntent, SummariseIntent,
                         ReadMessageIntent],
                   Field(discriminator="op")]


# -------------------------------------------------------- human-approvable

class MarkReadAction(_Strict):
    op: Literal["mark_read"]
    message_id: str = Field(pattern=THREAD_ID)


class LabelUrgentAction(_Strict):
    op: Literal["label_urgent"]
    message_id: str = Field(pattern=THREAD_ID)


ApprovedAction = Annotated[Union[MarkReadAction, LabelUrgentAction],
                           Field(discriminator="op")]


# ------------------------------------------------------------ query limits

ALLOWED_OPERATORS = {"from", "to", "subject", "newer_than", "older_than",
                     "is", "has", "label"}
_OPERATOR_RE = re.compile(r"(\w+):")


class BrokerRejection(Exception):
    """Raised inside validation; always caught and audited, never propagated."""


def validate_query(q: str) -> str:
    """Gmail's query syntax is expressive. Read-only access makes this defence
    in depth rather than a critical control, but it is three lines and the
    principle should be applied consistently."""
    for token in _OPERATOR_RE.findall(q):
        if token.lower() not in ALLOWED_OPERATORS:
            raise BrokerRejection(f"operator not permitted: {token}")
    return q
