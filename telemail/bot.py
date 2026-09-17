"""Telegram interface. Long polling, so no inbound network endpoint exists.

Security properties, in order:

  sender allowlist    every update is checked against one numeric chat id before
                      anything else happens. There is no command a stranger can
                      reach, including /start.

  escaped rendering   subjects and senders are attacker-authored and are escaped
                      before they enter MarkdownV2. Unescaped, a crafted subject
                      can forge the layout of an alert — spoofing the interface
                      rather than the mail.

  opaque callbacks    buttons carry a single-use transaction token, never a
                      message id. The target was bound when the alert was built,
                      so nothing the user (or anything that reaches the callback)
                      supplies can select what the action applies to.

The pure functions below are tested directly; the handlers are thin wrappers.
"""
from __future__ import annotations

import asyncio
import logging
from collections import deque
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path

from telemail.models import Email, TriageResult
from telemail.report import ReportEntry, build_report, caption, render_pdf
from telemail.triage.assess import assess_email
from telemail.triage.converse import (answer_from_bodies, answer_from_snippets,
                                      interpret, retrieve)
from telemail.triage.expect import match_keyword, parse_keywords

log = logging.getLogger(__name__)

# MarkdownV2 reserves these. Telegram rejects the message if any are unescaped.
_MD_SPECIAL = r"_*[]()~`>#+-=|{}.!"

URGENCY_MARK = {5: "🔴", 4: "🟠", 3: "🟡", 2: "⚪", 1: "⚪"}


def escape_md(text: str) -> str:
    return "".join("\\" + c if c in _MD_SPECIAL else c for c in str(text or ""))


def is_authorised(chat_id: int | None, allowed_chat_id: int) -> bool:
    return chat_id is not None and int(chat_id) == int(allowed_chat_id)


def format_alert(email: Email, triage: TriageResult) -> str:
    """Every interpolated value is attacker-influenced except our own labels."""
    mark = URGENCY_MARK.get(triage.urgency, "⚪")
    lines = [f"{mark} *{escape_md(triage.category.upper())}* "
             f"\\(urgency {triage.urgency}\\)",
             "",
             f"*From:* {escape_md(email.sender_name or email.sender_email)}",
             f"`{escape_md(email.sender_email)}`",
             f"*Subject:* {escape_md(email.subject)}",
             "",
             f"_{escape_md(triage.reason)}_"]

    failed = email.signals.failed_checks()
    if failed:
        lines += ["", f"⚠️ *Failed checks:* {escape_md(', '.join(failed))}"]
    if not email.signals.auth_source:
        lines += ["⚠️ _No trusted authentication assertion_"]
    if triage.source == "fallback":
        lines += ["", "_Classification unavailable; surfaced by default_"]

    lines += ["", f"`{escape_md(email.message_id)}`"]
    return "\n".join(lines)


HELP = """*TeleMail*

/sync — fetch new mail, triage it, and summarise it
/expect `[keywords | clear]` — emails you expect today

Works without a model:
/recent `[n]` — latest messages
/urgent — anything triaged urgency 4+
/suspicious — failed sender authentication
/search `<query>` — e\\.g\\. `from:uni\\.edu`, `subject:invoice`
/status — counts and watermark

Needs `OPENROUTER_API_KEY` and `MODEL_NAME`:
/ask `<question>` — ask about your inbox in plain English

Any other message is treated as /ask\\."""

ASK_EXPECTED = ("Which emails are you expecting today? Send keywords, comma- or "
                "line-separated — e.g. fee receipt, visa letter.")
NEEDS_MODEL = ("/ask needs a model. Set OPENROUTER_API_KEY and MODEL_NAME in .env "
               "and restart.\n\nWorking now without one: /recent /urgent "
               "/suspicious /search /status")
NO_ANSWER = ("I couldn't get a usable answer from the model right now. "
             "Slash commands still work.")


def format_email_line(email, triage=None) -> str:
    mark = URGENCY_MARK.get(triage.urgency, "⚪") if triage else "·"
    who = email.sender_name or email.sender_email
    line = (f"{mark} *{escape_md(escape_trim(email.subject, 58))}*\n"
            f"   {escape_md(escape_trim(who, 34))}  "
            f"·  {email.received_at:%d %b %H:%M}")
    failed = email.signals.failed_checks()
    if any(f in failed for f in ("spf", "dkim", "dmarc")):
        line += "  ⚠️"
    return line


def escape_trim(text: str, n: int) -> str:
    text = str(text or "")
    return text if len(text) <= n else text[:n - 1] + "…"


def format_email_list(items: list, empty: str) -> str:
    if not items:
        return f"_{escape_md(empty)}_"
    return "\n\n".join(format_email_line(e, t) for e, t in items)


@dataclass
class ExpectedLine:
    keyword: str
    matches: list[tuple[Email, TriageResult | None, float]]
    levels: dict[str, str] = field(default_factory=dict)   # message_id -> report level


def warning_reason(email: Email, triage: TriageResult | None,
                   level: str | None = None) -> str | None:
    """Computed by code. An expected match never removes this."""
    if triage and triage.category == "suspicious":
        return "flagged suspicious"
    if any(getattr(email.signals, k) == "fail" for k in ("spf", "dkim", "dmarc")):
        return "failed sender checks"
    if level in ("CAUTION", "THREAT"):
        return f"assessed as {level.lower()}"
    return None


@dataclass
class SyncSummary:
    new: int
    important: int
    suspicious: list[tuple[Email, TriageResult | None]]
    top: list[tuple[Email, TriageResult | None]]
    expected: list[ExpectedLine] = field(default_factory=list)

    @property
    def listed(self) -> list[tuple[Email, TriageResult | None]]:
        """Suspicious, then expected matches, then top — each email once. This is
        the order [Open] buttons are numbered in."""
        matched = [(e, t) for line in self.expected for e, t, _ in line.matches]
        seen, out = set(), []
        for e, t in self.suspicious + matched + self.top:
            if e.message_id not in seen:
                seen.add(e.message_id)
                out.append((e, t))
        return out


def build_sync_summary(items: list[tuple[Email | None, TriageResult | None]],
                       top_n: int = 5, expected=()) -> SyncSummary:
    """Pure: which of this sync's emails to show, and in what order.

    Every suspicious email is shown (uncapped, newest first); expected matches
    next; then the top `top_n` of the rest by urgency, newest first on ties.
    Untriaged emails rank last. No email appears twice.
    """
    pairs = [(e, t) for e, t in items if e is not None]
    expected = list(expected)

    def newest(pair):
        return -pair[0].received_at.timestamp()

    suspicious = sorted((p for p in pairs if p[1] and p[1].category == "suspicious"),
                        key=newest)
    taken = ({e.message_id for e, _ in suspicious}
             | {e.message_id for line in expected for e, _, _ in line.matches})
    rest = sorted((p for p in pairs if p[0].message_id not in taken),
                  key=lambda p: (-(p[1].urgency if p[1] else 0), newest(p)))
    return SyncSummary(new=len(pairs),
                       important=sum(1 for _, t in pairs if t and t.urgency >= 4),
                       suspicious=suspicious, top=rest[:top_n], expected=expected)


def format_expected_section(lines: list[ExpectedLine], number: dict[str, int]) -> list[str]:
    out = ["🎯 *Expected today*"]
    for line in lines:
        kw = escape_md(line.keyword)
        if not line.matches:
            out.append(f"⏳ {kw} — nothing yet")
            continue
        for email, triage, score in line.matches:
            ref = f"*{number[email.message_id]}\\.* " if email.message_id in number else ""
            text = (f"{ref}📌 {kw} → *{escape_md(escape_trim(email.subject, 50))}* — "
                    f"{escape_md(escape_trim(email.sender_name or email.sender_email, 30))} "
                    f"\\({escape_md(f'{score:.2f}')}\\)")
            why = warning_reason(email, triage, line.levels.get(email.message_id))
            if why:
                text += f"\n   ⚠️ _matches “{kw}” but {escape_md(why)}_"
            out.append(text)
    return out


def format_sync_summary(summary: SyncSummary, notes: list[str] | tuple = ()) -> str:
    number = {e.message_id: i for i, (e, _) in enumerate(summary.listed, 1)}
    if summary.new:
        lines = ["📬 *Sync complete*",
                 escape_md(f"{summary.new} new · {summary.important} important · "
                           f"{len(summary.suspicious)} suspicious")]
    else:
        lines = ["📭 *No new mail*"]
    if summary.suspicious:
        lines += ["", "⚠️ *Suspicious*"]
        lines += [f"*{number[e.message_id]}\\.* " + format_email_line(e, t)
                  for e, t in summary.suspicious]
    if summary.expected:
        lines += [""] + format_expected_section(summary.expected, number)
    if summary.top:
        lines += ["", "📌 *Top emails*"]
        lines += [f"*{number[e.message_id]}\\.* " + format_email_line(e, t)
                  for e, t in summary.top]
    if notes:
        lines += [""] + [f"_{escape_md(note)}_" for note in notes]
    return "\n".join(lines)


def format_expected_reply(lines: list[ExpectedLine]) -> str:
    summary = SyncSummary(new=0, important=0, suspicious=[], top=[], expected=lines)
    number = {e.message_id: i for i, (e, _) in enumerate(summary.listed, 1)}
    return "\n".join(format_expected_section(lines, number))


def open_buttons(summary: SyncSummary) -> list[tuple[str, str]]:
    """(label, callback_data) per listed email. Telegram caps callback data at
    64 bytes, so an id that does not fit gets no button rather than a broken one."""
    out = []
    for i, (email, _) in enumerate(summary.listed, 1):
        data = f"open:{email.message_id}"
        if len(data.encode()) <= 64:
            out.append((f"Open {i}", data))
    return out


def format_email_details(email: Email, triage: TriageResult | None,
                         assessment: dict | None = None) -> str:
    """Metadata and verdict only. Never snippet or body text."""
    s = email.signals
    auth = f"SPF {s.spf} · DKIM {s.dkim} · DMARC {s.dmarc}"
    if not s.auth_source:
        auth += " (no trusted assertion)"
    lines = [f"*From:* {escape_md(email.sender_name or email.sender_email)}",
             f"`{escape_md(email.sender_email)}`",
             f"*Subject:* {escape_md(email.subject)}",
             f"*Date:* {escape_md(f'{email.received_at:%d %b %Y %H:%M}')}",
             f"*Sender checks:* {escape_md(auth)}"]
    failed = s.failed_checks()
    if failed:
        lines.append(f"⚠️ *Failed:* {escape_md(', '.join(failed))}")
    if triage:
        lines += ["",
                  f"*Verdict:* {escape_md(triage.category)}, urgency {triage.urgency} "
                  f"\\({escape_md(triage.source)}\\)",
                  f"_{escape_md(triage.reason)}_"]
    else:
        lines += ["", "_Not triaged yet_"]
    if assessment:
        lines += ["", f"*Report verdict:* {escape_md(assessment['level'])}"]
        lines += [f"• {escape_md(item)}" for item in assessment["evidence"]]
    return "\n".join(lines)


def format_answer(answer: str,
                  sources: list[tuple[Email, TriageResult | None, str | None]]) -> str:
    """Warnings first, computed by code from the cited emails; then the model's
    answer; then the sources, numbered to match the [Open] buttons."""
    lines = []
    flagged = [(e, why) for e, t, level in sources if (why := warning_reason(e, t, level))]
    if flagged:
        lines.append("⚠️ *Check before trusting this answer:*")
        lines += [f"• {escape_md(escape_trim(e.subject, 50))} — {escape_md(why)}"
                  for e, why in flagged]
        lines.append("")
    lines.append(escape_md(answer))
    if sources:
        lines += ["", "*Sources*"]
        lines += [f"*{i}\\.* {escape_md(escape_trim(e.subject, 55))} — "
                  f"{escape_md(escape_trim(e.sender_name or e.sender_email, 30))}"
                  for i, (e, _, _) in enumerate(sources, 1)]
    return "\n".join(lines)


def _keyboard(buttons: list[tuple[str, str]]):
    """Inline keyboard, three buttons per row. None when there is nothing to open."""
    if not buttons:
        return None
    from telegram import InlineKeyboardButton, InlineKeyboardMarkup
    rows = [buttons[i:i + 3] for i in range(0, len(buttons), 3)]
    return InlineKeyboardMarkup(
        [[InlineKeyboardButton(label, callback_data=data) for label, data in row]
         for row in rows])


def format_search_results(rows: list[dict]) -> str:
    if not rows:
        return "_No matching messages_"
    out = []
    for r in rows[:10]:
        out.append(f"• *{escape_md(r.get('subject', '(no subject)'))}*\n"
                   f"  {escape_md(r.get('sender', ''))}")
    return "\n".join(out)


@dataclass
class Button:
    label: str
    token: str          # a broker transaction id; never a message id


def build_buttons(broker, email: Email, triage: TriageResult) -> list[Button]:
    """Bind actions to this message BEFORE the user sees the alert.

    An injected instruction arriving later cannot redirect an approved action,
    because the target was fixed at registration and the token is single use.
    """
    actions = [("Mark read", "mark_read")]
    if triage.urgency >= 4:
        actions.append(("Flag urgent", "label_urgent"))

    buttons = []
    for label, action in actions:
        try:
            buttons.append(Button(label,
                                  broker.register_transaction(
                                      message_id=email.message_id, action=action)))
        except Exception as e:                     # BrokerRejection, etc.
            log.warning("could not register %s for %s: %s", action,
                        email.message_id, e)
    return buttons


class TeleMailBot:
    """Thin I/O shell. All decisions live in the pure functions above."""

    def __init__(self, token: str, allowed_chat_id: int, *, db, broker,
                 planner=None, adapter=None, sync_fn=None, triage_fn=None):
        self.token = token
        self.allowed_chat_id = int(allowed_chat_id)
        self.db = db
        self.broker = broker
        self.planner = planner
        self.adapter = adapter
        # Injected by the composition root so the bot never imports sync or
        # triage: sync_fn() -> SyncStats, triage_fn() -> emails still untriaged.
        self.sync_fn = sync_fn
        self.triage_fn = triage_fn
        self._sync_lock = asyncio.Lock()
        # Overridable clocks, so tests control what "today" is.
        self.today = lambda: date.today().isoformat()
        self.now = lambda: datetime.now().astimezone()
        self._awaiting_keywords: str | None = None
        # Set by the composition root; None disables the reading/report stage
        # (bots built without it, e.g. in tests, never read mail).
        self.reports_dir: Path | None = None
        # Conversation memory: the user's messages and the bot's answers only —
        # never retrieved email text, so an email cannot steer later turns.
        self.memory: deque[tuple[str, str]] = deque(maxlen=10)

    # ------------------------------------------------------------ guards

    def _guard(self, update) -> bool:
        chat = getattr(getattr(update, "effective_chat", None), "id", None)
        if is_authorised(chat, self.allowed_chat_id):
            return True
        self.db.log(actor="bot", event="unauthorised_update",
                    payload={"chat_id": chat})
        log.warning("dropped update from unauthorised chat %s", chat)
        return False

    # ---------------------------------------------------------- outbound

    async def send_alert(self, app, email: Email, triage: TriageResult) -> None:
        buttons = build_buttons(self.broker, email, triage)
        markup = None
        if buttons:
            from telegram import InlineKeyboardButton, InlineKeyboardMarkup
            markup = InlineKeyboardMarkup([[
                InlineKeyboardButton(b.label, callback_data=f"tx:{b.token}")
                for b in buttons]])
        await app.bot.send_message(chat_id=self.allowed_chat_id,
                                   text=format_alert(email, triage),
                                   parse_mode="MarkdownV2",
                                   reply_markup=markup)
        self.db.log(actor="bot", event="alert_sent",
                    payload={"message_id": email.message_id,
                             "urgency": triage.urgency})

    # ---------------------------------------------------------- handlers

    async def on_callback(self, update, _context) -> None:
        if not self._guard(update):
            return
        query = update.callback_query
        await query.answer()

        data = str(query.data or "")
        if data == "expect:skip":
            self._awaiting_keywords = None
            await query.edit_message_text("Skipped — use /expect any time.")
            return
        if data.startswith("open:"):
            # Read-only: shows stored metadata; the summary message is left intact.
            email = self.db.get_email(data[len("open:"):])
            if email is None:
                await query.message.reply_text(
                    "That email is no longer in the database.")
                return
            await query.message.reply_text(
                format_email_details(email, self.db.get_triage(email.message_id),
                                     self.db.get_assessment(email.message_id)),
                parse_mode="MarkdownV2")
            return
        if not data.startswith("tx:"):
            await query.edit_message_text("Unrecognised action")
            return

        result = self.broker.approve(data[3:], actor="user")
        await query.edit_message_text(
            "✅ Done" if result.ok else f"❌ Rejected: {result.reason}")

    def _planner_ready(self) -> bool:
        return self.planner is not None and getattr(
            self.planner, "configured", bool(getattr(self.planner, "api_key", "x")))

    def _answer(self, question: str) -> tuple[str, list[Email], bool]:
        """Blocking (1–2 model calls, up to 3 Gmail reads): run via to_thread.
        Returns (answer, cited emails, whether the model answered)."""
        # ponytail: loads the whole mailbox per question; index it if it grows large.
        emails = self.db.recent_emails(days=36_500, now=self.now())
        candidates = retrieve(question, emails)
        history = list(self.memory)
        first = answer_from_snippets(self.planner, question, history, candidates)
        if first is None:
            return NO_ANSWER, [], False
        answer, cited = first.answer, first.cited_ids

        if first.need_full_body and first.message_ids:
            reads = []
            for n in first.message_ids:
                email = candidates[n - 1]
                try:
                    result = self.broker.execute(
                        {"op": "read_message", "message_id": email.message_id},
                        actor="planner")
                except Exception:
                    log.exception("could not read %s", email.message_id)
                    continue
                if result.ok:
                    reads.append((n, email, result.data.get("body", "")))
            second = answer_from_bodies(self.planner, question, history, reads)
            if second is not None:
                answer, cited = second.answer, second.cited_ids
        return answer, [candidates[n - 1] for n in cited], True

    async def _handle_question(self, update, question: str) -> None:
        if not self._planner_ready():
            await update.message.reply_text(NEEDS_MODEL)
            return
        answer, cited, answered = await asyncio.to_thread(self._answer, question)
        sources = []
        for e in cited:
            a = self.db.get_assessment(e.message_id)
            sources.append((e, self.db.get_triage(e.message_id), a["level"] if a else None))
        if answered:
            self.memory.append((question, answer))
        buttons = open_buttons(SyncSummary(new=0, important=0, suspicious=[],
                                           top=[(e, t) for e, t, _ in sources]))
        await update.message.reply_text(format_answer(answer, sources),
                                        parse_mode="MarkdownV2",
                                        reply_markup=_keyboard(buttons))

    async def on_ask(self, update, context) -> None:
        """Straight to the answer pipeline; no intent routing."""
        if not self._guard(update):
            return
        question = " ".join(getattr(context, "args", None) or [])
        if not question:
            await update.message.reply_text("Usage: /ask <question>")
            return
        await self._handle_question(update, question)

    async def on_forget(self, update, _context) -> None:
        if not self._guard(update):
            return
        self.memory.clear()
        await update.message.reply_text("Conversation forgotten.")

    async def on_start(self, update, _context) -> None:
        if not self._guard(update):
            return
        await update.message.reply_text(HELP, parse_mode="MarkdownV2")

    async def on_recent(self, update, context) -> None:
        if not self._guard(update):
            return
        n = 10
        if getattr(context, "args", None):
            try:
                n = max(1, min(int(context.args[0]), 25))
            except ValueError:
                pass
        rows = self.db.con.execute(
            "SELECT message_id FROM emails ORDER BY received_at DESC LIMIT ?",
            (n,)).fetchall()
        items = [(self.db.get_email(r["message_id"]),
                  self.db.get_triage(r["message_id"])) for r in rows]
        await update.message.reply_text(
            format_email_list([i for i in items if i[0]], "No messages yet"),
            parse_mode="MarkdownV2")

    async def on_urgent(self, update, _context) -> None:
        if not self._guard(update):
            return
        rows = self.db.con.execute(
            "SELECT message_id FROM triage WHERE urgency >= 4 "
            "ORDER BY urgency DESC, decided_at DESC LIMIT 15").fetchall()
        items = [(self.db.get_email(r["message_id"]),
                  self.db.get_triage(r["message_id"])) for r in rows]
        await update.message.reply_text(
            format_email_list([i for i in items if i[0]],
                              "Nothing urgent. Run triage first."),
            parse_mode="MarkdownV2")

    async def on_suspicious(self, update, _context) -> None:
        if not self._guard(update):
            return
        rows = self.db.con.execute(
            "SELECT message_id FROM emails WHERE spf='fail' OR dkim='fail' "
            "OR dmarc='fail' OR display_name_mismatch=1 "
            "ORDER BY received_at DESC LIMIT 15").fetchall()
        items = [(self.db.get_email(r["message_id"]),
                  self.db.get_triage(r["message_id"])) for r in rows]
        await update.message.reply_text(
            format_email_list([i for i in items if i[0]],
                              "No authentication failures found"),
            parse_mode="MarkdownV2")

    async def on_search(self, update, context) -> None:
        """A human's search crosses the same gate as a model's. Complete
        mediation means complete, not 'except when we trust the caller'."""
        if not self._guard(update):
            return
        query = " ".join(getattr(context, "args", None) or [])
        if not query:
            await update.message.reply_text(
                "Usage: /search from:uni.edu", parse_mode=None)
            return

        result = self.broker.execute(
            {"op": "search", "query": query, "max_results": 10}, actor="user")
        if not result.ok:
            await update.message.reply_text(f"Rejected: {result.reason}")
            return
        await update.message.reply_text(
            format_search_results(result.data or []), parse_mode="MarkdownV2")

    async def on_text(self, update, context) -> None:
        """The reply right after the daily question is keywords; anything else
        is a question."""
        if not self._guard(update):
            return
        if self._awaiting_keywords == self.today():
            self._awaiting_keywords = None
            await self._add_expectations(update, update.message.text or "")
            return

        await self._handle_question(update, update.message.text or "")

    def _expected_lines(self, keywords: list[str]) -> list[ExpectedLine]:
        """Blocking (TF-IDF and a model call per keyword): run via to_thread."""
        emails = self.db.recent_emails(days=7, now=self.now())
        lines = []
        for keyword in keywords:
            m = match_keyword(self.planner, keyword, emails)
            levels = {e.message_id: a["level"] for e, _, _ in m.matches
                      if (a := self.db.get_assessment(e.message_id))}
            lines.append(ExpectedLine(keyword, [
                (e, self.db.get_triage(e.message_id), score)
                for e, score, _ in m.matches], levels))
        return lines

    async def _reply_expected(self, update, keywords: list[str]) -> None:
        lines = await asyncio.to_thread(self._expected_lines, keywords)
        summary = SyncSummary(new=0, important=0, suspicious=[], top=[], expected=lines)
        await update.message.reply_text(format_expected_reply(lines),
                                        parse_mode="MarkdownV2",
                                        reply_markup=_keyboard(open_buttons(summary)))

    async def _add_expectations(self, update, text: str) -> None:
        keywords = parse_keywords(text)
        if not keywords:
            await update.message.reply_text(
                "No keywords found. Try: fee receipt, visa letter")
            return
        self.db.add_expectations(self.today(), keywords)
        await self._reply_expected(update, keywords)

    async def on_expect(self, update, context) -> None:
        if not self._guard(update):
            return
        args = list(getattr(context, "args", None) or [])
        today = self.today()
        if args == ["clear"]:
            n = self.db.clear_expectations(today)
            self._awaiting_keywords = None
            await update.message.reply_text(f"Cleared {n} expectation(s) for today.")
            return
        if not args:
            keywords = self.db.expectations_for(today)
            if not keywords:
                await update.message.reply_text(
                    "Nothing expected today. Add some: /expect fee receipt, visa letter")
                return
            await self._reply_expected(update, keywords)
            return
        await self._add_expectations(update, " ".join(args))

    def _is_bulk(self, message_id: str) -> bool:
        t = self.db.get_triage(message_id)
        return bool(t and t.source == "prefilter" and t.category == "promotional")

    def _read_and_assess(self, message_ids: list[str]
                         ) -> tuple[list[ReportEntry], list[tuple[str, str]]]:
        """Blocking (a Gmail read and a model call per email): run via to_thread.
        Bodies are read through the broker and discarded; only the verdict is stored."""
        entries, not_read = [], []
        for mid in message_ids:
            email, triage = self.db.get_email(mid), self.db.get_triage(mid)
            if email is None:
                continue
            sender = email.sender_name or email.sender_email
            if self._is_bulk(mid):
                not_read.append((sender, email.subject))
                continue
            try:
                result = self.broker.execute({"op": "read_message", "message_id": mid},
                                             actor="report")
                read = result.data if result.ok else None
            except Exception:
                log.exception("could not read %s", mid)
                read = None
            verdict = assess_email(email, triage, read, self.planner)
            self.db.upsert_assessment(mid, verdict.level.name, verdict.evidence)
            entries.append(ReportEntry(
                message_id=mid, sender=sender, subject=email.subject,
                date=email.received_at, urgency=triage.urgency if triage else 0,
                level=verdict.level, evidence=verdict.evidence,
                next_step=verdict.next_step, gist=verdict.gist))
        return entries, not_read

    async def on_sync(self, update, _context) -> None:
        """Fetch, triage and summarise — only when asked. Blocking Gmail and
        model calls run off the event loop so the bot keeps answering."""
        if not self._guard(update):
            return
        if self.sync_fn is None or self.triage_fn is None:
            await update.message.reply_text("Sync is not configured.")
            return
        if self._sync_lock.locked():
            await update.message.reply_text("⏳ Sync already running.")
            return

        async with self._sync_lock:
            progress = await update.message.reply_text("🔄 Syncing: fetching mail…")
            try:
                stats = await asyncio.to_thread(self.sync_fn)
            except Exception:
                log.exception("sync failed")
                await progress.edit_text("❌ Gmail sync failed. Nothing was lost — "
                                         "run /sync again.")
                return

            notes = []
            if stats.errors:
                notes.append(f"{len(stats.errors)} email(s) could not be fetched; "
                             f"the next /sync retries them.")

            await progress.edit_text(f"🔄 Syncing: {stats.inserted} new — triaging…")
            try:
                remaining = await asyncio.to_thread(self.triage_fn)
            except Exception:
                log.exception("triage failed")
                remaining = None
            if remaining is None:
                notes.append("Triage failed; untriaged emails are retried on the "
                             "next /sync.")
            elif remaining:
                notes.append(f"Model unavailable — {remaining} email(s) left untriaged.")

            report = None
            if stats.inserted_ids and self.reports_dir is not None:
                to_read = [i for i in stats.inserted_ids if not self._is_bulk(i)]
                await progress.edit_text(f"📖 Reading {len(to_read)} new email(s) "
                                         f"for the report…")
                try:
                    entries, not_read = await asyncio.to_thread(
                        self._read_and_assess, stats.inserted_ids)
                    report = build_report(entries, not_read, self.now())
                except Exception:
                    log.exception("report failed")
                    notes.append("The report could not be built this time.")

            items = [(self.db.get_email(i), self.db.get_triage(i))
                     for i in stats.inserted_ids]
            keywords = self.db.expectations_for(self.today())
            expected = (await asyncio.to_thread(self._expected_lines, keywords)
                        if keywords else [])
            summary = build_sync_summary(items, expected=expected)
            await progress.edit_text(format_sync_summary(summary, notes),
                                     parse_mode="MarkdownV2",
                                     reply_markup=_keyboard(open_buttons(summary)))

            if report is not None:
                path = await asyncio.to_thread(
                    render_pdf, report,
                    self.reports_dir / f"report-{self.now():%Y%m%d-%H%M%S}.pdf")
                with open(path, "rb") as fh:
                    await update.message.reply_document(
                        document=fh, filename="report.pdf", caption=caption(report))

            if self.db.get_state("expect_asked_on") != self.today():
                self.db.set_state("expect_asked_on", self.today())
                self._awaiting_keywords = self.today()
                await update.message.reply_text(
                    ASK_EXPECTED, reply_markup=_keyboard([("Skip", "expect:skip")]))

    async def on_status(self, update, _context) -> None:
        if not self._guard(update):
            return
        counts = self.db.source_counts()
        rejections = len(self.db.audit_entries(event="rejected"))
        await update.message.reply_text(
            f"Messages: {self.db.count_emails()}\n"
            f"Triage by source: {counts or 'none yet'}\n"
            f"Broker rejections: {rejections}")

    # -------------------------------------------------------------- run

    def build_app(self):                                   # pragma: no cover
        from telegram.ext import (ApplicationBuilder, CallbackQueryHandler,
                                  CommandHandler)
        from telegram.ext import MessageHandler, filters
        app = ApplicationBuilder().token(self.token).build()
        for name, handler in (("sync", self.on_sync), ("expect", self.on_expect),
                              ("start", self.on_start), ("help", self.on_start),
                              ("recent", self.on_recent),
                              ("urgent", self.on_urgent),
                              ("suspicious", self.on_suspicious),
                              ("search", self.on_search),
                              ("ask", self.on_ask), ("forget", self.on_forget),
                              ("status", self.on_status)):
            app.add_handler(CommandHandler(name, handler))
        app.add_handler(CallbackQueryHandler(self.on_callback))
        app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND,
                                       self.on_text))
        return app

    def run(self) -> None:                                 # pragma: no cover
        self.build_app().run_polling()
