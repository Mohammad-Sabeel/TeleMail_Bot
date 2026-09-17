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

import logging
from dataclasses import dataclass

from telemail.models import Email, TriageResult

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

Works without a model:
/recent `[n]` — latest messages
/urgent — anything triaged urgency 4+
/suspicious — failed sender authentication
/search `<query>` — e\\.g\\. `from:uni\\.edu`, `subject:invoice`
/status — counts and watermark

Needs `OPENROUTER_API_KEY` and `MODEL_NAME`:
/ask `<question>` — ask about your inbox in plain English

Any other message is treated as /ask\\."""


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
class SyncSummary:
    new: int
    important: int
    suspicious: list[tuple[Email, TriageResult | None]]
    top: list[tuple[Email, TriageResult | None]]

    @property
    def listed(self) -> list[tuple[Email, TriageResult | None]]:
        """Suspicious first, then top — the order [Open] buttons are numbered in."""
        return self.suspicious + self.top


def build_sync_summary(items: list[tuple[Email | None, TriageResult | None]],
                       top_n: int = 5) -> SyncSummary:
    """Pure: which of this sync's emails to show, and in what order.

    Every suspicious email is shown (uncapped, newest first); then the top
    `top_n` of the rest by urgency, newest first on ties. Untriaged emails rank
    last. No email appears twice.
    """
    pairs = [(e, t) for e, t in items if e is not None]

    def newest(pair):
        return -pair[0].received_at.timestamp()

    suspicious = sorted((p for p in pairs if p[1] and p[1].category == "suspicious"),
                        key=newest)
    shown = {e.message_id for e, _ in suspicious}
    rest = sorted((p for p in pairs if p[0].message_id not in shown),
                  key=lambda p: (-(p[1].urgency if p[1] else 0), newest(p)))
    return SyncSummary(new=len(pairs),
                       important=sum(1 for _, t in pairs if t and t.urgency >= 4),
                       suspicious=suspicious, top=rest[:top_n])


def format_sync_summary(summary: SyncSummary, notes: list[str] | tuple = ()) -> str:
    if not summary.new:
        lines = ["📭 *No new mail*"]
    else:
        lines = ["📬 *Sync complete*",
                 escape_md(f"{summary.new} new · {summary.important} important · "
                           f"{len(summary.suspicious)} suspicious")]
        n = 0
        for title, group in (("⚠️ *Suspicious*", summary.suspicious),
                             ("📌 *Top emails*", summary.top)):
            if not group:
                continue
            lines += ["", title]
            for email, triage in group:
                n += 1
                lines.append(f"*{n}\\.* " + format_email_line(email, triage))
    if notes:
        lines += [""] + [f"_{escape_md(note)}_" for note in notes]
    return "\n".join(lines)


def open_buttons(summary: SyncSummary) -> list[tuple[str, str]]:
    """(label, callback_data) per listed email. Telegram caps callback data at
    64 bytes, so an id that does not fit gets no button rather than a broken one."""
    out = []
    for i, (email, _) in enumerate(summary.listed, 1):
        data = f"open:{email.message_id}"
        if len(data.encode()) <= 64:
            out.append((f"Open {i}", data))
    return out


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
                 planner=None, adapter=None):
        self.token = token
        self.allowed_chat_id = int(allowed_chat_id)
        self.db = db
        self.broker = broker
        self.planner = planner
        self.adapter = adapter

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
        if not data.startswith("tx:"):
            await query.edit_message_text("Unrecognised action")
            return

        result = self.broker.approve(data[3:], actor="user")
        await query.edit_message_text(
            "✅ Done" if result.ok else f"❌ Rejected: {result.reason}")

    async def on_ask(self, update, context) -> None:
        if not self._guard(update):
            return
        question = " ".join(context.args) if getattr(context, "args", None) else ""
        if not question:
            await update.message.reply_text("Usage: /ask <question>")
            return
        ready = self.planner is not None and getattr(
            self.planner, "configured", bool(getattr(self.planner, "api_key", "x")))
        if not ready:
            await update.message.reply_text(
                "/ask needs a model. Set OPENROUTER_API_KEY and MODEL_NAME in "
                ".env and restart.\n\nWorking now without one: /recent /urgent "
                "/suspicious /search /status")
            return

        # The model proposes; the broker decides. The raw dict is deliberately
        # unvalidated here — validation belongs on the other side of the gate.
        proposal = self.planner.propose(question, context=[])
        result = self.broker.execute(proposal, actor="planner")

        if not result.ok:
            await update.message.reply_text(
                f"That request was not permitted: {result.reason}")
            return
        await update.message.reply_text(
            format_search_results(result.data if isinstance(result.data, list) else []),
            parse_mode="MarkdownV2")

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
        """Anything that is not a command is a question."""
        if not self._guard(update):
            return

        class _Ctx:
            args = (update.message.text or "").split()
        await self.on_ask(update, _Ctx())

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
        for name, handler in (("start", self.on_start), ("help", self.on_start),
                              ("recent", self.on_recent),
                              ("urgent", self.on_urgent),
                              ("suspicious", self.on_suspicious),
                              ("search", self.on_search),
                              ("ask", self.on_ask),
                              ("status", self.on_status)):
            app.add_handler(CommandHandler(name, handler))
        app.add_handler(CallbackQueryHandler(self.on_callback))
        app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND,
                                       self.on_text))
        return app

    def run(self) -> None:                                 # pragma: no cover
        self.build_app().run_polling()
