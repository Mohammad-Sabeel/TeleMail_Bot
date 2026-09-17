"""Phase 2 check: a spoofed message becomes a Telegram alert with NO model.

The message is built in delivered form — Gmail's failing verdict on top, the
sender's forged claims below — and then goes through the real parser, prefilter,
alert policy and alert formatter. No planner is constructed at any point.

What this does not do: send a genuinely spoofed email through Gmail. That needs
an SMTP server able to claim a domain it does not control; Gmail itself will not
let you send as someone else. The header path from Gmail onward is identical.

    python -m scripts.demo_spoof_alert           # print the alert
    python -m scripts.demo_spoof_alert --send    # also deliver it to your bot
"""
from __future__ import annotations

import argparse
import asyncio
from datetime import datetime

from telemail.bot import format_alert
from telemail.gmail.normalise import from_eml_bytes
from telemail.policy import should_alert
from telemail.triage.prefilter import prefilter

SPOOFED = b"""Authentication-Results: mx.google.com;
       dkim=fail header.i=@uni.edu;
       spf=fail (google.com: domain of registrar@uni.edu does not designate 203.0.113.9 as permitted sender) smtp.mailfrom=registrar@uni.edu;
       dmarc=fail (p=REJECT sp=REJECT dis=NONE) header.from=uni.edu
Authentication-Results: attacker.example.com; spf=pass; dkim=pass; dmarc=pass
From: "registrar@uni.edu" <registrar@uni-edu-portal.example>
Reply-To: fees@collect.example
To: you@uni.edu
Subject: Final notice: enrolment suspended pending fee verification
Date: Wed, 16 Sep 2026 23:40:00 +0000
Message-ID: <demo-spoof-0001@uni-edu-portal.example>

Your enrolment will be suspended within 24 hours unless payment is verified.
"""


def build():
    email = from_eml_bytes(SPOOFED, own_address="you@uni.edu")
    verdict = prefilter(email)
    decision = should_alert(verdict, email, now=datetime(2026, 9, 16, 23, 45)) \
        if verdict else None
    return email, verdict, decision


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--send", action="store_true")
    args = ap.parse_args()

    email, verdict, decision = build()
    print(f"signals   spf={email.signals.spf} dkim={email.signals.dkim} "
          f"dmarc={email.signals.dmarc} source={email.signals.auth_source}")
    print(f"failed    {email.signals.failed_checks()}")
    print(f"verdict   {verdict.category} urgency={verdict.urgency} "
          f"source={verdict.source}")
    print(f"policy    alert={decision.alert} ({decision.reason}) "
          f"— at 23:45, inside quiet hours")
    print("model     never constructed\n")
    text = format_alert(email, verdict)
    print(text)

    if args.send:
        from telegram import Bot
        from telemail.config import get_settings
        s = get_settings()

        async def send():
            await Bot(s.telegram_bot_token).send_message(
                chat_id=s.telegram_allowed_chat_id,
                text="🧪 *DEMO* — synthetic spoof, no model involved\n\n" + text,
                parse_mode="MarkdownV2")
        asyncio.run(send())
        print("\nsent to Telegram")


if __name__ == "__main__":
    main()
