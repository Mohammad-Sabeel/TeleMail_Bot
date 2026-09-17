"""Prove the Telegram half works before Gmail is involved.

1. getMe       — is the token valid?            (read-only)
2. sendMessage — does the chat exist?            (catches the skipped-A5 case)

    python -m scripts.test_telegram
"""
import asyncio

from telemail.config import get_settings


async def main():
    from telegram import Bot
    from telegram.error import Forbidden, InvalidToken, BadRequest

    s = get_settings()
    bot = Bot(token=s.telegram_bot_token)

    try:
        me = await bot.get_me()
        print(f"1. token valid     @{me.username}  ({me.first_name})")
    except InvalidToken:
        print("1. token INVALID   — re-copy it from @BotFather"); return

    try:
        await bot.send_message(
            chat_id=s.telegram_allowed_chat_id,
            text="✅ TeleMail connected. Telegram half verified — "
                 "Gmail is next.")
        print(f"2. message sent    to chat {s.telegram_allowed_chat_id}")
        print("\nCheck Telegram. If it arrived, Part A is done.")
    except Forbidden:
        print("2. FORBIDDEN       — you have not messaged the bot yet.\n"
              f"   Open Telegram, find @{me.username}, press Start, re-run.")
    except BadRequest as e:
        print(f"2. BAD REQUEST     — {e}. Is the chat id your numeric id "
              "from @userinfobot?")


if __name__ == "__main__":
    asyncio.run(main())
