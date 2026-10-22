"""Pre-flight check. Tells you which step you are on, without printing secrets.

    python -m scripts.check_setup
"""
from pathlib import Path


def main():
    ok = True

    print("\n1. .env")
    if not Path(".env").exists():
        print("   MISSING — run: cp .env.example .env"); return
    try:
        from telemail.config import get_settings
        s = get_settings()
    except Exception as e:
        print(f"   INCOMPLETE — {type(e).__name__}")
        print("   fill in TELEGRAM_BOT_TOKEN and TELEGRAM_ALLOWED_CHAT_ID")
        return

    tok = s.telegram_bot_token
    print(f"   bot token   {'set' if tok else 'EMPTY'}"
          f"{f' ({len(tok)} chars, ends ...{tok[-4:]})' if tok else ''}")
    print(f"   chat id     {s.telegram_allowed_chat_id or 'EMPTY'}")
    print(f"   model       {s.model_name or 'EMPTY — choose one with scripts.probe_model --model <id>'}")
    print(f"   api key     {'set' if s.openrouter_api_key else 'EMPTY (needed from Phase 4)'}")
    if not tok or not s.telegram_allowed_chat_id:
        ok = False

    print("\n2. Google credentials")
    cred = Path(s.gmail_credentials_path)
    if cred.exists():
        import json
        try:
            body = json.loads(cred.read_text())
            kind = "installed" if "installed" in body else \
                   "web" if "web" in body else "unknown"
            print(f"   {cred}  present, type '{kind}'")
            if kind != "installed":
                print("   WRONG TYPE — you need Application type 'Desktop app'.")
                ok = False
        except Exception:
            print(f"   {cred} present but unreadable"); ok = False
    else:
        print(f"   {cred}  MISSING — download it from Google Cloud Console")
        ok = False

    print("\n3. OAuth token")
    tokf = Path(s.gmail_token_path)
    print(f"   {tokf}  {'present' if tokf.exists() else 'not yet (created on first consent)'}")

    print("\n4. Database")
    db = Path(s.db_path)
    if db.exists():
        from telemail.db import Database
        d = Database(str(db))
        print(f"   {db}  {d.count_emails()} messages, {d.label_count()} labels")
        d.close()
    else:
        print(f"   {db}  not yet (created on first sync)")

    if not ok:
        print("\nFinish the steps marked above, then re-run this.")
    elif not (tokf.exists() and db.exists()):
        print("\nREADY — run: python -m telemail sync")
    elif not (s.openrouter_api_key and s.model_name):
        print("\nGmail and Telegram work. Next: set OPENROUTER_API_KEY, then "
              "make probe MODEL=<id> and set MODEL_NAME. Label daily: make label")
    else:
        print("\nFully configured. Label daily (make label); run make evaluate "
              "once you have 20+ labels.")


if __name__ == "__main__":
    main()
