"""Phase 0 milestone: authenticate, fetch 10 subjects, send them to Telegram.

Run:  python -m scripts.hello_gmail
Needs: data/credentials.json (from Google Cloud), .env filled in.
"""
import asyncio

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from telegram import Bot

from telemail.config import get_settings

# D1: read-only, and never anything else. gmail.modify and gmail.compose each
# confer send capability at the token layer regardless of what the code calls.
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]


def gmail_service():
    settings = get_settings()
    creds = None
    try:
        creds = Credentials.from_authorized_user_file(settings.gmail_token_path, SCOPES)
    except FileNotFoundError:
        pass

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                settings.gmail_credentials_path, SCOPES)
            creds = flow.run_local_server(port=0)
        with open(settings.gmail_token_path, "w") as f:
            f.write(creds.to_json())

    return build("gmail", "v1", credentials=creds)


def latest_subjects(service, n=10) -> list[str]:
    listing = service.users().messages().list(userId="me", maxResults=n).execute()
    subjects = []
    for ref in listing.get("messages", []):
        msg = service.users().messages().get(
            userId="me", id=ref["id"], format="metadata",
            metadataHeaders=["Subject", "From"]).execute()
        headers = {h["name"]: h["value"] for h in msg["payload"]["headers"]}
        subjects.append(f"{headers.get('From','?')} — {headers.get('Subject','(no subject)')}")
    return subjects


async def main():
    settings = get_settings()
    subjects = latest_subjects(gmail_service())
    text = "TeleMail is alive.\n\n" + "\n".join(f"• {s}" for s in subjects)
    bot = Bot(token=settings.telegram_bot_token)
    await bot.send_message(chat_id=settings.telegram_allowed_chat_id, text=text[:4000])
    print(f"sent {len(subjects)} subjects")


if __name__ == "__main__":
    asyncio.run(main())
