"""OAuth 2.0 credentials. One scope, and it is read-only.

D1: `gmail.modify` and `gmail.compose` each confer *send* capability at the
token layer. Withholding a send function in code does not remove send power from
the credential — a successful injection would not need our button. The scope is
therefore the control, and it is declared here, once.

D2: the consent screen must be Internal (Workspace) or published to Production
(consumer). Apps left in Testing issue refresh tokens that expire in exactly
seven days, and the failure is silent.
"""
from __future__ import annotations

from pathlib import Path

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

# Anything on this list would widen the credential beyond D1. Asserted by tests.
FORBIDDEN_SCOPES = {
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.compose",
    "https://www.googleapis.com/auth/gmail.send",
    "https://mail.google.com/",
}


def load_credentials(credentials_path: str, token_path: str):
    """Return usable credentials, running the consent flow only if needed."""
    from google.auth.transport.requests import Request
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import InstalledAppFlow

    creds = None
    if Path(token_path).exists():
        creds = Credentials.from_authorized_user_file(token_path, SCOPES)

    if creds and creds.valid:
        return creds

    if creds and creds.expired and creds.refresh_token:
        creds.refresh(Request())
    else:
        flow = InstalledAppFlow.from_client_secrets_file(credentials_path, SCOPES)
        creds = flow.run_local_server(port=0)

    Path(token_path).parent.mkdir(parents=True, exist_ok=True)
    Path(token_path).write_text(creds.to_json())
    return creds


def build_service(credentials_path: str, token_path: str):
    from googleapiclient.discovery import build
    return build("gmail", "v1",
                 credentials=load_credentials(credentials_path, token_path),
                 cache_discovery=False)
