"""Settings. Fails loudly on missing keys — but at first use, not at import.

Importing a module must never require a populated .env, or the test suite and
any offline tooling become hostage to deployment configuration. `get_settings()`
raises the moment something actually needs a missing value, which is where the
error is useful.
"""
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    openrouter_api_key: str = ""
    model_name: str = ""          # any JSON-capable open-weight model; chosen via probe_model

    telegram_bot_token: str
    telegram_allowed_chat_id: int

    gmail_credentials_path: str = "data/credentials.json"
    gmail_token_path: str = "data/token.json"
    db_path: str = "data/telemail.db"
    poll_seconds: int = 60
    retention_days: int = 3   # after this, mail keeps its metadata but loses its preview text
    own_address: str = ""

    virustotal_api_key: str = ""   # optional; empty means no lookups are made

    daily_token_budget: int = 300_000  # OWASP LLM10: a daily ceiling on model tokens
    max_reads_per_sync: int = 40       # OWASP LLM10: a cap on emails read per /sync


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
