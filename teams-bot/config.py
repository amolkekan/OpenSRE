# teams-bot/config.py
"""Environment-backed configuration for the Teams bot."""

import os

from dotenv import load_dotenv

load_dotenv()

# allowlist (default): only TEAMS_ALLOWED_USER_IDS (AAD object IDs) may act;
# empty allowlist denies everyone. open: local-dev escape hatch (allow all).
VALID_AUTHZ_MODES = frozenset({"allowlist", "open"})


def _parse_csv_set(value: str) -> frozenset[str]:
    return frozenset(
        item.strip().lower() for item in (value or "").split(",") if item.strip()
    )


def _export_sdk_env(app_id: str, password: str, tenant_id: str) -> None:
    """Map OpenSRE TEAMS_* names to Teams SDK CLIENT_* env vars."""
    if app_id:
        os.environ.setdefault("CLIENT_ID", app_id)
    if password:
        os.environ.setdefault("CLIENT_SECRET", password)
    if tenant_id:
        os.environ.setdefault("TENANT_ID", tenant_id)


class Config:
    PORT = int(os.environ.get("PORT", "3978"))

    TEAMS_APP_ID = os.environ.get("TEAMS_APP_ID", "")
    TEAMS_APP_PASSWORD = os.environ.get("TEAMS_APP_PASSWORD", "")
    TEAMS_TENANT_ID = os.environ.get("TEAMS_TENANT_ID", "")

    SRE_AGENT_URL = os.environ.get("SRE_AGENT_URL", "http://localhost:8000")
    INVESTIGATE_AUTH_TOKEN = os.environ.get("INVESTIGATE_AUTH_TOKEN", "")

    def __init__(self) -> None:
        _export_sdk_env(
            self.TEAMS_APP_ID, self.TEAMS_APP_PASSWORD, self.TEAMS_TENANT_ID
        )
        mode = os.environ.get("TEAMS_AUTHZ_MODE", "allowlist").strip().lower()
        self.authz_mode = mode if mode in VALID_AUTHZ_MODES else "allowlist"
        self.allowed_user_ids = _parse_csv_set(
            os.environ.get("TEAMS_ALLOWED_USER_IDS", "")
        )

    def is_user_authorized(self, *, user_id: str | None) -> bool:
        """Return True when the sender may start investigations or submit answers."""
        if self.authz_mode == "open":
            return True
        if not self.allowed_user_ids:
            return False
        uid = (user_id or "").strip().lower()
        return bool(uid and uid in self.allowed_user_ids)

    def is_configured(self) -> bool:
        return bool(
            self.TEAMS_APP_ID and self.TEAMS_APP_PASSWORD and self.TEAMS_TENANT_ID
        )
