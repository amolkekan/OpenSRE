import importlib
import os


def _reload_config(monkeypatch, **env):
    for key in (
        "TEAMS_APP_ID",
        "TEAMS_APP_PASSWORD",
        "TEAMS_TENANT_ID",
        "TEAMS_AUTHZ_MODE",
        "TEAMS_ALLOWED_USER_IDS",
        "TEAMS_ALLOWED_UPNS",
        "CLIENT_ID",
        "CLIENT_SECRET",
        "TENANT_ID",
        "SRE_AGENT_URL",
        "INVESTIGATE_AUTH_TOKEN",
        "PORT",
    ):
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    # Keep deleted TEAMS_* vars empty so parent .env cannot repopulate them
    # (load_dotenv uses override=False by default).
    for key in ("TEAMS_APP_ID", "TEAMS_APP_PASSWORD", "TEAMS_TENANT_ID"):
        if key not in env:
            monkeypatch.setenv(key, "")
    import config

    importlib.reload(config)
    return config


def test_config_reads_teams_env_and_exports_sdk_aliases(monkeypatch):
    config = _reload_config(
        monkeypatch,
        TEAMS_APP_ID="app-id-123",
        TEAMS_APP_PASSWORD="secret-abc",
        TEAMS_TENANT_ID="tenant-xyz",
        SRE_AGENT_URL="http://sre-agent:8000",
        INVESTIGATE_AUTH_TOKEN="tok",
    )
    cfg = config.Config()
    assert cfg.TEAMS_APP_ID == "app-id-123"
    assert cfg.TEAMS_APP_PASSWORD == "secret-abc"
    assert cfg.TEAMS_TENANT_ID == "tenant-xyz"
    assert cfg.SRE_AGENT_URL == "http://sre-agent:8000"
    assert cfg.INVESTIGATE_AUTH_TOKEN == "tok"
    assert cfg.PORT == 3978
    assert cfg.is_configured() is True
    # SDK env aliases applied for microsoft-teams-apps
    assert os.environ["CLIENT_ID"] == "app-id-123"
    assert os.environ["CLIENT_SECRET"] == "secret-abc"
    assert os.environ["TENANT_ID"] == "tenant-xyz"


def test_config_not_configured_without_app_id(monkeypatch):
    config = _reload_config(
        monkeypatch, TEAMS_APP_PASSWORD="secret", TEAMS_TENANT_ID="tenant"
    )
    cfg = config.Config()
    assert cfg.is_configured() is False


def test_authz_open_mode_allows_anyone(monkeypatch):
    config = _reload_config(monkeypatch, TEAMS_AUTHZ_MODE="open")
    cfg = config.Config()
    assert cfg.is_user_authorized(user_id=None, upn=None) is True


def test_authz_empty_allowlist_denies(monkeypatch):
    config = _reload_config(monkeypatch, TEAMS_AUTHZ_MODE="allowlist")
    cfg = config.Config()
    assert cfg.is_user_authorized(user_id="user-1", upn="alice@example.com") is False


def test_authz_allowlist_matches_user_id_and_upn(monkeypatch):
    config = _reload_config(
        monkeypatch,
        TEAMS_AUTHZ_MODE="allowlist",
        TEAMS_ALLOWED_USER_IDS="User-ABC, user-def",
        TEAMS_ALLOWED_UPNS="Bob@Example.COM",
    )
    cfg = config.Config()
    assert cfg.is_user_authorized(user_id="user-abc", upn=None) is True
    assert cfg.is_user_authorized(user_id="user-def", upn=None) is True
    assert cfg.is_user_authorized(user_id=None, upn="bob@example.com") is True
    assert cfg.is_user_authorized(user_id="other", upn="bob@example.com") is True
    assert cfg.is_user_authorized(user_id="other", upn="eve@example.com") is False
