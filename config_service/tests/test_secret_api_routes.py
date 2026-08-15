"""Route-level tests for secret redaction and internal credential APIs."""

import os
from types import SimpleNamespace
from typing import Generator

import pytest

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from src.api.main import create_app
from src.core.security import hash_token
from src.db.base import Base
from src.db.config_models import ConfigChangeHistory, NodeConfiguration
from src.db.models import NodeType, OrgNode, SlackApp, TeamToken


@pytest.fixture()
def encryption_env(monkeypatch):
    from cryptography.fernet import Fernet

    from src.crypto.encryption import reset_encryption_service

    key = Fernet.generate_key().decode()
    monkeypatch.setenv("ENCRYPTION_KEY", key)
    monkeypatch.setenv("CONFIG_MODE", "local")
    monkeypatch.delenv("ENCRYPTION_KEY_PREVIOUS", raising=False)
    reset_encryption_service()
    yield
    os.environ.pop("ENCRYPTION_KEY", None)
    os.environ.pop("CONFIG_MODE", None)
    reset_encryption_service()


def _sqlite_engine():
    return create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )


def _override_db(app, SessionLocal):
    from src.api.routes import admin as admin_routes
    from src.api.routes import internal as internal_routes
    from src.db.session import get_db as session_get_db

    def override_get_db() -> Generator[Session, None, None]:
        with SessionLocal() as s:
            try:
                yield s
                s.commit()
            except Exception:
                s.rollback()
                raise

    app.dependency_overrides[internal_routes.get_db] = override_get_db
    app.dependency_overrides[admin_routes.get_db] = override_get_db
    app.dependency_overrides[session_get_db] = override_get_db


@pytest.fixture()
def app_slack_internal(encryption_env, monkeypatch):
    engine = _sqlite_engine()
    Base.metadata.create_all(bind=engine, tables=[SlackApp.__table__])
    SessionLocal = sessionmaker(bind=engine)

    with SessionLocal() as s:
        s.add(
            SlackApp(
                slug="opensre",
                display_name="OpenSRE",
                client_id="cid-123",
                client_secret="client-secret-live",
                signing_secret="signing-secret-live",
                is_active=True,
            )
        )
        s.commit()

    app = create_app()
    _override_db(app, SessionLocal)
    return app


@pytest.fixture()
def app_credentials_internal(encryption_env, monkeypatch):
    app = create_app()

    integration = SimpleNamespace(
        org_id="org1",
        integration_id="slack",
        status="configured",
        config={"bot_token": "xoxb-live-token", "team": "demo"},
    )

    class _Query:
        def filter(self, *args, **kwargs):
            return self

        def first(self):
            return integration

    class _Session:
        def query(self, model):
            return _Query()

    def override_get_db():
        yield _Session()

    from src.api.routes import internal as internal_routes

    app.dependency_overrides[internal_routes.get_db] = override_get_db
    return app


@pytest.fixture()
def app_admin_team(encryption_env, monkeypatch):
    engine = _sqlite_engine()
    tables = [
        OrgNode.__table__,
        NodeConfiguration.__table__,
        ConfigChangeHistory.__table__,
        TeamToken.__table__,
    ]
    Base.metadata.create_all(bind=engine, tables=tables)
    SessionLocal = sessionmaker(bind=engine)

    monkeypatch.setenv("TOKEN_PEPPER", "test-pepper")
    monkeypatch.setenv("ADMIN_TOKEN", "admin-secret")

    with SessionLocal() as s:
        s.add(
            OrgNode(
                org_id="org1",
                node_id="root",
                parent_id=None,
                node_type=NodeType.org,
                name="Root",
            )
        )
        s.add(
            OrgNode(
                org_id="org1",
                node_id="teamA",
                parent_id="root",
                node_type=NodeType.team,
                name="Team A",
            )
        )
        s.add(
            NodeConfiguration(
                id="cfg-root",
                org_id="org1",
                node_id="root",
                node_type="org",
                config_json={},
                version=1,
            )
        )
        s.add(
            NodeConfiguration(
                id="cfg-teamA",
                org_id="org1",
                node_id="teamA",
                node_type="team",
                config_json={},
                version=1,
            )
        )
        token_secret = "toksecret"
        s.add(
            TeamToken(
                org_id="org1",
                team_node_id="teamA",
                token_id="tokid",
                token_hash=hash_token(token_secret, pepper="test-pepper"),
            )
        )
        s.commit()

    app = create_app()
    _override_db(app, SessionLocal)
    return app, "tokid.toksecret", SessionLocal


INTERNAL_HEADERS = {"X-Internal-Service": "slack-bot"}
ADMIN_HEADERS = {"Authorization": "Bearer admin-secret"}


def test_slack_apps_list_returns_live_secrets(app_slack_internal):
    client = TestClient(app_slack_internal)

    resp = client.get("/api/v1/internal/slack/apps", headers=INTERNAL_HEADERS)
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 1
    assert body[0]["signing_secret"] == "signing-secret-live"
    assert body[0]["client_secret"] == "client-secret-live"


def test_slack_apps_list_redacts_when_requested(app_slack_internal):
    client = TestClient(app_slack_internal)

    resp = client.get(
        "/api/v1/internal/slack/apps?include_secrets=false",
        headers=INTERNAL_HEADERS,
    )
    assert resp.status_code == 200
    body = resp.json()[0]
    assert body["signing_secret"].startswith("***")
    assert body["client_secret"].startswith("***")
    assert "signing-secret-live" not in str(body)


def test_credentials_get_returns_live_config(app_credentials_internal):
    client = TestClient(app_credentials_internal)

    resp = client.get(
        "/api/v1/internal/credentials/org1/slack",
        headers=INTERNAL_HEADERS,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["config"]["bot_token"] == "xoxb-live-token"


def test_credentials_decrypted_alias_matches_get(app_credentials_internal):
    client = TestClient(app_credentials_internal)

    live = client.get(
        "/api/v1/internal/credentials/org1/slack",
        headers=INTERNAL_HEADERS,
    ).json()
    alias = client.get(
        "/api/v1/internal/credentials/org1/slack/decrypted",
        headers=INTERNAL_HEADERS,
    ).json()
    assert alias == live


def test_admin_raw_and_config_get_redact_secrets(app_admin_team):
    app, _, SessionLocal = app_admin_team
    client = TestClient(app)

    secret = "sk-live-secret-value"
    with SessionLocal() as s:
        cfg = (
            s.query(NodeConfiguration)
            .filter(
                NodeConfiguration.org_id == "org1",
                NodeConfiguration.node_id == "teamA",
            )
            .first()
        )
        cfg.config_json = {
            "integrations": {"github": {"api_key": secret, "domain": "example.com"}}
        }
        s.commit()

    cfg_resp = client.get(
        "/api/v1/admin/orgs/org1/nodes/teamA/config",
        headers=ADMIN_HEADERS,
    ).json()["config"]
    assert cfg_resp["integrations"]["github"]["api_key"].startswith("***")
    assert secret not in str(cfg_resp)

    raw = client.get(
        "/api/v1/admin/orgs/org1/nodes/teamA/raw",
        headers=ADMIN_HEADERS,
    ).json()["configs"]["teamA"]
    assert raw["integrations"]["github"]["api_key"].startswith("***")
    assert secret not in str(raw)

    with SessionLocal() as s:
        stored = (
            s.query(NodeConfiguration)
            .filter(
                NodeConfiguration.org_id == "org1",
                NodeConfiguration.node_id == "teamA",
            )
            .first()
        )
        assert stored.config_json["integrations"]["github"]["api_key"] == secret


def test_admin_patch_preserves_secrets_when_mask_submitted(app_admin_team):
    app, _, SessionLocal = app_admin_team
    client = TestClient(app)

    secret = "sk-live-secret-value"
    client.put(
        "/api/v1/admin/orgs/org1/nodes/teamA/config",
        headers=ADMIN_HEADERS,
        json={"patch": {"integrations": {"github": {"api_key": secret}}}},
    )

    masked = client.put(
        "/api/v1/admin/orgs/org1/nodes/teamA/config",
        headers=ADMIN_HEADERS,
        json={
            "patch": {
                "integrations": {
                    "github": {"api_key": "***alue", "domain": "updated.example.com"}
                }
            }
        },
    )
    assert masked.status_code == 200

    with SessionLocal() as s:
        stored = (
            s.query(NodeConfiguration)
            .filter(
                NodeConfiguration.org_id == "org1",
                NodeConfiguration.node_id == "teamA",
            )
            .first()
        )
        github = stored.config_json["integrations"]["github"]
        assert github["api_key"] == secret
        assert github["domain"] == "updated.example.com"


def test_me_raw_redacts_secrets(app_admin_team):
    app, team_token, SessionLocal = app_admin_team
    client = TestClient(app)
    headers = {"Authorization": f"Bearer {team_token}"}

    secret = "xoxb-team-token-secret"
    with SessionLocal() as s:
        cfg = (
            s.query(NodeConfiguration)
            .filter(
                NodeConfiguration.org_id == "org1",
                NodeConfiguration.node_id == "teamA",
            )
            .first()
        )
        cfg.config_json = {
            "integrations": {"slack": {"bot_token": secret, "enabled": True}}
        }
        s.commit()

    raw = client.get("/api/v1/config/me/raw", headers=headers).json()
    team_cfg = raw["configs"]["teamA"]
    assert "bot_token" not in team_cfg.get("integrations", {}).get("slack", {})
    assert secret not in str(raw)
