"""Tests for agent API authentication (simple mode + sandbox paths)."""

from unittest.mock import MagicMock, patch

import pytest
from agent_api_auth import AgentAuthContext
from fastapi.testclient import TestClient


@pytest.fixture
def auth_enabled(monkeypatch):
    monkeypatch.delenv("AGENT_AUTH_DISABLED", raising=False)
    monkeypatch.setenv("INVESTIGATE_AUTH_TOKEN", "service-token-secret")


@pytest.fixture
def client():
    import server_simple

    return TestClient(server_simple.app)


def test_investigate_401_without_token(auth_enabled, client):
    resp = client.post("/investigate", json={"prompt": "hello"})
    assert resp.status_code == 401


def test_investigate_403_invalid_token(auth_enabled, client):
    with patch(
        "agent_api_auth.validate_team_token",
        return_value=None,
    ):
        resp = client.post(
            "/investigate",
            json={"prompt": "hello"},
            headers={"Authorization": "Bearer bad-token"},
        )
    assert resp.status_code == 403


def test_investigate_200_with_service_token(auth_enabled, monkeypatch, client):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    import server_simple

    async def fake_bg(thread_id, resume_session_id=None):
        pass

    monkeypatch.setattr(server_simple, "agent_background_task", fake_bg)
    monkeypatch.setattr(server_simple, "_background_tasks", {})
    monkeypatch.setattr(server_simple, "_message_queues", {})
    monkeypatch.setattr(server_simple, "_response_queues", {})

    with patch.object(
        server_simple, "create_investigation_stream", return_value=iter([])
    ):
        resp = client.post(
            "/investigate",
            json={"prompt": "hello"},
            headers={"Authorization": "Bearer service-token-secret"},
        )
    assert resp.status_code == 200


def test_investigate_200_with_team_token(auth_enabled, monkeypatch, client):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    import server_simple

    async def fake_bg(thread_id, resume_session_id=None):
        pass

    monkeypatch.setattr(server_simple, "agent_background_task", fake_bg)
    monkeypatch.setattr(server_simple, "_background_tasks", {})
    monkeypatch.setattr(server_simple, "_message_queues", {})
    monkeypatch.setattr(server_simple, "_response_queues", {})

    with (
        patch(
            "agent_api_auth.validate_team_token",
            return_value=("local", "default"),
        ),
        patch.object(
            server_simple, "create_investigation_stream", return_value=iter([])
        ),
    ):
        resp = client.post(
            "/investigate",
            json={"prompt": "hello"},
            headers={"Authorization": "Bearer team-token-valid"},
        )
    assert resp.status_code == 200


def test_interrupt_401_without_token(auth_enabled, client):
    resp = client.post("/interrupt", json={"thread_id": "t1"})
    assert resp.status_code == 401


def test_thread_active_401_without_token(auth_enabled, client):
    resp = client.get("/threads/t1/active")
    assert resp.status_code == 401


def test_health_unauthenticated_minimal(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body == {"status": "healthy", "mode": "simple"}
    assert "active_sessions" not in body


def test_sandbox_execute_401_without_token(auth_enabled):
    import sandbox_server

    client = TestClient(sandbox_server.app)
    resp = client.post("/execute", json={"prompt": "run"})
    assert resp.status_code == 401


def test_sandbox_execute_200_with_service_token(auth_enabled, monkeypatch):
    import sandbox_server

    async def fake_execute(*_args, **_kwargs):
        from events import StreamEvent

        yield StreamEvent(type="result", data={"text": "ok", "success": True})

    session = MagicMock()
    session.execute = fake_execute

    async def fake_get_or_create(_thread_id):
        return session

    monkeypatch.setattr(sandbox_server, "get_or_create_session", fake_get_or_create)

    client = TestClient(sandbox_server.app)
    resp = client.post(
        "/execute",
        json={"prompt": "run"},
        headers={"Authorization": "Bearer service-token-secret"},
    )
    assert resp.status_code == 200


def test_sandbox_sessions_401_without_token(auth_enabled):
    import sandbox_server

    client = TestClient(sandbox_server.app)
    resp = client.get("/sessions")
    assert resp.status_code == 401


def test_sandbox_sessions_200_with_service_token(auth_enabled):
    import sandbox_server

    client = TestClient(sandbox_server.app)
    resp = client.get(
        "/sessions",
        headers={"Authorization": "Bearer service-token-secret"},
    )
    assert resp.status_code == 200
    assert resp.json() == {"sessions": []}


def test_sandbox_cleanup_401_without_token(auth_enabled):
    import sandbox_server

    client = TestClient(sandbox_server.app)
    resp = client.post("/cleanup", params={"thread_id": "t1"})
    assert resp.status_code == 401


def test_sandbox_cleanup_200_with_service_token(auth_enabled):
    import sandbox_server

    client = TestClient(sandbox_server.app)
    resp = client.post(
        "/cleanup",
        params={"thread_id": "missing"},
        headers={"Authorization": "Bearer service-token-secret"},
    )
    assert resp.status_code == 200
    assert resp.json() == {"status": "not_found", "thread_id": "missing"}


def test_sandbox_router_401_without_token(auth_enabled):
    import sys
    from pathlib import Path

    router_dir = Path(__file__).resolve().parent.parent / "sandbox-router"
    if str(router_dir) not in sys.path:
        sys.path.insert(0, str(router_dir))

    import sandbox_router

    client = TestClient(sandbox_router.app)
    resp = client.get(
        "/health",
        headers={
            "X-Sandbox-ID": "sb-1",
            "X-Sandbox-Namespace": "default",
        },
    )
    assert resp.status_code == 401


def test_verify_agent_request_auth_service_token(auth_enabled):
    from agent_api_auth import verify_agent_request_auth

    request = MagicMock()
    request.headers = {"Authorization": "Bearer service-token-secret"}
    ctx = verify_agent_request_auth(request)
    assert ctx == AgentAuthContext(token="service-token-secret", is_service_token=True)
