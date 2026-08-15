"""Hardening bucket F: untrusted Cypher helpers, download URLs, memory framing."""

import pytest
from fastapi.testclient import TestClient


def test_generate_cypher_from_question_removed():
    from tools.neo4j_semantic_layer import KubernetesGraphTools

    assert not hasattr(KubernetesGraphTools, "generate_cypher_from_question")


@pytest.mark.parametrize(
    "url",
    [
        "https://files.slack.com/files-pri/T123/F456/download",
        "https://files-origin.slack.com/files-pri/T123/F456/download",
    ],
)
def test_validate_download_url_allows_slack_hosts(url):
    import server_simple

    server_simple._validate_download_url(url)


@pytest.mark.parametrize(
    "url,match",
    [
        ("http://127.0.0.1/secret", "private IP"),
        ("https://169.254.169.254/latest/meta-data/", "private IP"),
        ("https://10.0.0.1/internal", "private IP"),
        ("https://192.168.1.1/config", "private IP"),
        ("ftp://files.slack.com/x", "Invalid URL scheme"),
        ("https://evil.example.com/steal", "not in allowlist"),
        ("https:///no-host", "Missing hostname"),
    ],
)
def test_validate_download_url_rejects_unsafe_urls(url, match):
    import server_simple

    with pytest.raises(ValueError, match=match):
        server_simple._validate_download_url(url)


def test_validate_download_url_allows_env_extra_hosts(monkeypatch):
    import server_simple

    monkeypatch.setenv("ALLOWED_DOWNLOAD_HOSTS", "cdn.example.com")
    server_simple._validate_download_url("https://cdn.example.com/file.pdf")


def test_validate_download_url_allows_hostname_containing_private(monkeypatch):
    """Hostnames with 'private' in the name must not trip the IP-block path."""
    import server_simple

    monkeypatch.setenv("ALLOWED_DOWNLOAD_HOSTS", "my-private-cdn.example.com")
    server_simple._validate_download_url(
        "https://my-private-cdn.example.com/file.pdf"
    )


def test_investigate_rejects_private_attachment_url(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    import server_simple

    async def fake_bg(thread_id, resume_session_id=None):
        pass

    monkeypatch.setattr(server_simple, "agent_background_task", fake_bg)
    monkeypatch.setattr(server_simple, "_background_tasks", {})
    monkeypatch.setattr(server_simple, "_message_queues", {})
    monkeypatch.setattr(server_simple, "_response_queues", {})

    client = TestClient(server_simple.app)
    resp = client.post(
        "/investigate",
        json={
            "prompt": "review attachment",
            "file_attachments": [
                {
                    "download_url": "http://127.0.0.1/admin",
                    "auth_header": "Bearer x",
                    "filename": "leak.txt",
                    "media_type": "text/plain",
                    "size": 1,
                }
            ],
        },
    )
    assert resp.status_code == 400
    assert "Invalid file attachment URL" in resp.json()["detail"]
