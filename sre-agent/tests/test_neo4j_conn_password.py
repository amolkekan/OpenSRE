"""Unit tests for neo4j_conn password resolution.

Stub load_dotenv so a repo-root .env cannot re-inject NEO4J_PASSWORD.
"""

import importlib

import pytest


def _reload_neo4j_conn(monkeypatch, **env):
    # Prevent dotenv from undoing monkeypatched env during import/reload.
    monkeypatch.setattr("dotenv.load_dotenv", lambda *a, **k: False)
    for key in ("NEO4J_URI", "NEO4J_PASSWORD"):
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        if value is None:
            monkeypatch.delenv(key, raising=False)
        else:
            monkeypatch.setenv(key, value)
    import memory.neo4j_conn as neo4j_conn

    return importlib.reload(neo4j_conn)


def test_localhost_uri_allows_dev_default_without_env_password(monkeypatch):
    mod = _reload_neo4j_conn(monkeypatch, NEO4J_URI="bolt://localhost:7688", NEO4J_PASSWORD=None)
    assert mod.NEO4J_PASSWORD == "localdev"


def test_remote_uri_requires_password(monkeypatch):
    with pytest.raises(RuntimeError, match="NEO4J_PASSWORD must be set"):
        _reload_neo4j_conn(
            monkeypatch,
            NEO4J_URI="bolt://neo4j.example.com:7687",
            NEO4J_PASSWORD=None,
        )


def test_remote_uri_uses_env_password(monkeypatch):
    mod = _reload_neo4j_conn(
        monkeypatch,
        NEO4J_URI="bolt://neo4j.example.com:7687",
        NEO4J_PASSWORD="secret",
    )
    assert mod.NEO4J_PASSWORD == "secret"


def test_resolve_helper_remote_without_password():
    """Direct unit check of fail-closed helper (no import side effects)."""
    from memory.neo4j_conn import _resolve_neo4j_password

    # Call with env already empty for this process snapshot — use the helper
    # after ensuring getenv returns empty via os.environ pop in a isolated way.
    import os

    old = os.environ.pop("NEO4J_PASSWORD", None)
    try:
        with pytest.raises(RuntimeError, match="NEO4J_PASSWORD must be set"):
            _resolve_neo4j_password("bolt://db.internal:7687")
        assert _resolve_neo4j_password("bolt://localhost:7688") == "localdev"
    finally:
        if old is not None:
            os.environ["NEO4J_PASSWORD"] = old
