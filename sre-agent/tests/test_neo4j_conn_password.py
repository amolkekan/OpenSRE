"""Unit tests for neo4j_conn password resolution."""

import importlib

import pytest


def _reload_neo4j_conn(monkeypatch, **env):
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
