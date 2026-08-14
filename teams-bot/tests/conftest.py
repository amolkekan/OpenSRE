import pytest


@pytest.fixture(autouse=True)
def teams_authz_open_for_legacy_tests(monkeypatch):
    """Existing handler tests predate authz; open mode keeps them unchanged."""
    monkeypatch.setenv("TEAMS_AUTHZ_MODE", "open")
