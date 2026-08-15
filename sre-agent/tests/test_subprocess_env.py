"""Unit tests for subprocess_env allowlist helper."""

from subprocess_env import (
    SUBPROCESS_ENV_ALLOWLIST,
    SUBPROCESS_ENV_BLOCKLIST,
    allowlisted_subprocess_env,
)


class TestAllowlistedSubprocessEnv:
    def test_keeps_safe_wiring_vars(self):
        source = {
            "PATH": "/usr/bin",
            "AWS_PROFILE": "dev",
            "KUBECONFIG": "/home/agent/.kube/config",
            "CONFIG_SERVICE_URL": "http://config-service:8080",
            "JIRA_URL": "https://jira.example.com",
        }
        result = allowlisted_subprocess_env(source)
        assert result == source

    def test_strips_secret_tokens(self):
        source = {
            "PATH": "/usr/bin",
            "ANTHROPIC_API_KEY": "sk-secret",
            "GITHUB_TOKEN": "ghp_secret",
            "JIRA_API_TOKEN": "jira-secret",
            "NEO4J_PASSWORD": "localdev",
        }
        result = allowlisted_subprocess_env(source)
        assert result == {"PATH": "/usr/bin"}

    def test_blocklist_wins_over_allowlist(self):
        # Guard against accidental overlap between the two sets.
        overlap = SUBPROCESS_ENV_ALLOWLIST & SUBPROCESS_ENV_BLOCKLIST
        assert overlap == set()

    def test_omits_empty_values(self):
        source = {"PATH": "/usr/bin", "AWS_PROFILE": ""}
        result = allowlisted_subprocess_env(source)
        assert result == {"PATH": "/usr/bin"}

    def test_defaults_to_os_environ(self, monkeypatch):
        monkeypatch.setenv("PATH", "/test/bin")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        result = allowlisted_subprocess_env()
        assert "PATH" in result
        assert "ANTHROPIC_API_KEY" not in result
