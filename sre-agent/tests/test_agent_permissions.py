"""Unit tests for agent_permissions tool gating."""

import pytest

from agent_permissions import (
    AgentPermissionMode,
    evaluate_tool_permission,
    parse_permission_mode,
    sdk_permission_mode,
)


class TestParsePermissionMode:
    def test_default_is_restricted(self, monkeypatch):
        monkeypatch.delenv("AGENT_PERMISSION_MODE", raising=False)
        assert parse_permission_mode() == AgentPermissionMode.RESTRICTED

    def test_empty_string_is_restricted(self):
        assert parse_permission_mode("") == AgentPermissionMode.RESTRICTED

    def test_restricted_explicit(self):
        assert parse_permission_mode("restricted") == AgentPermissionMode.RESTRICTED

    def test_accept_edits_camel(self):
        assert parse_permission_mode("acceptEdits") == AgentPermissionMode.ACCEPT_EDITS

    def test_accept_edits_variants(self):
        assert parse_permission_mode("accept_edits") == AgentPermissionMode.ACCEPT_EDITS
        assert parse_permission_mode("ACCEPTEDITS") == AgentPermissionMode.ACCEPT_EDITS

    def test_invalid_raises(self):
        with pytest.raises(ValueError, match="Invalid AGENT_PERMISSION_MODE"):
            parse_permission_mode("wide-open")

    def test_reads_env_when_raw_omitted(self, monkeypatch):
        monkeypatch.setenv("AGENT_PERMISSION_MODE", "acceptEdits")
        assert parse_permission_mode() == AgentPermissionMode.ACCEPT_EDITS


class TestSdkPermissionMode:
    def test_restricted_maps_to_default(self):
        assert sdk_permission_mode(AgentPermissionMode.RESTRICTED) == "default"

    def test_accept_edits_maps_to_accept_edits(self):
        assert sdk_permission_mode(AgentPermissionMode.ACCEPT_EDITS) == "acceptEdits"


class TestEvaluateToolPermission:
    def test_restricted_denies_write(self):
        decision = evaluate_tool_permission("Write", AgentPermissionMode.RESTRICTED)
        assert decision.allowed is False
        assert "Write" in decision.message

    def test_restricted_denies_edit(self):
        decision = evaluate_tool_permission("Edit", AgentPermissionMode.RESTRICTED)
        assert decision.allowed is False

    def test_restricted_allows_bash(self):
        decision = evaluate_tool_permission("Bash", AgentPermissionMode.RESTRICTED)
        assert decision.allowed is True

    def test_restricted_allows_read(self):
        decision = evaluate_tool_permission("Read", AgentPermissionMode.RESTRICTED)
        assert decision.allowed is True

    def test_accept_edits_allows_write(self):
        decision = evaluate_tool_permission("Write", AgentPermissionMode.ACCEPT_EDITS)
        assert decision.allowed is True

    def test_accept_edits_allows_edit(self):
        decision = evaluate_tool_permission("Edit", AgentPermissionMode.ACCEPT_EDITS)
        assert decision.allowed is True
