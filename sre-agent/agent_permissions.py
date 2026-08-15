"""Tool permission gating for the Claude Agent SDK session.

AGENT_PERMISSION_MODE controls how high-risk file tools (Write/Edit) are gated:
  - restricted (default): remove Write/Edit from allowed_tools and pass
    disallowed_tools so the CLI blocks them (can_use_tool is not invoked for
    tools already listed in allowed_tools).
  - acceptEdits: keep Write/Edit in allowed_tools (legacy local-dev behaviour).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum

# Tools that mutate files on disk outside explicit skill scripts.
HIGH_RISK_FILE_TOOLS: frozenset[str] = frozenset({"Write", "Edit"})


class AgentPermissionMode(str, Enum):
    RESTRICTED = "restricted"
    ACCEPT_EDITS = "acceptEdits"


@dataclass(frozen=True)
class ToolPermissionDecision:
    allowed: bool
    message: str = ""


def parse_permission_mode(raw: str | None = None) -> AgentPermissionMode:
    """Resolve permission mode from explicit value or AGENT_PERMISSION_MODE env."""
    value = raw if raw is not None else os.getenv("AGENT_PERMISSION_MODE", "")
    normalized = value.strip()
    if not normalized or normalized.lower() == AgentPermissionMode.RESTRICTED.value.lower():
        return AgentPermissionMode.RESTRICTED
    if normalized.lower() in {
        "acceptedits",
        "accept_edits",
        AgentPermissionMode.ACCEPT_EDITS.value.lower(),
    }:
        return AgentPermissionMode.ACCEPT_EDITS
    raise ValueError(
        f"Invalid AGENT_PERMISSION_MODE={value!r}; "
        f"use {AgentPermissionMode.RESTRICTED.value!r} or "
        f"{AgentPermissionMode.ACCEPT_EDITS.value!r}"
    )


def sdk_permission_mode(mode: AgentPermissionMode) -> str:
    """Map our mode to Claude SDK permission_mode option."""
    if mode == AgentPermissionMode.ACCEPT_EDITS:
        return "acceptEdits"
    return "default"


def resolve_tool_permission_lists(
    allowed_tools: list[str], mode: AgentPermissionMode
) -> tuple[list[str], list[str]]:
    """Return (allowed_tools, disallowed_tools) for ClaudeAgentOptions.

    Restricted mode must not list Write/Edit in allowed_tools — the SDK
    auto-approves those without calling can_use_tool. disallowed_tools enforces
    CLI-level denial as a second layer.
    """
    if mode == AgentPermissionMode.ACCEPT_EDITS:
        return allowed_tools, []
    disallowed = sorted(HIGH_RISK_FILE_TOOLS)
    filtered = [tool for tool in allowed_tools if tool not in HIGH_RISK_FILE_TOOLS]
    return filtered, disallowed


def evaluate_tool_permission(
    tool_name: str, mode: AgentPermissionMode
) -> ToolPermissionDecision:
    """Return allow/deny for a tool before the SDK executes it."""
    if mode == AgentPermissionMode.ACCEPT_EDITS:
        return ToolPermissionDecision(allowed=True)
    if tool_name in HIGH_RISK_FILE_TOOLS:
        return ToolPermissionDecision(
            allowed=False,
            message=(
                f"{tool_name} is disabled in restricted permission mode "
                f"(set AGENT_PERMISSION_MODE=acceptEdits to allow file edits)."
            ),
        )
    return ToolPermissionDecision(allowed=True)
