"""Tool permission gating for the Claude Agent SDK session.

AGENT_PERMISSION_MODE controls how can_use_tool treats high-risk file tools:
  - restricted (default): deny Write and Edit; investigations still use Bash/Read.
  - acceptEdits: auto-approve all tools (legacy local-dev behaviour).
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
