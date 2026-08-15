"""Authentication for simple-mode agent control/recon APIs and sandbox execution.

Fail closed by default: callers must present a valid config-service team token
(Authorization: Bearer or X-OpenSRE-Team-Token) or the shared service token
INVESTIGATE_AUTH_TOKEN (slack-bot, teams-bot, sandbox router/manager).

Local development escape hatch: set AGENT_AUTH_DISABLED=true (never in production).
"""

from __future__ import annotations

import logging
import os
import secrets
from dataclasses import dataclass
from typing import Optional, Tuple

import httpx
from fastapi import HTTPException, Request

logger = logging.getLogger(__name__)

CONFIG_SERVICE_URL = os.getenv("CONFIG_SERVICE_URL", "http://config-service:8080")


def _investigate_auth_token() -> str:
    return os.getenv("INVESTIGATE_AUTH_TOKEN", "")


def agent_auth_disabled() -> bool:
    return os.getenv("AGENT_AUTH_DISABLED", "").lower() in ("1", "true", "yes")


def extract_bearer_token(request: Request) -> Optional[str]:
    """Parse team/service token from Authorization or X-OpenSRE-Team-Token."""
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        token = auth[7:].strip()
        if token:
            return token
    header_token = request.headers.get("X-OpenSRE-Team-Token")
    if header_token:
        return header_token.strip() or None
    return None


def is_service_token(token: str) -> bool:
    service_token = _investigate_auth_token()
    if not service_token:
        return False
    return secrets.compare_digest(token, service_token)


def validate_team_token(token: str) -> Optional[Tuple[str, str]]:
    """Validate team token via config-service /auth/me. Returns (org_id, team_node_id)."""
    try:
        resp = httpx.get(
            f"{CONFIG_SERVICE_URL}/api/v1/auth/me",
            headers={"Authorization": f"Bearer {token}"},
            timeout=5.0,
        )
        if resp.status_code != 200:
            return None
        data = resp.json()
        org_id = (data.get("org_id") or "").strip()
        team_node_id = (data.get("team_node_id") or "").strip()
        if not org_id or not team_node_id:
            return None
        return org_id, team_node_id
    except Exception as exc:
        logger.warning("Team token validation failed: %s", exc)
        return None


@dataclass(frozen=True)
class AgentAuthContext:
    token: str
    is_service_token: bool
    org_id: Optional[str] = None
    team_node_id: Optional[str] = None


def verify_agent_request_auth(request: Request) -> AgentAuthContext:
    """Verify request auth. Raises HTTPException on failure."""
    if agent_auth_disabled():
        token = extract_bearer_token(request) or ""
        if not token:
            return AgentAuthContext(token="", is_service_token=False)
        if is_service_token(token):
            return AgentAuthContext(token=token, is_service_token=True)
        identity = validate_team_token(token)
        if identity:
            org_id, team_node_id = identity
            return AgentAuthContext(
                token=token,
                is_service_token=False,
                org_id=org_id,
                team_node_id=team_node_id,
            )
        return AgentAuthContext(token=token, is_service_token=False)

    token = extract_bearer_token(request)
    if not token:
        raise HTTPException(status_code=401, detail="Missing Authorization header")

    if is_service_token(token):
        return AgentAuthContext(token=token, is_service_token=True)

    identity = validate_team_token(token)
    if identity:
        org_id, team_node_id = identity
        return AgentAuthContext(
            token=token,
            is_service_token=False,
            org_id=org_id,
            team_node_id=team_node_id,
        )

    raise HTTPException(status_code=403, detail="Invalid or expired token")
