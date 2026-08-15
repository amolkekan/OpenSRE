"""
Redact sensitive values from API responses.

Browser-facing and admin endpoints must never return live tokens, keys, or
passwords. Internal service-to-service credential fetch endpoints may still
return decrypted secrets when explicitly requested.
"""

from __future__ import annotations

import copy
import re
from typing import Any, Dict, Iterable, Optional, Set

MASK = "***"

# Key substrings that indicate a secret value (aligned with encrypt_dict).
SENSITIVE_KEY_TERMS: Set[str] = {
    "token",
    "secret",
    "password",
    "webhook_url",
    "api_key",
    "bot_token",
    "client_secret",
    "private_key",
    "signing_secret",
    "access_key",
    "refresh_token",
    "session_cookie",
}

# Keys that contain sensitive substrings but are not secret material.
SENSITIVE_KEY_EXCEPTIONS: Set[str] = {
    "token_expiry_days",
    "token_warn_before_days",
    "token_revoke_inactive_days",
    "key_id",
    "key_name",
    "public_key",
    "key_type",
    "key_algorithm",
}

_MASK_WITH_SUFFIX_RE = re.compile(r"^\*{3}(.+)?$")


def is_sensitive_key(key: str) -> bool:
    """Return True when a dict key likely holds secret material."""
    lowered = key.lower()
    if lowered in SENSITIVE_KEY_EXCEPTIONS:
        return False
    return any(term in lowered for term in SENSITIVE_KEY_TERMS)


def is_masked_value(value: Any) -> bool:
    """Return True when a value looks like a client-submitted masked placeholder."""
    return isinstance(value, str) and bool(_MASK_WITH_SUFFIX_RE.match(value))


def mask_secret_value(value: str, *, show_last: int = 4) -> str:
    """Mask a secret, optionally preserving the last N characters."""
    if not value:
        return value
    if show_last <= 0 or len(value) <= show_last:
        return MASK
    return f"{MASK}{value[-show_last:]}"


def redact_secrets(
    data: Any,
    *,
    show_last: int = 4,
    presence_flags: bool = True,
) -> Any:
    """
    Recursively redact sensitive fields in dict/list structures.

    Secret string values become ``***`` or ``***1234`` (last-4). When
    ``presence_flags`` is True, sibling ``has_<field>`` booleans are added for
    non-empty secrets.
    """
    if isinstance(data, dict):
        redacted: Dict[str, Any] = {}
        for key, value in data.items():
            if is_sensitive_key(key):
                if isinstance(value, str) and value:
                    redacted[key] = mask_secret_value(value, show_last=show_last)
                    if presence_flags:
                        redacted[f"has_{key}"] = True
                elif value is not None and value != "":
                    redacted[key] = MASK
                    if presence_flags:
                        redacted[f"has_{key}"] = True
                else:
                    redacted[key] = value
                    if presence_flags:
                        redacted[f"has_{key}"] = False
            elif isinstance(value, (dict, list)):
                redacted[key] = redact_secrets(
                    value, show_last=show_last, presence_flags=presence_flags
                )
            else:
                redacted[key] = value
        return redacted

    if isinstance(data, list):
        return [
            redact_secrets(item, show_last=show_last, presence_flags=presence_flags)
            for item in data
        ]

    return data


def redact_integration_config(config: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Redact integration credential fields for admin API responses."""
    if not config:
        return {}
    return redact_secrets(copy.deepcopy(config))


def merge_config_preserving_secrets(
    existing: Optional[Dict[str, Any]],
    incoming: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Merge incoming integration config without overwriting secrets with masks.

    Used on PUT/PATCH when the client echoes masked placeholders back.
    """
    base = copy.deepcopy(existing or {})

    def _merge(dst: Dict[str, Any], src: Dict[str, Any]) -> Dict[str, Any]:
        for key, value in src.items():
            if isinstance(value, dict) and isinstance(dst.get(key), dict):
                dst[key] = _merge(dict(dst[key]), value)
                continue
            if is_sensitive_key(key) and is_masked_value(value):
                continue
            dst[key] = value
        return dst

    return _merge(base, incoming)


def strip_injected_runtime_secrets(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Remove server-injected OAuth/App credentials from client-visible config.

    Only strips fields injected by config_v2 runtime helpers (Slack bot_token,
    GitHub App private_key). Team-configured integration secrets are left in
    place for redact_secrets() to mask.
    """
    cleaned = copy.deepcopy(config)
    integrations = cleaned.get("integrations")
    if not isinstance(integrations, dict):
        return cleaned

    slack = integrations.get("slack")
    if isinstance(slack, dict):
        slack.pop("bot_token", None)
        slack.pop("user_token", None)

    github = integrations.get("github")
    if isinstance(github, dict):
        github.pop("private_key", None)

    return cleaned


def redact_config_for_client_response(config: Dict[str, Any]) -> Dict[str, Any]:
    """Full redaction pipeline for team/admin effective-config API responses."""
    without_injected = strip_injected_runtime_secrets(config)
    return redact_secrets(without_injected)


def redact_slack_app_secrets(app_data: Dict[str, Any]) -> Dict[str, Any]:
    """Redact Slack app registry fields that hold OAuth secrets."""
    redacted = copy.deepcopy(app_data)
    for field in ("client_secret", "signing_secret"):
        if field in redacted and redacted[field]:
            redacted[field] = mask_secret_value(str(redacted[field]))
            redacted[f"has_{field}"] = True
        else:
            redacted[f"has_{field}"] = bool(redacted.get(field))
            redacted.pop(field, None)
    return redacted


def redact_slack_installation_tokens(installation_data: Dict[str, Any]) -> Dict[str, Any]:
    """Redact Slack installation tokens for non-credential API responses."""
    redacted = copy.deepcopy(installation_data)
    for field in (
        "bot_token",
        "user_token",
        "incoming_webhook_url",
    ):
        if field in redacted and redacted[field]:
            redacted[field] = mask_secret_value(str(redacted[field]))
            redacted[f"has_{field}"] = True
        else:
            redacted[f"has_{field}"] = bool(redacted.get(field))
            if field in redacted:
                redacted.pop(field, None)
    return redacted
