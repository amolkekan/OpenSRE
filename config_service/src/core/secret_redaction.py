"""
Redact sensitive values from API responses.

Browser-facing and admin endpoints must never return live tokens, keys, or
passwords. Internal service-to-service credential fetch endpoints may still
return decrypted secrets when explicitly requested.
"""

from __future__ import annotations

import copy
import re
from typing import Any, Dict, Optional, Set

MASK = "***"

# Exact key names (lowercase) that hold secret material.
EXACT_SENSITIVE_KEYS: Set[str] = {
    "access_key",
    "api_key",
    "app_key",
    "aws_access_key_id",
    "bot_token",
    "client_secret",
    "password",
    "private_key",
    "refresh_token",
    "service_account_json",
    "service_account_key",
    "session_cookie",
    "signing_secret",
    "webhook_url",
}

# Substrings that indicate secrets in compound key names.
SENSITIVE_KEY_SUBSTRINGS: Set[str] = {
    "secret",
    "password",
    "webhook_url",
    "session_cookie",
}

# Keys that resemble secrets but are config/metadata, not credentials.
SENSITIVE_KEY_EXCEPTIONS: Set[str] = {
    "completion_tokens",
    "input_tokens",
    "key_algorithm",
    "key_id",
    "key_name",
    "key_type",
    "max_completion_tokens",
    "max_tokens",
    "output_tokens",
    "prompt_tokens",
    "public_key",
    "token_expiry_days",
    "token_revoke_inactive_days",
    "token_warn_before_days",
    "total_tokens",
}

# Singular credential token fields (_token / token_) — not token *counts* (_tokens).
_TOKEN_FIELD_RE = re.compile(r"(^|_)token($|_)")

_MASK_WITH_SUFFIX_RE = re.compile(r"^\*{3}(.+)?$")


def is_sensitive_key(key: str) -> bool:
    """Return True when a dict key likely holds secret material."""
    lowered = key.lower()
    if lowered in SENSITIVE_KEY_EXCEPTIONS:
        return False
    if lowered in EXACT_SENSITIVE_KEYS:
        return True
    # LLM usage counters (max_tokens, input_tokens, …) are never credentials.
    if lowered.endswith("_tokens") or lowered == "tokens":
        return False
    if any(term in lowered for term in SENSITIVE_KEY_SUBSTRINGS):
        return True
    # AWS-style access key id fields (schema type=secret) without "secret" in the name.
    if "access_key" in lowered:
        return True
    return bool(_TOKEN_FIELD_RE.search(lowered))


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


def redact_configs_map(configs: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """Redact secrets in a node_id -> config_json map (raw lineage responses)."""
    return {
        node_id: redact_config_for_client_response(cfg or {})
        for node_id, cfg in configs.items()
    }


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
