"""Allowlisted environment for skill subprocesses.

The Claude SDK Bash tool still inherits the full process environment (residual
risk). Skill scripts that spawn subprocesses should pass env through
allowlisted_subprocess_env() so API tokens and other secrets are not forwarded.
"""

from __future__ import annotations

import os

# Non-secret wiring vars safe to pass to diagnostic CLIs and skill scripts.
SUBPROCESS_ENV_ALLOWLIST: frozenset[str] = frozenset(
    {
        # Shell / locale
        "PATH",
        "HOME",
        "USER",
        "LOGNAME",
        "SHELL",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "TERM",
        "PWD",
        "TMPDIR",
        "HOSTNAME",
        # AWS / kube config paths (credentials live in mounted files, not env)
        "AWS_PROFILE",
        "AWS_DEFAULT_REGION",
        "AWS_REGION",
        "AWS_SHARED_CREDENTIALS_FILE",
        "AWS_CONFIG_FILE",
        "KUBECONFIG",
        # OpenSRE service wiring (non-secret endpoints)
        "CONFIG_SERVICE_URL",
        "OPENSRE_TENANT_ID",
        "OPENSRE_TEAM_ID",
        "NEO4J_URI",
        "NEO4J_USERNAME",
        "NEO4J_DATABASE",
        # Skill endpoints (URLs/domains — not tokens)
        "JIRA_URL",
        "JIRA_API_VERSION",
        "JIRA_AUTH_SCHEME",
        "CORALOGIX_DOMAIN",
        "KRONOS_BASE_URL",
        "ARGOCD_SERVER",
        "ARGOCD_OPTS",
        "BKT_SERVER",
        "BKT_PROJECT",
        "BKT_REPO",
        "GITHUB_REPOSITORY",
    }
)

# Explicitly blocked even if accidentally added to the allowlist.
SUBPROCESS_ENV_BLOCKLIST: frozenset[str] = frozenset(
    {
        "ANTHROPIC_API_KEY",
        "OPENROUTER_API_KEY",
        "NVIDIA_API_KEY",
        "NEO4J_PASSWORD",
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "JIRA_API_TOKEN",
        "JIRA_EMAIL",
        "SLACK_BOT_TOKEN",
        "SLACK_APP_TOKEN",
        "TEAMS_APP_PASSWORD",
        "TOKEN_PEPPER",
        "ADMIN_TOKEN",
        "LMNR_PROJECT_API_KEY",
    }
)


def allowlisted_subprocess_env(
    source: dict[str, str] | None = None,
) -> dict[str, str]:
    """Return a copy of *source* (default os.environ) with only allowlisted keys."""
    src = source if source is not None else os.environ
    return {
        key: value
        for key, value in src.items()
        if key in SUBPROCESS_ENV_ALLOWLIST
        and key not in SUBPROCESS_ENV_BLOCKLIST
        and value != ""
    }
