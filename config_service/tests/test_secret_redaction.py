"""Tests for API secret redaction and encryption hardening."""

import os

import pytest
from cryptography.fernet import Fernet

from src.core.secret_redaction import (
    MASK,
    is_masked_value,
    is_sensitive_key,
    merge_config_preserving_secrets,
    redact_config_for_client_response,
    redact_integration_config,
    redact_secrets,
)
from src.crypto.encryption import EncryptionError, reset_encryption_service
from src.crypto.sqlalchemy_types import EncryptedText


@pytest.fixture
def fernet_key():
    key = Fernet.generate_key().decode()
    os.environ["ENCRYPTION_KEY"] = key
    os.environ.pop("ENCRYPTION_KEY_PREVIOUS", None)
    reset_encryption_service()
    yield key
    os.environ.pop("ENCRYPTION_KEY", None)
    os.environ.pop("ENCRYPTION_KEY_PREVIOUS", None)
    reset_encryption_service()


def test_is_sensitive_key_preserves_token_counts():
    assert not is_sensitive_key("max_tokens")
    assert not is_sensitive_key("max_completion_tokens")
    assert not is_sensitive_key("input_tokens")
    assert not is_sensitive_key("output_tokens")

    config = {"model": {"max_tokens": 16000, "temperature": 0.3}}
    redacted = redact_secrets(config)
    assert redacted["model"]["max_tokens"] == 16000


def test_aws_access_key_id_is_sensitive():
    assert is_sensitive_key("aws_access_key_id")
    assert is_sensitive_key("AWS_ACCESS_KEY_ID")
    redacted = redact_secrets({"aws_access_key_id": "AKIAIOSFODNN7EXAMPLE"})
    assert "AKIA" not in str(redacted["aws_access_key_id"])
    assert redacted["aws_access_key_id"].startswith(MASK)


def test_is_sensitive_key_redacts_credential_tokens():
    assert is_sensitive_key("bot_token")
    assert is_sensitive_key("api_token")

    config = {"bot_token": "xoxb-secret", "api_token": "ghp_secret123456"}
    redacted = redact_secrets(config)
    assert redacted["bot_token"].startswith(MASK)
    assert redacted["api_token"].startswith(MASK)


def test_is_sensitive_key_redacts_schema_secret_fields():
    assert is_sensitive_key("app_key")
    assert is_sensitive_key("service_account_key")
    assert is_sensitive_key("service_account_json")

    config = {
        "integrations": {
            "datadog": {
                "app_key": "dd-app-key-secret1234",
                "api_key": "dd-api-key-secret5678",
            },
            "gcp": {
                "service_account_key": "-----BEGIN PRIVATE KEY-----",
                "service_account_json": '{"type": "service_account"}',
            },
        }
    }
    redacted = redact_secrets(config)
    datadog = redacted["integrations"]["datadog"]
    gcp = redacted["integrations"]["gcp"]

    assert datadog["app_key"].startswith(MASK)
    assert datadog["api_key"].startswith(MASK)
    assert gcp["service_account_key"].startswith(MASK)
    assert gcp["service_account_json"].startswith(MASK)


def test_redact_secrets_masks_sensitive_keys():
    config = {
        "api_key": "sk-live-abcdef123456",
        "domain": "example.com",
        "nested": {"bot_token": "xoxb-secret-token"},
    }

    redacted = redact_secrets(config)

    assert redacted["api_key"].startswith(MASK)
    assert redacted["api_key"].endswith("3456")
    assert redacted["has_api_key"] is True
    assert redacted["domain"] == "example.com"
    assert redacted["nested"]["bot_token"].startswith(MASK)
    assert redacted["nested"]["has_bot_token"] is True


def test_redact_integration_config_empty():
    assert redact_integration_config(None) == {}
    assert redact_integration_config({}) == {}


def test_is_masked_value_detects_placeholders():
    assert is_masked_value("***")
    assert is_masked_value("***1234")
    assert not is_masked_value("sk-live")


def test_merge_config_preserving_secrets_skips_masks():
    existing = {"api_key": "sk-live-secret", "domain": "example.com"}
    incoming = {"api_key": "***cret", "domain": "new.example.com"}

    merged = merge_config_preserving_secrets(existing, incoming)

    assert merged["api_key"] == "sk-live-secret"
    assert merged["domain"] == "new.example.com"


def test_redact_config_for_client_response_strips_injected_credentials():
    config = {
        "integrations": {
            "slack": {"enabled": True, "bot_token": "xoxb-injected"},
            "github": {
                "app_id": "123",
                "private_key": "-----BEGIN PRIVATE KEY-----",
                "installation_id": "99",
            },
            "grafana": {"api_key": "glsa_abcdef987654"},
        }
    }

    redacted = redact_config_for_client_response(config)
    slack = redacted["integrations"]["slack"]
    github = redacted["integrations"]["github"]
    grafana = redacted["integrations"]["grafana"]

    assert "bot_token" not in slack
    assert "private_key" not in github
    assert github["app_id"] == "123"
    assert grafana["api_key"].startswith(MASK)


def test_multi_key_decrypt_with_previous_key(fernet_key):
    from src.crypto import decrypt, encrypt

    previous = Fernet.generate_key().decode()
    os.environ["ENCRYPTION_KEY"] = previous
    reset_encryption_service()
    ciphertext = encrypt("rotate-me")

    os.environ["ENCRYPTION_KEY"] = fernet_key
    os.environ["ENCRYPTION_KEY_PREVIOUS"] = previous
    reset_encryption_service()

    assert decrypt(ciphertext) == "rotate-me"


def test_encrypted_text_plaintext_fail_closed_outside_local(fernet_key, monkeypatch):
    monkeypatch.delenv("CONFIG_MODE", raising=False)
    monkeypatch.delenv("ALLOW_PLAINTEXT_SECRETS", raising=False)

    type_obj = EncryptedText()
    with pytest.raises(EncryptionError, match="Refusing to return plaintext"):
        type_obj.process_result_value("plaintext-token", None)


def test_encrypted_text_plaintext_allowed_in_local_mode(fernet_key, monkeypatch):
    monkeypatch.setenv("CONFIG_MODE", "local")

    type_obj = EncryptedText()
    assert type_obj.process_result_value("plaintext-token", None) == "plaintext-token"


def test_security_integration_response_redacts_config():
    from datetime import datetime

    from src.api.routes.security import _integration_to_response
    from src.db.models import Integration

    integration = Integration(
        org_id="org1",
        integration_id="slack",
        status="configured",
        config={"bot_token": "xoxb-super-secret-token", "team": "demo"},
        updated_at=datetime.utcnow(),
    )

    response = _integration_to_response(integration)
    assert response.config["bot_token"].startswith("***")
    assert response.config["team"] == "demo"
    assert "xoxb-super-secret-token" not in str(response.config)


def test_me_effective_redacts_injected_github_private_key(monkeypatch):
    from src.api.routes.config_v2 import _inject_github_app_credentials
    from src.core.secret_redaction import redact_config_for_client_response

    monkeypatch.setenv("GITHUB_APP_ID", "12345")
    monkeypatch.setenv(
        "GITHUB_APP_PRIVATE_KEY",
        "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----",
    )

    effective = {
        "integrations": {"github": {}},
        "agents": {},
    }

    class _Installation:
        installation_id = 4242
        account_login = "acme"

    class _Query:
        def filter(self, *args, **kwargs):
            return self

        def first(self):
            return _Installation()

    class _Session:
        def query(self, model):
            return _Query()

    injected = _inject_github_app_credentials(
        effective, "org1", "teamA", _Session()
    )
    redacted = redact_config_for_client_response(injected)
    github = redacted["integrations"]["github"]

    assert "private_key" not in github
    assert github["installation_id"] == "4242"
    assert github["app_id"] == "12345"
