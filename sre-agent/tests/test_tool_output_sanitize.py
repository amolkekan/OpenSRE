"""Unit tests for tool output/input sanitization and secret redaction."""

import json

from events import tool_start_event
from tool_output_sanitize import (
    is_env_dump_command,
    sanitize_bash_output,
    sanitize_command,
    sanitize_tool_end_payload,
    sanitize_tool_input,
)


def test_is_env_dump_command_matches_env_printenv_export_p_bare_set():
    assert is_env_dump_command("env")
    assert is_env_dump_command("env | grep TOKEN")
    assert is_env_dump_command("printenv BKT_HOST")
    assert is_env_dump_command("export -p")
    assert is_env_dump_command("set")
    assert is_env_dump_command("set; echo done")


def test_is_env_dump_command_rejects_normal_commands():
    assert not is_env_dump_command("kubectl get pods")
    assert not is_env_dump_command("kubectl set image deploy/foo bar=img:v1")
    assert not is_env_dump_command("cat config.env")
    assert not is_env_dump_command("ls -la")


def test_env_grep_redacts_secret_values():
    output = "BKT_TOKEN=ATATT3xFfGF0secretvalue\nOTHER=also-secret"
    sanitized = sanitize_bash_output("env | grep TOKEN", output)
    assert sanitized is not None
    assert "ATATT" not in sanitized
    assert "also-secret" not in sanitized
    assert "BKT_TOKEN=<redacted>" in sanitized
    assert "OTHER=<redacted>" in sanitized


def test_printenv_single_var_redacted():
    output = "BKT_HOST=api.bitbucket.org"
    sanitized = sanitize_bash_output("printenv BKT_HOST", output)
    assert sanitized == "BKT_HOST=<redacted>"


def test_kubectl_output_redacts_embedded_secrets():
    secret = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"
    output = f"NAME    READY   STATUS\npod-1   1/1     Running token={secret}"
    sanitized = sanitize_bash_output("kubectl get pods", output)
    assert secret not in sanitized
    assert "<redacted>" in sanitized


def test_json_stdout_wrapper_sanitized():
    secret = "ATATT3xFfGF0secret"
    wrapper = {
        "stdout": f"BKT_TOKEN={secret}\n",
        "stderr": "",
        "returncode": 0,
    }
    raw = json.dumps(wrapper)
    sanitized = sanitize_bash_output("env", raw)
    parsed = json.loads(sanitized)
    assert secret not in parsed["stdout"]
    assert "BKT_TOKEN=<redacted>" in parsed["stdout"]


def test_authorization_header_redacted_in_output():
    output = "HTTP/1.1 200 OK\nAuthorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig"
    sanitized, _ = sanitize_tool_end_payload("Read", None, output, None)
    assert "eyJhbGciOiJIUzI1NiJ9" not in sanitized
    assert "Authorization: Bearer <redacted>" in sanitized


def test_aws_access_key_redacted():
    key = "AKIAIOSFODNN7EXAMPLE"
    output = f"Using credentials {key} for request"
    sanitized, _ = sanitize_tool_end_payload(
        "Bash", {"command": "aws sts get-caller-identity"}, output, None
    )
    assert key not in sanitized
    assert "<redacted>" in sanitized


def test_generic_api_key_assignment_redacted():
    output = "config: api_key=supersecretvalue12345"
    sanitized, _ = sanitize_tool_end_payload("Read", None, output, None)
    assert "supersecretvalue12345" not in sanitized
    assert "api_key=<redacted>" in sanitized


def test_sanitize_tool_end_payload_early_return_for_non_bash():
    output, error = sanitize_tool_end_payload(
        "Read",
        {"file_path": "/etc/passwd"},
        "root:x:0:0",
        None,
    )
    assert output == "root:x:0:0"
    assert error is None


def test_sanitize_tool_end_payload_redacts_bash_env():
    output, error = sanitize_tool_end_payload(
        "Bash",
        {"command": "printenv BKT_TOKEN"},
        "BKT_TOKEN=ATATTsecret",
        None,
    )
    assert output == "BKT_TOKEN=<redacted>"
    assert error is None


def test_sanitize_tool_end_payload_redacts_error_message():
    secret = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"
    _, error = sanitize_tool_end_payload(
        "Bash",
        {"command": "curl https://api.github.com"},
        None,
        f"401 Unauthorized token={secret}",
    )
    assert secret not in error
    assert "<redacted>" in error


def test_sanitize_command_redacts_embedded_bearer_token():
    secret = "sk-abcdefghijklmnopqrstuvwxyz123456"
    command = f"curl -H 'Authorization: Bearer {secret}' https://api.example.com"
    sanitized = sanitize_command(command)
    assert secret not in sanitized
    assert "Bearer <redacted>" in sanitized


def test_sanitize_tool_input_redacts_bash_command():
    secret = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"
    sanitized = sanitize_tool_input(
        "Bash",
        {"command": f"curl -H Authorization: Bearer {secret}"},
    )
    assert secret not in sanitized["command"]
    assert "<redacted>" in sanitized["command"]


def test_tool_start_event_redacts_command_in_sse_payload():
    secret = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"
    evt = tool_start_event(
        "thread-1",
        "Bash",
        {"command": f"curl -H Authorization: Bearer {secret}"},
        tool_use_id="t1",
    )
    assert secret not in evt.data["command"]
    assert "<redacted>" in evt.data["command"]
    assert secret not in json.dumps(evt.data["input"])


def test_json_quoted_token_key_redacted():
    secret = "supersecretvalue12345"
    body = json.dumps({"token": secret, "status": "ok"})
    sanitized, _ = sanitize_tool_end_payload("Read", None, body, None)
    assert secret not in sanitized
    assert '"token": "<redacted>"' in sanitized
    assert '"status": "ok"' in sanitized


def test_json_quoted_keys_with_whitespace_redacted():
    secret = "my-api-key-value12345"
    body = '{"api_key" : "' + secret + '", "password": "hunter2pass"}'
    sanitized, _ = sanitize_tool_end_payload("Read", None, body, None)
    assert secret not in sanitized
    assert "hunter2pass" not in sanitized
    assert '"api_key": "<redacted>"' in sanitized
    assert '"password": "<redacted>"' in sanitized


def test_json_quoted_secrets_inside_sdk_bash_wrapper():
    secret = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz"
    inner = json.dumps({"token": secret, "api-key": "anothersecret123"})
    wrapper = {"stdout": inner, "stderr": "", "returncode": 0}
    raw = json.dumps(wrapper)
    sanitized = sanitize_bash_output("curl https://api.example.com", raw)
    parsed = json.loads(sanitized)
    assert secret not in parsed["stdout"]
    assert "anothersecret123" not in parsed["stdout"]
    assert '"token": "<redacted>"' in parsed["stdout"]
    assert '"api-key": "<redacted>"' in parsed["stdout"]


def test_sk_hyphenated_vendor_keys_redacted():
    anthropic = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz123456"
    openai = "sk-proj-abcdefghijklmnopqrstuvwxyz123456"
    for key in (anthropic, openai):
        sanitized, _ = sanitize_tool_end_payload("Read", None, f"key={key}", None)
        assert key not in sanitized
        assert "<redacted>" in sanitized


def test_oauth_label_not_over_redacted():
    output = "oauth: github-enterprise"
    sanitized, _ = sanitize_tool_end_payload("Read", None, output, None)
    assert sanitized == output


def test_current_pwd_label_not_over_redacted():
    output = "current pwd: /Users/foo/project"
    sanitized, _ = sanitize_tool_end_payload("Read", None, output, None)
    assert sanitized == output


def test_invalid_token_message_redacted():
    output = "invalid token: expected-claim-missing"
    sanitized, _ = sanitize_tool_end_payload("Read", None, output, None)
    assert "expected-claim-missing" not in sanitized
    assert "token=<redacted>" in sanitized
