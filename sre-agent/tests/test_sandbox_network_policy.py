"""Static checks for sandbox egress NetworkPolicy alignment with sandbox_manager."""

from __future__ import annotations

import os
import pathlib
import shutil
import subprocess

# sandbox_manager imports auth, which requires JWT_SECRET at import time.
os.environ.setdefault("JWT_SECRET", "test-jwt-secret-for-unit-tests")

import pytest
import yaml

from sandbox_manager import (
    SANDBOX_ISOLATION_LABEL_KEY,
    SANDBOX_ISOLATION_LABEL_VALUE,
    SANDBOX_POD_LABEL_APP,
    sandbox_pod_labels,
)

K8S_DIR = pathlib.Path(__file__).resolve().parents[1] / "k8s"
POLICY_PATH = K8S_DIR / "sandbox-network-policy.yaml"


def _load_policy_documents() -> list[dict]:
    assert POLICY_PATH.is_file(), f"missing NetworkPolicy manifest: {POLICY_PATH}"
    documents = list(yaml.safe_load_all(POLICY_PATH.read_text()))
    policies = [
        doc for doc in documents if doc and doc.get("kind") == "NetworkPolicy"
    ]
    assert policies, "sandbox-network-policy.yaml must contain a NetworkPolicy"
    return policies


def test_policy_file_exists_and_parses():
    policies = _load_policy_documents()
    policy = policies[0]
    assert policy["apiVersion"] == "networking.k8s.io/v1"
    assert policy["metadata"]["name"] == "opensre-sandbox-egress"


def test_policy_pod_selector_matches_sandbox_manager_labels():
    policy = _load_policy_documents()[0]
    selector = policy["spec"]["podSelector"]["matchLabels"]

    assert selector == {
        SANDBOX_ISOLATION_LABEL_KEY: SANDBOX_ISOLATION_LABEL_VALUE,
    }

    pod_labels = sandbox_pod_labels("test-thread-01")
    assert pod_labels[SANDBOX_ISOLATION_LABEL_KEY] == selector[SANDBOX_ISOLATION_LABEL_KEY]
    assert pod_labels["app"] == SANDBOX_POD_LABEL_APP


def test_policy_is_egress_only_default_deny():
    policy = _load_policy_documents()[0]
    assert policy["spec"]["policyTypes"] == ["Egress"]
    egress = policy["spec"]["egress"]
    assert isinstance(egress, list) and len(egress) >= 2

    dns_rule = egress[0]
    assert 53 in {p["port"] for p in dns_rule["ports"]}


@pytest.mark.skipif(shutil.which("kubectl") is None, reason="kubectl not installed")
def test_policy_kubectl_client_dry_run():
    result = subprocess.run(
        [
            "kubectl",
            "apply",
            "--dry-run=client",
            "--validate=false",
            "-f",
            str(POLICY_PATH),
            "-n",
            "default",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        stderr = result.stderr or ""
        if "unable to recognize" in stderr or "failed to download openapi" in stderr:
            pytest.skip("kubectl dry-run needs cluster API discovery; PyYAML parse tests cover schema")
    assert result.returncode == 0, result.stderr or result.stdout
