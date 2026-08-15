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
WARMPOOL_TEMPLATE_PATHS = (
    K8S_DIR / "sandbox-template-warmpool.yaml",
    K8S_DIR / "sandbox-template-warmpool-local.yaml",
)


def _load_policy_documents() -> list[dict]:
    assert POLICY_PATH.is_file(), f"missing NetworkPolicy manifest: {POLICY_PATH}"
    documents = list(yaml.safe_load_all(POLICY_PATH.read_text()))
    policies = [
        doc for doc in documents if doc and doc.get("kind") == "NetworkPolicy"
    ]
    assert policies, "sandbox-network-policy.yaml must contain a NetworkPolicy"
    return policies



def _egress_rules(policy: dict) -> list[dict]:
    return policy["spec"]["egress"]


def _peer_selectors(rule: dict) -> list[dict]:
    return rule.get("to", [])


def _rule_ports(rule: dict) -> set[int]:
    return {p["port"] for p in rule.get("ports", [])}


def _pod_label(rule: dict, key: str) -> str | None:
    for peer in _peer_selectors(rule):
        labels = peer.get("podSelector", {}).get("matchLabels", {})
        if key in labels:
            return labels[key]
    return None


def _namespace_name(rule: dict) -> str | None:
    for peer in _peer_selectors(rule):
        ns_labels = peer.get("namespaceSelector", {}).get("matchLabels", {})
        if "kubernetes.io/metadata.name" in ns_labels:
            return ns_labels["kubernetes.io/metadata.name"]
    return None


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


def test_sandbox_router_not_in_egress_allowlist():
    policy = _load_policy_documents()[0]
    for rule in _egress_rules(policy):
        for peer in _peer_selectors(rule):
            labels = peer.get("podSelector", {}).get("matchLabels", {})
            if labels.get("app") == "sandbox-router":
                pytest.fail("sandbox-router must not appear in egress allowlist")
            for expr in peer.get("podSelector", {}).get("matchExpressions", []):
                if "sandbox-router" in expr.get("values", []):
                    pytest.fail("sandbox-router must not appear in egress allowlist")


def test_credential_resolver_pinned_to_opensre_prod_namespace():
    policy = _load_policy_documents()[0]
    cred_rules = [
        rule
        for rule in _egress_rules(policy)
        if _pod_label(rule, "app") == "credential-resolver"
    ]
    assert len(cred_rules) == 1, "expected exactly one credential-resolver egress rule"

    rule = cred_rules[0]
    assert _namespace_name(rule) == "opensre-prod"

    for peer in _peer_selectors(rule):
        ns_selector = peer.get("namespaceSelector", {})
        assert ns_selector != {}, "credential-resolver must not use empty namespaceSelector"
        assert ns_selector.get("matchLabels", {}).get(
            "kubernetes.io/metadata.name"
        ) == "opensre-prod"


def test_in_cluster_services_use_separate_port_rules():
    policy = _load_policy_documents()[0]
    service_ports = {
        "opensre-config-service": 8080,
        "opensre-k8s-gateway": 8085,
    }

    for app_label, expected_port in service_ports.items():
        matching = [
            rule
            for rule in _egress_rules(policy)
            if _pod_label(rule, "app") == app_label
        ]
        assert len(matching) == 1, f"expected one egress rule for {app_label}"
        rule = matching[0]
        assert _rule_ports(rule) == {expected_port}, (
            f"{app_label} must allow only port {expected_port}, got {_rule_ports(rule)}"
        )

    rag_rules = [
        rule
        for rule in _egress_rules(policy)
        if _rule_ports(rule) == {8000}
        and (
            _pod_label(rule, "app") == "opensre-rag"
            or any(
                expr.get("key") == "app.kubernetes.io/name"
                for peer in _peer_selectors(rule)
                for expr in peer.get("podSelector", {}).get("matchExpressions", [])
            )
        )
    ]
    assert len(rag_rules) == 1, "expected one RAG egress rule on port 8000"
    assert _rule_ports(rag_rules[0]) == {8000}

    # Lock real backend label values so the prior RAG-selector fix cannot regress.
    rag_names: set[str] = set()
    for peer in _peer_selectors(rag_rules[0]):
        for expr in peer.get("podSelector", {}).get("matchExpressions", []):
            if expr.get("key") == "app.kubernetes.io/name" and expr.get("operator") == "In":
                rag_names.update(expr.get("values", []))
    assert {"opensre-ultimate-rag", "opensre-knowledge-base"}.issubset(rag_names), rag_names
    assert _pod_label(rag_rules[0], "app") == "opensre-rag"

    multi_service_rules = [
        rule
        for rule in _egress_rules(policy)
        if len(_rule_ports(rule)) > 1
        and _namespace_name(rule) != "kube-system"
    ]
    assert not multi_service_rules, (
        "config-service, gateway, and RAG must not share one combined ports list"
    )


def test_sre_agent_file_proxy_allowlisted():
    """Slack/Teams attachments download via opensre-server-svc /proxy/files."""
    policy = _load_policy_documents()[0]
    proxy_rules = [
        rule
        for rule in _egress_rules(policy)
        if _pod_label(rule, "app") == "opensre-agent" and _rule_ports(rule) == {8000}
    ]
    assert len(proxy_rules) == 1, "expected one opensre-agent :8000 file-proxy egress rule"
    assert _namespace_name(proxy_rules[0]) == "opensre-prod"


def test_warmpool_templates_include_sandbox_isolation_label():
    for path in WARMPOOL_TEMPLATE_PATHS:
        assert path.is_file(), f"missing warmpool template: {path}"
        documents = list(yaml.safe_load_all(path.read_text()))
        templates = [
            doc for doc in documents if doc and doc.get("kind") == "SandboxTemplate"
        ]
        assert templates, f"{path.name} must contain a SandboxTemplate"
        pod_labels = templates[0]["spec"]["podTemplate"]["metadata"]["labels"]
        assert pod_labels.get(SANDBOX_ISOLATION_LABEL_KEY) == SANDBOX_ISOLATION_LABEL_VALUE


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
