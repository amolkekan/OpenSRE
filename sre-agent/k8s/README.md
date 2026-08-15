# OpenSRE sandbox Kubernetes manifests

Reference templates and operator manifests for agent-sandbox investigation workloads.

## Sandbox egress NetworkPolicy

`sandbox-network-policy.yaml` restricts outbound traffic from investigation sandbox pods to a minimal allowlist. Sandboxes are selected by the pod label `opensre.in/isolation=sandbox`, which `sandbox_manager.py` sets on every `podTemplate.metadata.labels` block.

**Prerequisites**

- A CNI that enforces Kubernetes NetworkPolicy (Calico, Cilium, Weave Net, etc.).
- Sandbox pods labeled with `opensre.in/isolation=sandbox` (programmatic creation via `sandbox_manager.py`, or warmpool templates updated to match).

**Apply**

```bash
# Replace <sandbox-namespace> with the namespace where investigation sandboxes run
kubectl apply -f sre-agent/k8s/sandbox-network-policy.yaml -n <sandbox-namespace>
```

**Allowed egress destinations**

| Destination | Port | Pod label (`app`) |
|-------------|------|-------------------|
| kube-system DNS | 53/tcp, 53/udp | (namespace selector) |
| config-service | 8080 | `opensre-config-service` |
| k8s-gateway | 8085 | `opensre-k8s-gateway` |
| RAG service | 8000 | `opensre-rag` |
| credential-resolver | 8002 | `credential-resolver` |
| sandbox-router | 8080 | `sandbox-router` |

External LLM and SaaS APIs are reached through the Envoy sidecar → credential-resolver path, not via direct sandbox egress.

If your deployment uses different component labels, edit the `podSelector` blocks in `sandbox-network-policy.yaml` before applying.

**Validate**

```bash
kubectl apply --dry-run=client -f sre-agent/k8s/sandbox-network-policy.yaml -n <sandbox-namespace>
```
