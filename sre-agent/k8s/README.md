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

| Destination | Port | Pod / namespace selector |
|-------------|------|--------------------------|
| kube-system DNS | 53/tcp, 53/udp | namespace `kube-system` |
| config-service | 8080 | `app=opensre-config-service` |
| k8s-gateway | 8085 | `app=opensre-k8s-gateway` |
| RAG service | 8000 | `app.kubernetes.io/name` in `opensre-ultimate-rag`, `opensre-knowledge-base`, or `app=opensre-rag` |
| credential-resolver | 8002 | namespace `opensre-prod`, `app=credential-resolver` |
| sre-agent file proxy | 8000 | namespace `opensre-prod`, `app=opensre-agent` (Slack/Teams `/proxy/files`) |

Each application has its own egress rule with a single port — rules are not combined across services.

**Not allowlisted**

- **sandbox-router** — sandboxes never initiate connections to the router; the server and router call into sandboxes. Adding sandbox-router with a broad namespace selector would let a compromised sandbox reach any sandbox-router cluster-wide.
- **Direct SaaS / internet upstreams** — `sandbox_manager.py` Envoy config still defines routes to external APIs (for example Coralogix at `api.us2.coralogix.com:443`) that originate from the sandbox pod network namespace (sidecar egress). This default-deny policy blocks those direct paths until traffic is routed through credential-resolver or operators add explicit allowlist rules. Do not add blanket internet egress; reconfigure Envoy to proxy SaaS via credential-resolver, or add targeted egress rules for the specific hosts your deployment needs.

**RAG pod labels**

Sandboxes call the in-cluster Service `opensre-rag.<namespace>:8000`, but NetworkPolicy matches pod labels, not Service names. The policy selects pods labeled `app.kubernetes.io/name` in `opensre-ultimate-rag` or `opensre-knowledge-base`, plus legacy `app=opensre-rag`. If your RAG deployment uses different labels, label the RAG pods accordingly or edit the RAG `podSelector` blocks in `sandbox-network-policy.yaml`.

**Credential-resolver namespace**

The cross-namespace rule pins credential-resolver to namespace `opensre-prod` (default for `CREDENTIAL_RESOLVER_NAMESPACE` in `sandbox_manager.py`). Edit the `namespaceSelector` if your install uses a different platform namespace.

**sre-agent file proxy**

Sandboxes download Slack/Teams attachments from `http://opensre-server-svc.<SERVER_NAMESPACE>:8000/proxy/files/{token}` (default `SERVER_NAMESPACE=opensre-prod`). The policy allows TCP 8000 to pods labeled `app=opensre-agent` in that namespace. Edit if your agent Deployment uses a different label or namespace.

If your deployment uses different component labels for other services, edit the corresponding `podSelector` blocks before applying.

**Validate**

```bash
kubectl apply --dry-run=client -f sre-agent/k8s/sandbox-network-policy.yaml -n <sandbox-namespace>
```
