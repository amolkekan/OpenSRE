# Security Policy

## Supported Versions

We release security updates for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| main    | :white_check_mark: |
| Latest release | :white_check_mark: |
| Older releases | :x: |

We strongly recommend running the latest version of OpenSRE.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via one of these methods:

### 1. GitHub Security Advisories (Preferred)

Report security vulnerabilities privately through GitHub:

1. Go to the [Security tab](https://github.com/swapnildahiphale/OpenSRE/security)
2. Click "Report a vulnerability"
3. Fill out the advisory form with details

### 2. Email

Send details to **swapnil@opensre.in** with:

- Type of vulnerability (RCE, injection, XSS, etc.)
- Affected component(s)
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### What to Expect

- **Acknowledgment**: Within 24 hours
- **Initial assessment**: Within 3 business days
- **Regular updates**: At least every 7 days until resolved
- **Disclosure timeline**: Coordinated disclosure after patch is available

We follow responsible disclosure practices and will credit reporters (unless you prefer to remain anonymous).

## Scope

### In Scope

Security issues in:

- **OpenSRE core** (agent, orchestrator, config-service)
- **Web console** (authentication, authorization, XSS, CSRF)
- **API endpoints** (injection, authentication bypass)
- **Slack bot** (command injection, unauthorized access)
- **Integrations** (credential leakage, SSRF)
- **Deployment configs** (Kubernetes, Docker)
- **Dependencies** (critical CVEs in direct dependencies)

### Out of Scope

- Social engineering attacks
- Physical attacks
- Attacks requiring MITM on local network
- DoS/DDoS attacks
- Issues in third-party services (Slack, AWS, etc.)
- Issues only exploitable with admin access
- Theoretical vulnerabilities without proof of concept
- Brute force attacks without additional vulnerability

## Security Best Practices

When deploying OpenSRE:

### Secrets Management

- **Never commit secrets** to version control
- Use **secrets proxy** in production (see [deployment guide](docs/DEPLOYMENT.md))
- Rotate credentials regularly
- Use separate credentials for dev/staging/prod

### Network Security

- Deploy behind a firewall
- Use TLS for all external communications
- Restrict API access to authorized networks
- Enable audit logging
- For simple-mode self-hosting, follow [Self-Hosting: TLS and DoS Posture](#self-hosting-tls-and-dos-posture) below

### Authentication & Authorization

- Enable SSO/OIDC for production deployments
- Use role-based access control (RBAC)
- Review team permissions regularly
- Enable approval workflows for critical changes

### Agent Sandboxing

- Use **Claude Sandbox** in production (isolated Kubernetes namespaces)
- Limit agent permissions to minimum required
- Monitor agent actions via audit logs
- Review tool usage patterns

### Updates & Monitoring

- Subscribe to security announcements (watch this repo)
- Update OpenSRE regularly
- Monitor dependency vulnerabilities (Dependabot enabled)
- Review audit logs for suspicious activity

## Self-Hosting: TLS and DoS Posture

OpenSRE's default path (`make dev`, Helm simple profile, `server_simple.py`) is **simple-mode**: the agent runs in-process with no Kubernetes sandbox isolation. It is designed for local development and trusted single-tenant self-hosting on a private network.

### Simple-mode is network-trust

Simple-mode assumes callers on the agent and datastore ports are trusted:

- **No application-layer auth on several control endpoints** — e.g. `POST /interrupt`, `POST /threads/{id}/queue-message`, and `POST /answer` on [`server_simple.py`](sre-agent/server_simple.py) accept requests without validating a team token. The web UI BFF adds session auth; chat bots and direct API callers must rely on network placement.
- **No filesystem or network isolation** — investigations run in the API process with access to mounted credentials and cluster tools.
- **Bind to localhost or a private network** — for local dev, published ports (`3002`, `8001`, `8081`, `5433`, Neo4j) are convenient; do **not** expose them on the public internet without a reverse proxy, firewall rules, and the hardening checklist below.
- **Do not port-forward simple-mode to the internet** — treat any host that can reach the agent API (compose host port `8001`, in-cluster `sre-agent:8000`) as able to start investigations.

For production isolation, use sandbox mode ([`server.py`](sre-agent/server.py) with per-thread Kubernetes sandboxes). See [Deployment modes](docs/ARCHITECTURE.md#deployment-modes).

### Cleartext HTTP in Docker Compose

[`docker-compose.yml`](docker-compose.yml) uses **HTTP between containers** (e.g. web-ui → sre-agent → config-service). That is intentional for local development: no TLS termination inside the compose network.

For production self-hosting:

- Terminate **TLS at the ingress or reverse proxy** (nginx, Caddy, Traefik, cloud load balancer, Kubernetes Ingress).
- Keep Postgres, Neo4j, and the agent API on private networks; only the web UI and any chat-bot webhook paths need public HTTPS endpoints.
- East-west mTLS or a service mesh is out of scope for the default stack; rely on network segmentation plus edge TLS.

### DoS and abuse mitigations

Simple-mode **does not ship** HTTP rate limiting, request body size caps, or global concurrency gates on the investigation API. A single client can open long-lived SSE streams and trigger expensive LLM/tool work.

Mitigations belong at the **edge** or in the **sandbox production path**:

| Layer | What to enforce |
|-------|-----------------|
| **Reverse proxy / WAF** | Per-IP and per-route rate limits; max request body size; connection limits; optional bot protection |
| **Ingress** | TLS, timeouts, and request size limits on public hostnames |
| **Application** | `AGENT_TIMEOUT_SECONDS` caps wall-clock time per investigation (compose default 600s) but is **not** a substitute for connection-level rate limiting |
| **Sandbox mode** | Per-thread resource limits and isolation via Kubernetes ([`server.py`](sre-agent/server.py)) |

Reporting DoS/DDoS as security vulnerabilities is [out of scope](#out-of-scope) for this policy; still harden deployments that face untrusted networks.

### Hardening checklist

Use this before exposing OpenSRE beyond a developer laptop:

- [ ] Agent (`8001`), config-service (`8081`), Postgres (`5432`/`5433`), and Neo4j Bolt (`7687`/`7688`) plus Browser (`7474`/`7475`) are **not** reachable from the public internet
- [ ] Web UI and chat-bot webhooks are served **only over HTTPS** (TLS at ingress/reverse proxy)
- [ ] Reverse proxy enforces **rate limits**, **max body size**, and **timeouts** on `/investigate` and SSE routes
- [ ] **Concurrent investigations** are capped at the proxy or orchestration layer if multiple untrusted users share one install
- [ ] Team and admin tokens are **rotated**, stored in secrets management, and never committed to git
- [ ] SSO/OIDC and RBAC are enabled for the web console when more than one operator uses the instance
- [ ] Audit logs are enabled and reviewed; dependency updates are applied regularly
- [ ] For untrusted prompts or multi-tenant use, plan a move to **sandbox mode** instead of widening simple-mode exposure

## Known Security Considerations

### Agent Tool Execution

OpenSRE agents execute commands against your infrastructure (kubectl, AWS CLI, etc.). This is by design for incident response.

**Mitigations:**
- Tools run in isolated sandboxes
- Secrets never touch the agent (injected by proxy)
- Approval workflows for critical operations
- Full audit trail of all actions

### LLM Prompt Injection

Like all LLM-powered tools, OpenSRE may be susceptible to prompt injection attacks.

**Mitigations:**
- Input validation and sanitization
- Separate system and user contexts
- Tool-specific safety checks
- Human approval for destructive operations

### Data Privacy

Agents may access sensitive data (logs, metrics, code).

**Mitigations:**
- On-premise deployment option (full data control)
- Configurable data retention policies
- Audit logs for data access
- RBAC for sensitive integrations

## Security Features

OpenSRE includes security features for production:

- **SOC 2 compliant** infrastructure (managed deployments)
- **End-to-end encryption** for data in transit
- **Secrets proxy** (credentials never touch agents)
- **Audit logging** (all actions tracked)
- **RBAC** (role-based access control)
- **SSO/OIDC** support
- **Approval workflows** for critical changes
- **Isolated sandboxes** (Kubernetes namespaces per agent)

See [Enterprise Ready](README.md#enterprise-ready) for details.

## Vulnerability Disclosure Policy

When we receive a security report:

1. **Confirmation**: We confirm the vulnerability
2. **Patch development**: We develop and test a fix
3. **Coordinated disclosure**: We coordinate with the reporter on disclosure timeline
4. **Release**: We release a patch and security advisory
5. **Public disclosure**: We publicly disclose the issue (typically 90 days after patch)

We credit security researchers in:
- Security advisories
- Release notes
- Public acknowledgments (if desired)

## Security Hall of Fame

We recognize security researchers who help keep OpenSRE secure:

<!-- This section will be updated as we receive security reports -->

*No security issues reported yet. Be the first!*

## Contact

- **Security issues**: swapnil@opensre.in
- **General questions**: swapnil@opensre.in
- **Community**: [Slack](https://join.slack.com/t/opensre/shared_invite/zt-3ojlxvs46-xuEJEplqBHPlymxtzQi8KQ) | [Discussions](https://github.com/swapnildahiphale/OpenSRE/discussions)

## Learn More

- [Deployment Guide](docs/DEPLOYMENT.md) — production deployment best practices
- [Architecture](docs/ARCHITECTURE.md) — system design and security architecture
- [Enterprise Ready](README.md#enterprise-ready) — advanced security features
