# GitHub Actions (public OpenSRE)

## Publish Docker images (`docker-publish.yml`)

Builds and pushes multi-arch (`linux/amd64`, `linux/arm64`) images to Docker Hub when a `v*` tag is pushed, or via manual `workflow_dispatch` with a tag input.

### Images

| Context | Docker Hub |
|---------|------------|
| `config_service/` | `swapnildahiphale/opensre-config-service` |
| `sre-agent/` | `swapnildahiphale/opensre-sre-agent` |
| `web_ui/` | `swapnildahiphale/opensre-web-ui` |
| `teams-bot/` | `swapnildahiphale/opensre-teams-bot` |

Each publish tags both the version (e.g. `v1.1.0`) and `latest`.

### Required secrets

Set on this repository (Settings → Secrets and variables → Actions):

| Secret | Purpose |
|--------|---------|
| `DOCKERHUB_USERNAME` | Docker Hub username (`swapnildahiphale`) |
| `DOCKERHUB_TOKEN` | Docker Hub access token with push permission |

```bash
gh secret set DOCKERHUB_USERNAME --repo swapnildahiphale/OpenSRE
gh secret set DOCKERHUB_TOKEN --repo swapnildahiphale/OpenSRE
```

### How to publish

1. Ensure Docker Hub repositories exist (or allow auto-create on first push).
2. Secrets above are set.
3. Push a version tag from `main` (or create a GitHub Release with tag `vX.Y.Z`):

```bash
git tag v1.1.0
git push origin v1.1.0
```

4. Or re-run: Actions → **Publish Docker images** → Run workflow → enter tag (e.g. `v1.1.0`).
