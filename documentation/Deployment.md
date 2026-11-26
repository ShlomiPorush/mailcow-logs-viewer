# Deploying a release

This page is for running the viewer from a version-pinned Compose file and
updating it release by release, for example with a zero-downtime rollout with
`docker rollout`. For a first installation, see
[Getting Started](GETTING_STARTED.md).

## Image tags

The image is `ghcr.io/shlomiporush/mailcow-logs-viewer`, also published as
`shlomip/mailcow-logs-viewer` on Docker Hub.

| Tag | Meaning |
|---|---|
| `X.Y.Z` | One release. It is pushed only when the git tag `vX.Y.Z` is pushed and every CI check passed on that commit. It never moves to another image. |
| `latest` | The newest release. It moves with every release. |
| `dev`, `dev-<sha>` | Preview builds of unreleased work, built by hand. Never use them in production. |

Pin a host to `X.Y.Z`, not to `latest`.

The release workflow refuses to push `X.Y.Z` when GitHub Container Registry or
Docker Hub already has it, so a re-run never replaces a published release. If
the push stopped half way, a re-run stops too. Finish the release by hand
instead: copy `X.Y.Z` to the registry that misses it, for example from GHCR to
Docker Hub, and copy `latest` the same way when `X.Y.Z` is the newest release:

```bash
docker buildx imagetools create -t shlomip/mailcow-logs-viewer:X.Y.Z ghcr.io/shlomiporush/mailcow-logs-viewer:X.Y.Z
```

The GitHub release and the closing of shipped issues run after the push, so
they are skipped too. Do them by hand as the last two jobs of the release
workflow do.

## Image labels

Release images published after 2.9.0 carry two labels that a rollout tool
compares between the running image and the new one.

| Label | Value |
|---|---|
| `mailcow-logs-viewer.compose-sha256` | The sha256 of the `docker-compose.yml` in the repository at that release. |
| `mailcow-logs-viewer.rollout-from` | The oldest running release that this image may run beside during a rollout. |

The image also has a health check: it passes only when the app has finished
starting and can reach its database.

### Why every release is updated with downtime

`rollout-from` is always the version of the image itself, so a rollout tool
refuses every release, and each update stops the old container before it starts
the new one. Two copies of the app cannot yet run side by side:

- every copy runs the background jobs, so log imports, alerts, DMARC mailbox
  imports, and the jobs that change mailcow, such as quarantine rules and queue
  cleanup, would run twice;
- a new copy updates the database schema when it starts, while the old copy
  still uses it;
- OAuth2 sign-in sessions are kept in the memory of one copy.

## The host's Compose file and `.env`

The tracked `docker-compose.yml` is an example for a first installation. A host
that updates by version uses its own file, with these differences on the `app`
service:

- `image: ghcr.io/shlomiporush/mailcow-logs-viewer:${VERSION}`
- no `container_name`, no `build`, and one replica;
- no published port (`ports:`). Put a reverse proxy in front of the app on a
  shared Docker network, see [Reverse Proxy](Reverse_Proxy.md).

Without `container_name`, the proxy recipes no longer find the app as
`mailcow-logs-app`. Give the app that name as an alias on the network it shares
with the proxy, for example the `mailcow-network` from the first
[Reverse Proxy](Reverse_Proxy.md) recipe:

```yaml
services:
  app:
    networks:
      mailcow-logs-network:
      mailcow-network:
        aliases:
          - mailcow-logs-app
```

At the top of the file, set the Compose project name:

```yaml
name: mailcow-logs-viewer
```

`.env` holds exactly one line `VERSION=X.Y.Z`, next to the app's other settings.

### Switching an existing installation

Compose names containers, networks and volumes after the project. If the stack
already runs under another project name, switch it once:

1. Stop the stack with the file it runs from now. This removes its containers
   and network and keeps its volumes:

   ```bash
   docker compose down
   ```

   If you started it with `-p` or `COMPOSE_PROJECT_NAME`, give the same name
   here. Then remove that setting wherever it is set, in `.env` or in the
   shell, because it overrides `name:`.

2. Find the existing volumes, for example `oldname_postgres_data` and
   `oldname_mailcowlogs_data`:

   ```bash
   docker volume ls
   ```

3. Change the file as described above, and point it at those volumes:

   ```yaml
   volumes:
     postgres_data:
       external: true
       name: oldname_postgres_data
     mailcowlogs_data:
       external: true
       name: oldname_mailcowlogs_data
   ```

4. Start the stack:

   ```bash
   docker compose up -d --wait --wait-timeout 300
   ```

   Then reload nginx as described in the next section.

With `external: true`, Compose refuses to start when a name is wrong instead of
creating an empty volume.

## Update with downtime

Run this in the directory of the host's `docker-compose.yml`, with the release
you are updating to:

```bash
NEW=X.Y.Z
docker pull "ghcr.io/shlomiporush/mailcow-logs-viewer:$NEW" &&
  sed -i "s/^VERSION=.*/VERSION=$NEW/" .env &&
  docker compose stop app &&
  docker compose up -d --wait --wait-timeout 300 app
```

The command ends when the new container is healthy. nginx looks up the app's
address only when it loads its configuration, and the new container can get
another address. If nginx is your proxy, reload it now, for mailcow's nginx in
the mailcow directory with `docker compose exec nginx-mailcow nginx -s reload`.

To go back, run it again
with the version that ran before. A release that changed the database schema
may not run on the newer schema, so read the release notes first.
