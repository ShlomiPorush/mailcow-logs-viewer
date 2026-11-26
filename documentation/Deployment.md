# Deploying a release

This page is for running the viewer from a version-pinned Compose file and
updating it release by release, with a short downtime or with a zero-downtime
rollout with `docker rollout`. For a first installation, see
[Getting Started](GETTING_STARTED.md).

## Image tags

The image is `ghcr.io/shlomiporush/mailcow-logs-viewer`, also published as
`shlomip/mailcow-logs-viewer` on Docker Hub.

| Tag | Meaning |
|---|---|
| `X.Y.Z` | One release. Pushed only when the git tag `vX.Y.Z` is pushed and every CI check passed on that commit. It never moves to another image. |
| `latest` | The newest release. It moves with every release. |
| `X.Y.Z-demo`, `demo` | The public demo of a release. Not for a real mail server. |
| `dev`, `dev-<sha>` | Preview builds of unreleased work. Never use them in production. |

Pin a host to `X.Y.Z`, not to `latest`.

The release workflow pushes a version tag once. A re-run builds only the images
that neither GitHub Container Registry nor Docker Hub has, and skips the ones
both have. When a push stopped half way and a tag is on one registry only, the
run stops. Finish that release by hand instead: copy the tag to the registry
that misses it, and copy `latest` the same way when the release is the newest
one, for example from GHCR to Docker Hub:

```bash
docker buildx imagetools create -t shlomip/mailcow-logs-viewer:X.Y.Z ghcr.io/shlomiporush/mailcow-logs-viewer:X.Y.Z
```

Then publish the GitHub release and close the shipped issues by hand, as the
last two jobs of the release workflow do. To protect the tags on Docker Hub as
well, turn on its immutable tags setting for the repository.

## Image labels

The app image of every release carries two labels that a rollout tool compares
between the running image and the new one.

| Label | Value |
|---|---|
| `mailcow-logs-viewer.compose-sha256` | The sha256 of the `docker-compose.yml` in the repository at that release. |
| `mailcow-logs-viewer.rollout-from` | The oldest running release that this image may run beside during an update. |

The image also has a health check: it passes when the app has finished
starting and can reach its database. Before `docker rollout` stops the old
container, the image's `docker-rollout.pre-stop-hook` label turns that health
check red and waits 30 seconds, so the proxy stops sending requests to the old
container before it stops.

### The rule for `rollout-from`

Every database revision from `0033` on says whether the previous release keeps
working on the migrated database: `downtime = False` (a new table, a nullable
column, an index built with `CREATE INDEX CONCURRENTLY`, nothing the previous
release reads changes) or `downtime = True` (anything else). A test fails on a
revision without it, and on a `downtime = False` revision that drops, renames
or alters a column or adds a unique constraint.

`rollout-from` is the first release that contains the newest revision with
`downtime = True`, where every revision up to `0033` counts as one. So the
first release with `0033` rolls out from itself and is updated with downtime,
and later releases roll out from it until a revision with `downtime = True`
ships. A release that cannot run beside the previous one for a reason outside
the database adds an empty revision with `downtime = True`.

Put `CREATE INDEX CONCURRENTLY` in a revision of its own, inside Alembic's
`autocommit_block()`. If it fails, drop the `INVALID` index it leaves before
the next try.

## Two containers during an update

During a zero-downtime update the new container starts beside the old one,
and the old one stops about half a minute after the new one is healthy.

- Only one container runs the background jobs: log import, correlation,
  alerts, reports, DMARC mailbox import, GeoIP downloads and everything that
  changes mailcow. It holds a lock on the file `leader.lock` in the data volume.
  The new container serves pages at once and takes over the jobs when the old
  one has stopped, within 2 seconds. Run now and the other buttons that start a
  job answer "try again in a minute" on a container that is still waiting.
- Starting a container changes no data and takes no table lock while the other
  one runs. Database revisions follow the rule above. A revision that cannot get
  its lock within 15 seconds stops the new container, and the old one keeps
  serving.
- The import position, the Dovecot events that wait for their message and the
  settings are in the database, so the container that takes over continues
  where the old one stopped.

In the seconds when both containers answer:

- Sign-ins are kept per container. After the update everyone signs in again
  once, as after a restart. A request that reaches the other container in those
  seconds is signed out, and so is an OAuth2 sign-in or an agent approval that
  started on one container and finished on the other. Failed sign-in counts are
  per container.
- Live logs reconnect to the container that remains.
- A setting saved, a Rspamd map edited or an agent approved on the waiting
  container races the other container's own work, as two admins at the same
  time would: the last write wins, and the next cleanup removes data of a
  feature that was turned off.
- A page may load scripts from the other release.
- Both containers write to `container.log`; a log rotation in exactly those
  seconds can lose lines around it.
- A background job that runs when the old container stops is cut off, and a
  daily or weekly job that is due in the seconds before the new one takes over
  runs at its next time, as with any restart.

The first release with these changes is updated with downtime, because the
release before it runs its jobs in every container.

## The host's Compose file and `.env`

The tracked `docker-compose.yml` is an example for a first installation. A host
that updates by version uses its own file, with these differences on the `app`
service:

- `image: ghcr.io/shlomiporush/mailcow-logs-viewer:${VERSION}`
- no `container_name`, no `build`, and one replica;
- no `healthcheck:` of its own, so the image's health check, which the update
  turns red before it stops the old container, stays in effect;
- no published port (`ports:`). Put a reverse proxy in front of the app on a
  shared Docker network, see [Reverse Proxy](Reverse_Proxy.md). The proxy must
  route only to containers that Docker reports healthy and find a new container
  by itself, such as Traefik's Docker provider. nginx looks up the app's address only when it
  loads its configuration: reload it after every update, or use Docker's
  resolver (`resolver 127.0.0.11`) with a variable in `proxy_pass`;
- the data volume on `/app/data`, shared by the old and the new container, so
  both run on one Docker host;
- a restart policy, such as `restart: unless-stopped`;
- a direct connection to PostgreSQL, or one through a pooler in session mode.

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
   here. Then remove that setting wherever it is set, in `.env` or in the shell,
   because it overrides `name:`.

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

The command ends when the new container is healthy. To go back, run it again
with the version that ran before. An older release starts on a database that a
newer one migrated, but going back past a revision with `downtime = True` needs
the database backup from before the update.

## An update that stopped half way

When an update stopped with two app containers, or with one that is not
healthy, check `docker compose ps app`. Keep the healthy container, remove the
other with `docker rm -f <container>`, and set `VERSION` in `.env` to the
release the remaining container runs. Then update again.
