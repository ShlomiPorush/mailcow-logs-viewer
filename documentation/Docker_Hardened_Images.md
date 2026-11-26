# Building the image on Docker Hardened Images

> **Status: proposal.** This page describes how the image *would* be built on
> Docker Hardened Images (DHI). The `Dockerfile` and the workflows in this
> repository still use `python:3.11-slim`. The page explains what DHI requires
> (an account and a token), how that interacts with pull requests from forks,
> and which secrets the maintainer would have to set.

## The short answer

| Question | Answer |
|---|---|
| Are the images free? | Yes. The DHI catalog is free and open source (Apache 2.0); the free tier is called *DHI Community*. |
| Can they be pulled anonymously? | **No.** Docker's documentation: *"You must authenticate to the Docker Hardened Images registry (`dhi.io`) to pull DHI Community images."* A free Docker Hub account is enough; no paid subscription is needed. |
| Does a pull request from a fork still build? | **Not with DHI.** GitHub does not give secrets to workflows triggered by a pull request from a fork, so CI cannot log in to `dhi.io` there. The setup below has CI fall back to the public `python:3.11-slim` base image when no DHI credentials are available, so fork PRs are still built and tested. |
| What does the maintainer need? | A Docker Hub account, one read-only access token, and two repository secrets: `DHI_USERNAME` and `DHI_TOKEN`. |

## What DHI changes about the image

DHI images come in two variants:

| Variant | Tag form | Contains |
|---|---|---|
| runtime | `dhi.io/python:<version>-debian<N>` | Python only. **No shell, no package manager, runs as non-root.** |
| dev | `dhi.io/python:<version>-debian<N>-dev` | Adds a shell, `pip`, a root user and build tools. Meant for build stages. |

Pick the exact tags in the [DHI catalog](https://hub.docker.com/hardened-images/catalog) (Python 3.11 to match the current image, Debian variant for the
broadest compatibility) and pin them by digest, as the current base image is.

Because the runtime variant has no shell and no `apt`, the image becomes two
stages:

1. **Build stage** (`-dev` variant): installs `backend/requirements.txt` into a
   virtual environment with the same flags as today
   (`--require-hashes --no-deps --only-binary=:all:`).
2. **Runtime stage** (runtime variant): copies the virtual environment, the
   application, the Alembic migrations, the frontend and `VERSION`. It runs no
   `RUN` instruction.

Three things in the current image depend on a shell or Debian packages and
change with it:

| Today | With a DHI runtime image |
|---|---|
| `entrypoint.sh` (bash) starts as root, creates `/app/data`, `chown`s it to UID 1000 and drops privileges with `gosu`. | The container starts directly as UID 1000 (`USER 1000:1000`, exec-form `ENTRYPOINT` running uvicorn). Named volumes keep working because UID 1000 already owns them. **A host bind mount owned by root is no longer fixed up**: such a directory must be `chown 1000:1000` on the host. This needs a line in the release notes. |
| `HEALTHCHECK` runs `curl`. | `HEALTHCHECK` runs a Python one-liner with `urllib.request` against `/api/health`. |
| `postgresql-client` is installed. | Dropped. The application does not use it. Only someone running `psql` inside the container would notice, and `psql` is available in the database container. |

## How CI behaves

| Event | Secrets available? | Base image used |
|---|---|---|
| PR from a branch of this repository | yes | DHI |
| PR from a fork | **no** | `python:3.11-slim` (fallback) |
| PR opened by Dependabot | only *Dependabot* secrets (see step 4) | DHI if the Dependabot secrets are set, else the fallback |
| Version tag (`docker-publish.yml`), dev image (`docker-dev.yml`) | yes | DHI, and the job **fails** without credentials, so a release can never silently ship the fallback base |

The fallback means a fork PR is tested on a different base image from the
release. The application code, the Python packages (same lock file, same
hashes) and the smoke test are the same; only the OS layer differs. After a
fork PR is merged, the next DHI build (dev image or release) runs on DHI.

Do **not** switch the CI trigger to `pull_request_target` to get secrets into
fork PRs. That trigger runs with the base repository's secrets, and building
a fork's `Dockerfile` with them would hand the token to whoever opened the PR.

## Setup

### 1. Create a Docker Hub account

If the project already publishes to Docker Hub (the `DOCKER_HUB_USERNAME` and
`DOCKER_HUB_TOKEN` secrets), that account can be used and this step skipped.
Otherwise:

1. Go to <https://hub.docker.com/signup> and create a free *Personal* account.
2. Confirm the e-mail address. No payment details or subscription are needed
   to pull DHI Community images.

### 2. Create a read-only personal access token

Use a separate token for DHI pulls rather than the Docker Hub push token: a CI
job that only builds should never hold push rights.

1. Sign in at <https://app.docker.com>, open **Account settings → Personal
   access tokens**, and choose **Generate new token**.
2. Description: for example `mailcow-logs-viewer CI: dhi.io pull`.
3. Expiration: choose one, and note the date. CI fails with `unauthorized`
   when the token expires.
4. Access permissions: **Public Repo Read-only**. If pulls from `dhi.io` are
   refused with this scope, use **Read-only** instead. Both are read-only.
5. Choose **Generate** and copy the token now. It is shown only once.

Check it locally:

```bash
docker login dhi.io --username <docker-hub-username>
# paste the token as the password
docker pull dhi.io/python:<tag from the catalog>
```

An organization can use an organization access token (OAT) instead, with the
organization name as the username. In GitHub Actions an organization can also
use OIDC instead of a stored token; see Docker's [DHI usage
guide](https://docs.docker.com/dhi/how-to/use/).

### 3. Add the repository secrets

In the GitHub repository: **Settings → Secrets and variables → Actions → New
repository secret**:

| Name | Value |
|---|---|
| `DHI_USERNAME` | The Docker Hub username (or organization name for an OAT) |
| `DHI_TOKEN` | The token from step 2 |

Secrets are only readable by workflows of this repository, never by a
workflow triggered from a fork.

### 4. Optional: let Dependabot PRs build on DHI

Workflows triggered by Dependabot do not see Actions secrets, only
Dependabot secrets. To build its PRs on DHI too, add the same two secrets
under **Settings → Secrets and variables → Dependabot**. Without them,
Dependabot PRs use the fallback, like fork PRs.

### 5. Building locally

Without DHI (no account needed, the fallback base image):

```bash
docker build -t mailcow-logs-viewer:local .
```

With DHI:

```bash
docker login dhi.io
docker build \
  --build-arg BUILD_IMAGE=dhi.io/python:<dev tag>@sha256:<digest> \
  --build-arg RUNTIME_IMAGE=dhi.io/python:<runtime tag>@sha256:<digest> \
  -t mailcow-logs-viewer:local .
```

## Summary of names

| Kind | Name | Where | Required for |
|---|---|---|---|
| Actions secret | `DHI_USERNAME` | Settings → Secrets and variables → Actions | DHI builds in CI, the dev image and releases |
| Actions secret | `DHI_TOKEN` | Settings → Secrets and variables → Actions | DHI builds in CI, the dev image and releases |
| Dependabot secret | `DHI_USERNAME`, `DHI_TOKEN` | Settings → Secrets and variables → Dependabot | Optional: Dependabot PRs on DHI |
| Build argument | `BUILD_IMAGE` | `docker build --build-arg` | Choosing the build-stage base image |
| Build argument | `RUNTIME_IMAGE` | `docker build --build-arg` | Choosing the runtime base image |

The existing `DOCKER_HUB_USERNAME` / `DOCKER_HUB_TOKEN` secrets stay as they
are; they are used to push the image, not to pull the base image.

## Not covered by the documentation read for this page

- Pull rate limits for `dhi.io` on the free tier are not stated on Docker's DHI
  pages. If CI ever hits a limit, every authenticated pull counts against the
  account that owns the token.
- Mirroring DHI images into your own Docker Hub namespace needs a paid DHI
  Select or Enterprise subscription. It is not needed here: pulling directly
  from `dhi.io` is free.

## References

- [Docker Hardened Images overview](https://docs.docker.com/dhi/)
- [Using DHI: authentication, variants, CI](https://docs.docker.com/dhi/how-to/use/)
- [Mirroring DHI (paid tiers only)](https://docs.docker.com/dhi/how-to/mirror/)
- [GitHub: secrets are not passed to workflows triggered from forks](https://docs.github.com/actions/security-for-github-actions/security-guides/using-secrets-in-github-actions)
