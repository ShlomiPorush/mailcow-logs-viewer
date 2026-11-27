#!/usr/bin/env bash
set -euo pipefail

TAG=$1
CONTROL=latest
ACCEPT='application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json'

manifest_status() {
  curl -sS -o /dev/null -w '%{http_code}' -I -H "Authorization: Bearer $1" -H "Accept: $ACCEPT" "$2/manifests/$3"
}

tag_state() {
  local image=$1 token_url=$2 registry_repo=$3 token
  if ! token=$(curl -fsS "$token_url" | jq -er .token); then
    echo "::error::Could not get a read token for $image" >&2
    exit 1
  fi
  if [ "$(manifest_status "$token" "$registry_repo" "$CONTROL")" != 200 ]; then
    echo "::error::Could not read $image:$CONTROL, so whether $image:$TAG exists is unknown" >&2
    exit 1
  fi
  case "$(manifest_status "$token" "$registry_repo" "$TAG")" in
    404) echo absent ;;
    200) echo present ;;
    *) echo "::error::Could not check whether $image:$TAG exists" >&2; exit 1 ;;
  esac
}

GHCR_REPO="${GITHUB_REPOSITORY,,}"
ghcr=$(tag_state "ghcr.io/$GHCR_REPO" \
  "https://ghcr.io/token?scope=repository:$GHCR_REPO:pull" \
  "https://ghcr.io/v2/$GHCR_REPO")
hub=$(tag_state "docker.io/$DOCKER_HUB_REPO" \
  "https://auth.docker.io/token?service=registry.docker.io&scope=repository:$DOCKER_HUB_REPO:pull" \
  "https://registry-1.docker.io/v2/$DOCKER_HUB_REPO")

case "$ghcr/$hub" in
  absent/absent) echo build ;;
  present/present) echo skip ;;
  *)
    echo "::error::$TAG is on one registry only (GHCR: $ghcr, Docker Hub: $hub). Copy it to the other by hand, see documentation/Deployment.md; a rebuild would publish another image under the same tag." >&2
    exit 1
    ;;
esac
