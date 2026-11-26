#!/usr/bin/env bash
# Generate the hash-pinned Python lock files from their inputs:
#
#   backend/requirements.in      ->  backend/requirements.txt      (the image)
#   backend/requirements-dev.in  ->  backend/requirements-dev.txt  (CI, local tests)
#
# Usage, from anywhere in the repository:
#   bash .github/scripts/lock-requirements.sh            regenerate, keeping every
#                                                        pin the inputs still allow
#   bash .github/scripts/lock-requirements.sh --upgrade  move every transitive
#                                                        package to its newest
#                                                        allowed version
#   bash .github/scripts/lock-requirements.sh --check    fail if a lock file no
#                                                        longer matches its input
#                                                        (CI runs this)
#
# The lock is universal (Linux amd64/arm64 for the image, plus macOS and
# Windows for local tests) for Python 3.11, the version of the image, and it
# only admits packages that publish wheels: the image installs with
# --only-binary, so no sdist and no build backend is ever fetched or run.
#
# --check compares package versions, not hashes. PyPI can add a wheel to an
# existing release (a new platform), which would change the hash list without
# anything being wrong. A hash that does not match is caught where it matters:
# pip --require-hashes refuses the download.
set -euo pipefail

UV_VERSION="0.13.10"
PYTHON_VERSION="3.11"

mode="write"
case "${1:-}" in
    "") ;;
    --check) mode="check" ;;
    --upgrade) mode="upgrade" ;;
    *) echo "usage: $0 [--check|--upgrade]" >&2; exit 2 ;;
esac

cd "$(git rev-parse --show-toplevel)/backend"

# Same uv as CI, so a local run and the CI check produce the same file.
if command -v uv >/dev/null 2>&1 && [ "$(uv --version | cut -d' ' -f2)" = "${UV_VERSION}" ]; then
    uv=(uv)
else
    uv=(uvx "uv@${UV_VERSION}")
fi

compile() {  # <input> <output> [extra uv args]
    local input="$1" output="$2"; shift 2
    "${uv[@]}" pip compile "${input}" \
        --output-file "${output}" \
        --universal \
        --python-version "${PYTHON_VERSION}" \
        --only-binary :all: \
        --generate-hashes \
        --custom-compile-command "bash .github/scripts/lock-requirements.sh" \
        --quiet \
        "$@"
}

# Package lines only: name==version and its environment marker.
pins() { grep -E '^[A-Za-z0-9]' "$1" | sed -E 's/ *\\$//'; }

if [ "${mode}" = "check" ]; then
    work="$(mktemp -d)"
    trap 'rm -rf "${work}"' EXIT
    cp requirements.txt requirements-dev.txt "${work}/"
    status=0
    # requirements-dev.in constrains itself with -c requirements.txt, so the
    # runtime lock is regenerated first and the dev lock against that.
    compile requirements.in requirements.txt
    compile requirements-dev.in requirements-dev.txt
    for f in requirements.txt requirements-dev.txt; do
        if ! diff -u <(pins "${work}/${f}") <(pins "${f}") > "${work}/${f}.diff"; then
            echo "::error file=backend/${f}::backend/${f} does not match its .in file. Run: bash .github/scripts/lock-requirements.sh"
            cat "${work}/${f}.diff"
            status=1
        fi
        cp "${work}/${f}" "${f}"
    done
    exit "${status}"
fi

extra=()
[ "${mode}" = "upgrade" ] && extra=(--upgrade)
compile requirements.in requirements.txt "${extra[@]}"
compile requirements-dev.in requirements-dev.txt "${extra[@]}"
echo "Wrote backend/requirements.txt and backend/requirements-dev.txt"
