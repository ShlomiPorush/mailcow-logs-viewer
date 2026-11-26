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
    # Regenerate into a temporary directory and compare; the lock files in the
    # repository are never written, so an interrupted check cannot leave them
    # changed. Each fresh file starts from a copy of the committed one, which
    # uv keeps as its preference, exactly as in a normal run.
    work="$(mktemp -d)"
    trap 'rm -rf "${work}"' EXIT
    cp requirements.txt requirements-dev.txt "${work}/"
    stale() {
        echo "::error file=backend/$1::backend/$1 does not match its .in file. Run: bash .github/scripts/lock-requirements.sh"
    }
    check() {  # <input> <lock file>
        if ! compile "$1" "${work}/$2" 2> "${work}/$2.err"; then
            stale "$2"; cat "${work}/$2.err"; exit 1
        fi
        if ! diff -u <(pins "$2") <(pins "${work}/$2"); then
            stale "$2"; exit 1
        fi
    }
    # The runtime lock first: requirements-dev.in constrains itself with
    # -c requirements.txt (the committed file), so a stale runtime lock would
    # otherwise surface as an unsolvable dev resolution.
    check requirements.in requirements.txt
    check requirements-dev.in requirements-dev.txt
    exit 0
fi

extra=()
[ "${mode}" = "upgrade" ] && extra=(--upgrade)
compile requirements.in requirements.txt "${extra[@]}"
compile requirements-dev.in requirements-dev.txt "${extra[@]}"
echo "Wrote backend/requirements.txt and backend/requirements-dev.txt"
