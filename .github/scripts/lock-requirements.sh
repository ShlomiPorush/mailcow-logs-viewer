#!/usr/bin/env bash
# Generate the hash-pinned Python lock files from their inputs:
#
#   backend/requirements.in      ->  backend/requirements.txt      (the image)
#   backend/requirements-dev.in  ->  backend/requirements-dev.txt  (CI, local tests)
#   website/requirements.in      ->  website/requirements.txt      (docs.yml)
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
# The locks are universal (Linux amd64/arm64 for the image and CI, plus macOS
# and Windows for local work) for the Python version each one is installed
# with: 3.11 for the image, 3.12 for the documentation site. They only admit
# packages that publish wheels: everything installs with --only-binary, so no
# sdist and no build backend is ever fetched or run.
#
# --check compares package versions, not hashes. PyPI can add a wheel to an
# existing release (a new platform), which would change the hash list without
# anything being wrong. A hash that does not match is caught where it matters:
# pip --require-hashes refuses the download.
set -euo pipefail

UV_VERSION="0.13.10"

# <directory> <input> <lock file> <Python version>, in order: the dev lock is
# constrained by the runtime lock (-c requirements.txt), so it comes after it.
LOCKS=(
    "backend requirements.in requirements.txt 3.11"
    "backend requirements-dev.in requirements-dev.txt 3.11"
    "website requirements.in requirements.txt 3.12"
)

mode="write"
case "${1:-}" in
    "") ;;
    --check) mode="check" ;;
    --upgrade) mode="upgrade" ;;
    *) echo "usage: $0 [--check|--upgrade]" >&2; exit 2 ;;
esac

root="$(git rev-parse --show-toplevel)"

# Same uv as CI, so a local run and the CI check produce the same file.
if command -v uv >/dev/null 2>&1 && [ "$(uv --version | cut -d' ' -f2)" = "${UV_VERSION}" ]; then
    uv=(uv)
else
    uv=(uvx "uv@${UV_VERSION}")
fi

compile() {  # <input> <output> <Python version> [extra uv args]
    local input="$1" output="$2" python="$3"; shift 3
    "${uv[@]}" pip compile "${input}" \
        --output-file "${output}" \
        --universal \
        --python-version "${python}" \
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
    for entry in "${LOCKS[@]}"; do
        read -r dir input lock python <<< "${entry}"
        name="${dir}/${lock}"
        fresh="${work}/${dir}-${lock}"
        cp "${root}/${name}" "${fresh}"
        # A stale runtime lock would otherwise surface as an unsolvable dev
        # resolution: the dev input is constrained by the committed runtime lock.
        if ! (cd "${root}/${dir}" && compile "${input}" "${fresh}" "${python}") 2> "${fresh}.err"; then
            echo "::error file=${name}::${name} does not match ${dir}/${input}. Run: bash .github/scripts/lock-requirements.sh"
            cat "${fresh}.err"
            exit 1
        fi
        if ! diff -u <(pins "${root}/${name}") <(pins "${fresh}"); then
            echo "::error file=${name}::${name} does not match ${dir}/${input}. Run: bash .github/scripts/lock-requirements.sh"
            exit 1
        fi
    done
    exit 0
fi

extra=()
[ "${mode}" = "upgrade" ] && extra=(--upgrade)
for entry in "${LOCKS[@]}"; do
    read -r dir input lock python <<< "${entry}"
    (cd "${root}/${dir}" && compile "${input}" "${lock}" "${python}" "${extra[@]}")
    echo "Wrote ${dir}/${lock}"
done
