import argparse
import ast
import re
import subprocess
import sys
from pathlib import Path
from typing import Optional

VERSIONS_DIR = "backend/alembic/versions"
FIRST_MARKED_REVISION = "0033"
RELEASE_TAG = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")
VERSION = re.compile(r"^\d+\.\d+\.\d+$")


def module_value(path: Path, name: str):
    for node in ast.parse(path.read_text(encoding="utf-8")).body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
            return ast.literal_eval(node.value)
    return None


def revision_files(repo: Path) -> list:
    files = [(module_value(path, "revision"), path) for path in (repo / VERSIONS_DIR).glob("*.py")]
    return sorted((revision, path) for revision, path in files if revision)


def needs_downtime(revision: str, path: Path) -> bool:
    return revision < FIRST_MARKED_REVISION or module_value(path, "downtime") is True


def newest_downtime_revision(repo: Path) -> Path:
    return [path for revision, path in revision_files(repo) if needs_downtime(revision, path)][-1]


def first_release_with(repo: Path, relative_path: str) -> Optional[str]:
    tags = subprocess.run(["git", "-C", str(repo), "tag", "--list", "v*"],
                          check=True, capture_output=True, text=True).stdout.split()
    releases = sorted((tuple(int(part) for part in match.groups()), tag)
                      for tag in tags if (match := RELEASE_TAG.match(tag)))
    for version, tag in releases:
        found = subprocess.run(["git", "-C", str(repo), "cat-file", "-e", f"{tag}:{relative_path}"],
                               capture_output=True)
        if found.returncode == 0:
            return ".".join(str(part) for part in version)
    return None


def rollout_from(repo: Path, version: str) -> str:
    newest = newest_downtime_revision(repo)
    return first_release_with(repo, newest.relative_to(repo).as_posix()) or version


def main() -> int:
    parser = argparse.ArgumentParser(description="Print the oldest release that this release may run beside.")
    parser.add_argument("--version", required=True, help="The version being published, X.Y.Z")
    parser.add_argument("--repo", default=".", type=Path)
    args = parser.parse_args()
    if not VERSION.match(args.version):
        parser.error(f"--version must look like X.Y.Z, got {args.version!r}")
    value = rollout_from(args.repo.resolve(), args.version)
    if not VERSION.match(value):
        print(f"rollout-from is {value!r}, not X.Y.Z", file=sys.stderr)
        return 1
    print(value)
    return 0


if __name__ == "__main__":
    sys.exit(main())
