import ast
import importlib.util
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / ".github" / "scripts" / "rollout_from.py"
UNSAFE_FOR_THE_PREVIOUS_RELEASE = ("drop_table", "drop_column", "alter_column", "rename", "unique=True",
                                   "nullable=False", "DROP ", "RENAME ", "UNIQUE", "NOT NULL", "DELETE ",
                                   "TRUNCATE", "create_unique_constraint", "create_foreign_key",
                                   "create_check_constraint", "create_primary_key")


def _script():
    spec = importlib.util.spec_from_file_location("rollout_from", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


rollout = _script()


def _marked_revisions():
    return [(revision, path) for revision, path in rollout.revision_files(REPO)
            if revision >= rollout.FIRST_MARKED_REVISION]


def _upgrade_source(path: Path) -> str:
    source = path.read_text(encoding="utf-8")
    upgrade = next(node for node in ast.parse(source).body
                   if isinstance(node, ast.FunctionDef) and node.name == "upgrade")
    return ast.get_source_segment(source, upgrade)


def test_the_anchor_revision_exists_and_needs_downtime():
    revisions = dict(rollout.revision_files(REPO))
    assert rollout.module_value(revisions[rollout.FIRST_MARKED_REVISION], "downtime") is True


@pytest.mark.parametrize("revision,path", _marked_revisions(), ids=lambda value: str(value))
def test_every_revision_from_the_anchor_says_whether_it_needs_downtime(revision, path):
    assert isinstance(rollout.module_value(path, "downtime"), bool), (
        f"{path.name}: set downtime = False when the previous release keeps working on the migrated database, "
        "downtime = True otherwise")


@pytest.mark.parametrize("revision,path", _marked_revisions(), ids=lambda value: str(value))
def test_a_revision_without_downtime_changes_nothing_the_previous_release_uses(revision, path):
    if rollout.module_value(path, "downtime") is not False:
        return
    upgrade = _upgrade_source(path)
    found = [word for word in UNSAFE_FOR_THE_PREVIOUS_RELEASE if word in upgrade]
    assert not found, f"{path.name} is marked downtime = False but its upgrade uses {found}"


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True).stdout


def _revision(repo: Path, number: str, previous: str, downtime) -> None:
    versions = repo / rollout.VERSIONS_DIR
    versions.mkdir(parents=True, exist_ok=True)
    marker = "" if downtime is None else f"downtime = {downtime}\n"
    (versions / f"{number}_change.py").write_text(
        f'revision = "{number}"\ndown_revision = "{previous}"\n{marker}\n\ndef upgrade():\n    pass\n',
        encoding="utf-8")


def _commit(repo: Path, message: str) -> None:
    _git(repo, "add", "-A")
    _git(repo, "-c", "user.name=test", "-c", "user.email=test@example.invalid", "commit", "-q", "-m", message)


@pytest.fixture
def repo(tmp_path):
    if shutil.which("git") is None:
        pytest.skip("git is not installed")
    _git(tmp_path, "init", "-q")
    _revision(tmp_path, "0032", "0031", None)
    _revision(tmp_path, "0033", "0032", True)
    _commit(tmp_path, "anchor")
    return tmp_path


def test_the_first_release_with_the_anchor_rolls_out_from_itself(repo):
    assert rollout.rollout_from(repo, "3.0.0") == "3.0.0"


def test_later_releases_keep_the_first_release_while_no_revision_needs_downtime(repo):
    _git(repo, "tag", "v3.0.0")
    _revision(repo, "0034", "0033", False)
    _commit(repo, "expand")
    _git(repo, "tag", "v3.0.1")
    assert rollout.rollout_from(repo, "3.0.2") == "3.0.0"


def test_a_new_revision_that_needs_downtime_makes_its_release_roll_out_from_itself(repo):
    _git(repo, "tag", "v3.0.0")
    _revision(repo, "0034", "0033", True)
    _commit(repo, "breaking")
    assert rollout.rollout_from(repo, "3.1.0") == "3.1.0"


def test_a_released_revision_that_needs_downtime_sets_the_value_to_its_first_release(repo):
    _git(repo, "tag", "v3.0.0")
    _revision(repo, "0034", "0033", True)
    _commit(repo, "breaking")
    _git(repo, "tag", "v3.1.0")
    _git(repo, "tag", "v3.0.9", "v3.0.0")
    assert rollout.rollout_from(repo, "3.1.1") == "3.1.0"


def test_a_release_tagged_on_a_squashed_copy_still_counts(repo):
    default = _git(repo, "rev-parse", "--abbrev-ref", "HEAD").strip()
    _git(repo, "checkout", "-q", "--orphan", "release")
    _commit(repo, "squashed release")
    _git(repo, "tag", "v3.0.0")
    _git(repo, "checkout", "-q", default)
    assert rollout.rollout_from(repo, "3.0.1") == "3.0.0"


def test_tags_that_are_not_releases_are_ignored(repo):
    _git(repo, "tag", "v3.0.0-rc.1")
    _git(repo, "tag", "build-3")
    assert rollout.rollout_from(repo, "3.0.0") == "3.0.0"
