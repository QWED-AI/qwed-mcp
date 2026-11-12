"""The boundary gate scans every tracked Python file and fails closed (#65).

The gate lists files with `git ls-files`; these tests pass it a fixed
listing instead, so they need no git repository.
"""

import importlib.util
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "check_boundary.py"


def _load_gate():
    spec = importlib.util.spec_from_file_location("check_boundary_under_test", _SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CLEAN = "def add(a, b):\n    return a + b\n"
SHELL = "import os\nos.system('marker-not-run')\n"


def _tree(root: Path, files: dict) -> Path:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def _run(root: Path, tracked: list) -> int:
    gate = _load_gate()
    return gate.main(repo_root=root, list_files=lambda _root: list(tracked))


@pytest.mark.parametrize(
    "path",
    ["tests/test_violation.py", "scripts/tooling.py", "examples/evil.py", "root.py"],
)
def test_violation_outside_src_fails(tmp_path, path):
    root = _tree(tmp_path, {"src/pkg/clean.py": CLEAN, path: SHELL})
    assert _run(root, ["src/pkg/clean.py", path]) == 1


def test_clean_tree_passes(tmp_path):
    root = _tree(tmp_path, {"src/pkg/clean.py": CLEAN})
    assert _run(root, ["src/pkg/clean.py"]) == 0


def test_no_python_files_fails(tmp_path):
    assert _run(tmp_path, []) == 1


def test_listing_failure_fails(tmp_path):
    gate = _load_gate()

    def broken(_root):
        raise RuntimeError("not a git repository")

    assert gate.main(repo_root=tmp_path, list_files=broken) == 1


def test_checkout_under_an_excluded_name_is_still_scanned(tmp_path):
    root = _tree(tmp_path / "venv" / "repo", {"src/pkg/bad.py": SHELL})
    assert _run(root, ["src/pkg/bad.py"]) == 1


def test_excluded_directory_inside_the_repository_is_skipped(tmp_path):
    root = _tree(tmp_path, {"src/pkg/clean.py": CLEAN, ".venv/lib/x.py": SHELL})
    assert _run(root, ["src/pkg/clean.py", ".venv/lib/x.py"]) == 0


def test_this_repository_passes():
    gate = _load_gate()
    assert gate.main() == 0
