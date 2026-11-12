"""Every third-party module the package imports is a declared dependency,
and every declared dependency is imported or is a documented version floor
(#44, #64)."""

import ast
import re
import sys
from importlib.metadata import (
    PackageNotFoundError,
    distribution,
    packages_distributions,
)
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Declared only to raise the minimum version of a package mcp already
# installs (see the comment in pyproject.toml).
VERSION_FLOORS = {"cryptography", "pyjwt"}


def _normalise(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _declared(path: Path) -> set:
    text = path.read_text(encoding="utf-8")
    block = re.search(r"^dependencies = \[(.*?)^\]", text, re.M | re.S).group(1)
    return {
        _normalise(re.match(r"[A-Za-z0-9_.-]+", entry).group(0))
        for entry in re.findall(r'"([^"]+)"', block)
    }


def _imported_top_level_modules() -> set:
    modules = set()
    for path in (ROOT / "src").rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import):
                modules.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                modules.add(node.module.split(".")[0])
    return modules


def _distributions_of(module: str, mapping: dict) -> list:
    """The installed distributions providing ``module``. Some installers
    leave a distribution out of packages_distributions(), so a distribution
    named after the module is accepted too."""
    if module in mapping:
        return mapping[module]
    try:
        return [distribution(module).metadata["Name"]]
    except PackageNotFoundError:
        raise AssertionError(f"'{module}' is imported but not installed") from None


def _third_party_distributions() -> set:
    mapping = packages_distributions()
    distributions = set()
    for module in _imported_top_level_modules():
        if module in sys.stdlib_module_names or module == "qwed_mcp":
            continue
        distributions.update(
            _normalise(name) for name in _distributions_of(module, mapping)
        )
    return distributions


def test_every_imported_package_is_declared():
    declared = _declared(ROOT / "pyproject.toml")
    missing = _third_party_distributions() - declared
    assert not missing, f"imported but not declared: {sorted(missing)}"


def test_every_declared_package_is_imported_or_a_version_floor():
    declared = _declared(ROOT / "pyproject.toml")
    unused = declared - _third_party_distributions() - VERSION_FLOORS
    assert not unused, f"declared but never imported: {sorted(unused)}"


def test_requirements_txt_matches_pyproject():
    requirements = {
        _normalise(re.match(r"[A-Za-z0-9_.-]+", line).group(0))
        for line in (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    }
    assert requirements == _declared(ROOT / "pyproject.toml")
