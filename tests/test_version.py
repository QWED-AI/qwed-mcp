"""
Tests that the package version is consistent everywhere it is declared.
"""

import re
from pathlib import Path

import qwed_mcp
from qwed_mcp.server import create_server

ROOT = Path(__file__).resolve().parent.parent


def _pyproject_version():
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^version = "([^"]+)"', text, re.MULTILINE)
    assert match, "pyproject.toml has no static version"
    return match.group(1)


def test_package_version_matches_pyproject():
    assert qwed_mcp.__version__ == _pyproject_version()


def test_lockfile_records_the_same_version():
    lock = (ROOT / "uv.lock").read_text(encoding="utf-8")
    match = re.search(r'name = "qwed-mcp"\nversion = "([^"]+)"', lock)
    assert match, "uv.lock has no qwed-mcp entry"
    assert match.group(1) == _pyproject_version()


def test_server_reports_its_own_version():
    """Without an explicit version the MCP SDK reports its own package version."""
    options = create_server().create_initialization_options()
    assert options.server_name == "qwed-verification"
    assert options.server_version == qwed_mcp.__version__
