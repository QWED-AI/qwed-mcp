"""
Tests that the package version is consistent everywhere it is declared.
"""

import re
from pathlib import Path

import pytest
from packaging.requirements import Requirement

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
    lock_path = ROOT / "uv.lock"
    if not lock_path.exists():
        pytest.skip("uv.lock is not shipped in the sdist")
    lock = lock_path.read_text(encoding="utf-8")
    match = re.search(r'name = "qwed-mcp"\nversion = "([^"]+)"', lock)
    assert match, "uv.lock has no qwed-mcp entry"
    assert match.group(1) == _pyproject_version()


def test_server_reports_its_own_version():
    """Without an explicit version the MCP SDK reports its own package version."""
    options = create_server().create_initialization_options()
    assert options.server_name == "qwed-verification"
    assert options.server_version == qwed_mcp.__version__


@pytest.mark.parametrize("path", ["pyproject.toml", "requirements.txt"])
def test_mcp_requirement_stays_on_1x(path):
    """MCP SDK 2.x removed Server.list_tools and Server.call_tool, which register_tools uses."""
    file_path = ROOT / path
    if not file_path.exists():
        pytest.skip(f"{path} is not shipped in the sdist")
    text = file_path.read_text(encoding="utf-8")
    match = re.search(r'^\s*"?(mcp[<>=!~][^"\n]*)"?,?\s*$', text, re.MULTILINE)
    assert match, f"{path} declares no mcp requirement"
    spec = Requirement(match.group(1)).specifier
    assert "1.30.0" in spec
    assert "1.29.1" not in spec
    assert "2.0.0" not in spec
