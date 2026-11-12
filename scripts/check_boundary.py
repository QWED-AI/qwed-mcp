#!/usr/bin/env python3
"""Lightweight boundary check for QWED-MCP regression patterns.

Scans source files for forbidden patterns that have historically led to
CWE-95 / CWE-94 / CWE-78 vulnerabilities. This is a release gate, not a
replacement for proper security review.
"""

import ast
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
# Directories never scanned, matched against repo-root-relative path parts
# only, so the checkout location cannot remove files from the scan (#65).
EXCLUDED_DIRS = {".git", ".venv", "venv", "__pycache__", ".mypy_cache", ".pytest_cache"}

# Approved wrapper paths (relative to repo root)
APPROVED_WRAPPER_PATHS = {
    "src/qwed_mcp/engines/safe_parser.py",
}

# Full call names that are forbidden outside approved wrappers (dotted names)
FORBIDDEN_CALLS = {
    "os.system",
    "os.popen",
    "subprocess.Popen",
    "subprocess.call",
    "subprocess.run",
    "subprocess.check_call",
    "subprocess.check_output",
    "popen",
}


def get_call_names(node: ast.Call) -> list[str]:
    names = []
    if isinstance(node.func, ast.Name):
        names.append(node.func.id)
    elif isinstance(node.func, ast.Attribute):
        parts = []
        current = node.func
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
            names.append(".".join(reversed(parts)))
        # Chained call like get_runner().run(...) → skip, not a bare call
    return names


def _build_alias_map(tree: ast.Module) -> dict[str, str]:
    alias_map = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname or alias.name
                alias_map[local] = alias.name
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                if alias.name == "*":
                    if module == "subprocess":
                        for call in FORBIDDEN_CALLS:
                            if call.startswith("subprocess."):
                                alias_map[call.split(".", 1)[1]] = call
                    elif module == "os":
                        alias_map["system"] = "os.system"
                        alias_map["popen"] = "os.popen"
                    elif module == "builtins":
                        alias_map["eval"] = "builtins.eval"
                        alias_map["exec"] = "builtins.exec"
                    continue
                local = alias.asname or alias.name
                full = f"{module}.{alias.name}" if module else alias.name
                alias_map[local] = full
    return alias_map


def _shell_true_errors(node: ast.Call, relpath: str) -> list[str]:
    if any(
        keyword.arg == "shell"
        and isinstance(keyword.value, ast.Constant)
        and keyword.value.value is True
        for keyword in node.keywords
    ):
        return [f"  [SHELL_TRUE] {relpath}:{node.lineno}: Disallowed shell=True argument"]
    return []


def _resolve(name: str, alias_map: dict[str, str]) -> str:
    """The dotted name a call resolves to through import aliases."""
    resolved = alias_map.get(name, name)
    # Resolve module aliases in dotted names: import subprocess as sp; sp.run()
    if resolved == name and "." in name:
        module, rest = name.split(".", 1)
        if module in alias_map:
            resolved = f"{alias_map[module]}.{rest}"
    return resolved


def _call_name_errors(name: str, resolved: str, relpath: str, line: int) -> list[str]:
    leaf = resolved.split(".")[-1]
    errors = []
    # bare eval/exec, or through builtins: always dangerous
    if leaf in {"eval", "exec"} and (
        "." not in resolved or resolved.startswith(("builtins.", "__builtins__."))
    ):
        errors.append(
            f"  [BARE_EVAL] {relpath}:{line}: "
            f"Disallowed call '{name}()' \u2014 use approved wrappers"
        )
    # parse_expr: flag both bare and qualified (sympy.parse_expr etc.)
    if leaf == "parse_expr":
        errors.append(
            f"  [BARE_PARSE_EXPR] {relpath}:{line}: "
            f"Disallowed call '{name}()' \u2014 use approved wrappers"
        )
    # os.system, subprocess.*, popen (dotted or alias-resolved names)
    if resolved in FORBIDDEN_CALLS:
        errors.append(
            f"  [BARE_SHELL] {relpath}:{line}: "
            f"Disallowed call '{name}()' \u2014 use safe_shell() or approved wrapper"
        )
    return errors


def check_file(filepath: Path, repo_root: Path = REPO_ROOT) -> list[str]:
    relpath = filepath.relative_to(repo_root).as_posix()
    try:
        tree = ast.parse(filepath.read_text(encoding="utf-8"))
    except SyntaxError as exc:
        return [
            f"  [PARSE_ERROR] {relpath}:{exc.lineno}: "
            "File could not be parsed; boundary check must fail closed"
        ]
    if relpath in APPROVED_WRAPPER_PATHS:
        return []

    alias_map = _build_alias_map(tree)
    errors = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        # shell=True is checked on every call node, even unresolvable ones
        errors.extend(_shell_true_errors(node, relpath))
        for name in get_call_names(node):
            errors.extend(
                _call_name_errors(name, _resolve(name, alias_map), relpath, node.lineno)
            )
    return errors


def python_files(repo_root: Path) -> list[str]:
    """Repo-relative paths of every Python file under the repository root,
    skipping EXCLUDED_DIRS. The names are matched against path parts below
    the root only, so the checkout location cannot remove files (#65)."""
    def fail(error: OSError) -> None:
        # os.walk skips a directory it cannot read unless told otherwise; a
        # skipped directory would let the gate pass without scanning it.
        raise error

    found = []
    for directory, subdirs, filenames in os.walk(repo_root, onerror=fail):
        subdirs[:] = sorted(d for d in subdirs if d not in EXCLUDED_DIRS)
        relative_dir = Path(directory).relative_to(repo_root)
        found.extend(
            (relative_dir / filename).as_posix()
            for filename in filenames
            if filename.endswith(".py")
        )
    return found


def select_files(repo_root: Path, entries: list[str]) -> list[Path]:
    """The listed files to scan: every one whose repo-relative path has no
    excluded directory in it (#65)."""
    return sorted(
        repo_root / entry
        for entry in entries
        if not any(part in EXCLUDED_DIRS for part in Path(entry).parts)
    )


_FAILED = " QWED Boundary check FAILED"


def main(repo_root: Path = REPO_ROOT, list_files=python_files) -> int:
    try:
        pyfiles = select_files(repo_root, list_files(repo_root))
    except (OSError, RuntimeError) as exc:
        print(_FAILED)
        print(f"  [CONFIG_ERROR] Could not list files: {exc}")
        return 1

    if not pyfiles:
        print(_FAILED)
        print("  [CONFIG_ERROR] No Python files found to scan")
        return 1

    errors: list[str] = []
    for pyfile in pyfiles:
        errors.extend(check_file(pyfile, repo_root))

    if errors:
        print(_FAILED)
        for err in errors:
            print(err)
        return 1

    print(f" QWED Boundary check passed ({len(pyfiles)} files scanned)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
