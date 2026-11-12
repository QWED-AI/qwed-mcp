#!/usr/bin/env python3
"""Lightweight boundary check for QWED-MCP regression patterns.

Scans source files for forbidden patterns that have historically led to
CWE-95 / CWE-94 / CWE-78 vulnerabilities. This is a release gate, not a
replacement for proper security review.
"""

import ast
import subprocess  # nosec B404 - runs git with a fixed argument list
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
# Directories never scanned, matched against repo-root-relative path parts
# only, so the checkout location cannot remove files from the scan (#65).
EXCLUDED_DIRS = {".git", ".venv", "venv", "__pycache__", ".mypy_cache", ".pytest_cache"}

# Approved wrapper paths (relative to repo root)
APPROVED_WRAPPER_PATHS = {
    "src/qwed_mcp/engines/safe_parser.py",
    # The gate itself runs `git ls-files` with a fixed argument list.
    "scripts/check_boundary.py",
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


def check_file(filepath: Path, repo_root: Path = REPO_ROOT) -> list[str]:
    errors = []
    try:
        tree = ast.parse(filepath.read_text(encoding="utf-8"))
    except SyntaxError as exc:
        errors.append(
            f"  [PARSE_ERROR] {filepath.relative_to(repo_root)}:{exc.lineno}: "
            "File could not be parsed; boundary check must fail closed"
        )
        return errors

    relpath = filepath.relative_to(repo_root).as_posix()
    in_wrapper = relpath in APPROVED_WRAPPER_PATHS
    alias_map = _build_alias_map(tree)

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        # Check for shell=True on every call node, even unresolvable ones
        if not in_wrapper and any(
            keyword.arg == "shell"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is True
            for keyword in node.keywords
        ):
            errors.append(
                f"  [SHELL_TRUE] {relpath}:{node.lineno}: "
                "Disallowed shell=True argument"
            )

        call_names = get_call_names(node)
        if not call_names:
            continue

        for name in call_names:
            resolved = alias_map.get(name, name)

            # Resolve module aliases in dotted names
            # e.g. import subprocess as sp; sp.run(...)
            if resolved == name and "." in name:
                parts = name.split(".", 1)
                resolved_module = alias_map.get(parts[0])
                if resolved_module is not None:
                    resolved = f"{resolved_module}.{parts[1]}"

            leaf = resolved.split(".")[-1]

            # bare eval/exec → always dangerous
            if leaf in {"eval", "exec"} and not in_wrapper:
                if "." not in resolved or resolved.startswith("builtins.") or resolved.startswith("__builtins__."):
                    errors.append(
                        f"  [BARE_EVAL] {relpath}:{node.lineno}: "
                        f"Disallowed call '{name}()' \u2014 use approved wrappers"
                    )

            # parse_expr: flag both bare and qualified (sympy.parse_expr etc.)
            if leaf == "parse_expr" and not in_wrapper:
                errors.append(
                    f"  [BARE_PARSE_EXPR] {relpath}:{node.lineno}: "
                    f"Disallowed call '{name}()' \u2014 use approved wrappers"
                )

            # os.system, subprocess.*, popen (dotted or alias-resolved names)
            if resolved in FORBIDDEN_CALLS and not in_wrapper:
                errors.append(
                    f"  [BARE_SHELL] {relpath}:{node.lineno}: "
                    f"Disallowed call '{name}()' \u2014 use safe_shell() or approved wrapper"
                )

    return errors


def git_ls_python_files(repo_root: Path) -> list[str]:
    """Repo-relative paths of the Python files git tracks.

    Raises RuntimeError when git cannot list them, so the check fails closed
    instead of scanning nothing.
    """
    result = subprocess.run(  # nosec B603 B607 - fixed argument list
        ["git", "ls-files", "-z", "--", "*.py"],
        cwd=repo_root,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.decode(errors="replace").strip())
    return [entry for entry in result.stdout.decode().split("\0") if entry]


def select_files(repo_root: Path, entries: list[str]) -> list[Path]:
    """The listed files to scan: every one whose repo-relative path has no
    excluded directory in it (#65)."""
    files = []
    for entry in entries:
        relative = Path(entry)
        if any(part in EXCLUDED_DIRS for part in relative.parts):
            continue
        files.append(repo_root / relative)
    return sorted(files)


def main(repo_root: Path = REPO_ROOT, list_files=git_ls_python_files) -> int:
    errors: list[str] = []

    try:
        pyfiles = select_files(repo_root, list_files(repo_root))
    except (OSError, RuntimeError) as exc:
        print(" QWED Boundary check FAILED")
        print(f"  [CONFIG_ERROR] Could not list tracked files: {exc}")
        return 1

    if not pyfiles:
        print(" QWED Boundary check FAILED")
        print("  [CONFIG_ERROR] No Python files found to scan")
        return 1

    for pyfile in pyfiles:
        errors.extend(check_file(pyfile, repo_root))

    if errors:
        print(" QWED Boundary check FAILED")
        for err in errors:
            print(err)
        return 1

    print(f" QWED Boundary check passed ({len(pyfiles)} files scanned)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
