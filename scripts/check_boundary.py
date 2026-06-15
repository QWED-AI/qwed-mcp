#!/usr/bin/env python3
"""Lightweight boundary check for QWED-MCP regression patterns.

Scans source files for forbidden patterns that have historically led to
CWE-95 / CWE-94 / CWE-78 vulnerabilities. This is a release gate, not a
replacement for proper security review.
"""

import ast
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"

# Files that are intentionally exempt because they ARE the approved boundary
APPROVED_WRAPPER_FILES = {
    "safe_parser.py",
}


def get_call_names(node: ast.Call) -> list[str]:
    """Extract full dotted call name(s) from a Call node."""
    names = []

    # Direct call: eval(...)
    if isinstance(node.func, ast.Name):
        names.append(node.func.id)

    # Attribute call: os.system(...)
    elif isinstance(node.func, ast.Attribute):
        parts = []
        current = node.func
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        elif isinstance(current, ast.Call):
            return names
        names.append(".".join(reversed(parts)))

    return names


def check_file(filepath: Path) -> list[str]:
    errors = []
    try:
        tree = ast.parse(filepath.read_text(encoding="utf-8"))
    except SyntaxError:
        return errors

    filename = filepath.name

    for node in ast.walk(tree):
        # Only flag actual Call nodes, not string literals in sets/lists
        if not isinstance(node, ast.Call):
            continue

        call_names = get_call_names(node)

        # Check for bare parse_expr (not inside the approved wrapper)
        if "parse_expr" in call_names and filename not in APPROVED_WRAPPER_FILES:
            errors.append(
                f"  [BARE_PARSE_EXPR] {filepath.relative_to(REPO_ROOT)}:{node.lineno}: "
                f"Use safe_parse_expr() instead of bare parse_expr()"
            )

        # Check for bare eval/exec calls (not string definitions)
        for name in call_names:
            if name in {"eval", "exec"}:
                errors.append(
                    f"  [BARE_EVAL] {filepath.relative_to(REPO_ROOT)}:{node.lineno}: "
                    f"Call to '{name}()' is not allowed — use approved wrappers"
                )

    return errors


def main() -> int:
    errors: list[str] = []
    for pyfile in sorted(SRC_DIR.rglob("*.py")):
        errors.extend(check_file(pyfile))

    if errors:
        print(" QWED Boundary check FAILED")
        for err in errors:
            print(err)
        return 1

    print(" QWED Boundary check passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
