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

FORBIDDEN_PATTERNS: list[tuple[str, str, str]] = [
    ("BARE_PARSE_EXPR", r"(?<!safe_)(?:from sympy.*import.*parse_expr|parse_expr\s*\()",
     "Use safe_parse_expr() instead of bare parse_expr()"),
    ("BARE_EVAL", r"(?<!safe_)(?<!\w)(?:eval|exec)\s*\(",
     "Use approved evaluation wrappers instead of raw eval/exec"),
]

DENYLISTED_CALLS = {"eval", "exec", "compile", "parse_expr", "__import__"}


def check_regex_forbidden(filepath: Path) -> list[str]:
    errors = []
    content = filepath.read_text(encoding="utf-8")
    for tag, pattern, message in FORBIDDEN_PATTERNS:
        if re.search(pattern, content):
            errors.append(f"  [{tag}] {filepath.relative_to(REPO_ROOT)}: {message}")
    return errors


def check_ast_forbidden(filepath: Path) -> list[str]:
    errors = []
    try:
        tree = ast.parse(filepath.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id in DENYLISTED_CALLS:
                    errors.append(
                        f"  [AST_DENY] {filepath.relative_to(REPO_ROOT)}:{node.lineno}: "
                        f"Call to '{node.func.id}' is not allowed"
                    )
    except SyntaxError:
        pass
    return errors


def main() -> int:
    errors: list[str] = []
    for pyfile in sorted(SRC_DIR.rglob("*.py")):
        errors.extend(check_regex_forbidden(pyfile))
        errors.extend(check_ast_forbidden(pyfile))

    if errors:
        print("❌ QWED Boundary check FAILED")
        for err in errors:
            print(err)
        return 1

    print("✅ QWED Boundary check passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
