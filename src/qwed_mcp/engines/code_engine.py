"""
Code Security Verification Engine

Python code is admitted only when every module, builtin and attribute it uses
is on an allowlist (see ``python_allowlist``). JavaScript is pattern-scanned
only and is never admitted.
"""

import ast
import codecs
import re
import logging
from typing import List

from .python_allowlist import admission_issues

logger = logging.getLogger("qwed-mcp.engines.code")

# Dangerous patterns for JavaScript, as regular expressions. Compiled when the
# module loads, so a pattern that does not compile fails at import and cannot
# ship silently (#61).
DANGEROUS_JS_PATTERNS = [
    re.escape("eval("),
    re.escape("Function("),
    r"setTimeout\s*\(\s*['\"`]",
    r"setInterval\s*\(\s*['\"`]",
    re.escape("document.write"),
    re.escape("innerHTML"),
    re.escape("outerHTML"),
]
_COMPILED_JS_PATTERNS = [
    (pattern, re.compile(pattern, re.IGNORECASE)) for pattern in DANGEROUS_JS_PATTERNS
]

JAVASCRIPT_NOT_ADMITTED = (
    "JavaScript is only pattern-scanned, so it is never admitted: "
    "no assurance produced"
)

# SQL injection patterns
SQL_INJECTION_PATTERNS = [
    r"'\s*OR\s+'1'\s*=\s*'1",
    r"'\s*OR\s+1\s*=\s*1",
    r";\s*DROP\s+TABLE",
    r";\s*DELETE\s+FROM",
    r";\s*INSERT\s+INTO",
    r"--",
    r"/\*.*\*/",
    r"UNION\s+SELECT",
]


def verify_code_safety(code: str, language: str) -> dict:
    """
    Verify code for security issues.

    Args:
        code: The code to analyze
        language: Programming language ("python", "javascript", "sql")

    Returns:
        Verification result with security issues if any. ``verified`` is True
        only when the code was analysed and admitted.
    """
    if not isinstance(code, str) or not code.strip():
        return {
            "verified": False,
            "message": "Empty code: nothing was analysed, no assurance produced",
            "issues": ["Code is empty or whitespace only"],
        }
    if not isinstance(language, str):
        return {
            "verified": False,
            "message": f"Unsupported language: {language!r}",
            "issues": [f"Language {language!r} is not supported"],
        }

    language = language.lower()
    if language == "python":
        issues = analyze_python(code)
    elif language == "javascript":
        return {
            "verified": False,
            "message": JAVASCRIPT_NOT_ADMITTED,
            "issues": analyze_javascript(code) + [JAVASCRIPT_NOT_ADMITTED],
        }
    elif language == "sql":
        issues = analyze_sql(code)
    else:
        return {
            "verified": False,
            "message": f"Unsupported language: {language}",
            "issues": [f"Language '{language}' is not supported"],
        }

    if issues:
        return {
            "verified": False,
            "message": f"Found {len(issues)} security issue(s)",
            "issues": issues,
        }
    return {
        "verified": True,
        "message": "No security issues detected",
        "issues": [],
    }


# PEP 263 coding declaration: a comment line naming a codec.
_CODING_DECLARATION = re.compile(r"^[ \t\f]*#.*?coding[:=][ \t]*([-\w.]+)")


def _candidate_lines(code: str) -> set:
    """The first two lines of ``code`` under each way of splitting it.

    The interpreter reads a declaration only on the first two lines of the
    file. str.splitlines() breaks lines at characters (form feed, U+001C to
    U+001E, U+2028) where the tokenizer does not, and a lone carriage return
    may or may not end a line, so the first two lines are taken under each
    split and all of them are checked.
    """
    lines = set(code.splitlines()[:2])
    lines.update(code.split("\n")[:2])
    lines.update(re.split(r"\r\n|\r|\n", code)[:2])
    return lines


def _source_encoding_issues(code: str) -> List[str]:
    """Refuse a source encoding declaration other than UTF-8.

    The checks below read ``code`` as text, but the interpreter decodes the
    script file it is written to by its coding declaration. Under any other
    codec the code that runs would not be the code that was checked.
    """
    for line in sorted(_candidate_lines(code)):
        match = _CODING_DECLARATION.match(line)
        if not match:
            continue
        try:
            codec = codecs.lookup(match.group(1)).name
        except LookupError:
            codec = ""
        if codec != "utf-8":
            return [
                f"Source encoding declaration '{match.group(1)}' is not admitted "
                "(only UTF-8)"
            ]
    return []


def analyze_python(code: str) -> List[str]:
    """Why Python ``code`` is not admitted; an empty list when it is."""
    encoding_issues = _source_encoding_issues(code)
    if encoding_issues:
        return encoding_issues
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        return [f"Syntax error in code: {e}"]
    except (ValueError, RecursionError, MemoryError) as e:
        return [f"Code could not be parsed: {type(e).__name__}"]
    if not tree.body:
        return ["Code has no statements: nothing was analysed, no assurance produced"]

    try:
        issues = admission_issues(tree)
    except RecursionError:
        return ["Code is nested too deeply to analyse"]
    # Keep the order stable and drop repeats.
    return list(dict.fromkeys(issues))


def analyze_javascript(code: str) -> List[str]:
    """Pattern findings for JavaScript. Finding none is not an assurance."""
    issues = [
        f"Dangerous pattern detected: {pattern}"
        for pattern, compiled in _COMPILED_JS_PATTERNS
        if compiled.search(code)
    ]

    if re.search(r"innerHTML\s*=", code):
        issues.append("Potential XSS: Direct innerHTML assignment")

    if re.search(r"document\.write\s*\(", code):
        issues.append("Potential XSS: document.write usage")

    return issues


def analyze_sql(code: str) -> List[str]:
    """Analyze SQL for injection vulnerabilities."""
    issues = []

    for pattern in SQL_INJECTION_PATTERNS:
        if re.search(pattern, code, re.IGNORECASE):
            issues.append(f"Potential SQL injection: Pattern '{pattern}' detected")

    # Check for string concatenation patterns (common in injection)
    if re.search(r"\+\s*['\"]", code) or re.search(r"['\"\s]\+", code):
        issues.append("Warning: String concatenation in SQL query detected")

    return list(set(issues))
