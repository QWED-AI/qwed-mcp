"""
Code Security Verification Engine

Uses AST analysis for detecting dangerous patterns.
"""

import ast
import re
import logging
from typing import List

logger = logging.getLogger("qwed-mcp.engines.code")

_DANGEROUS_IMPORT_MODULES = {"subprocess"}
_DANGEROUS_IMPORTED_MEMBERS = {
    ("os", "system"),
    ("os", "popen"),
    ("pickle", "loads"),
    ("marshal", "loads"),
}
_DANGEROUS_CALLS = {
    "eval",
    "exec",
    "compile",
    "open",
    "__import__",
    "os.system",
    "os.popen",
    "pickle.loads",
    "marshal.loads",
}
_DANGEROUS_BARE_NAMES = {"__import__"}

# Dangerous patterns for Python
DANGEROUS_PYTHON_PATTERNS = [
    "eval",
    "exec",
    "__import__",
    "compile",
    "os.system",
    "os.popen",
    "subprocess",
    "pickle.loads",
    "marshal.loads",
]

# Dangerous patterns for JavaScript
DANGEROUS_JS_PATTERNS = [
    "eval(",
    "Function(",
    "setTimeout(.*string",
    "setInterval(.*string",
    "document.write",
    "innerHTML",
    "outerHTML",
]

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


def verify_code_safety(
    code: str,
    language: str
) -> dict:
    """
    Verify code for security issues using AST analysis.
    
    Args:
        code: The code to analyze
        language: Programming language ("python", "javascript", "sql")
    
    Returns:
        Verification result with security issues if any
    """
    issues = []
    
    if language.lower() == "python":
        issues = analyze_python(code)
    elif language.lower() == "javascript":
        issues = analyze_javascript(code)
    elif language.lower() == "sql":
        issues = analyze_sql(code)
    else:
        return {
            "verified": False,
            "message": f"Unsupported language: {language}",
            "issues": [f"Language '{language}' is not supported"]
        }
    
    if issues:
        return {
            "verified": False,
            "message": f"Found {len(issues)} security issue(s)",
            "issues": issues
        }
    else:
        return {
            "verified": True,
            "message": "No security issues detected",
            "issues": []
        }


def analyze_python(code: str) -> List[str]:
    """Analyze Python code for security issues."""
    issues = []
    ast_parsed_successfully = False
    module_aliases: dict[str, str] = {}
    imported_name_aliases: dict[str, str] = {}
    
    # Try AST analysis
    try:
        tree = ast.parse(code)
        ast_parsed_successfully = True

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported_name = alias.name
                    alias_name = alias.asname or imported_name.split(".")[0]
                    module_aliases[alias_name] = imported_name
                    if any(
                        imported_name == module
                        or imported_name.startswith(f"{module}.")
                        for module in _DANGEROUS_IMPORT_MODULES
                    ):
                        issues.append(
                            f"Dangerous import detected: {imported_name}"
                        )

            if isinstance(node, ast.ImportFrom):
                module_name = node.module or ""
                if any(
                    module_name == module
                    or module_name.startswith(f"{module}.")
                    for module in _DANGEROUS_IMPORT_MODULES
                ):
                    issues.append(
                        f"Dangerous import detected: from {module_name} import ..."
                    )
                for alias in node.names:
                    alias_name = alias.asname or alias.name
                    imported_name_aliases[alias_name] = f"{module_name}.{alias.name}"
                    if (module_name, alias.name) in _DANGEROUS_IMPORTED_MEMBERS:
                        issues.append(
                            f"Dangerous import detected: from {module_name} import {alias.name}"
                        )
        
        for node in ast.walk(tree):
            # Check for dangerous function calls
            if isinstance(node, ast.Call):
                resolved_name = resolve_call_name(
                    node.func,
                    module_aliases=module_aliases,
                    imported_name_aliases=imported_name_aliases,
                )
                if _is_dangerous_call_name(resolved_name):
                    issues.append(f"Dangerous function call: {resolved_name}()")

            if isinstance(node, ast.Name) and node.id in _DANGEROUS_BARE_NAMES:
                issues.append(f"Dangerous name reference detected: {node.id}")
                
    except SyntaxError as e:
        issues.append(f"Syntax error in code: {e}")
    
    # Fall back to raw pattern checks only if AST parsing failed.
    if not ast_parsed_successfully:
        for pattern in DANGEROUS_PYTHON_PATTERNS:
            if pattern in code:
                issues.append(f"Potentially dangerous pattern: {pattern}")

        if re.search(r"\bopen\s*\(", code):
            issues.append("Potentially dangerous pattern: open()")
    
    return list(set(issues))


def analyze_javascript(code: str) -> List[str]:
    """Analyze JavaScript code for security issues."""
    issues = []
    
    for pattern in DANGEROUS_JS_PATTERNS:
        if re.search(pattern, code, re.IGNORECASE):
            issues.append(f"Dangerous pattern detected: {pattern}")
    
    # Check for potential XSS
    if re.search(r"innerHTML\s*=", code):
        issues.append("Potential XSS: Direct innerHTML assignment")
    
    if re.search(r"document\.write\s*\(", code):
        issues.append("Potential XSS: document.write usage")
    
    return list(set(issues))


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


def get_attr_name(node) -> str:
    """Get the full attribute name from an AST node."""
    if isinstance(node, ast.Attribute):
        return f"{get_attr_name(node.value)}.{node.attr}"
    elif isinstance(node, ast.Name):
        return node.id
    return ""


def resolve_call_name(
    node: ast.AST,
    *,
    module_aliases: dict[str, str],
    imported_name_aliases: dict[str, str],
) -> str:
    """Resolve a function call name including common import aliases."""
    if isinstance(node, ast.Name):
        return imported_name_aliases.get(node.id, node.id)

    if isinstance(node, ast.Attribute):
        full_name = get_attr_name(node)
        root, separator, remainder = full_name.partition(".")
        if not separator:
            return full_name
        resolved_root = imported_name_aliases.get(root, module_aliases.get(root, root))
        return f"{resolved_root}.{remainder}"

    return ""


def _is_dangerous_call_name(resolved_name: str) -> bool:
    """Return True when a resolved call target is explicitly dangerous."""
    if resolved_name in _DANGEROUS_CALLS:
        return True
    return any(
        resolved_name == module or resolved_name.startswith(f"{module}.")
        for module in _DANGEROUS_IMPORT_MODULES
    )
