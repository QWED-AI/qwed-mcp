"""
Code Security Verification Engine

Uses AST analysis for detecting dangerous patterns.
"""

import ast
import re
import logging
from typing import List, Optional

logger = logging.getLogger("qwed-mcp.engines.code")

# Dangerous patterns for Python
DANGEROUS_PYTHON_PATTERNS = [
    "eval",
    "exec",
    "__import__",
    "compile",
    "open",
    "os.system",
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
    
    # Try AST analysis
    try:
        tree = ast.parse(code)
        
        for node in ast.walk(tree):
            # Check for dangerous function calls
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    if node.func.id in ["eval", "exec", "compile"]:
                        issues.append(f"Dangerous function call: {node.func.id}()")
                        
                elif isinstance(node.func, ast.Attribute):
                    full_name = f"{get_attr_name(node.func)}"
                    for pattern in DANGEROUS_PYTHON_PATTERNS:
                        if pattern in full_name:
                            issues.append(f"Dangerous pattern: {full_name}")
            
            # Check for __import__
            if isinstance(node, ast.Name) and node.id == "__import__":
                issues.append("Use of __import__ detected")
                
    except SyntaxError as e:
        issues.append(f"Syntax error in code: {e}")
    
    # Pattern-based checks
    for pattern in DANGEROUS_PYTHON_PATTERNS:
        if pattern in code:
            issues.append(f"Potentially dangerous pattern: {pattern}")
    
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
