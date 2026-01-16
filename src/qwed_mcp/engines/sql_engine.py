"""
SQL Verification Engine

Validates SQL queries for injection and schema compliance.
"""

import re
import logging
from typing import List, Optional

logger = logging.getLogger("qwed-mcp.engines.sql")

# Dangerous SQL patterns
DANGEROUS_PATTERNS = [
    r"DROP\s+TABLE",
    r"DROP\s+DATABASE",
    r"DELETE\s+FROM\s+\w+\s*;?\s*$",  # DELETE without WHERE
    r"TRUNCATE\s+TABLE",
    r"ALTER\s+TABLE",
    r"CREATE\s+USER",
    r"GRANT\s+",
    r"EXEC\s*\(",
    r"EXECUTE\s*\(",
    r"xp_cmdshell",
    r"sp_executesql",
]

# Injection patterns
INJECTION_PATTERNS = [
    r"'\s*OR\s+'1'\s*=\s*'1",
    r"'\s*OR\s+1\s*=\s*1",
    r"'\s*;\s*--",
    r"UNION\s+ALL\s+SELECT",
    r"UNION\s+SELECT",
    r"/\*.*\*/",
    r"--[^\n]*",
    r"'\s*OR\s+''='",
]

# Tautology patterns
TAUTOLOGY_PATTERNS = [
    r"1\s*=\s*1",
    r"'a'\s*=\s*'a'",
    r"1\s*<>\s*0",
    r"0\s*=\s*0",
]


def verify_sql_query(
    query: str,
    allowed_tables: Optional[List[str]] = None
) -> dict:
    """
    Verify SQL query for injection vulnerabilities and schema compliance.
    
    Args:
        query: The SQL query to verify
        allowed_tables: Optional list of allowed table names
    
    Returns:
        Verification result with issues if any
    """
    issues = []
    
    # Check for dangerous patterns
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, query, re.IGNORECASE):
            issues.append(f"Dangerous operation detected: {pattern}")
    
    # Check for injection patterns
    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, query, re.IGNORECASE):
            issues.append(f"Potential SQL injection: {pattern}")
    
    # Check for tautology patterns (common in injection)
    for pattern in TAUTOLOGY_PATTERNS:
        if re.search(pattern, query, re.IGNORECASE):
            issues.append(f"Suspicious tautology detected: {pattern}")
    
    # Check table access if allowed_tables is specified
    if allowed_tables:
        tables_in_query = extract_tables(query)
        unauthorized = [t for t in tables_in_query if t.lower() not in [a.lower() for a in allowed_tables]]
        if unauthorized:
            issues.append(f"Unauthorized table access: {', '.join(unauthorized)}")
    
    # Check for missing WHERE clause on UPDATE/DELETE
    if re.search(r"UPDATE\s+\w+\s+SET\s+", query, re.IGNORECASE):
        if not re.search(r"WHERE\s+", query, re.IGNORECASE):
            issues.append("Warning: UPDATE without WHERE clause")
    
    if re.search(r"DELETE\s+FROM\s+\w+", query, re.IGNORECASE):
        if not re.search(r"WHERE\s+", query, re.IGNORECASE):
            issues.append("Warning: DELETE without WHERE clause")
    
    if issues:
        return {
            "verified": False,
            "message": f"Found {len(issues)} issue(s) in SQL query",
            "issues": issues
        }
    else:
        return {
            "verified": True,
            "message": "SQL query passed verification",
            "issues": []
        }


def extract_tables(query: str) -> List[str]:
    """Extract table names from SQL query."""
    tables = []
    
    # FROM clause
    from_match = re.findall(r"FROM\s+([a-zA-Z_][a-zA-Z0-9_]*)", query, re.IGNORECASE)
    tables.extend(from_match)
    
    # JOIN clauses
    join_match = re.findall(r"JOIN\s+([a-zA-Z_][a-zA-Z0-9_]*)", query, re.IGNORECASE)
    tables.extend(join_match)
    
    # UPDATE clause
    update_match = re.findall(r"UPDATE\s+([a-zA-Z_][a-zA-Z0-9_]*)", query, re.IGNORECASE)
    tables.extend(update_match)
    
    # INSERT INTO clause
    insert_match = re.findall(r"INSERT\s+INTO\s+([a-zA-Z_][a-zA-Z0-9_]*)", query, re.IGNORECASE)
    tables.extend(insert_match)
    
    # DELETE FROM clause
    delete_match = re.findall(r"DELETE\s+FROM\s+([a-zA-Z_][a-zA-Z0-9_]*)", query, re.IGNORECASE)
    tables.extend(delete_match)
    
    return list(set(tables))
