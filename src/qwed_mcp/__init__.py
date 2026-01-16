"""
QWED-MCP: Model Context Protocol Server for QWED Verification

Provides deterministic verification tools for LLM outputs via MCP.
Works with Claude Desktop, VS Code, and any MCP-compatible client.
"""

from .server import mcp, main
from .tools import (
    verify_math,
    verify_logic,
    verify_code,
    verify_sql,
)

__version__ = "0.1.0"

__all__ = [
    "mcp",
    "main",
    "verify_math",
    "verify_logic",
    "verify_code",
    "verify_sql",
]
