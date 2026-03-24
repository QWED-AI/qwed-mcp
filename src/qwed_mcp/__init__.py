"""
QWED-MCP: Model Context Protocol Server for QWED Verification

Provides deterministic verification tools for LLM outputs via MCP.
Works with Claude Desktop, VS Code, and any MCP-compatible client.
"""

from .server import mcp, main
from .tools import register_tools

__version__ = "0.2.0"

__all__ = [
    "mcp",
    "main",
    "register_tools",
]
