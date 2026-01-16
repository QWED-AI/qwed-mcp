"""
QWED-MCP Tools

Verification tools exposed via MCP protocol.
Each tool provides deterministic verification for a specific domain.
"""

import logging
from typing import Any
from mcp.server import Server
from mcp.types import Tool, TextContent

from .engines.math_engine import verify_math_expression
from .engines.logic_engine import verify_logic_statement
from .engines.code_engine import verify_code_safety
from .engines.sql_engine import verify_sql_query

logger = logging.getLogger("qwed-mcp.tools")


def register_tools(server: Server) -> None:
    """Register all QWED verification tools with the MCP server."""
    
    @server.list_tools()
    async def list_tools() -> list[Tool]:
        """List all available QWED verification tools."""
        return [
            Tool(
                name="verify_math",
                description="Verify mathematical calculations using SymPy symbolic engine. "
                           "Checks if an LLM's mathematical output is correct.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "expression": {
                            "type": "string",
                            "description": "The mathematical expression to verify (e.g., 'derivative of x^2')"
                        },
                        "claimed_result": {
                            "type": "string", 
                            "description": "The result claimed by the LLM (e.g., '2x')"
                        },
                        "operation": {
                            "type": "string",
                            "enum": ["derivative", "integral", "simplify", "solve", "evaluate"],
                            "description": "The mathematical operation to perform"
                        }
                    },
                    "required": ["expression", "claimed_result"]
                }
            ),
            Tool(
                name="verify_logic",
                description="Verify logical statements using Z3 SMT solver. "
                           "Checks if a logical argument is valid.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "premises": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "List of premise statements"
                        },
                        "conclusion": {
                            "type": "string",
                            "description": "The conclusion to verify"
                        }
                    },
                    "required": ["premises", "conclusion"]
                }
            ),
            Tool(
                name="verify_code",
                description="Verify code for security issues using AST analysis. "
                           "Detects dangerous patterns like eval(), exec(), SQL injection.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "code": {
                            "type": "string",
                            "description": "The code to analyze"
                        },
                        "language": {
                            "type": "string",
                            "enum": ["python", "javascript", "sql"],
                            "description": "Programming language of the code"
                        }
                    },
                    "required": ["code", "language"]
                }
            ),
            Tool(
                name="verify_sql",
                description="Verify SQL queries for injection vulnerabilities and schema compliance.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "The SQL query to verify"
                        },
                        "allowed_tables": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Optional list of allowed table names"
                        }
                    },
                    "required": ["query"]
                }
            ),
        ]
    
    @server.call_tool()
    async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
        """Execute a QWED verification tool."""
        logger.info(f"Calling tool: {name} with args: {arguments}")
        
        try:
            if name == "verify_math":
                result = verify_math_expression(
                    expression=arguments["expression"],
                    claimed_result=arguments["claimed_result"],
                    operation=arguments.get("operation", "evaluate")
                )
            elif name == "verify_logic":
                result = verify_logic_statement(
                    premises=arguments["premises"],
                    conclusion=arguments["conclusion"]
                )
            elif name == "verify_code":
                result = verify_code_safety(
                    code=arguments["code"],
                    language=arguments["language"]
                )
            elif name == "verify_sql":
                result = verify_sql_query(
                    query=arguments["query"],
                    allowed_tables=arguments.get("allowed_tables")
                )
            else:
                return [TextContent(
                    type="text",
                    text=f"Unknown tool: {name}"
                )]
            
            return [TextContent(
                type="text",
                text=format_result(result)
            )]
            
        except Exception as e:
            logger.error(f"Tool {name} failed: {e}")
            return [TextContent(
                type="text",
                text=f"Verification error: {str(e)}"
            )]


def format_result(result: dict) -> str:
    """Format verification result for display."""
    if result.get("verified"):
        status = "✅ VERIFIED"
    else:
        status = "❌ FAILED"
    
    output = f"{status}\n"
    output += f"Result: {result.get('message', 'No message')}\n"
    
    if "expected" in result:
        output += f"Expected: {result['expected']}\n"
    if "actual" in result:
        output += f"Actual: {result['actual']}\n"
    if "issues" in result and result["issues"]:
        output += f"Issues: {', '.join(result['issues'])}\n"
    
    return output


# Export for direct use
async def verify_math(expression: str, claimed_result: str, operation: str = "evaluate") -> dict:
    """Verify a mathematical calculation."""
    return verify_math_expression(expression, claimed_result, operation)


async def verify_logic(premises: list[str], conclusion: str) -> dict:
    """Verify a logical argument."""
    return verify_logic_statement(premises, conclusion)


async def verify_code(code: str, language: str) -> dict:
    """Verify code for security issues."""
    return verify_code_safety(code, language)


async def verify_sql(query: str, allowed_tables: list[str] = None) -> dict:
    """Verify a SQL query."""
    return verify_sql_query(query, allowed_tables)
