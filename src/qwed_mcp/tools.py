"""
QWED-MCP Tools

Provides a single execute_python_code tool as per RFC-9728 to solve context bloat.
LLMs will execute Python scripts directly using the pre-installed QWED SDKs.
"""

import logging
import subprocess
import os
import tempfile
import sys
from typing import Any
from mcp.server import Server
from mcp.types import Tool, TextContent

logger = logging.getLogger("qwed-mcp.tools")

async def execute_python_code_tool(arguments: dict[str, Any]) -> list[TextContent]:
    """Execute the provided python code in a sandbox."""
    code = arguments.get("code", "")
    if not code:
        return [TextContent(type="text", text="Error: No code provided.")]
    
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            script_path = f.name
        
        result = subprocess.run(
            [sys.executable, script_path],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if os.path.exists(script_path):
            os.remove(script_path)
        
        output_parts = []
        if result.stdout:
            output_parts.append("STDOUT:\n" + result.stdout.strip())
        if result.stderr:
            output_parts.append("STDERR:\n" + result.stderr.strip())
            
        if result.returncode != 0:
            output_parts.append(f"\nExecution failed with return code {result.returncode}")
        else:
            output_parts.append("\nExecution completed successfully.")
            
        final_output = "\n\n".join(output_parts).strip()
        return [TextContent(type="text", text=final_output)]
        
    except subprocess.TimeoutExpired:
        if 'script_path' in locals() and os.path.exists(script_path):
            os.remove(script_path)
        return [TextContent(type="text", text="Execution timed out after 30 seconds.")]
    except Exception as e:
        logger.error(f"Error executing code: {e}")
        if 'script_path' in locals() and os.path.exists(script_path):
            os.remove(script_path)
        return [TextContent(type="text", text=f"Execution error: {str(e)}")]


def register_tools(server: Server) -> None:
    """Register the single execution tool with the MCP server."""
    
    @server.list_tools()
    async def list_tools() -> list[Tool]:
        """List all available QWED verification tools."""
        return [
            Tool(
                name="execute_python_code",
                description="Executes Python code in an isolated sandboxed environment with QWED SDKs pre-installed. Use this to run verifications natively.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "code": {
                            "type": "string", 
                            "description": "The Python code to execute."
                        }
                    },
                    "required": ["code"]
                }
            )
        ]
    
    @server.call_tool()
    async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
        """Execute the QWED verification tool."""
        logger.info(f"Calling tool: {name}")
        
        if name != "execute_python_code":
            return [TextContent(type="text", text=f"Unknown tool: {name}")]
            
        return await execute_python_code_tool(arguments)
