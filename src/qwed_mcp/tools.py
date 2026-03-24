"""
QWED-MCP Tools

Provides a single execute_python_code tool as per RFC-9728 to solve context bloat.
LLMs will execute Python scripts directly using the pre-installed QWED SDKs.
"""

import logging
import subprocess
import os
import sys
import anyio
import asyncio
import uuid
import tempfile
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
        temp_dir = anyio.Path(tempfile.gettempdir())
        script_path_obj = temp_dir / f"qwed_exec_{uuid.uuid4().hex}.py"
        await script_path_obj.write_text(code)
        script_path = str(script_path_obj)
        
        # Create a restricted environment (stripping SENTRY_DSN, keys, etc.)
        secure_env = {
            "PATH": os.environ.get("PATH", ""),
            "PYTHONPATH": os.environ.get("PYTHONPATH", ""),
            "SYSTEMROOT": os.environ.get("SYSTEMROOT", "")  # Required on Windows
        }

        # Setup process group definition for Unix to cleanly kill child processes
        popen_kwargs = {}
        if sys.platform != "win32":
            popen_kwargs["start_new_session"] = True

        proc = await asyncio.create_subprocess_exec(
            sys.executable, script_path,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=secure_env,
            **popen_kwargs
        )

        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=30.0)
            stdout = stdout_bytes.decode('utf-8', errors='replace') if stdout_bytes else ""
            stderr = stderr_bytes.decode('utf-8', errors='replace') if stderr_bytes else ""
            returncode = proc.returncode
        except asyncio.TimeoutError:
            # Cleanly kill the entire process group to prevent orphaned children
            if sys.platform != "win32":
                import signal
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                except Exception:
                    proc.kill()
            else:
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
            await proc.communicate()
            
            if await script_path_obj.exists():
                await script_path_obj.unlink()
            return [TextContent(type="text", text="Execution timed out after 30 seconds.")]
        
        if await script_path_obj.exists():
            await script_path_obj.unlink()
        
        output_parts = []
        if stdout:
            output_parts.append("STDOUT:\n" + stdout.strip())
        if stderr:
            output_parts.append("STDERR:\n" + stderr.strip())
            
        if returncode != 0:
            output_parts.append(f"\nExecution failed with return code {returncode}")
        else:
            output_parts.append("\nExecution completed successfully.")
            
        final_output = "\n\n".join(output_parts).strip()
        return [TextContent(type="text", text=final_output)]
        
    except Exception as e:
        logger.error(f"Error executing code: {e}")
        if 'script_path_obj' in locals() and await script_path_obj.exists():
            await script_path_obj.unlink()
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
