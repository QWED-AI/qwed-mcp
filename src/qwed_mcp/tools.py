"""
QWED-MCP Tools

Provides a single execute_python_code tool as per RFC-9728 to solve context bloat.
LLMs will execute Python scripts directly using the pre-installed QWED SDKs.
"""

import logging
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

async def _cleanup_script(script_path_obj: anyio.Path) -> None:
    """Remove temporary script file if it exists."""
    if await script_path_obj.exists():
        await script_path_obj.unlink()

async def _kill_process(proc: asyncio.subprocess.Process) -> None:
    """Terminate process and its children across platforms."""
    if sys.platform != "win32":
        import signal
        try:
            pgid = os.getpgid(proc.pid)
            # Validate the PGID (SonarCloud S4828)
            if isinstance(pgid, int) and pgid > 0:
                os.killpg(pgid, signal.SIGKILL)
            else:
                proc.kill()
        except Exception as e:
            logger.debug(f"Failed to kill process group: {e}, falling back to proc.kill()")
            proc.kill()
    else:
        try:
            proc.kill()
        except ProcessLookupError:
            pass
    await proc.communicate()

def _format_output(stdout: str, stderr: str, returncode: int | None) -> str:
    """Format execution results into a readable string."""
    output_parts = []
    if stdout:
        output_parts.append("STDOUT:\n" + stdout.strip())
    if stderr:
        output_parts.append("STDERR:\n" + stderr.strip())
    
    # If the process was killed via timeout, returncode might be None or negative
    actual_rc = returncode if returncode is not None else -9
    if actual_rc != 0:
        output_parts.append(f"\nExecution failed with return code {actual_rc}")
    else:
        output_parts.append("\nExecution completed successfully.")
    return "\n\n".join(output_parts).strip()


async def execute_python_code_tool(arguments: dict[str, Any]) -> list[TextContent]:
    """Execute the provided python code in a subprocess."""
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
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=secure_env,
            **popen_kwargs
        )

        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=30.0)
            stdout = stdout_bytes.decode('utf-8', errors='replace') if stdout_bytes else ""
            stderr = stderr_bytes.decode('utf-8', errors='replace') if stderr_bytes else ""
            returncode = proc.returncode
        except asyncio.TimeoutError:
            await _kill_process(proc)
            await _cleanup_script(script_path_obj)
            return [TextContent(type="text", text="Execution timed out after 30 seconds.")]
        
        await _cleanup_script(script_path_obj)
        final_output = _format_output(stdout, stderr, returncode)
        
        return [TextContent(type="text", text=final_output)]
        
    except Exception as e:
        logger.error(f"Error executing code: {e}")
        if 'script_path_obj' in locals():
            await _cleanup_script(script_path_obj)
        return [TextContent(type="text", text=f"Execution error: {str(e)}")]


def register_tools(server: Server) -> None:
    """Register the single execution tool with the MCP server."""
    
    @server.list_tools()
    async def list_tools() -> list[Tool]:
        """List all available QWED verification tools."""
        return [
            Tool(
                name="execute_python_code",
                description="Executes Python code in a subprocess with restricted environment variables. Note: This runs with server privileges; ensure inputs are trusted.",
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
