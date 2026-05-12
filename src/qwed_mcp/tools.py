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
import math
import uuid
import time
import tempfile
from subprocess import PIPE, DEVNULL
from typing import Any
from mcp.server import Server
from mcp.types import Tool, TextContent

from .security import RiskBasedExecutionGateway

logger = logging.getLogger("qwed-mcp.tools")

def _is_valid_pgid(pgid: Any) -> bool:
    """Validate that PGID is a valid positive integer to satisfy SonarCloud S4828."""
    return isinstance(pgid, int) and pgid > 0

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
            if _is_valid_pgid(pgid):
                os.killpg(pgid, signal.SIGKILL)  # nosonar
            else:
                proc.kill()
        except ProcessLookupError:
            logger.debug("Process already terminated")
        except Exception as e:
            logger.debug(f"Failed to kill process group: {e}, falling back to proc.kill()")
            try:
                proc.kill()
            except ProcessLookupError:
                pass
    else:
        try:
            proc.kill()
        except OSError:
            pass
    
    try:
        await asyncio.wait_for(proc.wait(), timeout=2.0)
    except asyncio.TimeoutError:
        pass

def _close_streams(proc: asyncio.subprocess.Process) -> None:
    """Explicitly close process streams to prevent FD leaks."""
    for stream_name in ('stdout', 'stderr', 'stdin'):
        stream = getattr(proc, stream_name, None)
        if stream:
            transport = getattr(stream, '_transport', None)
            if transport is not None:
                transport.close()
            elif hasattr(stream, 'close'):
                stream.close()

def _handle_cap_exceeded(proc: asyncio.subprocess.Process | None) -> None:
    """Kill process when output cap is exceeded."""
    if proc:
        try:
            proc.kill()
        except OSError:
            pass

async def _read_stream(stream: asyncio.StreamReader | None, proc: asyncio.subprocess.Process | None = None, cap_bytes: int = 1024 * 1024) -> bytes:
    """Read from an async stream up to a maximum byte cap to prevent OOM. Kills process if cap is reached."""
    if stream is None:
        return b""
    chunks: list[bytes] = []
    bytes_read: int = 0
    while True:
        chunk: bytes = await stream.read(4096)
        if not chunk:
            break
        
        if bytes_read + len(chunk) > cap_bytes:
            remaining = cap_bytes - bytes_read
            if remaining > 0:
                chunks.append(chunk[:remaining])
            chunks.append(b"\n\n[WARNING: OUTPUT TRUNCATED DUE TO 1MB SIZE CAP. PROCESS TERMINATED.]")
            _handle_cap_exceeded(proc)
            break
            
        chunks.append(chunk)
        bytes_read += len(chunk)
        
    return b"".join(chunks)

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


async def execute_python_code_tool(arguments: dict[str, Any]) -> tuple[bool, list[TextContent]]:
    """Execute the provided python code in a subprocess. Returns (success, TextContent)."""

    # Safety net: validated by RiskBasedExecutionGateway before normal dispatch.
    # These checks remain here to fail closed if this function is ever called directly.
    trusted_mode = os.getenv("QWED_MCP_TRUSTED_CODE_EXECUTION", "false").lower() == "true"
    if not trusted_mode:
        return False, [TextContent(type="text", text="Error: Code execution is disabled. The server admin must set QWED_MCP_TRUSTED_CODE_EXECUTION=true to enable this tool.")]
        
    code = arguments.get("code", "")
    if not code:
        return False, [TextContent(type="text", text="Error: No code provided.")]
    
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
            stdin=DEVNULL,
            stdout=PIPE,
            stderr=PIPE,
            env=secure_env,
            **popen_kwargs
        )

        async def _run_and_read() -> tuple[bytes, bytes]:
            out_task = asyncio.create_task(_read_stream(proc.stdout, proc=proc))
            err_task = asyncio.create_task(_read_stream(proc.stderr, proc=proc))
            
            # Run process wait and stream readers concurrently to avoid deadlock
            stdout_bytes, stderr_bytes, _ = await asyncio.gather(
                out_task,
                err_task,
                proc.wait()
            )
            return stdout_bytes, stderr_bytes

        try:
            # Run without timeout bounds; callers should manage timeouts
            stdout_bytes, stderr_bytes = await _run_and_read()
            stdout = stdout_bytes.decode('utf-8', errors='replace') if stdout_bytes else ""
            stderr = stderr_bytes.decode('utf-8', errors='replace') if stderr_bytes else ""
            returncode = proc.returncode
        except asyncio.CancelledError:
            await _kill_process(proc)
            await _cleanup_script(script_path_obj)
            raise
        finally:
            _close_streams(proc)
        
        await _cleanup_script(script_path_obj)
        final_output = _format_output(stdout, stderr, returncode)
        
        success = (returncode == 0)
        return success, [TextContent(type="text", text=final_output)]
        
    except Exception as e:
        logger.exception("Error executing code")
        if 'script_path_obj' in locals():
            await _cleanup_script(script_path_obj)
        return False, [TextContent(type="text", text=f"Execution error: {str(e)}")]

# Hard upper bound for background execution timeout (seconds).
# Configurable via QWED_MCP_BACKGROUND_TIMEOUT but never exceeds this ceiling.
_MAX_BACKGROUND_TIMEOUT_CEILING: float = 600.0
_DEFAULT_BACKGROUND_TIMEOUT: float = 120.0


def _get_background_timeout() -> float:
    """Return the background worker timeout in seconds.

    Reads QWED_MCP_BACKGROUND_TIMEOUT from the environment.  Values above
    the hard ceiling are clamped; non-numeric or non-positive values fall
    back to the default.
    """
    raw = os.getenv("QWED_MCP_BACKGROUND_TIMEOUT", "")
    if raw:
        try:
            value = float(raw)
            if not math.isfinite(value) or value <= 0:
                logger.warning(
                    "QWED_MCP_BACKGROUND_TIMEOUT must be a positive finite number, using default %.0fs",
                    _DEFAULT_BACKGROUND_TIMEOUT,
                )
                return _DEFAULT_BACKGROUND_TIMEOUT
            return min(value, _MAX_BACKGROUND_TIMEOUT_CEILING)
        except ValueError:
            logger.warning(
                "Invalid QWED_MCP_BACKGROUND_TIMEOUT '%s', using default %.0fs",
                raw,
                _DEFAULT_BACKGROUND_TIMEOUT,
            )
    return _DEFAULT_BACKGROUND_TIMEOUT


class AsyncMCPHandler:
    """
    Implements async job queues to avoid blocking on long-running MCP tool calls.
    Allows LLM clients to dispatch heavy tasks and poll them using the 'verification_status' tool.

    Background workers enforce a hard execution timeout (default 120s, max 600s)
    to prevent denial-of-service via unbounded execution.  See: Issue #10.
    """
    def __init__(self, max_concurrent_jobs: int = 5):
        self.pending_verifications: dict[str, dict[str, Any]] = {}
        self.semaphore = asyncio.Semaphore(max_concurrent_jobs)
        self.background_timeout: float = _get_background_timeout()

    def _prune_pending_verifications(self, ttl_seconds: float = 3600.0) -> None:
        """Removes pending verifications older than TTL to prevent memory leaks."""
        current_time = time.time()
        expired_keys = []
        for k, v in self.pending_verifications.items():
            if current_time - v.get("last_updated_at", v.get("created_at", current_time)) > ttl_seconds:
                if v.get("status") in ["running", "queued"] and v.get("task"):
                    v["task"].cancel()
                expired_keys.append(k)
        
        for k in expired_keys:
            del self.pending_verifications[k]

    def _update_job(self, job_id: str, status: str, result: str, **extra: Any) -> None:
        """Update a pending job's status, result, and timestamp in one place."""
        if job_id in self.pending_verifications:
            self.pending_verifications[job_id]["status"] = status
            self.pending_verifications[job_id]["result"] = result
            self.pending_verifications[job_id]["last_updated_at"] = time.time()
            for key, val in extra.items():
                self.pending_verifications[job_id][key] = val

    async def _worker(self, job_id: str, arguments: dict[str, Any]):
        try:
            async with self.semaphore:
                if job_id in self.pending_verifications:
                    self.pending_verifications[job_id]["status"] = "running"
                    self.pending_verifications[job_id]["last_updated_at"] = time.time()

                try:
                    success, result_list = await asyncio.wait_for(
                        execute_python_code_tool(arguments),
                        timeout=self.background_timeout,
                    )
                except asyncio.TimeoutError:
                    logger.warning(
                        "Background job %s timed out after %.0fs",
                        job_id,
                        self.background_timeout,
                    )
                    self._update_job(
                        job_id,
                        "timed_out",
                        f"Background verification timed out after "
                        f"{self.background_timeout:.0f} seconds. "
                        f"Process terminated to prevent resource exhaustion.",
                    )
                    return

                result_text = result_list[0].text if result_list else "No output"
                self._update_job(
                    job_id,
                    "success" if success else "failed",
                    result_text,
                )
        except asyncio.CancelledError:
            self._update_job(job_id, "cancelled", "Job was cancelled.")
            raise
        except Exception as e:
            self._update_job(job_id, "failed", str(e), error=str(e))

    def dispatch_background_worker(self, arguments: dict[str, Any]) -> str:
        self._prune_pending_verifications()
        job_id = str(uuid.uuid4())
        self.pending_verifications[job_id] = {
            "status": "queued",
            "result": None,
            "created_at": time.time(),
            "last_updated_at": time.time(),
            "task": None
        }
        task = asyncio.create_task(self._worker(job_id, arguments))
        self.pending_verifications[job_id]["task"] = task
        return job_id

    def get_status(self, job_id: str) -> str:
        if job_id in self.pending_verifications:
            job = self.pending_verifications[job_id]
            if job["status"] in ["success", "failed", "cancelled", "timed_out"]:
                result_str = f"Status: {job['status']}\n\nResult:\n{job['result']}"
                self._prune_pending_verifications()
                return result_str
                
        self._prune_pending_verifications()
        
        if job_id not in self.pending_verifications:
            return f"Error: Job ID '{job_id}' not found or expired."
        
        job = self.pending_verifications[job_id]
        
        if job["status"] in ["success", "failed", "cancelled", "timed_out"]:
            return f"Status: {job['status']}\n\nResult:\n{job['result']}"
        else:
            return f"Status: {job['status']}..."

def register_tools(server: Server) -> None:
    """Register the execution and background status tools with the MCP server."""
    
    async_handler = AsyncMCPHandler()
    risk_gateway = RiskBasedExecutionGateway()

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
                        },
                        "background": {
                            "type": "boolean",
                            "description": "Execute asynchronously in the background and return a tracking job_id. Set to True for heavy logic verifications."
                        }
                    },
                    "required": ["code"]
                }
            ),
            Tool(
                name="verification_status",
                description="Check the execution status and output of a background verification task.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "job_id": {
                            "type": "string",
                            "description": "The UUID returned by execute_python_code when background=True."
                        }
                    },
                    "required": ["job_id"]
                }
            )
        ]
    
    @server.call_tool()
    async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
        """Execute the QWED verification tool."""
        logger.info(f"Calling tool: {name}")
        decision = risk_gateway.evaluate_and_route(name, arguments)
        if not decision["verified"]:
            message = (
                f"{decision['status']}: {decision['message']} "
                f"(verification_id={decision['verification_id']})"
            )
            return [TextContent(type="text", text=message)]

        normalized_arguments = decision["normalized_arguments"]
        
        if name == "execute_python_code":
            if normalized_arguments.get("background"):
                job_id = async_handler.dispatch_background_worker(normalized_arguments)
                msg = f"Verification order is being placed for the request {job_id}. Check back using the 'verification_status' tool."
                return [TextContent(type="text", text=msg)]
                
            try:
                _, result_content = await asyncio.wait_for(execute_python_code_tool(normalized_arguments), timeout=30.0)
                return result_content
            except asyncio.TimeoutError:
                return [TextContent(type="text", text="Execution timed out after 30.0 seconds.")]
            
        elif name == "verification_status":
            job_id = normalized_arguments.get("job_id", "")
            if not job_id:
                return [TextContent(type="text", text="Error: Missing job_id in arguments.")]
            status_text = async_handler.get_status(job_id)
            return [TextContent(type="text", text=status_text)]

        # Safety net: unknown tools should already be blocked by _TOOL_POLICIES
        # via QWED-MCP-RISK-001 before dispatch reaches this point.
        logger.error(
            "Governance invariant violated: tool '%s' reached dispatch without verification",
            name,
        )
        return [
            TextContent(
                type="text",
                text=(
                    "BLOCKED: Internal governance error. Unexpected tool bypassed "
                    "policy QWED-MCP-RISK-001."
                ),
            )
        ]
