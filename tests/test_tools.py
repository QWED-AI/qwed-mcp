import os
import pytest
import asyncio
from unittest.mock import patch, AsyncMock, MagicMock
from qwed_mcp.tools import (
    execute_python_code_tool,
    AsyncMCPHandler,
    _get_background_timeout,
    _DEFAULT_BACKGROUND_TIMEOUT,
    _MAX_BACKGROUND_TIMEOUT_CEILING,
)

import pytest_asyncio

@pytest_asyncio.fixture
async def handler_fixture():
    """Provides an initialized AsyncMCPHandler in the running async event loop."""
    return AsyncMCPHandler()


@pytest.fixture
def mock_mcp_call_tool():
    """Register tools on a mock MCP server and return the call_tool handler."""
    from mcp.server import Server
    from qwed_mcp.tools import register_tools

    mock_server = MagicMock(spec=Server)
    registered_call_tool = None

    def call_tool_decorator(*args, **kwargs):
        def decorator(func):
            nonlocal registered_call_tool
            registered_call_tool = func
            return func
        return decorator

    def list_tools_decorator(*args, **kwargs):
        def decorator(func):
            return func
        return decorator

    mock_server.call_tool = call_tool_decorator
    mock_server.list_tools = list_tools_decorator
    register_tools(mock_server)
    return registered_call_tool

# Ensure tests bypass the trusted mode execution guard
os.environ["QWED_MCP_TRUSTED_CODE_EXECUTION"] = "true"

@pytest.mark.asyncio
async def test_execute_python_code_success():
    success, result = await execute_python_code_tool({"code": "print('Hello from sandboxed environment')"})
    
    assert success is True
    assert len(result) == 1
    assert "Hello from sandboxed environment" in result[0].text
    assert "Execution completed successfully." in result[0].text

@pytest.mark.asyncio
async def test_execute_python_code_error():
    success, result = await execute_python_code_tool({"code": "1 / 0"})
    
    assert success is False
    assert len(result) == 1
    assert "ZeroDivisionError" in result[0].text
    assert "Execution failed with return code" in result[0].text

@pytest.mark.asyncio
async def test_execute_python_code_empty():
    success, result = await execute_python_code_tool({})
    
    assert success is False
    assert len(result) == 1
    assert "Error: No code provided." in result[0].text



async def _wait_for_job(async_handler: AsyncMCPHandler, job_id: str, poll_interval: float = 0.1) -> str:
    """Poll until job completes."""
    while True:
        status = async_handler.get_status(job_id)
        if any(s in status for s in ["Status: success", "Status: failed", "Status: cancelled", "Status: timed_out"]):
            return status
        await asyncio.sleep(poll_interval)

@pytest.mark.asyncio
async def test_async_handler_success(handler_fixture):
    job_id = handler_fixture.dispatch_background_worker({"code": "print('async success')"})
    status = await asyncio.wait_for(_wait_for_job(handler_fixture, job_id), timeout=5.0)
    assert "Status: success" in status
    assert "async success" in status

@pytest.mark.asyncio
async def test_async_handler_error(handler_fixture):
    job_id = handler_fixture.dispatch_background_worker({"code": "1/0"})
    status = await asyncio.wait_for(_wait_for_job(handler_fixture, job_id), timeout=5.0)
    assert "Status: failed" in status  # Because exception makes it 'failed' or 0 exit code makes it false
    assert "ZeroDivisionError" in status

@pytest.mark.asyncio
async def test_async_handler_invalid_job(handler_fixture):
    status = handler_fixture.get_status("fake-uuid")
    assert "Error: Job ID 'fake-uuid' not found or expired." in status

@pytest.mark.asyncio
async def test_mcp_round_trip(mock_mcp_call_tool):
    import re

    dispatch_res = await mock_mcp_call_tool("execute_python_code", {"code": "print('mcp success')", "background": True})
    text = dispatch_res[0].text
    
    match = re.search(r"request ([a-f0-9\-]+)\.", text)
    assert match is not None, "Could not extract job ID from background execution response"
    job_id = match.group(1)
    
    # Poll using the public status tool
    status_text = ""
    for _ in range(50):
        status_res = await mock_mcp_call_tool("verification_status", {"job_id": job_id})
        status_text = status_res[0].text
        if "Status: success" in status_text or "Status: failed" in status_text:
            break
        await asyncio.sleep(0.1)
    else:
        pytest.fail(f"Job did not complete within 5 seconds. Last status: {status_text}")
        
    assert "Status: success" in status_text
    assert "mcp success" in status_text


@pytest.mark.asyncio
async def test_mcp_blocks_unknown_tool_before_dispatch(mock_mcp_call_tool):
    response = await mock_mcp_call_tool("unknown_tool", {})

    assert "BLOCKED" in response[0].text
    assert "verification_id=" in response[0].text


@pytest.mark.asyncio
async def test_mcp_blocks_unsafe_python_before_execution(
    monkeypatch, mock_mcp_call_tool
):
    monkeypatch.setenv("QWED_MCP_TRUSTED_CODE_EXECUTION", "true")

    with patch("qwed_mcp.tools.execute_python_code_tool", new_callable=AsyncMock) as mock_exec:
        response = await mock_mcp_call_tool(
            "execute_python_code", {"code": "eval(input())"}
        )

    mock_exec.assert_not_awaited()
    assert "BLOCKED" in response[0].text
    assert "verification_id=" in response[0].text


@pytest.mark.asyncio
async def test_background_worker_timeout_enforced():
    """Background job running beyond timeout must be marked timed_out, not left running."""
    handler = AsyncMCPHandler(max_concurrent_jobs=2)
    handler.background_timeout = 1.0  # 1 second for test speed

    # Code that sleeps longer than the timeout
    job_id = handler.dispatch_background_worker({"code": "import time; time.sleep(30)"})
    status = await asyncio.wait_for(_wait_for_job(handler, job_id), timeout=10.0)

    assert "Status: timed_out" in status
    assert "timed out" in status.lower()
    assert "resource exhaustion" in status.lower()


@pytest.mark.asyncio
async def test_background_timeout_does_not_block_fast_jobs():
    """Jobs completing within the timeout should succeed normally."""
    handler = AsyncMCPHandler(max_concurrent_jobs=2)
    handler.background_timeout = 30.0

    job_id = handler.dispatch_background_worker({"code": "print('fast job')"})
    status = await asyncio.wait_for(_wait_for_job(handler, job_id), timeout=10.0)

    assert "Status: success" in status
    assert "fast job" in status


def test_get_background_timeout_defaults():
    """Default timeout is applied when env var is unset."""
    with patch.dict(os.environ, {}, clear=True):
        # Remove the key if it exists
        os.environ.pop("QWED_MCP_BACKGROUND_TIMEOUT", None)
        assert _get_background_timeout() == _DEFAULT_BACKGROUND_TIMEOUT


def test_get_background_timeout_clamped_to_ceiling():
    """Values above the hard ceiling are clamped."""
    with patch.dict(os.environ, {"QWED_MCP_BACKGROUND_TIMEOUT": "9999"}):
        result = _get_background_timeout()
        assert result == _MAX_BACKGROUND_TIMEOUT_CEILING


def test_get_background_timeout_rejects_negative():
    """Negative or zero values fall back to default."""
    with patch.dict(os.environ, {"QWED_MCP_BACKGROUND_TIMEOUT": "-5"}):
        assert _get_background_timeout() == _DEFAULT_BACKGROUND_TIMEOUT


def test_get_background_timeout_rejects_garbage():
    """Non-numeric values fall back to default."""
    with patch.dict(os.environ, {"QWED_MCP_BACKGROUND_TIMEOUT": "not_a_number"}):
        assert _get_background_timeout() == _DEFAULT_BACKGROUND_TIMEOUT


def test_get_background_timeout_rejects_nan():
    """NaN must be rejected to prevent event loop crashes (Codex review)."""
    with patch.dict(os.environ, {"QWED_MCP_BACKGROUND_TIMEOUT": "nan"}):
        assert _get_background_timeout() == _DEFAULT_BACKGROUND_TIMEOUT


def test_get_background_timeout_rejects_inf():
    """Infinity must be rejected as a non-finite value."""
    with patch.dict(os.environ, {"QWED_MCP_BACKGROUND_TIMEOUT": "inf"}):
        assert _get_background_timeout() == _DEFAULT_BACKGROUND_TIMEOUT
