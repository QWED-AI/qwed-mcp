import os
import pytest
import asyncio
from unittest.mock import patch, AsyncMock, MagicMock
from qwed_mcp.tools import execute_python_code_tool, AsyncMCPHandler

import pytest_asyncio

@pytest_asyncio.fixture
async def handler_fixture():
    """Provides an initialized AsyncMCPHandler in the running async event loop."""
    return AsyncMCPHandler()

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
        if "Status: success" in status or "Status: failed" in status or "Status: cancelled" in status:
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
async def test_mcp_round_trip():
    from mcp.server import Server
    import re
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
    
    dispatch_res = await registered_call_tool("execute_python_code", {"code": "print('mcp success')", "background": True})
    text = dispatch_res[0].text
    
    match = re.search(r"request ([a-f0-9\-]+)\.", text)
    assert match is not None, "Could not extract job ID from background execution response"
    job_id = match.group(1)
    
    # Poll using the public status tool
    status_text = ""
    for _ in range(50):
        status_res = await registered_call_tool("verification_status", {"job_id": job_id})
        status_text = status_res[0].text
        if "Status: success" in status_text or "Status: failed" in status_text:
            break
        await asyncio.sleep(0.1)
    else:
        pytest.fail(f"Job did not complete within 5 seconds. Last status: {status_text}")
        
    assert "Status: success" in status_text
    assert "mcp success" in status_text
