import os
import pytest
import asyncio
from unittest.mock import patch, AsyncMock, MagicMock
from qwed_mcp.tools import execute_python_code_tool, AsyncMCPHandler

async_handler = AsyncMCPHandler()

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



async def _wait_for_job(job_id: str, poll_interval: float = 0.1) -> str:
    """Poll until job completes."""
    while True:
        status = async_handler.get_status(job_id)
        if "Status: success" in status or "Status: failed" in status:
            return status
        await asyncio.sleep(poll_interval)

@pytest.mark.asyncio
async def test_async_handler_success():
    job_id = async_handler.dispatch_background_worker({"code": "print('async success')"})
    status = await asyncio.wait_for(_wait_for_job(job_id), timeout=5.0)
    assert "Status: success" in status
    assert "async success" in status

@pytest.mark.asyncio
async def test_async_handler_error():
    job_id = async_handler.dispatch_background_worker({"code": "1/0"})
    status = await asyncio.wait_for(_wait_for_job(job_id), timeout=5.0)
    assert "Status: failed" in status  # Because exception makes it 'failed' or 0 exit code makes it false
    assert "ZeroDivisionError" in status

def test_async_handler_invalid_job():
    status = async_handler.get_status("fake-uuid")
    assert "Error: Job ID 'fake-uuid' not found." in status
