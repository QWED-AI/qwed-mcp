import os
import pytest
import asyncio
from unittest.mock import patch, AsyncMock, MagicMock
from qwed_mcp.tools import execute_python_code_tool, async_handler

# Ensure tests bypass the trusted mode execution guard
os.environ["QWED_MCP_TRUSTED_CODE_EXECUTION"] = "true"

@pytest.mark.asyncio
async def test_execute_python_code_success():
    result = await execute_python_code_tool({"code": "print('Hello from sandboxed environment')"})
    
    assert len(result) == 1
    assert "Hello from sandboxed environment" in result[0].text
    assert "Execution completed successfully." in result[0].text

@pytest.mark.asyncio
async def test_execute_python_code_error():
    result = await execute_python_code_tool({"code": "1 / 0"})
    
    assert len(result) == 1
    assert "ZeroDivisionError" in result[0].text
    assert "Execution failed with return code" in result[0].text

@pytest.mark.asyncio
async def test_execute_python_code_empty():
    result = await execute_python_code_tool({})
    
    assert len(result) == 1
    assert "Error: No code provided." in result[0].text

from unittest.mock import patch, AsyncMock, MagicMock
import asyncio

@pytest.mark.asyncio
@patch("qwed_mcp.tools.asyncio.wait_for", side_effect=asyncio.TimeoutError)
@patch("qwed_mcp.tools.asyncio.create_subprocess_exec")
async def test_execute_python_code_timeout(mock_create, mock_wait):
    mock_proc = MagicMock()
    mock_proc.pid = 12345
    mock_proc.returncode = None
    mock_proc.communicate = AsyncMock(return_value=(b"", b""))
    mock_create.return_value = mock_proc
    
    result = await execute_python_code_tool({"code": "while True: pass"})
    
    assert len(result) == 1
    assert "Execution timed out after 30 seconds." in result[0].text

@pytest.mark.asyncio
async def test_async_handler_success():
    job_id = async_handler.dispatch_background_worker({"code": "print('async success')"})
    
    # Wait for the background task to complete
    # It usually takes a fraction of a second to spin up bash/python and return
    await asyncio.sleep(1.5)
    
    status = async_handler.get_status(job_id)
    assert "Status: completed" in status
    assert "async success" in status

@pytest.mark.asyncio
async def test_async_handler_error():
    job_id = async_handler.dispatch_background_worker({"code": "1/0"})
    
    await asyncio.sleep(1.5)
    
    status = async_handler.get_status(job_id)
    assert "Status: completed" in status
    assert "ZeroDivisionError" in status

def test_async_handler_invalid_job():
    status = async_handler.get_status("fake-uuid")
    assert "Error: Job ID 'fake-uuid' not found." in status
