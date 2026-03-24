import os
import pytest
from qwed_mcp.tools import execute_python_code_tool

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
