import pytest
from qwed_mcp.tools import execute_python_code_tool

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
