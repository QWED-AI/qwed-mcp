"""
QWED-MCP Python Client Example

This script demonstrates how to use QWED-MCP programmatically via the MCP protocol.
"""

import asyncio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def main():
    """Connect to QWED-MCP server and test all verification tools."""
    
    # Connect to the server
    server_params = StdioServerParameters(
        command="python",
        args=["-m", "qwed_mcp.server"]
    )
    
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            # Initialize the session
            await session.initialize()
            
            # List available tools
            tools = await session.list_tools()
            print("=" * 60)
            print("QWED-MCP Available Tools:")
            print("=" * 60)
            for tool in tools.tools:
                print(f"  • {tool.name}: {tool.description[:50]}...")
            print()
            
            # Test 1: Math Verification
            print("=" * 60)
            print("Test 1: Math Verification (Derivative)")
            print("=" * 60)
            result = await session.call_tool(
                "verify_math",
                arguments={
                    "expression": "x**3",
                    "claimed_result": "3*x**2",
                    "operation": "derivative"
                }
            )
            print(f"Expression: x³")
            print(f"Claimed derivative: 3x²")
            print(f"Result: {result}")
            print()
            
            # Test 2: Wrong Math (should fail)
            print("=" * 60)
            print("Test 2: Math Verification (Wrong Answer)")
            print("=" * 60)
            result = await session.call_tool(
                "verify_math",
                arguments={
                    "expression": "x**2",
                    "claimed_result": "3*x",  # Wrong! Should be 2*x
                    "operation": "derivative"
                }
            )
            print(f"Expression: x²")
            print(f"Claimed derivative: 3x (WRONG)")
            print(f"Result: {result}")
            print()
            
            # Test 3: Logic Verification
            print("=" * 60)
            print("Test 3: Logic Verification (Syllogism)")
            print("=" * 60)
            result = await session.call_tool(
                "verify_logic",
                arguments={
                    "premises": [
                        "A implies B",
                        "A"
                    ],
                    "conclusion": "B"
                }
            )
            print(f"Premises: A → B, A")
            print(f"Conclusion: B")
            print(f"Result: {result}")
            print()
            
            # Test 4: Code Security
            print("=" * 60)
            print("Test 4: Code Security Check")
            print("=" * 60)
            result = await session.call_tool(
                "verify_code",
                arguments={
                    "code": "def run(cmd): os.system(cmd); eval(input())",
                    "language": "python"
                }
            )
            print(f"Code: def run(cmd): os.system(cmd); eval(input())")
            print(f"Result: {result}")
            print()
            
            # Test 5: SQL Injection
            print("=" * 60)
            print("Test 5: SQL Injection Detection")
            print("=" * 60)
            result = await session.call_tool(
                "verify_sql",
                arguments={
                    "query": "SELECT * FROM users WHERE id = '1' OR '1'='1'"
                }
            )
            print(f"Query: SELECT * FROM users WHERE id = '1' OR '1'='1'")
            print(f"Result: {result}")
            print()
            
            # Test 6: Safe SQL
            print("=" * 60)
            print("Test 6: Safe Parameterized Query")
            print("=" * 60)
            result = await session.call_tool(
                "verify_sql",
                arguments={
                    "query": "SELECT name, email FROM users WHERE id = ?"
                }
            )
            print(f"Query: SELECT name, email FROM users WHERE id = ?")
            print(f"Result: {result}")
            print()
            
            print("=" * 60)
            print("All tests completed!")
            print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
