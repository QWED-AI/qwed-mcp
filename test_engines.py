"""Test QWED-MCP verification engines."""

import sys
sys.path.insert(0, 'src')

from qwed_mcp.engines.math_engine import verify_math_expression
from qwed_mcp.engines.logic_engine import verify_logic_statement
from qwed_mcp.engines.code_engine import verify_code_safety
from qwed_mcp.engines.sql_engine import verify_sql_query

print("=" * 50)
print("QWED-MCP Engine Tests")
print("=" * 50)

# Test 1: Math verification
print("\n1. MATH ENGINE TEST:")
result = verify_math_expression("x**2", "2*x", "derivative")
print(f"   Expression: derivative of x^2")
print(f"   Claimed: 2x")
print(f"   Result: {result}")

# Test 2: Logic verification
print("\n2. LOGIC ENGINE TEST:")
result = verify_logic_statement(
    premises=["A implies B", "A"],
    conclusion="B"
)
print(f"   Premises: A implies B, A")
print(f"   Conclusion: B")
print(f"   Result: {result}")

# Test 3: Code security
print("\n3. CODE ENGINE TEST:")
result = verify_code_safety("eval(user_input)", "python")
print(f"   Code: eval(user_input)")
print(f"   Result: {result}")

# Test 4: SQL injection
print("\n4. SQL ENGINE TEST:")
result = verify_sql_query("SELECT * FROM users WHERE id = '1' OR '1'='1'")
print(f"   Query: SELECT * FROM users WHERE id = '1' OR '1'='1'")
print(f"   Result: {result}")

print("\n" + "=" * 50)
print("All tests completed!")
print("=" * 50)
