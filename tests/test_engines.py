"""
Basic tests for QWED-MCP verification engines.
"""
import pytest


class TestMathEngine:
    """Tests for the math verification engine."""

    def test_derivative_correct(self):
        from qwed_mcp.engines.math_engine import verify_math_expression
        
        result = verify_math_expression("x**2", "2*x", "derivative")
        assert result["verified"] is True

    def test_derivative_wrong(self):
        from qwed_mcp.engines.math_engine import verify_math_expression
        
        result = verify_math_expression("x**2", "3*x", "derivative")
        assert result["verified"] is False

    def test_integral_correct(self):
        from qwed_mcp.engines.math_engine import verify_math_expression
        
        result = verify_math_expression("2*x", "x**2", "integral")
        assert result["verified"] is True

    def test_simplify_correct(self):
        from qwed_mcp.engines.math_engine import verify_math_expression
        
        result = verify_math_expression("(x+1)**2 - x**2 - 2*x", "1", "simplify")
        assert result["verified"] is True


class TestLogicEngine:
    """Tests for the logic verification engine."""

    def test_valid_syllogism(self):
        from qwed_mcp.engines.logic_engine import verify_logic_statement
        
        result = verify_logic_statement(
            premises=["A implies B", "A"],
            conclusion="B"
        )
        assert result["verified"] is True

    def test_invalid_argument(self):
        from qwed_mcp.engines.logic_engine import verify_logic_statement
        
        result = verify_logic_statement(
            premises=["A implies B", "B"],
            conclusion="A"
        )
        assert result["verified"] is False


class TestCodeEngine:
    """Tests for the code security engine."""

    def test_dangerous_eval(self):
        from qwed_mcp.engines.code_engine import verify_code_safety
        
        result = verify_code_safety("eval(input())", "python")
        assert result["verified"] is False
        assert len(result["issues"]) > 0

    def test_safe_code(self):
        from qwed_mcp.engines.code_engine import verify_code_safety
        
        result = verify_code_safety("def add(a, b): return a + b", "python")
        assert result["verified"] is True
        assert len(result["issues"]) == 0


class TestSQLEngine:
    """Tests for the SQL verification engine."""

    def test_sql_injection_detected(self):
        from qwed_mcp.engines.sql_engine import verify_sql_query
        
        result = verify_sql_query("SELECT * FROM users WHERE id = '1' OR '1'='1'")
        assert result["verified"] is False

    def test_safe_query(self):
        from qwed_mcp.engines.sql_engine import verify_sql_query
        
        result = verify_sql_query("SELECT name, email FROM users WHERE id = ?")
        assert result["verified"] is True

    def test_drop_table_detected(self):
        from qwed_mcp.engines.sql_engine import verify_sql_query
        
        result = verify_sql_query("DROP TABLE users")
        assert result["verified"] is False
