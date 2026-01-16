"""
Math Verification Engine

Uses SymPy for symbolic mathematics verification.
"""

import logging
from typing import Optional

logger = logging.getLogger("qwed-mcp.engines.math")


def verify_math_expression(
    expression: str,
    claimed_result: str,
    operation: str = "evaluate"
) -> dict:
    """
    Verify a mathematical expression using SymPy.
    
    Args:
        expression: The mathematical expression (e.g., "x^2")
        claimed_result: The claimed result (e.g., "2x" for derivative)
        operation: One of "derivative", "integral", "simplify", "solve", "evaluate"
    
    Returns:
        Verification result with verified status and details
    """
    try:
        from sympy import (
            symbols, sympify, diff, integrate, simplify, solve,
            Eq, parse_expr, sqrt, sin, cos, exp, log, pi, E
        )
        from sympy.parsing.sympy_parser import (
            parse_expr, standard_transformations, 
            implicit_multiplication_application, convert_xor
        )
        
        # Common symbol
        x, y, z = symbols('x y z')
        
        # Transformation for parsing
        transformations = standard_transformations + (
            implicit_multiplication_application,
            convert_xor,
        )
        
        # Parse expression
        try:
            expr = parse_expr(
                expression.replace("^", "**"),
                local_dict={"x": x, "y": y, "z": z, "pi": pi, "e": E},
                transformations=transformations
            )
        except Exception as e:
            return {
                "verified": False,
                "message": f"Could not parse expression: {expression}",
                "error": str(e)
            }
        
        # Parse claimed result
        try:
            claimed = parse_expr(
                claimed_result.replace("^", "**"),
                local_dict={"x": x, "y": y, "z": z, "pi": pi, "e": E},
                transformations=transformations
            )
        except Exception as e:
            return {
                "verified": False,
                "message": f"Could not parse claimed result: {claimed_result}",
                "error": str(e)
            }
        
        # Perform operation
        if operation == "derivative":
            actual = diff(expr, x)
        elif operation == "integral":
            actual = integrate(expr, x)
        elif operation == "simplify":
            actual = simplify(expr)
        elif operation == "solve":
            actual = solve(expr, x)
        else:  # evaluate
            actual = simplify(expr)
        
        # Compare results
        if operation == "solve":
            # For solve, check if solutions match
            verified = set(actual) == set([claimed]) if not isinstance(claimed, list) else set(actual) == set(claimed)
        else:
            # For other operations, simplify and compare
            difference = simplify(actual - claimed)
            verified = difference == 0
        
        return {
            "verified": verified,
            "message": "Calculation verified" if verified else "Calculation incorrect",
            "expected": str(actual),
            "actual": str(claimed),
            "operation": operation
        }
        
    except ImportError:
        return {
            "verified": False,
            "message": "SymPy not installed. Install with: pip install sympy",
            "error": "ImportError"
        }
    except Exception as e:
        logger.error(f"Math verification failed: {e}")
        return {
            "verified": False,
            "message": f"Verification error: {str(e)}",
            "error": str(e)
        }
