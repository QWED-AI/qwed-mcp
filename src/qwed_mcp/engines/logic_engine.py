"""
Logic Verification Engine

Uses Z3 SMT solver for logical verification.
"""

import logging
from typing import List

logger = logging.getLogger("qwed-mcp.engines.logic")


def verify_logic_statement(
    premises: List[str],
    conclusion: str
) -> dict:
    """
    Verify a logical argument using Z3 SMT solver.
    
    Args:
        premises: List of premise statements
        conclusion: The conclusion to verify
    
    Returns:
        Verification result with validity status
    """
    try:
        from z3 import Solver, Bool, And, Or, Not, Implies, sat, unsat
        
        # Create solver
        solver = Solver()
        
        # Parse simple propositional logic
        # Format: "A implies B", "A and B", "not A", etc.
        variables = {}
        
        def get_var(name: str):
            name = name.strip()
            if name not in variables:
                variables[name] = Bool(name)
            return variables[name]
        
        def parse_statement(stmt: str):
            stmt = stmt.strip().lower()
            
            # Handle "not"
            if stmt.startswith("not "):
                return Not(parse_statement(stmt[4:]))
            
            # Handle "implies"
            if " implies " in stmt:
                parts = stmt.split(" implies ", 1)
                return Implies(parse_statement(parts[0]), parse_statement(parts[1]))
            
            # Handle "and"
            if " and " in stmt:
                parts = stmt.split(" and ")
                return And([parse_statement(p) for p in parts])
            
            # Handle "or"
            if " or " in stmt:
                parts = stmt.split(" or ")
                return Or([parse_statement(p) for p in parts])
            
            # Handle "if ... then ..."
            if stmt.startswith("if ") and " then " in stmt:
                parts = stmt[3:].split(" then ", 1)
                return Implies(parse_statement(parts[0]), parse_statement(parts[1]))
            
            # Handle "all X are Y" pattern
            if " are " in stmt:
                parts = stmt.split(" are ", 1)
                return Implies(get_var(parts[0].replace("all ", "")), get_var(parts[1]))
            
            # Handle "X is Y" pattern
            if " is " in stmt:
                parts = stmt.split(" is ", 1)
                if parts[1].startswith("not "):
                    return Not(get_var(parts[0]))
                return get_var(parts[0])
            
            # Simple variable
            return get_var(stmt)
        
        try:
            # Add premises
            for premise in premises:
                solver.add(parse_statement(premise))
            
            # Check if conclusion follows
            # We prove by contradiction: if premises AND NOT(conclusion) is UNSAT,
            # then premises imply conclusion
            solver.push()
            solver.add(Not(parse_statement(conclusion)))
            
            result = solver.check()
            
            if result == unsat:
                # Premises + NOT(conclusion) is unsatisfiable
                # Therefore, premises imply conclusion
                return {
                    "verified": True,
                    "message": "The conclusion logically follows from the premises",
                    "method": "proof by contradiction (Z3 SMT solver)"
                }
            else:
                # Found a model where premises are true but conclusion is false
                return {
                    "verified": False,
                    "message": "The conclusion does not logically follow from the premises",
                    "counterexample": "A counterexample exists where premises are true but conclusion is false"
                }
                
        except Exception as e:
            return {
                "verified": False,
                "message": f"Could not parse logic statements: {str(e)}",
                "error": str(e)
            }
            
    except ImportError:
        return {
            "verified": False,
            "message": "Z3 solver not installed. Install with: pip install z3-solver",
            "error": "ImportError"
        }
    except Exception as e:
        logger.error(f"Logic verification failed: {e}")
        return {
            "verified": False,
            "message": f"Verification error: {str(e)}",
            "error": str(e)
        }
