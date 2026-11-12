"""
Logic Verification Engine

Uses Z3 SMT solver for logical verification.

Every result carries a ``verification_mode``:

- ``PROVEN``: the premises entail the conclusion (``verified`` is True);
- ``DISPROVEN``: Z3 found an assignment where the premises hold and the
  conclusion does not;
- ``UNVERIFIABLE``: a statement could not be read as propositional logic, so
  nothing was decided.
"""

import logging
import re
from typing import List

logger = logging.getLogger("qwed-mcp.engines.logic")

PROVEN = "PROVEN"
DISPROVEN = "DISPROVEN"
UNVERIFIABLE = "UNVERIFIABLE"

# A proposition is a plain name: letters, digits and underscores, starting
# with a letter. Anything else is not read as a variable.
_VARIABLE = re.compile(r"[a-z][a-z0-9_]*\Z")


class UnsupportedStatementError(ValueError):
    """A statement the engine cannot read as propositional logic."""


def _unverifiable(message: str, error: str) -> dict:
    return {
        "verified": False,
        "verification_mode": UNVERIFIABLE,
        "message": message,
        "error": error,
    }


def verify_logic_statement(premises: List[str], conclusion: str) -> dict:
    """
    Verify a logical argument using Z3 SMT solver.

    Args:
        premises: List of premise statements
        conclusion: The conclusion to verify

    Returns:
        Verification result with validity status and ``verification_mode``
    """
    try:
        from z3 import Solver, Bool, And, Or, Not, Implies, unsat
    except ImportError:
        return _unverifiable(
            "Z3 solver not installed. Install with: pip install z3-solver",
            "ImportError",
        )

    variables = {}

    def get_var(name: str):
        name = name.strip()
        if not _VARIABLE.match(name):
            raise UnsupportedStatementError(
                f"'{name}' is not a proposition name (letters, digits, underscores)"
            )
        if name not in variables:
            variables[name] = Bool(name)
        return variables[name]

    def parse_statement(stmt: str):
        if not isinstance(stmt, str) or not stmt.strip():
            raise UnsupportedStatementError("Empty statement")
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

        # "X is Y" has no single propositional reading (identity, membership,
        # implication), and reading it as X alone drops Y. Refuse it (#26).
        if " is " in stmt:
            raise UnsupportedStatementError(
                f"'{stmt}': 'is' statements are not supported; "
                "write them with 'implies', 'and', 'or' or 'not'"
            )

        # Simple variable
        return get_var(stmt)

    if not isinstance(premises, list) or not all(isinstance(p, str) for p in premises):
        return _unverifiable(
            "Premises must be a list of strings", "UnsupportedStatementError"
        )

    try:
        parsed_premises = [parse_statement(premise) for premise in premises]
        parsed_conclusion = parse_statement(conclusion)
    except UnsupportedStatementError as e:
        return _unverifiable(f"Could not parse logic statements: {e}", str(e))
    except Exception as e:  # z3 rejects a construct
        return _unverifiable(f"Could not parse logic statements: {e}", str(e))

    try:
        solver = Solver()
        for premise in parsed_premises:
            solver.add(premise)
        # Proof by contradiction: if premises AND NOT(conclusion) is UNSAT,
        # the premises imply the conclusion.
        solver.add(Not(parsed_conclusion))
        result = solver.check()
    except Exception as e:
        logger.error(f"Logic verification failed: {e}")
        return _unverifiable(f"Verification error: {e}", str(e))

    if result == unsat:
        return {
            "verified": True,
            "verification_mode": PROVEN,
            "message": "The conclusion logically follows from the premises",
            "method": "proof by contradiction (Z3 SMT solver)",
        }
    if str(result) == "sat":
        return {
            "verified": False,
            "verification_mode": DISPROVEN,
            "message": "The conclusion does not logically follow from the premises",
            "counterexample": (
                "A counterexample exists where premises are true but "
                "conclusion is false"
            ),
        }
    return _unverifiable(f"Z3 returned {result}", str(result))
