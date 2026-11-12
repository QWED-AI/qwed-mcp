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
# Operator words are never proposition names: "A and not" has no operand
# after "not", and must not become a variable called "not".
_RESERVED = frozenset({"all", "and", "are", "if", "implies", "is", "not", "or", "then"})


class UnsupportedStatementError(ValueError):
    """A statement the engine cannot read as propositional logic."""


def _unverifiable(message: str, error: str) -> dict:
    return {
        "verified": False,
        "verification_mode": UNVERIFIABLE,
        "message": message,
        "error": error,
    }


class _StatementParser:
    """Reads the small propositional language into Z3 terms."""

    def __init__(self, z3) -> None:
        self.z3 = z3
        self.variables = {}

    def variable(self, name: str):
        name = name.strip()
        if not _VARIABLE.match(name) or name in _RESERVED:
            raise UnsupportedStatementError(
                f"'{name}' is not a proposition name (letters, digits, underscores)"
            )
        if name not in self.variables:
            self.variables[name] = self.z3.Bool(name)
        return self.variables[name]

    def parse(self, stmt: str):
        if not isinstance(stmt, str) or not stmt.strip():
            raise UnsupportedStatementError("Empty statement")
        stmt = stmt.strip().lower()
        z3 = self.z3

        # "if A then B and C" reads A -> (B and C), so the conditional is
        # split before any connective inside it.
        if stmt.startswith("if ") and " then " in stmt:
            left, right = stmt[3:].split(" then ", 1)
            return z3.Implies(self.parse(left), self.parse(right))
        if stmt.startswith("not "):
            return z3.Not(self.parse(stmt[4:]))
        if " implies " in stmt:
            left, right = stmt.split(" implies ", 1)
            return z3.Implies(self.parse(left), self.parse(right))
        if " and " in stmt:
            return z3.And([self.parse(part) for part in stmt.split(" and ")])
        if " or " in stmt:
            return z3.Or([self.parse(part) for part in stmt.split(" or ")])
        if " are " in stmt:  # "all X are Y"
            left, right = stmt.split(" are ", 1)
            return z3.Implies(
                self.variable(left.replace("all ", "")), self.variable(right)
            )
        # "X is Y" has no single propositional reading (identity, membership,
        # implication), and reading it as X alone drops Y. Refuse it (#26).
        if " is " in stmt:
            raise UnsupportedStatementError(
                f"'{stmt}': 'is' statements are not supported; "
                "write them with 'implies', 'and', 'or' or 'not'"
            )
        return self.variable(stmt)


def _decide(z3, premises, conclusion) -> dict:
    """Proof by contradiction: premises AND NOT(conclusion) is UNSAT exactly
    when the premises imply the conclusion."""
    solver = z3.Solver()
    for premise in premises:
        solver.add(premise)
    solver.add(z3.Not(conclusion))
    result = solver.check()

    if result == z3.unsat:
        return {
            "verified": True,
            "verification_mode": PROVEN,
            "message": "The conclusion logically follows from the premises",
            "method": "proof by contradiction (Z3 SMT solver)",
        }
    if result == z3.sat:
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
        import z3
    except ImportError:
        return _unverifiable(
            "Z3 solver not installed. Install with: pip install z3-solver",
            "ImportError",
        )

    if not isinstance(premises, list) or not all(isinstance(p, str) for p in premises):
        return _unverifiable(
            "Premises must be a list of strings", "UnsupportedStatementError"
        )

    parser = _StatementParser(z3)
    try:
        parsed_premises = [parser.parse(premise) for premise in premises]
        parsed_conclusion = parser.parse(conclusion)
    except Exception as e:  # UnsupportedStatementError, or z3 rejects a construct
        return _unverifiable(f"Could not parse logic statements: {e}", str(e))

    try:
        return _decide(z3, parsed_premises, parsed_conclusion)
    except Exception as e:
        logger.error(f"Logic verification failed: {e}")
        return _unverifiable(f"Verification error: {e}", str(e))
