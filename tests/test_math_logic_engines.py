"""Math and logic engines: fail closed on what they cannot decide.

Covers #15 (unknown math operations), #16 (parse failures reported as
refutations), #26 ('is' statements that dropped an operand) and the parser
half of #25 (eagerly evaluated huge integers).
"""

import time

import pytest

from qwed_mcp.engines.logic_engine import verify_logic_statement
from qwed_mcp.engines.math_engine import verify_math_expression
from qwed_mcp.engines.safe_parser import SafeParserError, safe_parse_expr


# --- #15 -------------------------------------------------------------------


@pytest.mark.parametrize("operation", ["fourier_transform", "laplace", "", "EVALUATE"])
def test_unknown_math_operation_is_refused(operation):
    result = verify_math_expression("x**2", "x**2", operation)
    assert result["verified"] is False
    assert "Unsupported operation" in result["message"]


@pytest.mark.parametrize(
    "expression,claimed,operation",
    [
        ("x**2", "2*x", "derivative"),
        ("2*x", "x**2", "integral"),
        ("(x+1)**2 - x**2 - 2*x", "1", "simplify"),
        ("x - 2", "2", "solve"),
        ("2 + 3", "5", "evaluate"),
    ],
)
def test_supported_math_operations_still_verify(expression, claimed, operation):
    result = verify_math_expression(expression, claimed, operation)
    assert result["operation"] == operation
    assert result["verified"] is True


def test_solve_with_a_missing_root_is_not_verified():
    # x**2 - 4 has roots -2 and 2; claiming only 2 is incomplete.
    assert verify_math_expression("x**2 - 4", "2", "solve")["verified"] is False


# --- #16 and #26 -----------------------------------------------------------


def test_valid_argument_is_proven():
    result = verify_logic_statement(["A implies B", "A"], "B")
    assert result["verified"] is True
    assert result["verification_mode"] == "PROVEN"


def test_invalid_argument_is_disproven():
    result = verify_logic_statement(["A implies B", "A"], "not B")
    assert result["verified"] is False
    assert result["verification_mode"] == "DISPROVEN"


@pytest.mark.parametrize(
    "premises,conclusion",
    [
        (["$$%%^^&&"], "!!@@##"),
        (["A implies B"], ""),
        ([""], "A"),
        (["A is B"], "A"),
        (["A is not B"], "not A"),
        (["A implies"], "A"),
        (["A and not"], "A"),
        (["not"], "A"),
        (["A or and"], "A"),
        (["A"], "A or not"),
    ],
)
def test_unreadable_statement_is_unverifiable(premises, conclusion):
    result = verify_logic_statement(premises, conclusion)
    assert result["verified"] is False
    assert result["verification_mode"] == "UNVERIFIABLE"


def test_conditional_binds_looser_than_and():
    # "if A then B and C" is A -> (B and C): C does not follow on its own.
    result = verify_logic_statement(["if A then B and C"], "C")
    assert result["verification_mode"] == "DISPROVEN"
    result = verify_logic_statement(["if A then B and C", "A"], "C")
    assert result["verification_mode"] == "PROVEN"


def test_keyword_arguments_to_factorial_are_refused():
    with pytest.raises(SafeParserError):
        safe_parse_expr("factorial(100000000, evaluate=True)")


def test_premises_must_be_a_list_of_strings():
    result = verify_logic_statement("A implies B", "B")
    assert result["verification_mode"] == "UNVERIFIABLE"


# --- #25 (parser) ----------------------------------------------------------


@pytest.mark.parametrize(
    "expression",
    [
        "10**10**10",
        "10**10**6",
        "9**9**9",
        "-10**10**10",
        "2*10**10**10",
        "(10**10000)**10000",
        "x**(10**10**6)",
        "factorial(10**9)",
        "factorial(100000)",
        "binomial(10**9, 5)",
        # not valid Python: checked on the code SymPy's transformations produce
        "100000!",
        "(10**9)!",
        "2x + (10**10000)**10000",
        "2x + 10**1_000_000_000",
        "1_000_000_000!",
        # numeric constructors are constants too
        "Integer(10)**1000000000",
        "factorial(Integer(100000000))",
        "Rational(10, 1)**1000000000",
        # factorial and binomial values feed the bounds of what contains them
        "factorial(1000)**1000",
        "binomial(1000, 500)**2000",
        "factorial(100000000)(1)",
        "binomial(-1, 100000000)",
        "2x + 100_000_000!",
    ],
)
def test_expression_beyond_cost_bound_is_refused_quickly(expression):
    start = time.monotonic()
    with pytest.raises(SafeParserError, match="cost bound"):
        safe_parse_expr(expression)
    assert time.monotonic() - start < 5


@pytest.mark.parametrize(
    "expression",
    [
        "x**2",
        "10**100",
        "2**-10",
        "1**(10**100)",
        "factorial(10)",
        "x**(1/2)",
        "(x+1)**3",
        "2x**3",
        "5!",
        "n!",
        "2x**(n+1)",
        # a symbolic power with a bounded exponent stays symbolic
        "2x**10**10",
        "2x**(10**9)",
        "Integer(10)**100",
        "Rational(1, 3)**2",
        "factorial(20)**2",
        "binomial(10, 3)",
        "binomial(x, 3)",
    ],
)
def test_bounded_expression_still_parses(expression):
    safe_parse_expr(expression)


def test_long_flat_expression_is_a_parser_error_or_a_result():
    # A flat sum deeper than the recursion limit must not leak RecursionError.
    expression = "+".join(["1"] * 1200)
    try:
        outcome = safe_parse_expr(expression)
    except SafeParserError as exc:
        outcome = exc
    assert outcome == 1200 or isinstance(outcome, SafeParserError)


def test_math_engine_reports_cost_bound_as_unparseable():
    result = verify_math_expression("10**10**10", "0", "evaluate")
    assert result["verified"] is False
    assert "cost bound" in result["error"]
