"""Regression tests for safe_parse_expr sandbox hardening.

Covers GHSA-mw6r-2hvm-4rp2 (original CWE-94 fix) and
GHSA-2p69-jpm6-jrxh (residual bypass of that fix via unlisted dunders
and string-literal splitting).
"""

import pytest

from qwed_mcp.engines.safe_parser import SafeParserError, safe_parse_expr


class TestSandboxEscapeBlocked:
    """Every escape primitive must be rejected before parse_expr's eval."""

    @pytest.mark.parametrize(
        "payload",
        [
            # GHSA-mw6r-2hvm-4rp2: original payload
            "__import__('os').system('id')",
            # GHSA-2p69-jpm6-jrxh: full bypass chain (split tokens +
            # unlisted __getattribute__/__call__ + .get())
            "sqrt.__getattribute__('__glo'+'bals'+'__')"
            ".get('__buil'+'tins'+'__')"
            ".get('__imp'+'ort'+'__').__call__('o'+'s')"
            ".__getattribute__('sy'+'stem').__call__('id')",
            # Attribute traversal primitives
            "x.__class__",
            "x.__getattribute__('__class__')",
            "sqrt.__func__.__globals__",
            "sqrt.__call__(4).__class__",
            "sqrt.__globals__['__builtins__']",
            # String-literal concatenation alone
            "'__glo'+'bals'+'__'",
            # NFKC-encoded dunder (PEP 3131 normalization bypass)
            "x.__\U0001d41c\U0001d425\U0001d41a\U0001d42c\U0001d42c__",
            # Dot/quote smuggled through the implicit-multiplication branch
            "2x.__class__",
            "2x + 'a'",
        ],
    )
    def test_blocked(self, payload):
        with pytest.raises((SafeParserError, ValueError)):
            safe_parse_expr(payload)


class TestLegitimateMathAccepted:
    """Documented math forms must keep working after the hardening."""

    @pytest.mark.parametrize(
        "expression,expected",
        [
            ("sqrt(4)", "2"),
            ("2x", "2*x"),
            ("sin(x)", "sin(x)"),
            ("sin x", "sin(x)"),
            ("x**2+1", "x**2 + 1"),
            ("x^2", "x**2"),
            ("2.5x", "2.5*x"),
            ("1.5 + 2.25", "3.75000000000000"),
            ("factorial(5)", "120"),
            ("binomial(5, 2)", "10"),
            ("log(8, 2)", "3"),
            ("Rational(1, 3)", "1/3"),
            ("pi * 2", "2*pi"),
            ("exp(1)", "E"),
            ("2(x+1)", "2*x + 2"),
            ("x*y + y*x", "2*x*y"),
        ],
    )
    def test_accepted(self, expression, expected):
        result = safe_parse_expr(expression.replace("^", "**"))
        assert str(result) == expected
