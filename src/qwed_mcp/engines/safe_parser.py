"""
Safe SymPy expression parser for QWED-MCP.

Wraps sympy.parsing.sympy_parser.parse_expr with input validation,
a denylist for dangerous constructs, and a restricted evaluation
namespace.  This module is the ONLY approved entry point for parsing
user-supplied math expressions.

Security fix for GHSA-mw6r-2hvm-4rp2 (CWE-94).
"""

import ast
import re
import unicodedata
from typing import Any, Dict, Optional, Tuple

import sympy
from sympy import (
    E, I, Integer, Float, Rational, Symbol, oo, pi,
)
from sympy.parsing.sympy_parser import (
    parse_expr,
    standard_transformations,
    implicit_multiplication_application,
    convert_xor,
)

__all__ = ["safe_parse_expr", "SafeParserError"]

MAX_EXPRESSION_LENGTH = 5_000

_DENYLIST_PATTERN = re.compile(
    r"(?:"
    r"__import__|__builtins__|__subclasses__|__globals__|__locals__"
    r"|__getattr__|__setattr__|__delattr__|__class__|__bases__|__mro__"
    r"|\beval\b|\bexec\b|\bcompile\b|\bgetattr\b|\bsetattr\b|\bdelattr\b"
    r"|\bimport\b|\bimportlib\b"
    r"|\bos\b|\bsys\b|\bsubprocess\b|\bshutil\b|\bsocket\b"
    r"|\bpopen\b|\bsystem\b|\bspawn\b"
    r"|\bopen\b|\bfile\b|\bpath\b|\bglob\b"
    r"|\bchr\b|\bord\b|\bhex\b|\btype\b|\bvars\b|\bdir\b|\brepr\b"
    r"|\binput\b|\bprint\b|\bbreakpoint\b|\bexit\b|\bquit\b"
    r"|\bcodecs\b|\bcode\b|\bctypes\b"
    r")",
    re.IGNORECASE,
)

_SAFE_GLOBAL_DICT_TEMPLATE: Dict[str, Any] = {"__builtins__": {}}

# CWE-94 hardening (GHSA-2p69-jpm6-jrxh): allow-list the AST node types
# that may appear in a mathematical expression.  Anything outside this
# set -- Attribute access, Subscript, string/bytes constants, lambdas,
# list/tuple displays, comprehensions -- is rejected BEFORE parse_expr
# reaches its internal eval().  The raw-source denylist above is kept as
# defense in depth, but a substring scan of untokenized source cannot by
# itself defend an eval sink: unlisted dunder names (``__getattribute__``,
# ``__func__``, ``__call__``) and string-literal splitting
# (``'__glo'+'bals'+'__'``) both bypass it, and PEP 3131 NFKC identifier
# normalization makes ASCII-only matching unsound.
_ALLOWED_AST_NODES = (
    ast.Expression, ast.BinOp, ast.UnaryOp, ast.Call, ast.Name, ast.Load,
    ast.Add, ast.Sub, ast.Mult, ast.Div, ast.Pow, ast.Mod, ast.FloorDiv,
    ast.USub, ast.UAdd, ast.Constant, ast.keyword,
)

_IMPLICIT_FORBIDDEN_CHARS = re.compile(r"""['"`,\[\]{}:;\\]""")


def _validate_ast_nodes(expression: str) -> None:
    """Reject expressions containing non-arithmetic syntax (CWE-94).

    Runs on the raw input before parse_expr.  Every sandbox-escape
    traversal needs an Attribute or Subscript node, while legitimate
    user math (sqrt(4), 2x, sin(x), x**2 + 1) never does.
    """
    try:
        tree = ast.parse(expression, mode="eval")
    except SyntaxError:
        # Implicit-multiplication input (e.g. "2x", "sin x") is not valid
        # Python and cannot be AST-checked here; restrict the charset so
        # that quotes, subscripts and separators can never reappear in
        # the transformed code.  Attribute access ("." not used as a
        # decimal point) is likewise never legitimate in math input.
        if _IMPLICIT_FORBIDDEN_CHARS.search(expression):
            raise SafeParserError(
                "Expression contains disallowed construct"
            )
        for i, ch in enumerate(expression):
            if ch == "." and not (
                (i > 0 and expression[i - 1].isdigit())
                or (i + 1 < len(expression) and expression[i + 1].isdigit())
            ):
                raise SafeParserError(
                    "Expression contains disallowed construct: attribute access"
                )
        return
    for node in ast.walk(tree):
        if not isinstance(node, _ALLOWED_AST_NODES):
            raise SafeParserError(
                f"Expression contains disallowed syntax: {type(node).__name__}"
            )
        # String/bytes literals are concatenation gadgets; math
        # expressions never need them.
        if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
            raise SafeParserError(
                "Expression contains disallowed string literal"
            )


def _build_safe_local_dict(
    extra_symbols: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    safe: Dict[str, Any] = {
        "x": Symbol("x"), "y": Symbol("y"), "z": Symbol("z"),
        "a": Symbol("a"), "b": Symbol("b"), "c": Symbol("c"),
        "d": Symbol("d"), "f": Symbol("f"), "g": Symbol("g"),
        "h": Symbol("h"), "k": Symbol("k"), "m": Symbol("m"),
        "n": Symbol("n", integer=True, positive=True),
        "p": Symbol("p"), "q": Symbol("q"), "r": Symbol("r"),
        "s": Symbol("s"), "t": Symbol("t"), "u": Symbol("u"),
        "v": Symbol("v"), "w": Symbol("w"),
        "alpha": Symbol("alpha"), "beta": Symbol("beta"),
        "gamma": Symbol("gamma"), "delta": Symbol("delta"),
        "epsilon": Symbol("epsilon"), "zeta": Symbol("zeta"),
        "eta": Symbol("eta"), "theta": Symbol("theta"),
        "iota": Symbol("iota"), "kappa": Symbol("kappa"),
        "mu": Symbol("mu"), "nu": Symbol("nu"),
        "xi": Symbol("xi"), "omicron": Symbol("omicron"),
        "rho": Symbol("rho"), "sigma": Symbol("sigma"),
        "tau": Symbol("tau"), "phi": Symbol("phi"),
        "chi": Symbol("chi"), "psi": Symbol("psi"),
        "omega": Symbol("omega"),
        "pi": pi, "e": E, "E": E, "I": I, "oo": oo,
        "sin": sympy.sin, "cos": sympy.cos, "tan": sympy.tan,
        "cot": sympy.cot, "sec": sympy.sec, "csc": sympy.csc,
        "asin": sympy.asin, "acos": sympy.acos, "atan": sympy.atan,
        "atan2": sympy.atan2,
        "sinh": sympy.sinh, "cosh": sympy.cosh, "tanh": sympy.tanh,
        "log": sympy.log, "ln": sympy.log, "exp": sympy.exp,
        "sqrt": sympy.sqrt, "cbrt": sympy.cbrt,
        "abs": sympy.Abs, "Abs": sympy.Abs,
        "factorial": sympy.factorial, "binomial": sympy.binomial,
        "Integer": Integer, "Float": Float, "Rational": Rational,
        "Symbol": Symbol,
    }
    if extra_symbols:
        for key, value in extra_symbols.items():
            if isinstance(value, (Symbol, sympy.Basic)):
                safe[key] = value
    return safe


class SafeParserError(ValueError):
    pass


def safe_parse_expr(
    expression: str,
    *,
    extra_symbols: Optional[Dict[str, Any]] = None,
    transformations: Optional[Tuple] = None,
) -> Any:
    if not isinstance(expression, str):
        raise SafeParserError(
            f"Expression must be a string, got {type(expression).__name__}"
        )
    stripped = expression.strip()
    if not stripped:
        raise SafeParserError("Expression is empty")
    # PEP 3131: CPython NFKC-normalizes identifiers when eval() compiles
    # the transformed code, so NFKC-equivalent codepoints (mathematical
    # bold letters, fullwidth forms, ...) written in the raw input would
    # bypass the ASCII denylist below.  Normalize first so the denylist
    # and the AST check see what the compiler will see.
    stripped = unicodedata.normalize("NFKC", stripped)
    if len(stripped) > MAX_EXPRESSION_LENGTH:
        raise SafeParserError(
            f"Expression exceeds maximum length of {MAX_EXPRESSION_LENGTH} characters"
        )
    match = _DENYLIST_PATTERN.search(stripped)
    if match:
        raise SafeParserError(
            f"Expression contains disallowed construct: {match.group()!r}"
        )
    _validate_ast_nodes(stripped)
    local_dict = _build_safe_local_dict(extra_symbols)
    if transformations is None:
        transformations = standard_transformations + (
            implicit_multiplication_application,
            convert_xor,
        )
    global_dict = dict(_SAFE_GLOBAL_DICT_TEMPLATE)
    try:
        return parse_expr(
            stripped,
            local_dict=local_dict,
            global_dict=global_dict,
            transformations=transformations,
        )
    except Exception as exc:
        raise ValueError(f"Failed to parse expression: {exc}") from exc
