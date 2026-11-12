"""
Safe SymPy expression parser for QWED-MCP.

Wraps sympy.parsing.sympy_parser.parse_expr with input validation,
a denylist for dangerous constructs, and a restricted evaluation
namespace.  This module is the ONLY approved entry point for parsing
user-supplied math expressions.

Security fix for GHSA-mw6r-2hvm-4rp2 (CWE-94).
"""

import ast
import math
import re
import unicodedata
from fractions import Fraction
from typing import Any, Dict, Optional, Tuple, Union

import sympy
from sympy import (
    E,
    I,
    Integer,
    Float,
    Rational,
    Symbol,
    oo,
    pi,
)
from sympy.parsing.sympy_parser import (
    parse_expr,
    standard_transformations,
    stringify_expr,
    implicit_multiplication_application,
    convert_xor,
)

__all__ = ["safe_parse_expr", "SafeParserError"]

MAX_EXPRESSION_LENGTH = 5_000


# CWE-400 (#25): parse_expr evaluates integer arithmetic eagerly, so
# ``10**10**10`` or ``factorial(10**9)`` would build a huge integer before any
# check could run. The code SymPy's transformations produce (the same code
# parse_expr then evaluates, with implicit multiplication and ``n!`` already
# rewritten) is checked first. Every constant subexpression gets either its
# exact value or an upper bound on its size, and any operation whose result
# could exceed the bound, or whose cost cannot be bounded, is refused.
MAX_INTEGER_BITS = 1_000_000
MAX_FACTORIAL_ARGUMENT = 10_000

_COST_ERROR = "Expression exceeds the evaluation cost bound"

# Names that stand for constants in the parser's namespace.
_CONSTANT_NAMES = frozenset({"pi", "E", "e", "I", "oo"})

# Functions whose result can be far larger than their argument
# (exp(k * log(n)) evaluates to n**k).
_GROWING_FUNCTIONS = frozenset({"exp", "sinh", "cosh"})


class _Approx:
    """A constant whose exact value is not computed here, with an upper
    bound on its size in bits."""

    __slots__ = ("bits",)

    def __init__(self, bits: int) -> None:
        if bits > MAX_INTEGER_BITS:
            raise SafeParserError(_COST_ERROR)
        self.bits = max(int(bits), 1)


# A value is an exact Fraction, an _Approx, or None when it depends on a
# symbol (SymPy keeps those symbolic, so they cost nothing to build).
_Value = Union[Fraction, _Approx, None]


def _bits(value: Fraction) -> int:
    return max(abs(value.numerator).bit_length(), value.denominator.bit_length())


def _size(value: _Value) -> int:
    return value.bits if isinstance(value, _Approx) else _bits(value)


def _bounded(value: Fraction) -> Fraction:
    if _bits(value) > MAX_INTEGER_BITS:
        raise SafeParserError(_COST_ERROR)
    return value


def _factorial_value(n: _Value) -> _Value:
    if n is None:
        return None
    if isinstance(n, _Approx):
        raise SafeParserError(_COST_ERROR)  # the argument cannot be bounded
    if n.denominator != 1 or n < 0:
        return None  # SymPy gives zoo or a gamma value, not a big integer
    if n > MAX_FACTORIAL_ARGUMENT:
        raise SafeParserError(_COST_ERROR)
    return _bounded(Fraction(math.factorial(int(n))))


def _binomial_value(n: _Value, k: _Value) -> _Value:
    # SymPy multiplies k factors for a negative or non-integer n, so both
    # arguments are bounded, not only n.
    for arg in (n, k):
        if isinstance(arg, _Approx):
            raise SafeParserError(_COST_ERROR)
        if arg is not None and abs(arg) > MAX_FACTORIAL_ARGUMENT:
            raise SafeParserError(_COST_ERROR)
    if n is None or k is None or n.denominator != 1 or k.denominator != 1 or k < 0:
        return None
    n_int, k_int = int(n), int(k)
    if n_int >= 0:
        return _bounded(Fraction(math.comb(n_int, k_int)))
    # For a negative n the value is the sign of k times the binomial of
    # (k - n - 1) and k.
    sign = -1 if k_int % 2 else 1
    return _bounded(Fraction(sign * math.comb(k_int - n_int - 1, k_int)))


def _exact_root(value: Fraction, degree: int) -> Optional[Fraction]:
    if value < 0 or value.denominator != 1:
        return None
    root = round(int(value) ** (1 / degree)) if _bits(value) < 1000 else None
    if root is not None and root**degree == value:
        return Fraction(root)
    return None


def _root_value(args: list, degree: int) -> _Value:
    if len(args) != 1 or args[0] is None:
        return None
    arg = args[0]
    if isinstance(arg, Fraction):
        exact = _exact_root(arg, degree)
        if exact is not None:
            return exact
    return _Approx(_size(arg) // degree + 1)


def _constructor_value(args: list) -> _Value:
    """Integer(n) and Rational(p[, q])."""
    if any(arg is None for arg in args) or not 1 <= len(args) <= 2:
        return None
    if any(isinstance(arg, _Approx) for arg in args):
        return _Approx(sum(_size(arg) for arg in args))
    if len(args) == 2:
        return _bounded(args[0] / args[1]) if args[1] != 0 else None
    return args[0]


def _abs_value(args: list) -> _Value:
    if len(args) != 1 or args[0] is None:
        return None
    return abs(args[0]) if isinstance(args[0], Fraction) else args[0]


_VALUED_CALLS = {
    "factorial": lambda args: _factorial_value(args[0]) if len(args) == 1 else None,
    "binomial": lambda args: (
        _binomial_value(args[0], args[1]) if len(args) == 2 else None
    ),
    "Integer": _constructor_value,
    "Rational": _constructor_value,
    "abs": _abs_value,
    "Abs": _abs_value,
    "sqrt": lambda args: _root_value(args, 2),
    "cbrt": lambda args: _root_value(args, 3),
}


def _call_value(node: ast.Call, args: list) -> _Value:
    """The value or size bound of a call on constants. A call target that is
    itself a call is a child node, so it is bounded on its own."""
    name = node.func.id if isinstance(node.func, ast.Name) else ""
    if name in {"factorial", "binomial"} and node.keywords:
        # evaluate=... and the like change what SymPy computes; refuse them.
        raise SafeParserError(f"Keyword arguments to {name} are not admitted")
    if name in _VALUED_CALLS:
        return _VALUED_CALLS[name](args)
    if name == "Symbol" or any(arg is None for arg in args):
        return None
    sizes = [_size(arg) for arg in args] or [1]
    if name in _GROWING_FUNCTIONS:
        # |exp(x)| <= e**|x| and |x| < 2**bits, so the result has at most
        # 1.45 * 2**bits bits.
        if max(sizes) > 20:
            raise SafeParserError(_COST_ERROR)
        return _Approx(int(1.45 * 2 ** max(sizes)) + 1)
    return _Approx(sum(sizes) + 2)


def _pow_value(left: _Value, right: _Value) -> _Value:
    if right is None:
        return None  # a symbolic exponent stays symbolic
    if isinstance(left, Fraction) and left in (0, 1, -1):
        if isinstance(right, Fraction) and right.denominator == 1:
            return None if left == 0 and right < 0 else left ** int(right)
        return _Approx(2)
    if isinstance(right, _Approx):
        if left is None:
            return None
        raise SafeParserError(_COST_ERROR)  # a constant exponent it cannot bound
    if left is None:
        return None
    if right.denominator != 1:
        # A root of a constant: SymPy may fold it exactly, so keep a bound.
        return _Approx(_size(left) * abs(right.numerator) // right.denominator + 1)
    if abs(right) > MAX_INTEGER_BITS or _size(left) * abs(right) > MAX_INTEGER_BITS:
        raise SafeParserError(_COST_ERROR)
    if isinstance(left, _Approx):
        return _Approx(left.bits * abs(int(right)))
    if left == 0 and right < 0:
        return None  # division by zero: SymPy gives zoo
    return left ** int(right)


def _exact_binop(op: ast.operator, left: Fraction, right: Fraction) -> _Value:
    if isinstance(op, ast.Add):
        return _bounded(left + right)
    if isinstance(op, ast.Sub):
        return _bounded(left - right)
    if isinstance(op, ast.Mult):
        if _bits(left) + _bits(right) > MAX_INTEGER_BITS:
            raise SafeParserError(_COST_ERROR)
        return left * right
    if right == 0:
        return None
    if isinstance(op, ast.Div):
        return _bounded(left / right)
    if isinstance(op, ast.FloorDiv):
        return _bounded(Fraction(left // right))
    if isinstance(op, ast.Mod):
        return _bounded(left % right)
    return None


def _binop_value(op: ast.operator, left: _Value, right: _Value) -> _Value:
    if isinstance(op, ast.Pow):
        return _pow_value(left, right)
    if left is None or right is None:
        return None
    if isinstance(left, Fraction) and isinstance(right, Fraction):
        return _exact_binop(op, left, right)
    if isinstance(op, (ast.Add, ast.Sub)):
        return _Approx(max(_size(left), _size(right)) + 1)
    return _Approx(_size(left) + _size(right))


def _node_value(node: ast.AST, values: dict) -> _Value:
    """The value or size bound of ``node`` from its children's, or None
    when it depends on a symbol."""
    if isinstance(node, ast.Constant):
        value = node.value
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return None
        if isinstance(value, float):
            return _Approx(64)
        return _bounded(Fraction(value))
    if isinstance(node, ast.Name):
        return _Approx(2) if node.id in _CONSTANT_NAMES else None
    if isinstance(node, ast.UnaryOp):
        operand = values.get(id(node.operand))
        if isinstance(node.op, ast.USub) and isinstance(operand, Fraction):
            return -operand
        return operand
    if isinstance(node, ast.BinOp):
        return _binop_value(
            node.op, values.get(id(node.left)), values.get(id(node.right))
        )
    if isinstance(node, ast.Call):
        return _call_value(node, [values.get(id(arg)) for arg in node.args])
    return None


def _check_evaluation_cost(code: str) -> None:
    """Refuse code whose constant arithmetic would exceed the cost bounds.

    The walk is iterative, so a long flat expression cannot exhaust the
    recursion limit.
    """
    try:
        tree = ast.parse(code, mode="eval")
    except (SyntaxError, ValueError, RecursionError, MemoryError) as exc:
        raise SafeParserError(f"Expression could not be checked: {exc}") from exc
    values: dict = {}
    stack = [(tree.body, False)]
    while stack:
        node, children_done = stack.pop()
        if children_done:
            values[id(node)] = _node_value(node, values)
            continue
        stack.append((node, True))
        stack.extend((child, False) for child in ast.iter_child_nodes(node))


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
    ast.Expression,
    ast.BinOp,
    ast.UnaryOp,
    ast.Call,
    ast.Name,
    ast.Load,
    ast.Add,
    ast.Sub,
    ast.Mult,
    ast.Div,
    ast.Pow,
    ast.Mod,
    ast.FloorDiv,
    ast.USub,
    ast.UAdd,
    ast.Constant,
    ast.keyword,
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
            raise SafeParserError("Expression contains disallowed construct")
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
            raise SafeParserError("Expression contains disallowed string literal")


def _build_safe_local_dict(
    extra_symbols: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    safe: Dict[str, Any] = {
        "x": Symbol("x"),
        "y": Symbol("y"),
        "z": Symbol("z"),
        "a": Symbol("a"),
        "b": Symbol("b"),
        "c": Symbol("c"),
        "d": Symbol("d"),
        "f": Symbol("f"),
        "g": Symbol("g"),
        "h": Symbol("h"),
        "k": Symbol("k"),
        "m": Symbol("m"),
        "n": Symbol("n", integer=True, positive=True),
        "p": Symbol("p"),
        "q": Symbol("q"),
        "r": Symbol("r"),
        "s": Symbol("s"),
        "t": Symbol("t"),
        "u": Symbol("u"),
        "v": Symbol("v"),
        "w": Symbol("w"),
        "alpha": Symbol("alpha"),
        "beta": Symbol("beta"),
        "gamma": Symbol("gamma"),
        "delta": Symbol("delta"),
        "epsilon": Symbol("epsilon"),
        "zeta": Symbol("zeta"),
        "eta": Symbol("eta"),
        "theta": Symbol("theta"),
        "iota": Symbol("iota"),
        "kappa": Symbol("kappa"),
        "mu": Symbol("mu"),
        "nu": Symbol("nu"),
        "xi": Symbol("xi"),
        "omicron": Symbol("omicron"),
        "rho": Symbol("rho"),
        "sigma": Symbol("sigma"),
        "tau": Symbol("tau"),
        "phi": Symbol("phi"),
        "chi": Symbol("chi"),
        "psi": Symbol("psi"),
        "omega": Symbol("omega"),
        "pi": pi,
        "e": E,
        "E": E,
        "I": I,
        "oo": oo,
        "sin": sympy.sin,
        "cos": sympy.cos,
        "tan": sympy.tan,
        "cot": sympy.cot,
        "sec": sympy.sec,
        "csc": sympy.csc,
        "asin": sympy.asin,
        "acos": sympy.acos,
        "atan": sympy.atan,
        "atan2": sympy.atan2,
        "sinh": sympy.sinh,
        "cosh": sympy.cosh,
        "tanh": sympy.tanh,
        "log": sympy.log,
        "ln": sympy.log,
        "exp": sympy.exp,
        "sqrt": sympy.sqrt,
        "cbrt": sympy.cbrt,
        "abs": sympy.Abs,
        "Abs": sympy.Abs,
        "factorial": sympy.factorial,
        "binomial": sympy.binomial,
        "Integer": Integer,
        "Float": Float,
        "Rational": Rational,
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
        code = stringify_expr(stripped, local_dict, global_dict, transformations)
    except Exception as exc:
        raise SafeParserError(f"Expression could not be checked: {exc}") from exc
    _check_evaluation_cost(code)
    try:
        return parse_expr(
            stripped,
            local_dict=local_dict,
            global_dict=global_dict,
            transformations=transformations,
        )
    except Exception as exc:
        raise ValueError(f"Failed to parse expression: {exc}") from exc
