"""
Allowlist admission for Python code.

The code engine used to refuse a list of dangerous names. A list of what is
dangerous cannot be complete: process creation outside ``subprocess``,
``importlib``, ``builtins.eval``, rebinding (``f = eval``), computed call
targets, ``operator.methodcaller`` and star imports all reached code execution
with no listed name in the payload (#24, #49 to #54, #57, #59).

So code is now admitted only when everything it reaches is listed here, the
approach qwed-verification's ``CodeVerifier`` takes:

- every module it imports is in ``ADMITTED_MODULES`` and every name it uses
  from a module is listed for that module;
- every builtin it reads is in ``ADMITTED_BUILTINS``, and any other builtin
  name is refused wherever it appears, so it cannot be rebound or passed on;
- a module is used only as ``module.listed_name``, never as a value;
- no special or private attribute (``_x``, ``__x__``) is read or written,
  apart from reading ``__init__`` and ``__name__``, and no frame, code or
  traceback attribute is read;
- no attribute is read by a name made at run time (``str.format`` fields).

The modules listed are standard-library modules that compute without touching
files, the network, processes, the environment or the import system, and in
each, only the names that keep to that. Anything else, third-party packages
included, is not admitted.
"""

from __future__ import annotations

import ast
import builtins
import string
from typing import Dict, FrozenSet, List, Optional, Set


def _names(text: str) -> FrozenSet[str]:
    """The space-separated names in ``text``."""
    return frozenset(text.split())


# Module -> the names code may use from it. A dotted key is a submodule; its
# parent is listed too. ``operator`` is not listed: attrgetter and
# methodcaller read attributes by a name given at run time (#57).
ADMITTED_MODULES: Dict[str, FrozenSet[str]] = {
    "__future__": _names(
        "absolute_import annotations division generator_stop generators "
        "nested_scopes print_function unicode_literals with_statement"
    ),
    # Not ABCMeta: called with a namespace it builds a class whose special
    # attributes (__match_args__, __instancecheck__) come from strings.
    "abc": _names("ABC abstractmethod"),
    "array": _names("array typecodes"),
    "base64": _names(
        "a85decode a85encode b16decode b16encode b32decode b32encode b64decode "
        "b64encode b85decode b85encode standard_b64decode standard_b64encode "
        "urlsafe_b64decode urlsafe_b64encode"
    ),
    "binascii": _names("Error a2b_hex b2a_hex crc32 hexlify unhexlify"),
    "bisect": _names("bisect bisect_left bisect_right insort insort_left insort_right"),
    "calendar": _names(
        "day_abbr day_name isleap leapdays month_abbr month_name monthcalendar "
        "monthrange weekday"
    ),
    "cmath": _names(
        "acos acosh asin asinh atan atanh cos cosh e exp inf infj isclose isfinite "
        "isinf isnan log log10 nan nanj phase pi polar rect sin sinh sqrt tan tanh tau"
    ),
    "collections": _names(
        "ChainMap Counter OrderedDict UserDict UserList UserString defaultdict "
        "deque namedtuple"
    ),
    "collections.abc": _names(
        "AsyncGenerator AsyncIterable AsyncIterator Awaitable Callable Collection "
        "Container Coroutine Generator Hashable ItemsView Iterable Iterator "
        "KeysView Mapping MappingView MutableMapping MutableSequence MutableSet "
        "Reversible Sequence Set Sized ValuesView"
    ),
    "csv": _names(
        "Dialect DictReader DictWriter Error QUOTE_ALL QUOTE_MINIMAL QUOTE_NONE "
        "QUOTE_NONNUMERIC excel excel_tab reader unix_dialect writer"
    ),
    # Not fields, asdict, astuple or replace, which read attributes by the
    # names a Field object holds, and Field objects can be changed.
    "dataclasses": _names("dataclass field"),
    "datetime": _names(
        "MAXYEAR MINYEAR UTC date datetime time timedelta timezone tzinfo"
    ),
    "decimal": _names(
        "BasicContext Context Decimal DecimalException DefaultContext "
        "DivisionByZero ExtendedContext Inexact InvalidOperation Overflow "
        "ROUND_05UP ROUND_CEILING ROUND_DOWN ROUND_FLOOR ROUND_HALF_DOWN "
        "ROUND_HALF_EVEN ROUND_HALF_UP ROUND_UP Rounded Underflow getcontext "
        "localcontext"
    ),
    "difflib": _names(
        "Differ SequenceMatcher context_diff get_close_matches ndiff unified_diff"
    ),
    "enum": _names("Enum Flag IntEnum IntFlag StrEnum auto unique"),
    "fractions": _names("Fraction"),
    # Not singledispatch, wraps or update_wrapper: the first evaluates
    # annotations, the others copy attributes named by strings.
    "functools": _names("cache cmp_to_key lru_cache partial reduce total_ordering"),
    "graphlib": _names("CycleError TopologicalSorter"),
    # Not file_digest, which reads a file object.
    "hashlib": _names(
        "algorithms_available algorithms_guaranteed blake2b blake2s md5 new "
        "pbkdf2_hmac sha1 sha224 sha256 sha384 sha3_224 sha3_256 sha3_384 "
        "sha3_512 sha512 shake_128 shake_256"
    ),
    "heapq": _names(
        "heapify heappop heappush heappushpop heapreplace merge nlargest nsmallest"
    ),
    "hmac": _names("HMAC compare_digest digest new"),
    "html": _names("escape unescape"),
    # In-memory streams only.
    "io": _names("BytesIO StringIO"),
    "itertools": _names(
        "accumulate batched chain combinations combinations_with_replacement "
        "compress count cycle dropwhile filterfalse groupby islice pairwise "
        "permutations product repeat starmap takewhile tee zip_longest"
    ),
    # Not load or dump, which take a file object.
    "json": _names("JSONDecodeError JSONDecoder JSONEncoder dumps loads"),
    "math": _names(
        "acos acosh asin asinh atan atan2 atanh cbrt ceil comb copysign cos cosh "
        "degrees dist e erf erfc exp exp2 expm1 fabs factorial floor fma fmod frexp "
        "fsum gamma gcd hypot inf isclose isfinite isinf isnan isqrt lcm ldexp "
        "lgamma log log10 log1p log2 modf nan nextafter perm pi pow prod radians "
        "remainder sin sinh sqrt sumprod tan tanh tau trunc ulp"
    ),
    "numbers": _names("Complex Integral Number Rational Real"),
    "pprint": _names("pformat pp pprint"),
    "random": _names(
        "Random betavariate choice choices expovariate gammavariate gauss "
        "lognormvariate normalvariate randbytes randint random randrange sample "
        "seed shuffle triangular uniform vonmisesvariate"
    ),
    "re": _names(
        "A ASCII DOTALL I IGNORECASE M MULTILINE Match NOFLAG Pattern S VERBOSE X "
        "error escape findall finditer fullmatch match search split sub subn"
    ),
    "statistics": _names(
        "NormalDist StatisticsError correlation covariance fmean geometric_mean "
        "harmonic_mean linear_regression mean median median_grouped median_high "
        "median_low mode multimode pstdev pvariance quantiles stdev variance"
    ),
    # Not Formatter or Template, which read attributes or items by a name in
    # the template.
    "string": _names(
        "ascii_letters ascii_lowercase ascii_uppercase capwords digits hexdigits "
        "octdigits printable punctuation whitespace"
    ),
    "struct": _names(
        "Struct calcsize error iter_unpack pack pack_into unpack unpack_from"
    ),
    "textwrap": _names("TextWrapper dedent fill indent shorten wrap"),
    "time": _names(
        "gmtime monotonic monotonic_ns perf_counter perf_counter_ns process_time "
        "process_time_ns sleep strftime struct_time time time_ns"
    ),
    # Type hints only; not get_type_hints, ForwardRef or anything else that
    # evaluates a string.
    "typing": _names(
        "Any Callable Dict FrozenSet Iterable Iterator List Mapping Optional "
        "Sequence Set Tuple Union"
    ),
    "unicodedata": _names(
        "bidirectional category combining decimal digit east_asian_width lookup "
        "mirrored name normalize numeric"
    ),
    "zlib": _names("adler32 compress crc32 decompress error"),
}

_EXCEPTIONS: FrozenSet[str] = frozenset(
    name
    for name, value in vars(builtins).items()
    if isinstance(value, type) and issubclass(value, BaseException)
)

# Builtins that compute. Not open, input, eval, exec, compile, __import__,
# getattr, setattr, delattr, hasattr, vars, dir, globals, locals, type,
# memoryview, breakpoint, help, exit, quit or any builtin a later Python adds.
ADMITTED_BUILTINS: FrozenSet[str] = (
    _names(
        "abs aiter all anext any ascii bin bool bytearray bytes callable chr "
        "classmethod complex dict divmod enumerate filter float frozenset hash hex "
        "id int isinstance issubclass iter len list map max min next object oct "
        "ord pow print property range repr reversed round set slice sorted "
        "staticmethod str sum super tuple zip Ellipsis NotImplemented"
    )
    | _EXCEPTIONS
)

# Every other name the builtins module holds. Refused in any position, so a
# refused builtin cannot be bound to another name, passed as an argument,
# shadowed and then deleted, or used as an import alias.
REFUSED_BUILTINS: FrozenSet[str] = frozenset(dir(builtins)) - ADMITTED_BUILTINS

# Special attributes code may read. Writing them is still refused.
_READABLE_SPECIAL_ATTRIBUTES: FrozenSet[str] = _names("__init__ __name__")

# Attributes that lead to frames, code objects or tracebacks, and through
# them to the builtins and every loaded module.
REFUSED_ATTRIBUTES: FrozenSet[str] = _names(
    "ag_await ag_code ag_frame cr_await cr_code cr_frame evaluate f_back "
    "f_builtins f_code f_generator f_globals f_locals f_trace gi_code gi_frame "
    "gi_yieldfrom tb_frame tb_next"
)

# Builtin classes whose positional class pattern matches the subject itself
# (``case int(x)``). Any other class reads the attributes its __match_args__
# names, which code can set from strings.
_SELF_MATCHING_CLASSES: FrozenSet[str] = _names(
    "bool bytearray bytes dict float frozenset int list set str tuple"
)

# str.format and format_map read the attribute a field names.
_FORMAT_METHODS: FrozenSet[str] = _names("format format_map")

_Scope = (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)

# Type parameters (Python 3.12+) bind names too.
try:
    _TYPE_PARAMS: tuple = (ast.TypeVar, ast.ParamSpec, ast.TypeVarTuple)
except AttributeError:  # Python < 3.12 has no type parameters
    _TYPE_PARAMS = ()


def _is_special(name: str) -> bool:
    return len(name) > 4 and name.startswith("__") and name.endswith("__")


def _template_reads_attribute(template: str, depth: int = 0) -> bool:
    """Whether a format template has a field that reads an attribute."""
    if depth > 2:
        return True
    try:
        parsed = list(string.Formatter().parse(template))
    except ValueError:
        return True
    for _, field_name, format_spec, _ in parsed:
        if field_name is not None and "." in field_name:
            return True
        if format_spec and _template_reads_attribute(format_spec, depth + 1):
            return True
    return False


class _Admission:
    """One pass over a parsed module, collecting why it is not admitted."""

    def __init__(self, tree: ast.AST) -> None:
        self.tree = tree
        self.issues: List[str] = []
        self.parents: Dict[int, ast.AST] = {}
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                self.parents[id(child)] = parent
        # Local name -> every dotted module an import binds it to. Imports
        # are not scoped here, so a name bound to two modules is checked
        # against both.
        self.modules: Dict[str, Set[str]] = {}
        # Every name the code binds anywhere, imports included.
        self.bound: Set[str] = set()

    def refuse(self, node: Optional[ast.AST], message: str) -> None:
        line = getattr(node, "lineno", None)
        self.issues.append(f"{message} (line {line})" if line else message)

    def run(self) -> List[str]:
        nodes = list(ast.walk(self.tree))
        for node in nodes:
            self._collect(node)
        for node in nodes:
            self._check(node)
        return self.issues

    # --- pass 1: imports and bound names ---------------------------------

    def _collect(self, node: ast.AST) -> None:
        if isinstance(node, ast.Import):
            self._collect_import(node)
        elif isinstance(node, ast.ImportFrom):
            self._collect_import_from(node)
        for name in self._bound_by(node):
            self.bound.add(name)

    def _scope_of(self, node: ast.AST) -> ast.AST:
        parent = self.parents.get(id(node))
        while parent is not None and not isinstance(parent, _Scope):
            parent = self.parents.get(id(parent))
        return parent if parent is not None else self.tree

    def _module_admitted(self, node: ast.AST, dotted: str) -> bool:
        parts = dotted.split(".")
        for end in range(1, len(parts) + 1):
            prefix = ".".join(parts[:end])
            if prefix not in ADMITTED_MODULES:
                self.refuse(node, f"Module '{prefix}' is not admitted")
                return False
        return True

    def _collect_import(self, node: ast.Import) -> None:
        if isinstance(self._scope_of(node), ast.ClassDef):
            self.refuse(node, "Import in a class body is not admitted")
        for alias in node.names:
            if not self._module_admitted(node, alias.name):
                continue
            if alias.asname:
                self.modules.setdefault(alias.asname, set()).add(alias.name)
            else:
                top = alias.name.split(".")[0]
                self.modules.setdefault(top, set()).add(top)

    def _collect_import_from(self, node: ast.ImportFrom) -> None:
        if isinstance(self._scope_of(node), ast.ClassDef):
            self.refuse(node, "Import in a class body is not admitted")
        if node.level:
            self.refuse(node, "Relative import is not admitted")
            return
        module = node.module or ""
        if not self._module_admitted(node, module):
            return
        for alias in node.names:
            local = alias.asname or alias.name
            if alias.name == "*":
                self.refuse(node, f"Star import from '{module}' is not admitted")
            elif f"{module}.{alias.name}" in ADMITTED_MODULES:
                self.modules.setdefault(local, set()).add(f"{module}.{alias.name}")
            elif alias.name not in ADMITTED_MODULES[module]:
                self.refuse(
                    node, f"Name '{alias.name}' from module '{module}' is not admitted"
                )

    @staticmethod
    def _bound_by(node: ast.AST) -> List[str]:
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            return [node.id]
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return [node.name]
        if isinstance(node, ast.arg):
            return [node.arg]
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            return [
                alias.asname or alias.name.split(".")[0]
                for alias in node.names
                if alias.name != "*"
            ]
        if isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)):
            return [node.name] if node.name else []
        if isinstance(node, ast.MatchMapping):
            return [node.rest] if node.rest else []
        if isinstance(node, (ast.Global, ast.Nonlocal)):
            return list(node.names)
        if isinstance(node, _TYPE_PARAMS):
            return [node.name]
        return []

    # --- pass 2: every identifier, attribute and module use --------------

    def _check(self, node: ast.AST) -> None:
        for name in self._identifiers(node):
            self._check_identifier(node, name)
        if isinstance(node, ast.Name):
            self._check_name(node)
        elif isinstance(node, ast.Attribute):
            self._check_attribute(node)
        elif isinstance(node, ast.MatchClass):
            self._check_class_pattern(node)

    @staticmethod
    def _identifiers(node: ast.AST) -> List[str]:
        if isinstance(node, ast.Name):
            return [node.id]
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return [node.name]
        if isinstance(node, ast.arg):
            return [node.arg]
        if isinstance(node, ast.alias):
            names = [node.asname] if node.asname else []
            return names + [part for part in node.name.split(".") if part != "*"]
        if isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)):
            return [node.name] if node.name else []
        if isinstance(node, ast.MatchMapping):
            return [node.rest] if node.rest else []
        if isinstance(node, (ast.Global, ast.Nonlocal)):
            return list(node.names)
        if isinstance(node, _TYPE_PARAMS):
            return [node.name]
        return []

    def _check_identifier(self, node: ast.AST, name: str) -> None:
        if name in REFUSED_BUILTINS and not (
            name == "__name__"
            and isinstance(node, ast.Name)
            and isinstance(node.ctx, ast.Load)
        ):
            self.refuse(node, f"Name '{name}' is not admitted")
            return
        if not _is_special(name) or name == "__future__":
            return
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return  # defining a special method (__init__, __eq__, ...) is fine
        if (
            name == "__name__"
            and isinstance(node, ast.Name)
            and isinstance(node.ctx, ast.Load)
        ):
            return
        self.refuse(node, f"Special name '{name}' is not admitted")

    def _check_class_pattern(self, node: ast.MatchClass) -> None:
        for attr in node.kwd_attrs:
            self._check_attribute_name(node, attr, write=False)
        if not node.patterns:
            return
        cls = node.cls
        if not (
            isinstance(cls, ast.Name)
            and cls.id in _SELF_MATCHING_CLASSES
            and cls.id not in self.bound
        ):
            self.refuse(
                node,
                "Positional class pattern is admitted only on a builtin class "
                "that matches itself (int, str, list, ...)",
            )

    def _check_name(self, node: ast.Name) -> None:
        name = node.id
        if name in self.modules:
            parent = self.parents.get(id(node))
            if not (
                isinstance(node.ctx, ast.Load)
                and isinstance(parent, ast.Attribute)
                and parent.value is node
            ):
                modules = ", ".join(sorted(self.modules[name]))
                self.refuse(node, f"Module '{modules}' used as a value")
            return
        if not isinstance(node.ctx, ast.Load):
            return
        if name in self.bound or name in ADMITTED_BUILTINS or name == "__name__":
            return
        if name not in REFUSED_BUILTINS and not _is_special(name):
            self.refuse(node, f"Name '{name}' is neither defined nor admitted")

    def _check_attribute(self, node: ast.Attribute) -> None:
        write = not isinstance(node.ctx, ast.Load)
        self._check_attribute_name(node, node.attr, write=write)
        if node.attr in _FORMAT_METHODS and not (
            isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
            and not _template_reads_attribute(node.value.value)
        ):
            self.refuse(
                node,
                f"'.{node.attr}' is admitted only on a string literal whose "
                "fields read no attribute",
            )
        if isinstance(node.value, ast.Name) and node.value.id in self.modules:
            for module in sorted(self.modules[node.value.id]):
                self._check_module_chain(node, module)

    def _check_attribute_name(self, node: ast.AST, attr: str, *, write: bool) -> None:
        if attr.startswith("_"):
            if write or attr not in _READABLE_SPECIAL_ATTRIBUTES:
                self.refuse(node, f"Attribute '{attr}' is not admitted")
            return
        if attr in REFUSED_ATTRIBUTES:
            self.refuse(node, f"Attribute '{attr}' is not admitted")

    def _check_module_chain(self, node: ast.Attribute, module: str) -> None:
        """``module.a.b``: walk submodules, then require a listed name."""
        current = node
        while True:
            attr = current.attr
            submodule = f"{module}.{attr}"
            if submodule in ADMITTED_MODULES:
                parent = self.parents.get(id(current))
                if isinstance(parent, ast.Attribute) and parent.value is current:
                    module, current = submodule, parent
                    continue
                self.refuse(current, f"Module '{submodule}' used as a value")
                return
            if attr not in ADMITTED_MODULES.get(module, frozenset()):
                self.refuse(
                    current, f"Name '{attr}' from module '{module}' is not admitted"
                )
            elif not isinstance(current.ctx, ast.Load):
                self.refuse(current, f"Writing '{module}.{attr}' is not admitted")
            return


def admission_issues(tree: ast.AST) -> List[str]:
    """Why ``tree`` is not admitted; an empty list when it is."""
    return _Admission(tree).run()
