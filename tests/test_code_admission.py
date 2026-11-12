"""Allowlist admission of Python code by the code engine.

The refused payloads are the repro forms from #24, #49, #50, #51, #52, #53,
#54, #57 and #59. Under the old denylist each one returned verified=True.
"""

import pytest

from qwed_mcp.engines.code_engine import verify_code_safety
from qwed_mcp.security.risk_gateway import RiskBasedExecutionGateway


REFUSED = {
    # #24: indirection, network and file access, frames
    "getattr": 'import os\ngetattr(os, "system")("id")',
    "module_dict": 'import os\nos.__dict__["system"]("id")',
    "vars": 'import os\nvars(os)["system"]("id")',
    "globals": 'globals()["eval"]("1")',
    "builtins_subscript": '__builtins__["eval"]("1")',
    "subclasses": "().__class__.__base__.__subclasses__()",
    "socket": "import socket",
    "urllib": 'import urllib.request\nurllib.request.urlopen("https://example.invalid")',
    "httpx": "import httpx",
    "pathlib_read": 'import pathlib\npathlib.Path("/etc/passwd").read_bytes()',
    "sys_getframe": "import sys\nsys._getframe(0).f_globals",
    "inspect_frame": "import inspect\ninspect.currentframe().f_globals",
    "breakpoint": "breakpoint()",
    "generator_frame": "def g():\n    yield 1\ng().gi_frame.f_globals",
    # #49: process creation outside subprocess
    "os_execv": 'import os\nos.execv("/bin/sh", ["sh", "-c", "id"])',
    "os_posix_spawn": 'import os\nos.posix_spawn("/bin/sh", ["/bin/sh"], {})',
    "pty_spawn": 'import pty\npty.spawn(["sh", "-c", "id"])',
    "ctypes": 'import ctypes\nctypes.CDLL(None).system(b"id")',
    "asyncio_subprocess": 'import asyncio\nasyncio.create_subprocess_exec("id")',
    # #50: dynamic imports
    "import_module": 'import importlib\nimportlib.import_module("subprocess")',
    "import_module_concat": 'import importlib\nimportlib.import_module("sub" + "process")',
    "importlib_dunder_import": 'import importlib\nimportlib.__import__("subprocess")',
    # #51: dotted-import alias
    "dotted_import_system": 'import os.path\nos.system("id")',
    "dotted_import_popen": 'import os.path\nos.popen("id").read()',
    # #52: namespace-qualified builtins
    "builtins_eval": 'import builtins\nbuiltins.eval("1+1")',
    "dunder_builtins_eval": '__builtins__.eval("1+1")',
    "builtins_import": 'import builtins\nbuiltins.__import__("subprocess")',
    "builtins_open": 'import builtins\nbuiltins.open("/etc/passwd").read()',
    "from_builtins_eval": 'from builtins import eval\neval("1+1")',
    # #53: rebinding and value positions
    "rebind_eval": 'f = eval\nf("1+1")',
    "rebind_exec": 'g = exec\ng("x = 1")',
    "rebind_os_system": 'import os\ns = os.system\ns("id")',
    "map_eval": 'list(map(eval, ["1+1"]))',
    "rebind_open": 'o = open\no("/etc/passwd").read()',
    "rebind_dunder_import": 'fn = __import__\nfn("os")',
    "pass_eval_as_argument": 'def g(f):\n    return f("1")\ng(eval)',
    # #54: computed call targets
    "getattr_concat": 'getattr(__builtins__, "ev" + "al")("1+1")',
    "walrus_eval": '(f := eval)("1+1")',
    "subscript_eval": '[eval][0]("1+1")',
    # #57: operator.methodcaller / attrgetter
    "methodcaller": 'import os, operator\noperator.methodcaller("system", "id")(os)',
    "attrgetter": 'import operator\noperator.attrgetter("system")',
    # #59: star imports
    "star_os_system": 'from os import *\nsystem("id")',
    "star_os_popen": 'from os import *\npopen("id")',
    "star_pickle_loads": 'from pickle import *\nloads(b"")',
    "star_marshal_loads": 'from marshal import *\nloads(b"")',
    "star_in_function": 'def f():\n    from os import *\n    system("id")',
}


@pytest.mark.parametrize("code", REFUSED.values(), ids=REFUSED.keys())
def test_bypass_payload_is_refused(code):
    result = verify_code_safety(code, "python")
    assert result["verified"] is False
    assert result["issues"]


@pytest.mark.parametrize("code", REFUSED.values(), ids=REFUSED.keys())
def test_gateway_does_not_admit_bypass_payload(monkeypatch, code):
    monkeypatch.setenv("QWED_MCP_TRUSTED_CODE_EXECUTION", "true")
    decision = RiskBasedExecutionGateway().evaluate_and_route(
        "execute_python_code", {"code": code}
    )
    assert decision["verified"] is False
    assert decision["status"] == "BLOCKED"
    assert decision["error_code"] == "QWED-MCP-RISK-005"


# Ways a module, a refused builtin or an attribute could leave the allowlist.
ESCAPES = {
    "module_as_value": "import json\nm = json",
    "module_as_argument": "import json\nprint(json)",
    "submodule_as_value": "import collections\nc = collections.abc",
    "private_module_attribute": 'import random\nrandom._os.system("id")',
    "unlisted_module_attribute": "import typing\ntyping.sys.modules",
    "import_in_class_body": "class A:\n    import math\nA.math",
    "write_module_attribute": "import math\nmath.pi = 3",
    "relative_import": "from . import x",
    "unlisted_from_import": "from functools import singledispatch",
    "get_type_hints": "from typing import get_type_hints",
    "refused_builtin_as_alias": "from math import sqrt as eval",
    "shadow_then_delete": 'eval = 1\ndel eval\neval("1")',
    "type_builtin": "type(1)",
    "function_globals": "def f():\n    pass\nf.__globals__",
    "special_name_assignment": 'class C:\n    __match_args__ = ("x",)',
    "format_reads_attribute": '"{0.__class__}".format(1)',
    "format_on_variable": 'x = "{0.real}"\nx.format(1)',
    "str_format": 'str.format("{0.__class__}", 1)',
    "class_pattern_special": "match 1:\n    case int(__class__=c):\n        pass",
    "traceback_frame": "try:\n    1 / 0\nexcept Exception as e:\n    e.__traceback__.tb_frame",
    "undefined_name": "x = undefined_name",
}


@pytest.mark.parametrize("code", ESCAPES.values(), ids=ESCAPES.keys())
def test_allowlist_escape_is_refused(code):
    result = verify_code_safety(code, "python")
    assert result["verified"] is False


ADMITTED = {
    "print": 'print("hello")',
    "function": "def add(a, b):\n    return a + b\nprint(add(1, 2))",
    "math": "import math\nprint(math.sqrt(2))",
    "from_import_alias": "from math import sqrt as s\nprint(s(4))",
    "submodule": "import collections.abc\nprint(isinstance([], collections.abc.Iterable))",
    "from_submodule": "from collections import abc\nprint(abc.Mapping)",
    "json": 'import json\nprint(json.dumps({"a": 1}))',
    "class_with_init": (
        "class A:\n"
        "    def __init__(self, x):\n"
        "        super().__init__()\n"
        "        self.x = x\n"
        "    def __repr__(self):\n"
        '        return f"A({self.x!r})"\n'
        "print(A(1))"
    ),
    "main_guard": 'if __name__ == "__main__":\n    print("main")',
    "decimal": (
        "from decimal import Decimal, getcontext\n"
        "getcontext().prec = 30\n"
        "print(Decimal(10000) * (1 + Decimal('0.075')) ** 5)"
    ),
    "format_literal": 'print("{} {:>5}".format(1, 2))',
    "dataclass": "from dataclasses import dataclass\n@dataclass\nclass P:\n    x: int\nprint(P(1))",
    "typing_hints": (
        "from __future__ import annotations\n"
        "from typing import List\n"
        "def total(x: List[int]) -> int:\n"
        "    return sum(x)\n"
        "print(total([1, 2]))"
    ),
    "itertools": "import itertools\nprint(list(itertools.permutations([1, 2])))",
    "exception_handler": "try:\n    1 / 0\nexcept ZeroDivisionError as e:\n    print(e.args)",
    "comprehension": "print(sum(i * i for i in range(10)))",
    "match": "match [1, 2]:\n    case [a, b]:\n        print(a + b)",
    "statistics": "import statistics\nprint(statistics.mean([1, 2, 3]))",
    "fractions": "from fractions import Fraction\nprint(Fraction(1, 3) + Fraction(1, 6))",
}


@pytest.mark.parametrize("code", ADMITTED.values(), ids=ADMITTED.keys())
def test_computation_only_code_is_admitted(code):
    result = verify_code_safety(code, "python")
    assert result["issues"] == []
    assert result["verified"] is True


@pytest.mark.parametrize("code", ["", " ", "\n\t ", "# nothing to see here"])
def test_code_with_nothing_to_analyse_is_not_verified(code):
    # #62: no findings in code that was never analysed is no assurance.
    result = verify_code_safety(code, "python")
    assert result["verified"] is False


@pytest.mark.parametrize(
    "code", ["", "var a = 1;", "eval(1)", "el.innerHTML = userInput"]
)
@pytest.mark.parametrize("language", ["javascript", "JavaScript"])
def test_javascript_returns_a_verdict_and_never_admits(code, language):
    # #61: the branch raised re.error on every input.
    result = verify_code_safety(code, language)
    assert result["verified"] is False
    assert result["issues"]


def test_javascript_patterns_still_report_findings():
    result = verify_code_safety("eval(x); el.innerHTML = y", "javascript")
    issues = " ".join(result["issues"])
    assert "eval" in issues
    assert "innerHTML" in issues


def test_unsupported_language_is_not_verified():
    result = verify_code_safety("x", "ruby")
    assert result["verified"] is False
    assert "Unsupported language" in result["message"]


@pytest.mark.parametrize(
    "code",
    [
        "# -*- coding: utf-7 -*-\nprint('x')",
        "#!/usr/bin/env python\n# vim: set fileencoding=latin-1 :\nprint('x')",
        "# coding=no-such-codec\nprint('x')",
        # Line breaks that str.splitlines() and the tokenizer disagree on.
        "x = 1 \x0c y\n# coding: utf-7\nprint('x')",
        "x = 1\x1c\n# coding: utf-7\nprint('x')",
        "# a\rb\n# coding: utf-7\nprint('x')",
        "\x0c# coding: latin-1\nprint('x')",
        "#\x1ccoding: utf-7\nprint('x')",
    ],
)
def test_source_encoding_other_than_utf8_is_refused(code):
    # The interpreter decodes the script file by its coding declaration, so
    # under another codec the code that runs is not the code that was checked.
    result = verify_code_safety(code, "python")
    assert result["verified"] is False
    assert any("encoding declaration" in issue for issue in result["issues"])


@pytest.mark.parametrize(
    "code", ["# -*- coding: utf-8 -*-\nprint('x')", "# coding: UTF8\nprint('x')"]
)
def test_utf8_encoding_declaration_is_admitted(code):
    assert verify_code_safety(code, "python")["verified"] is True


def test_class_built_from_a_namespace_cannot_feed_a_class_pattern():
    code = (
        "import abc\n"
        "M = abc.ABCMeta('M', (abc.ABCMeta,), {'__instancecheck__': lambda s, o: True})\n"
        "C = M('C', (), {'__match_args__': ('__globals__',)})\n"
        "def f():\n"
        "    pass\n"
        "match f:\n"
        "    case C(g):\n"
        "        print(g)\n"
    )
    result = verify_code_safety(code, "python")
    assert result["verified"] is False
    issues = " ".join(result["issues"])
    assert "ABCMeta" in issues
    assert "Positional class pattern" in issues


@pytest.mark.parametrize(
    "code",
    [
        "match 1:\n    case int(x):\n        print(x)",
        "match 'a':\n    case str() | bytes():\n        pass",
    ],
)
def test_builtin_class_patterns_are_admitted(code):
    assert verify_code_safety(code, "python")["verified"] is True


def test_positional_pattern_on_user_class_is_refused():
    code = (
        "from dataclasses import dataclass\n"
        "@dataclass\n"
        "class P:\n"
        "    x: int\n"
        "match P(1):\n"
        "    case P(x):\n"
        "        print(x)\n"
    )
    assert verify_code_safety(code, "python")["verified"] is False


def test_name_imported_as_two_modules_is_checked_against_both():
    # Imports are not scoped by the check, so ``m`` may be either module.
    code = (
        "import math as m\n"
        "def f():\n"
        "    import json as m\n"
        "    print(m.dumps({}))\n"
        "print(m.sqrt(4))"
    )
    result = verify_code_safety(code, "python")
    assert result["verified"] is False
    issues = " ".join(result["issues"])
    assert "'sqrt' from module 'json'" in issues
    assert "'dumps' from module 'math'" in issues
