"""
SQL Verification Engine

Validates a SQL query by parsing it, not by matching patterns in its text.
A query passes only when it parses as exactly one statement of an admitted
kind (SELECT, INSERT, UPDATE or DELETE), and none of the checks below finds
an issue. Anything the parser cannot read is refused, so the absence of a
finding is never taken for an assurance about text that was not analysed.
"""

import logging
from typing import Iterable, List, Optional

import sqlglot
from sqlglot import exp
from sqlglot.errors import SqlglotError

logger = logging.getLogger("qwed-mcp.engines.sql")

# Statement kinds that may appear anywhere other than the root. A nested DML
# statement (WITH d AS (DELETE ... RETURNING *) SELECT ...) is refused too.
_STATEMENT_TYPES = (
    exp.Alter,
    exp.Analyze,
    exp.Attach,
    exp.Cache,
    exp.Command,
    exp.Commit,
    exp.Copy,
    exp.Create,
    exp.Delete,
    exp.Describe,
    exp.Detach,
    exp.Drop,
    exp.Grant,
    exp.Insert,
    exp.Install,
    exp.Kill,
    exp.LoadData,
    exp.Merge,
    exp.Pragma,
    exp.Refresh,
    exp.Revoke,
    exp.Rollback,
    exp.Set,
    exp.Transaction,
    exp.TruncateTable,
    exp.Uncache,
    exp.Update,
    exp.Use,
)

_ROOT_TYPES = (exp.Select, exp.Insert, exp.Update, exp.Delete)

# Boolean connectives a condition is split on before its parts are checked.
_CONNECTIVES = (exp.And, exp.Or, exp.Xor)


def verify_sql_query(
    query: str,
    allowed_tables: Optional[List[str]] = None,
    dialect: Optional[str] = None,
) -> dict:
    """
    Verify a SQL query for injection patterns and schema compliance.

    Args:
        query: The SQL query to verify
        allowed_tables: Optional list of allowed table names. A name may be
            qualified (``schema.table``); an unqualified name matches the
            table part of a qualified one.
        dialect: Optional sqlglot dialect to parse with (for example
            ``"mysql"`` for backtick-quoted identifiers). The default is the
            dialect-neutral parser.

    Returns:
        Verification result with issues if any
    """
    issues = sql_issues(query, allowed_tables=allowed_tables, dialect=dialect)
    if issues:
        return {
            "verified": False,
            "message": f"Found {len(issues)} issue(s) in SQL query",
            "issues": issues,
        }
    return {
        "verified": True,
        "message": "SQL query passed verification",
        "issues": [],
    }


def sql_issues(
    query: str,
    allowed_tables: Optional[List[str]] = None,
    dialect: Optional[str] = None,
) -> List[str]:
    """Why ``query`` does not pass; an empty list when it does."""
    if not isinstance(query, str) or not query.strip():
        return ["Empty query: nothing was analysed, no assurance produced"]

    lexical = _lexical_issues(query, dialect)
    if lexical:
        return lexical

    try:
        statements = [
            statement
            for statement in sqlglot.parse(query, read=dialect)
            if statement is not None
        ]
    except (SqlglotError, ValueError, RecursionError) as e:
        return [f"Query could not be parsed, no assurance produced: {type(e).__name__}"]

    if len(statements) != 1:
        return [
            f"Expected exactly one SQL statement, found {len(statements)}: "
            "no assurance produced"
        ]

    root = statements[0]
    issues: List[str] = []
    issues.extend(_statement_issues(root))
    issues.extend(_condition_issues(root))
    issues.extend(_function_issues(root))
    if allowed_tables is not None:
        issues.extend(_table_issues(root, allowed_tables))
    return list(dict.fromkeys(issues))


_CLOSERS = {"'": "'", '"': '"', "`": "`"}
# Brackets quote identifiers only in these dialects; elsewhere they are
# array subscripts and their contents are scanned like any other text.
_BRACKET_DIALECTS = frozenset({"tsql", "sqlite"})


def _quoted_end(query: str, start: int, closers: dict):
    """The index after the quoted string or identifier opening at
    ``start``, or an issue when it is unterminated or holds a backslash."""
    opener = query[start]
    closer = closers[opener]
    j = start + 1
    while j < len(query):
        if opener in "'\"" and query[j] == "\\":
            return "Backslash inside a string literal is not admitted"
        if query[j] != closer:
            j += 1
        elif opener != "[" and query.startswith(closer * 2, j):
            j += 2  # a doubled quote is an escaped quote
        else:
            return j + 1
    return "Unterminated quoted string or identifier"


def _comment_end(query: str, start: int):
    """The index after a comment starting at ``start`` (None when there is
    none), or an issue for a comment form databases read differently."""
    if query.startswith("--", start):
        following = query[start + 2 : start + 3]
        if following and not following.isspace():
            return "'--' not followed by whitespace is not admitted"
        newline = query.find("\n", start)
        return len(query) if newline == -1 else newline + 1
    if query.startswith("/*", start):
        return "Block comment is not admitted"
    if query[start] == "#":
        return "'#' outside a string is not admitted"
    return None


def _lexical_issues(query: str, dialect: Optional[str] = None) -> List[str]:
    """Comment and quoting forms that databases do not read the same way.

    A ``--`` comment is kept only when whitespace follows it (MySQL reads
    ``--x`` as two minus signs). Block comments are refused because MySQL runs
    the text of ``/*! ... */``, ``#`` because only some databases read it as a
    comment, and a backslash inside a quoted string because only some
    databases read it as an escape.
    """
    closers = dict(_CLOSERS)
    if (dialect or "").lower() in _BRACKET_DIALECTS:
        closers["["] = "]"
    i = 0
    while i < len(query):
        if query[i] in closers:
            step = _quoted_end(query, i, closers)
        else:
            step = _comment_end(query, i)
            if step is None:
                step = i + 1
        if isinstance(step, str):
            return [step]
        i = step
    return []


def _statement_issues(root: exp.Expression) -> List[str]:
    issues = []
    if not isinstance(root, _ROOT_TYPES):
        issues.append(
            f"Statement type {type(root).__name__.upper()} is not admitted "
            "(only SELECT, INSERT, UPDATE and DELETE)"
        )
    if isinstance(root, exp.Select) and root.args.get("into"):
        issues.append("SELECT ... INTO is not admitted")
    if isinstance(root, (exp.Update, exp.Delete)) and not root.args.get("where"):
        kind = "UPDATE" if isinstance(root, exp.Update) else "DELETE"
        issues.append(f"Warning: {kind} without WHERE clause")
    for node in root.find_all(_STATEMENT_TYPES):
        if node is not root:
            issues.append(
                f"Nested {type(node).__name__.upper()} statement is not admitted"
            )
    for node in root.find_all(exp.SetOperation):
        issues.append(f"Set operation {type(node).__name__.upper()} is not admitted")
    return issues


def _condition_parts(condition: exp.Expression) -> Iterable[exp.Expression]:
    """The parts of a condition joined by AND/OR/XOR, through NOT and parens."""
    if isinstance(condition, _CONNECTIVES):
        yield from _condition_parts(condition.this)
        yield from _condition_parts(condition.expression)
    elif isinstance(condition, (exp.Not, exp.Paren)):
        yield from _condition_parts(condition.this)
    else:
        yield condition


def _data_free(node: exp.Expression) -> bool:
    """Whether ``node`` reads no column and no bound parameter."""
    if isinstance(node, (exp.Column, exp.Placeholder, exp.Parameter)):
        return False
    return not any(node.find_all(exp.Column, exp.Placeholder, exp.Parameter))


def _self_comparison(node: exp.Expression) -> bool:
    """``x = x`` and the like: true for every row where x is not NULL."""
    if isinstance(node, (exp.EQ, exp.GTE, exp.LTE, exp.NullSafeEQ)):
        return node.this == node.expression
    return False


def _condition_issues(root: exp.Expression) -> List[str]:
    conditions = []
    for clause in root.find_all(exp.Where, exp.Having):
        conditions.append(clause.this)
    for join in root.find_all(exp.Join):
        if join.args.get("on") is not None:
            conditions.append(join.args["on"])
    issues = []
    for condition in conditions:
        for part in _condition_parts(condition):
            if _data_free(part):
                issues.append(
                    f"Suspicious tautology detected: constant condition '{part.sql()}'"
                )
            elif _self_comparison(part):
                issues.append(
                    f"Suspicious tautology detected: self-comparison '{part.sql()}'"
                )
    return issues


def _function_issues(root: exp.Expression) -> List[str]:
    """Functions the parser does not know (vendor procedures such as
    xp_cmdshell, pg_sleep or load_file) are refused rather than guessed."""
    return [
        f"Function '{node.name}' is not admitted"
        for node in root.find_all(exp.Anonymous)
    ]


def _identifier_key(identifier) -> str:
    """How a database resolves a name: unquoted identifiers fold to lower
    case, quoted ones keep their case ("USERS" and users differ)."""
    if isinstance(identifier, exp.Identifier):
        return identifier.name if identifier.quoted else identifier.name.lower()
    return str(identifier or "").lower()


def _cte_key(cte: exp.CTE) -> str:
    alias = cte.args.get("alias")
    return _identifier_key(alias.this if alias is not None else None)


def _visible_ctes(node: exp.Expression):
    """The CTEs a WITH on ``node`` itself defines."""
    for value in node.args.values():
        if isinstance(value, exp.With):
            yield from value.expressions


def _is_write_target(table: exp.Table) -> bool:
    """The table an INSERT, UPDATE or DELETE writes: always a stored table,
    whatever CTE shares its name."""
    parent = table.parent
    if isinstance(parent, (exp.Insert, exp.Update, exp.Delete)):
        return parent.this is table
    return (
        isinstance(parent, exp.Schema)
        and isinstance(parent.parent, exp.Insert)
        and parent.parent.this is parent
    )


def _is_cte_reference(table: exp.Table) -> bool:
    """Whether ``table`` names a CTE rather than a stored table.

    It must be unqualified, read rather than written, and a CTE with its name
    (compared as the database resolves names) must be defined by a WITH on
    one of its enclosing queries, outside that CTE's own body
    (``WITH t AS (SELECT * FROM t)`` reads the stored table ``t``). A CTE in
    an unrelated subquery does not count.
    """
    if table.args.get("db") or table.args.get("catalog") or _is_write_target(table):
        return False
    key = _identifier_key(table.this)
    inside = set()
    node = table.parent
    while node is not None:
        if isinstance(node, exp.CTE):
            inside.add(id(node))
        for cte in _visible_ctes(node):
            if _cte_key(cte) == key and id(cte) not in inside:
                return True
        node = node.parent
    return False


def _table_allowed(table: exp.Table, allowed: set) -> bool:
    """Whether ``table`` is in ``allowed``, by its table part or its full
    qualified name. Each part is compared as the database resolves it: an
    unquoted identifier case-insensitively, a quoted one exactly, so
    ["users"] does not admit "Users" but ["Users"] does."""
    parts = [part for part in table.parts if isinstance(part, exp.Identifier)]
    for entry in allowed:
        wanted = entry.split(".")
        if len(wanted) > len(parts):
            continue
        tail = parts[len(parts) - len(wanted) :]
        if len(wanted) not in (1, len(parts)):
            continue
        if all(
            part.name == want if part.quoted else part.name.lower() == want.lower()
            for part, want in zip(tail, wanted)
        ):
            return True
    return False


def _table_issues(root: exp.Expression, allowed_tables: List[str]) -> List[str]:
    allowed = {name.strip() for name in allowed_tables if name and name.strip()}
    unauthorized = []
    for table in root.find_all(exp.Table):
        name = table.name
        if not name:
            return ["Could not determine an accessed table: no assurance produced"]
        if _is_cte_reference(table):
            continue
        if not _table_allowed(table, allowed):
            qualified = ".".join(
                part.name for part in table.parts if isinstance(part, exp.Identifier)
            )
            unauthorized.append(qualified or name)
    if unauthorized:
        return [f"Unauthorized table access: {', '.join(sorted(set(unauthorized)))}"]
    return []


def extract_tables(query: str, dialect: Optional[str] = None) -> List[str]:
    """Table names (the table part of any qualified name) the query reads or
    writes; an empty list when the query does not parse."""
    try:
        statements = sqlglot.parse(query, read=dialect)
    except (SqlglotError, ValueError, RecursionError):
        return []
    names = set()
    for statement in statements:
        if statement is None:
            continue
        for table in statement.find_all(exp.Table):
            if table.name and not _is_cte_reference(table):
                names.add(table.name)
    return sorted(names)
