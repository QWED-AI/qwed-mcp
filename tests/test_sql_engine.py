"""SQL engine: parse the query, then check it.

The refused statements are the repro lists from #27, #60 (and the three
forms added in its comments) and #62. Each one returned verified=True from
at least one shipped SQL entry point before the parser-based engine.
"""

import pytest

from qwed_mcp.engines.sql_engine import extract_tables, verify_sql_query


REFUSED = {
    # #60: standalone destructive DDL/DCL
    "drop_table": "DROP TABLE users",
    "drop_database": "DROP DATABASE production",
    "truncate": "TRUNCATE TABLE orders",
    "alter": "ALTER TABLE users ADD COLUMN is_admin int",
    "delete_all": "DELETE FROM users",
    "update_all": "UPDATE users SET admin = 1",
    "grant": "GRANT ALL PRIVILEGES TO guest",
    "create_user": "CREATE USER attacker PASSWORD 'x'",
    "exec_xp_cmdshell": "EXEC(xp_cmdshell('whoami'))",
    "stacked": "SELECT 1; DROP TABLE x",
    "leading_semicolon_drop": ";DROP TABLE users",
    # #60: tautologies
    "numeric_tautology": "SELECT * FROM users WHERE id = 1 OR 1=1",
    "quoted_tautology": "SELECT * FROM users WHERE id = '1' OR '1' = '1'",
    "letter_tautology": "SELECT * FROM t WHERE a = 'x' OR 'a' = 'a'",
    "zero_tautology": "SELECT id FROM accounts WHERE x = 0 OR 0 = 0",
    "glued_tautology": "SELECT * FROM users WHERE name = ''OR'1'='1'",
    "parenthesised_tautology": "SELECT * FROM users WHERE id = 1 OR(1)=(1)",
    "in_tautology": "SELECT * FROM t WHERE id = 1 OR 1 IN (1, 2)",
    "true_literal": "SELECT * FROM t WHERE TRUE",
    "self_comparison": "SELECT * FROM t WHERE id = id",
    "tautology_in_update": "UPDATE users SET admin = 1 WHERE 1 = 1",
    "tautology_in_join": "SELECT * FROM a JOIN b ON 1 = 1",
    # #60: set operations
    "union": "SELECT a FROM t UNION SELECT b FROM u",
    "union_all": "SELECT name FROM products UNION ALL SELECT password FROM users",
    "union_parenthesised": "SELECT name FROM products UNION (SELECT password FROM users)",
    # other statement shapes
    "select_into": "SELECT * INTO new_table FROM t",
    "dml_in_cte": "WITH d AS (DELETE FROM users RETURNING *) SELECT * FROM d",
    "unknown_function": "SELECT pg_sleep(5)",
    "load_file": "SELECT load_file('/etc/passwd')",
    # comment and quoting forms databases read differently
    "block_comment": "SELECT * FROM t WHERE a = 1 /*! OR 1=1 */",
    "hash_comment": "SELECT * FROM t WHERE a = 1 # x",
    "dash_dash_without_space": "SELECT * FROM t WHERE a = 1 --1 OR 1=1",
    "backslash_in_string": r"SELECT * FROM t WHERE a = '\' OR a = 1 -- '",
    "unterminated_string": "SELECT * FROM t WHERE a = 'x",
    # #62: nothing to analyse
    "empty": "",
    "blank": "   ",
    "whitespace": "\n\t ",
    "prose": "not sql at all",
    "semicolons": ";;;",
}


@pytest.mark.parametrize("query", REFUSED.values(), ids=REFUSED.keys())
def test_query_is_refused(query):
    result = verify_sql_query(query)
    assert result["verified"] is False
    assert result["issues"]


ADMITTED = {
    "placeholder": "SELECT name, email FROM users WHERE id = ?",
    "named_placeholder": "SELECT * FROM users WHERE id = :id",
    "numbered_placeholder": "SELECT * FROM users WHERE id = $1",
    "insert": "INSERT INTO t (a) VALUES (1)",
    "update_with_where": "UPDATE t SET a = 1 WHERE id = 2",
    "delete_with_where": "DELETE FROM t WHERE id = 3",
    "join": (
        "SELECT u.name FROM users u JOIN orders o ON o.user_id = u.id "
        "WHERE o.total > 10"
    ),
    "cte": "WITH x AS (SELECT id FROM users) SELECT * FROM x",
    "escaped_quote": "SELECT * FROM t WHERE name = 'it''s'",
    "in_list": "SELECT COUNT(*) FROM t WHERE a IN (1, 2)",
    # #31: line comments are not injection
    "trailing_comment": "SELECT a FROM t -- note",
    "comment_between_clauses": (
        "SELECT id, email FROM users  -- only fetch non-PII columns\n"
        "WHERE active = 1"
    ),
}


@pytest.mark.parametrize("query", ADMITTED.values(), ids=ADMITTED.keys())
def test_query_is_admitted(query):
    result = verify_sql_query(query)
    assert result["issues"] == []
    assert result["verified"] is True


def test_quoted_tautology_after_comment_is_still_refused():
    # #31: dropping the blanket '--' rule must not admit this.
    result = verify_sql_query("SELECT * FROM t WHERE a = '' OR '1'='1' -- x")
    assert result["verified"] is False


# #27: quoted and qualified identifiers name the table they read.
TABLE_REFUSED = [
    ("SELECT * FROM `secret_table`", ["users"], "mysql"),
    ('SELECT * FROM "secret_table"', ["users"], None),
    ("SELECT * FROM [secret_table]", ["users"], "tsql"),
    ("SELECT * FROM main.users", ["main"], None),
    ("SELECT * FROM db.schema.secret", ["db"], None),
    ("SELECT * FROM public.secret_data", ["public"], None),
    # backticks under the default parser do not parse, so nothing is admitted
    ("SELECT * FROM `hidden_users`", ["users"], None),
    ("SELECT * FROM users JOIN secret ON secret.id = users.id", ["users"], None),
    ("WITH users AS (SELECT * FROM secret) SELECT * FROM users", ["users"], None),
]


@pytest.mark.parametrize("query,allowed,dialect", TABLE_REFUSED)
def test_unauthorized_table_is_refused(query, allowed, dialect):
    result = verify_sql_query(query, allowed_tables=allowed, dialect=dialect)
    assert result["verified"] is False


TABLE_ADMITTED = [
    ("SELECT * FROM `users`", ["users"], "mysql"),
    ("SELECT * FROM [users]", ["users"], "tsql"),
    ("SELECT * FROM public.users", ["users"], None),
    ("SELECT * FROM public.users", ["public.users"], None),
    ("SELECT * FROM Users", ["users"], None),
    ("WITH x AS (SELECT id FROM users) SELECT * FROM x", ["users"], None),
]


@pytest.mark.parametrize("query,allowed,dialect", TABLE_ADMITTED)
def test_allowed_table_is_admitted(query, allowed, dialect):
    result = verify_sql_query(query, allowed_tables=allowed, dialect=dialect)
    assert result["issues"] == []
    assert result["verified"] is True


def test_extract_tables_returns_the_table_part():
    assert extract_tables("SELECT * FROM db.schema.users") == ["users"]
    assert extract_tables("SELECT * FROM `t`", dialect="mysql") == ["t"]
    assert extract_tables("not sql at all") == []
