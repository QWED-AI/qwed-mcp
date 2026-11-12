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
    # a CTE named after the stored table it reads does not hide that read
    ("WITH secret AS (SELECT * FROM secret) SELECT * FROM secret", ["users"], None),
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
    assert extract_tables("WITH t AS (SELECT * FROM t) SELECT * FROM t") == ["t"]


def test_empty_allowlist_admits_no_table():
    result = verify_sql_query("SELECT * FROM secret", allowed_tables=[])
    assert result["verified"] is False


def test_null_safe_self_comparison_is_refused():
    query = "UPDATE users SET is_admin = 1 WHERE id IS NOT DISTINCT FROM id"
    assert verify_sql_query(query, dialect="postgres")["verified"] is False


def test_quoted_table_name_keeps_its_case():
    allowed = ["users"]
    query = 'SELECT * FROM "Users"'
    assert verify_sql_query(query, allowed, dialect="postgres")["verified"] is False
    query = 'SELECT * FROM "users"'
    assert verify_sql_query(query, allowed, dialect="postgres")["verified"] is True
    assert verify_sql_query("SELECT * FROM Users", allowed)["verified"] is True


def test_quoted_name_is_not_resolved_to_an_unquoted_cte():
    # In PostgreSQL "USERS" is a stored table, not the CTE users.
    query = 'WITH users AS (SELECT 1 AS id) SELECT * FROM "USERS"'
    assert verify_sql_query(query, ["users"], dialect="postgres")["verified"] is False
    assert extract_tables(query, dialect="postgres") == ["USERS"]


def test_unquoted_name_resolves_to_the_cte_in_any_case():
    query = "WITH users AS (SELECT id FROM accounts) SELECT * FROM USERS"
    assert verify_sql_query(query, ["accounts"])["verified"] is True
    assert extract_tables(query) == ["accounts"]


def test_cte_in_an_unrelated_subquery_does_not_hide_a_table():
    query = (
        "SELECT s.* FROM secret AS s CROSS JOIN "
        "(WITH secret AS (SELECT 1 AS id) SELECT id FROM secret) AS x"
    )
    assert verify_sql_query(query, ["users"])["verified"] is False
    assert "secret" in extract_tables(query)


@pytest.mark.parametrize(
    "query",
    [
        "WITH secret AS (SELECT id FROM users) UPDATE secret SET flag = 1 WHERE id = 7",
        "WITH secret AS (SELECT id FROM users) DELETE FROM secret WHERE id = 7",
        "WITH secret AS (SELECT id FROM users) INSERT INTO secret (id) VALUES (7)",
    ],
)
def test_write_target_named_like_a_cte_is_checked(query):
    result = verify_sql_query(query, ["users"], dialect="postgres")
    assert result["verified"] is False
    assert "secret" in extract_tables(query, dialect="postgres")


def test_quoted_mixed_case_table_can_be_allowed_by_its_exact_name():
    query = 'SELECT * FROM "Users"'
    assert verify_sql_query(query, ["Users"], dialect="postgres")["verified"] is True
    assert verify_sql_query(query, ["users"], dialect="postgres")["verified"] is False


def test_brackets_are_subscripts_outside_tsql():
    # In PostgreSQL a block comment inside a subscript is still a comment.
    query = "SELECT arr[1 /*! OR 1=1 */] FROM t WHERE id = 1"
    assert verify_sql_query(query, dialect="postgres")["verified"] is False
    assert (
        verify_sql_query("SELECT arr[1] FROM t WHERE id = 1", dialect="postgres")[
            "verified"
        ]
        is True
    )


def test_comparison_inside_a_function_is_checked():
    query = "UPDATE users SET is_admin = TRUE WHERE COALESCE(id = id, TRUE)"
    assert verify_sql_query(query)["verified"] is False


def test_sibling_subquery_cte_does_not_hide_a_table():
    query = (
        "SELECT * FROM (SELECT * FROM secret) AS s, "
        "(WITH secret AS (SELECT 1) SELECT * FROM secret) AS c"
    )
    assert verify_sql_query(query, [])["verified"] is False


def test_later_cte_is_not_visible_to_an_earlier_one():
    query = (
        "WITH first AS (SELECT * FROM secret), secret AS (SELECT 1) SELECT * FROM first"
    )
    assert verify_sql_query(query, ["users"], dialect="postgres")["verified"] is False


def test_earlier_cte_is_visible_to_a_later_one():
    query = "WITH a AS (SELECT id FROM users), b AS (SELECT id FROM a) SELECT * FROM b"
    assert verify_sql_query(query, ["users"])["verified"] is True


def test_quoted_dotted_name_is_not_a_qualified_name():
    allowed = ["public.users"]
    query = 'SELECT * FROM "public.users"'
    assert verify_sql_query(query, allowed, dialect="postgres")["verified"] is False
    # A table whose own name contains a dot is allowed by a quoted entry.
    query = 'SELECT * FROM "audit.events"'
    quoted_entry = verify_sql_query(query, ['"audit.events"'], dialect="postgres")
    assert quoted_entry["verified"] is True
    dotted_entry = verify_sql_query(query, ["audit.events"], dialect="postgres")
    assert dotted_entry["verified"] is False


def test_mixed_case_entry_admits_only_the_quoted_name():
    assert (
        verify_sql_query('SELECT * FROM "Users"', ["Users"], dialect="postgres")[
            "verified"
        ]
        is True
    )
    assert (
        verify_sql_query("SELECT * FROM users", ["Users"], dialect="postgres")[
            "verified"
        ]
        is False
    )


def test_tsql_update_through_a_cte_checks_its_body():
    query = "WITH x AS (SELECT id, flag FROM users) UPDATE x SET flag = 1 WHERE id = 7"
    assert verify_sql_query(query, ["users"], dialect="tsql")["verified"] is True
    query = "WITH x AS (SELECT id, flag FROM secret) UPDATE x SET flag = 1 WHERE id = 7"
    assert verify_sql_query(query, ["users"], dialect="tsql")["verified"] is False
