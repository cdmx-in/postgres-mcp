"""Tests for the read-only query validation guard.

Regression coverage for an arbitrary-file-read issue: a query that "starts with SELECT" and
runs in a READ ONLY transaction can still call built-in functions like ``pg_read_file`` to
read server-side files. ``validate_readonly_query`` rejects those.
"""

import pytest

from postgres_mcp_server import validate_readonly_query


@pytest.mark.parametrize(
    "query",
    [
        "SELECT id, name FROM users WHERE active = true",
        "  select 1  ",
        "SELECT copy_count FROM stats",  # identifier containing 'copy' is fine
        "SELECT file_path FROM audit",   # identifier containing 'file' is fine
        "SELECT (SELECT count(*) FROM orders) AS n",  # subquery, no forbidden fn
    ],
)
def test_allows_plain_select(query):
    validate_readonly_query(query)  # should not raise


@pytest.mark.parametrize(
    "query",
    [
        "SELECT pg_read_file('/etc/passwd')",
        "select PG_READ_FILE('/etc/passwd')",            # case-insensitive
        "SELECT   pg_ls_dir ('/etc')",                    # whitespace before paren
        "SELECT pg_read_binary_file('/etc/shadow')",
        "SELECT pg_stat_file('/etc/passwd')",
        "SELECT lo_export(1, '/tmp/x')",
        "SELECT * FROM dblink('host=x', 'SELECT 1') AS t(a int)",
        "SELECT/* hide */ pg_read_file('/etc/passwd')",   # comment cannot smuggle it
        "SELECT pg_read_file('/etc/passwd') -- trailing comment",
    ],
)
def test_blocks_file_and_external_reads(query):
    with pytest.raises(ValueError):
        validate_readonly_query(query)


@pytest.mark.parametrize(
    "query",
    ["UPDATE users SET x = 1", "DELETE FROM users", "DROP TABLE users", "COPY users TO '/tmp/x'"],
)
def test_blocks_non_select(query):
    with pytest.raises(ValueError):
        validate_readonly_query(query)
