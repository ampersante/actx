import unittest
from unittest import mock

from actx_lib.filters import ascii_table_filter

PSQL_TABLE = """\
+----+----------+------------+
| id | username | created_at |
+----+----------+------------+
|  1 | alice    | 2026-01-15 |
|  2 | bob      | 2026-02-03 |
|  7 | charlie  | 2026-08-30 |
+----+----------+------------+
"""

PSQL_COMPACT = """\
id,username,created_at
1,alice,2026-01-15
2,bob,2026-02-03
7,charlie,2026-08-30
"""

MYSQL_TABLE = """\
+----+-------+--------+
| id | name  | role   |
+----+-------+--------+
|  1 | alice | admin  |
|  2 | bob   | editor |
+----+-------+--------+
2 rows in set (0.00 sec)
"""

MYSQL_COMPACT = """\
id,name,role
1,alice,admin
2,bob,editor
2 rows in set (0.00 sec)
"""

# 'a|b' makes the data row split into 3 cells vs the header's 2.
PIPE_VALUE_TABLE = """\
+----+---------+
| id | pattern |
+----+---------+
|  1 | a|b     |
|  2 | x       |
+----+---------+
"""

EMPTY_TABLE = """\
+----+------+
| id | name |
+----+------+
+----+------+
"""

# psql border-0/border-1 aligned output: no frame lines -> out of scope.
UNFRAMED_TEXT = """\
 id | name
----+------
  1 | alice
(1 row)
"""


class CompactTableDoDTests(unittest.TestCase):
    """The five TK-44 DoD fixtures."""

    def test_psql_table_compacts_to_csv(self):
        self.assertEqual(ascii_table_filter.compact_table(PSQL_TABLE), PSQL_COMPACT)

    def test_mysql_table_compacts_and_keeps_footer(self):
        self.assertEqual(ascii_table_filter.compact_table(MYSQL_TABLE), MYSQL_COMPACT)

    def test_pipe_in_value_falls_back_to_raw(self):
        # Red gate 5: dropping the fallback must turn this test red.
        out = ascii_table_filter.compact_table(PIPE_VALUE_TABLE)
        self.assertIs(out, PIPE_VALUE_TABLE)

    def test_empty_table_compacts_to_marker(self):
        self.assertEqual(
            ascii_table_filter.compact_table(EMPTY_TABLE), "id,name\n(0 rows)\n"
        )

    def test_unframed_text_passes_through(self):
        out = ascii_table_filter.compact_table(UNFRAMED_TEXT)
        self.assertIs(out, UNFRAMED_TEXT)


class CompactTableBehaviourTests(unittest.TestCase):
    def test_frames_without_header_yield_marker(self):
        self.assertEqual(ascii_table_filter.compact_table("+----+\n+----+\n"), "(0 rows)\n")

    def test_header_only_table_without_double_frame(self):
        text = "+----+------+\n| id | name |\n+----+------+\n"
        self.assertEqual(ascii_table_filter.compact_table(text), "id,name\n(0 rows)\n")

    def test_lines_around_table_are_preserved(self):
        text = (
            "CREATE TABLE\n"
            "+----+-----+\n"
            "| id | val |\n"
            "+----+-----+\n"
            "|  1 | foo |\n"
            "+----+-----+\n"
            "INSERT 0 1\n"
        )
        expected = "CREATE TABLE\nid,val\n1,foo\nINSERT 0 1\n"
        self.assertEqual(ascii_table_filter.compact_table(text), expected)

    def test_two_tables_in_one_text(self):
        text = (
            "+---+---+\n"
            "| a | b |\n"
            "+---+---+\n"
            "| 1 | 2 |\n"
            "+---+---+\n"
            "mid text\n"
            "+---+---+\n"
            "| c | d |\n"
            "+---+---+\n"
            "| 3 | 4 |\n"
            "+---+---+\n"
        )
        expected = "a,b\n1,2\nmid text\nc,d\n3,4\n"
        self.assertEqual(ascii_table_filter.compact_table(text), expected)

    def test_interior_whitespace_and_commas_preserved_verbatim(self):
        text = (
            "+---------+--------------+\n"
            "| phrase  | names        |\n"
            "+---------+--------------+\n"
            "| a  b    | last, first  |\n"
            "+---------+--------------+\n"
        )
        self.assertEqual(
            ascii_table_filter.compact_table(text), "phrase,names\na  b,last, first\n"
        )

    def test_trailing_whitespace_on_rows_tolerated(self):
        text = (
            "+----+-----+\n"
            "| id | val |   \n"
            "+----+-----+\n"
            "|  1 | foo |  \n"
            "+----+-----+\n"
        )
        self.assertEqual(ascii_table_filter.compact_table(text), "id,val\n1,foo\n")

    def test_no_trailing_newline_preserved(self):
        text = "+---+---+\n| a | b |\n+---+---+\n| 1 | 2 |\n+---+---+"
        self.assertEqual(ascii_table_filter.compact_table(text), "a,b\n1,2")

    def test_lone_frame_line_is_not_a_table(self):
        text = "hello\n+--+\nworld\n"
        self.assertIs(ascii_table_filter.compact_table(text), text)

    def test_plain_text_without_plus_passes_through(self):
        for text in ("", "just text\n", "a\n\nb\n", "| pipe row without frames |\n"):
            self.assertIs(ascii_table_filter.compact_table(text), text, repr(text))


class CompactTableFailOpenTests(unittest.TestCase):
    def test_misaligned_pipes_same_cell_count_fall_back_to_raw(self):
        # Cell count matches (3 vs 3) but interior pipes sit in different
        # columns -- the tell-tale of a '|' swallowed into a value.
        text = (
            "+-----+-------+-----+\n"
            "| a   | bbb   | c   |\n"
            "+-----+-------+-----+\n"
            "|  x | y     | z   |\n"
            "+-----+-------+-----+\n"
        )
        self.assertIs(ascii_table_filter.compact_table(text), text)

    def test_row_not_ending_with_pipe_falls_back_to_raw(self):
        text = "+----+-----+\n| id | val |\n+----+-----+\n|  1 | broken\n+----+-----+\n"
        self.assertIs(ascii_table_filter.compact_table(text), text)

    def test_row_not_starting_with_pipe_falls_back_to_raw(self):
        text = "+----+-----+\n| id | val |\n+----+-----+\nbroken |  1 |\n+----+-----+\n"
        self.assertIs(ascii_table_filter.compact_table(text), text)

    def test_unclosed_frame_block_falls_back_to_raw(self):
        text = "+----+\n| id |\n"
        self.assertIs(ascii_table_filter.compact_table(text), text)

    def test_shorter_data_row_falls_back_to_raw(self):
        text = "+----+-----+\n| id | val |\n+----+-----+\n|  1 |\n+----+-----+\n"
        self.assertIs(ascii_table_filter.compact_table(text), text)

    def test_internal_error_returns_original(self):
        text = PSQL_TABLE
        with mock.patch.object(
            ascii_table_filter, "_compact_block", side_effect=RuntimeError("boom")
        ):
            self.assertIs(ascii_table_filter.compact_table(text), text)

    def test_frame_detect_error_returns_original(self):
        with mock.patch.object(
            ascii_table_filter, "_is_frame", side_effect=RuntimeError("boom")
        ):
            self.assertIs(ascii_table_filter.compact_table(PSQL_TABLE), PSQL_TABLE)

    def test_non_string_input_returned_unchanged(self):
        for value in (None, 42, b"bytes"):
            self.assertIs(ascii_table_filter.compact_table(value), value)


if __name__ == "__main__":
    unittest.main()
