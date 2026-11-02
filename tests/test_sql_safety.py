"""No value a caller sends ever becomes part of an SQL statement.

The static check reads store.py and schema.py from disk: every statement handed to
execute or q, and every _SQL_* constant, may only be built from fixed text and a short
list of fixed names, and a statement can't come from any other variable. It is a guard
on the source code, so it can't tell whether a function swapped in at run time is safe;
the tests after it send hostile text through the tools and the store and check that
nothing moved. Another static check makes sure no statement takes back an audit record.
"""

import ast
import re
from pathlib import Path

import pytest
from helpers import actor, mcp_client, payload, raw, refusal, rows, running_app, snapshot, team_fixture

from flashcards_teams import schema
from flashcards_teams import store as store_module
from flashcards_teams.server import M_INVITE, M_NO_TEAM
from flashcards_teams.store import Outcome, SqliteCardStore

pytestmark = pytest.mark.anyio

PACKAGE = Path(store_module.__file__).parent
# The only names that may be put into SQL, besides the _SQL_* constants (each checked
# itself): fixed column lists, a fixed number, and the Postgres store's " FOR UPDATE".
ALLOWED_IN_SQL = {"_CARD_COLUMNS", "_AUDIT_COLUMNS", "LOCK_WAIT_SECONDS", "lock_team_suffix"}
SQL_CONSTANT = re.compile(r"_SQL_[A-Z0-9_]+")
# What may be handed to an executor other than a statement written out in the call or an
# _SQL_* constant: the stores' q() passing on a statement it was given (checked where that
# was written), and the fixed table definitions and grants.
PASSED_ON = {"sql", "sql.replace('?', '%s')", "schema.SQLITE_SCHEMA", "PG_TABLES", "PG_AUDIT", "statement"}
# What runs SQL: a driver's execute, or the store's own q(sql, params).
EXECUTORS = {"execute", "executescript", "q"}

INJECTIONS = [
    "' OR '1'='1",
    "x'); DROP TABLE cards; --",
    "%s %(name)s ? ?",
    "\\'; DELETE FROM members; --",
    "t_' OR 1=1--",
]
TABLES = ("teams", "members", "invites", "cards", "audit_events")


def interpolated(node: ast.AST) -> list[str]:
    """Everything an expression puts into a string besides fixed text: what f-strings
    insert and the parts joined with "+", plus "%", ".format" and ".join" for the other
    ways of building one."""
    found = []
    for sub in ast.walk(node):
        if isinstance(sub, ast.FormattedValue):
            found.append(ast.unparse(sub.value))
        elif isinstance(sub, ast.BinOp) and isinstance(sub.op, ast.Add):
            for part in (sub.left, sub.right):
                if isinstance(part, ast.Name):
                    found.append(part.id)
                elif isinstance(part, ast.Attribute):
                    found.append(part.attr)
                elif not isinstance(part, (ast.JoinedStr, ast.BinOp)) and not (
                    isinstance(part, ast.Constant) and isinstance(part.value, str)
                ):
                    found.append(ast.unparse(part))  # f-strings and nested "+" are walked on their own
        elif isinstance(sub, ast.BinOp) and isinstance(sub.op, ast.Mod):
            found.append("%")
        elif isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute) and sub.func.attr in ("format", "join"):
            found.append("." + sub.func.attr)
    return found


def allowed_in_sql(name: str) -> bool:
    return name in ALLOWED_IN_SQL or SQL_CONSTANT.fullmatch(name) is not None


def problems(expression: ast.AST, *, executed: bool) -> list[str]:
    """What in a statement isn't fixed text or an allowed name. A statement that is
    ``executed`` (handed to execute or q) must also be written out in the call, or be an
    _SQL_* constant or one of PASSED_ON: never some other variable or expression."""
    found = [name for name in interpolated(expression) if not allowed_in_sql(name)]
    if executed and not isinstance(expression, (ast.Constant, ast.JoinedStr, ast.BinOp)):
        text = ast.unparse(expression)
        if text not in PASSED_ON and SQL_CONSTANT.fullmatch(text) is None:
            found.append(text)
    return found


def sql_expressions(path: Path) -> list[tuple[ast.AST, bool]]:
    """Every statement handed to a call that runs SQL (paired with True), and every
    _SQL_* constant (paired with False)."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and node.args:
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
            if name in EXECUTORS:
                found.append((node.args[0], True))
        elif isinstance(node, ast.Assign):
            if any(isinstance(t, ast.Name) and t.id.startswith("_SQL_") for t in node.targets):
                found.append((node.value, False))
    return found


@pytest.mark.parametrize("module", ["store.py", "schema.py"])
def test_sql_is_built_only_from_fixed_names(module):
    expressions = sql_expressions(PACKAGE / module)
    # The scan must find the statements, or it would pass by finding nothing.
    assert len(expressions) >= (40 if module == "store.py" else 4)
    for expression, executed in expressions:
        assert problems(expression, executed=executed) == [], ast.unparse(expression)


@pytest.mark.parametrize(
    ("expression", "executed", "refused"),
    [
        ("'SELECT 1 FROM t WHERE x = ' + team_id", False, True),
        ("'SELECT 1 FROM t WHERE x = ' + str(n)", False, True),
        ("' '.join(['SELECT 1 FROM t WHERE x =', team_id])", False, True),
        ("f'SELECT 1 FROM t WHERE x = {team_id}'", False, True),
        ("'SELECT 1 FROM t WHERE x = %s' % team_id", False, True),
        ("'SELECT 1 FROM t WHERE x = {}'.format(team_id)", False, True),
        # A value hidden behind a constant's name, or a statement kept in a variable.
        ("f'{_SQL_MEMBER.replace(old, team_id)}'", False, True),
        ("'SELECT 1 ' + _SQL_TAIL(team_id)", False, True),
        ("_SQL_MEMBER.replace(old, team_id)", True, True),
        ("stmt", True, True),
        # What the stores themselves do.
        ("f'SELECT {_CARD_COLUMNS} FROM cards'", False, False),
        ("_SQL_LOCK_TEAM + x.lock_team_suffix", True, False),
        ("_SQL_MEMBER", True, False),
        ("sql.replace('?', '%s')", True, False),
    ],
)
def test_the_scan_catches_values_put_into_a_statement(expression, executed, refused):
    found = problems(ast.parse(expression, mode="eval").body, executed=executed)
    assert bool(found) is refused, found


def test_shared_sql_has_no_percent_sign():
    # The Postgres store turns "?" into "%s"; a "%" of its own would be read as a placeholder.
    constants = {name: value for name, value in vars(store_module).items() if name.startswith("_SQL_")}
    assert len(constants) >= 30
    for name, sql in constants.items():
        assert isinstance(sql, str) and "%" not in sql, name


# What would take back an audit record: deleting, changing, emptying or overwriting one.
TAKES_BACK = re.compile(
    r"\bDELETE\s+FROM\s+audit_events\b|\bUPDATE\s+audit_events\b|\bTRUNCATE\b|\bINSERT\s+OR\s+REPLACE\b|\bREPLACE\s+INTO\b",
    re.IGNORECASE,
)
# A team's audit counters, wherever a statement sets one.
COUNTER_SET = re.compile(r"\b(next_audit_seq|audit_writes|audit_reads)\s*=\s*(.+?)(?=,|\s+WHERE\b|$)", re.IGNORECASE)


def test_no_statement_takes_back_an_audit_record():
    # In the code, records are only ever added and a team's audit counters only go up, so
    # a place in its allowance, once used, never comes back. (Step 3 adds the triggers and
    # database rights that enforce this; this checks the statements the code can run.)
    statements = [value for name, value in vars(store_module).items() if name.startswith("_SQL_")]
    statements += [schema.SQLITE_SCHEMA, schema.PG_TABLES, schema.PG_AUDIT, *schema._PG_GRANTS]
    counters = []
    for sql in statements:
        assert not TAKES_BACK.search(sql), sql
        assert not ("audit_events" in sql and re.search(r"\bDO\s+UPDATE\b", sql, re.IGNORECASE)), sql
        counters += COUNTER_SET.findall(sql)
    # The scan must see the two statements that hand out audit numbers, with both counters each.
    assert sorted(counters) == sorted([
        ("next_audit_seq", "next_audit_seq + 1"), ("audit_writes", "audit_writes + 1"),
        ("next_audit_seq", "next_audit_seq + 1"), ("audit_reads", "audit_reads + 1"),
    ])


def structure(store) -> list[tuple]:
    """The tables, their columns and their indexes."""
    if isinstance(store, SqliteCardStore):
        return raw(store, "SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name")
    return raw(
        store,
        "SELECT table_name, column_name, data_type, is_nullable FROM information_schema.columns"
        " WHERE table_schema = 'public' ORDER BY 1, 2",
    ) + raw(store, "SELECT tablename, indexname, indexdef FROM pg_indexes WHERE schemaname = 'public' ORDER BY 1, 2")


def counts(store) -> dict[str, int]:
    return {table: rows(store, table) for table in TABLES}


async def test_hostile_text_through_the_tools_changes_nothing_it_shouldnt(store):
    f = await team_fixture(store)
    shape = structure(store)
    async with running_app(store) as app, mcp_client(app, "dave-1", "auto") as dave:
        for text in INJECTIONS:
            # team_id: never a team, for every team tool.
            before = counts(store)
            for tool, args in (
                ("list_cards", {}), ("review", {}), ("add_card", {"question": "q?", "answer": "a", "topic": "t"}),
                ("grade_card", {"card_id": 1, "correct": True}), ("delete_card", {"card_id": 1}),
                ("create_invite", {"role": "editor"}), ("set_member_role", {"member_no": 2, "role": "viewer"}),
                ("remove_member", {"member_no": 2}), ("read_audit_log", {}), ("leave_team", {}),
            ):
                assert refusal(await dave.call_tool(tool, {**args, "team_id": text})) == M_NO_TEAM, (tool, text)
            # code: just an invalid invite.
            assert refusal(await dave.call_tool("join_team", {"code": text})) == M_INVITE
            # topic: a filter that matches nothing.
            for tool in ("list_cards", "review"):
                result = payload(await dave.call_tool(tool, {"topic": text, "team_id": f.team}))
                assert result.get("total", 0) == 0 and result.get("card_id") is None
            assert counts(store) == before
            # name and topic stored: kept as typed, and only the rows they belong to were added.
            team = payload(await dave.call_tool("create_team", {"name": text}))
            card = payload(await dave.call_tool("add_card", {"question": "q?", "answer": "a", "topic": text, "team_id": f.team}))
            assert card["card"]["topic"] == text
            assert payload(await dave.call_tool("list_cards", {"topic": text, "team_id": f.team}))["total"] == 1
            assert raw(store, "SELECT name FROM teams WHERE team_id = ?", (team["team_id"],)) == [(text,)]
            # The new team (its row, its owner, its team.create) and the card (with its card.add).
            assert counts(store) == {**before, "teams": before["teams"] + 1, "members": before["members"] + 1,
                                     "cards": before["cards"] + 1, "audit_events": before["audit_events"] + 2}
    assert structure(store) == shape


async def test_store_team_id_is_parameterized(store):
    # Straight to the store, past the server's format check: the id must still be a value.
    f = await team_fixture(store)
    dave = actor("dave")
    before = snapshot(store)
    assert await store.add(dave, "t_'", "q", "a", "t") == Outcome("not_member")
    assert await store.delete(dave, "t_'", f.card_no) == Outcome("not_member")
    for text in INJECTIONS:
        for call in (
            store.add(dave, text, "q", "a", "t"),
            store.delete(dave, text, f.card_no),
            store.record_review(dave, text, f.card_no, True),
            store.list_page(dave, text, "", 51, 0),
            store.least_recently_reviewed(dave, text, ""),
            store.create_invite(dave, text, "editor", "0" * 64),
            store.set_member_role(dave, text, 2, "viewer"),
            store.remove_member(dave, text, 2),
            store.leave_team(dave, text),
            store.read_audit_log(dave, text, 101, 0),
        ):
            assert await call == Outcome("not_member"), text
    assert snapshot(store) == before
