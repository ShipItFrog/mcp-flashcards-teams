"""The audit records can only be added to, never changed or removed, straight in the
database too: SQLite's triggers refuse it; on Postgres the triggers refuse it to
everyone (the superuser included, in a replica session too), and the app role hasn't
even the rights to try.

Every test builds its tables anew (the store fixtures do), so a mutation of the table
definitions always reaches them.
"""

import sqlite3

import psycopg
import pytest
from helpers import fresh_postgres_store, team_fixture

from flashcards_teams.store import SqliteCardStore

pytestmark = pytest.mark.anyio

EVERYTHING = "SELECT * FROM audit_events ORDER BY team_id, seq"


@pytest.fixture
def sqlite_store(tmp_path):
    s = SqliteCardStore(tmp_path / "cards.db")
    yield s
    s.close()


@pytest.fixture
def pg_store(pg_cluster):
    s = fresh_postgres_store(pg_cluster.admin_url, pg_cluster.app_url)
    yield s
    s.close()


# --- SQLite -------------------------------------------------------------------------


async def test_sqlite_refuses_to_change_or_remove_a_record(sqlite_store):
    f = await team_fixture(sqlite_store)
    conn = sqlite_store._conn
    before = conn.execute(EVERYTHING).fetchall()
    assert before
    for statement, params in (
        ("UPDATE audit_events SET result = 'ok'", ()),
        ("DELETE FROM audit_events WHERE seq = 1", ()),
        # Without WHERE: a table with triggers skips the truncate optimization.
        ("DELETE FROM audit_events", ()),
        # A REPLACE conflict deletes the old row without the delete trigger, unless
        # recursive_triggers is on: the third trigger refuses a key that is taken.
        (
            "INSERT OR REPLACE INTO audit_events (team_id, seq, at, member_no, client_id, action, target, result, reason)"
            " VALUES (?, 1, '2026-01-01T00:00:00+00:00', 1, '', 'card.add', 'team', 'ok', '')",
            (f.team,),
        ),
    ):
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            with conn:
                conn.execute(statement, params)
        assert conn.execute(EVERYTHING).fetchall() == before, statement


async def test_sqlite_lets_an_update_of_no_rows_through_but_it_changes_nothing(sqlite_store):
    # Unlike Postgres, whose statement-level triggers refuse even this: SQLite's triggers
    # are per row, so an UPDATE that matches no row fires none. It changes nothing either.
    await team_fixture(sqlite_store)
    conn = sqlite_store._conn
    before = conn.execute(EVERYTHING).fetchall()
    with conn:
        assert conn.execute("UPDATE audit_events SET result = 'ok' WHERE 0").rowcount == 0
    assert conn.execute(EVERYTHING).fetchall() == before


# --- Postgres: the triggers stop even a superuser -------------------------------------


@pytest.mark.postgres
async def test_postgres_triggers_refuse_even_the_superuser(pg_store):
    await team_fixture(pg_store)
    with psycopg.connect(pg_store._admin_url, autocommit=True) as conn:
        before = conn.execute(EVERYTHING).fetchall()
        assert before
        for statement in (
            "UPDATE audit_events SET result = 'ok' WHERE seq = 1",
            # Statement-level triggers fire even when no row is affected.
            "UPDATE audit_events SET result = 'ok' WHERE false",
            "DELETE FROM audit_events",
            # TRUNCATE fires no DELETE trigger: it has a trigger of its own.
            "TRUNCATE audit_events",
        ):
            with pytest.raises(psycopg.errors.RaiseException, match="append-only"):
                conn.execute(statement)
        assert conn.execute(EVERYTHING).fetchall() == before


@pytest.mark.postgres
async def test_postgres_triggers_fire_even_in_a_replica_session(pg_store):
    # A trigger enabled the default way doesn't fire where session_replication_role is
    # replica, which a superuser (or a role granted SET on it) may choose; these are
    # enabled ALWAYS.
    await team_fixture(pg_store)
    with psycopg.connect(pg_store._admin_url, autocommit=True) as conn:
        before = conn.execute(EVERYTHING).fetchall()
        assert before
        conn.execute("SET session_replication_role = replica")
        for statement in (
            "UPDATE audit_events SET result = 'ok' WHERE seq = 1",
            "DELETE FROM audit_events",
            "TRUNCATE audit_events",
        ):
            with pytest.raises(psycopg.errors.RaiseException, match="append-only"):
                conn.execute(statement)
        assert conn.execute("SHOW session_replication_role").fetchone()[0] == "replica"
        assert conn.execute(EVERYTHING).fetchall() == before


# --- Postgres: the app role can't even try ----------------------------------------------


@pytest.mark.postgres
async def test_the_app_role_has_no_right_to_change_or_remove_records(pg_store, pg_cluster):
    f = await team_fixture(pg_store)
    with psycopg.connect(pg_cluster.app_url, autocommit=True) as app:
        for statement in (
            "UPDATE audit_events SET result = 'ok' WHERE seq = 1",
            "DELETE FROM audit_events WHERE seq = 1",
            "TRUNCATE audit_events",
            "INSERT INTO audit_events (team_id, seq, at, member_no, client_id, action, target, result, reason)"
            f" VALUES ('{f.team}', 1, '2026-01-01T00:00:00+00:00', 1, '', 'card.add', 'team', 'ok', '')"
            " ON CONFLICT (team_id, seq) DO UPDATE SET result = 'ok'",
            "ALTER TABLE audit_events DISABLE TRIGGER ALL",
            "DROP TRIGGER audit_events_no_truncate ON audit_events",
            "CREATE TRIGGER audit_events_test BEFORE INSERT ON audit_events"
            " FOR EACH STATEMENT EXECUTE FUNCTION audit_events_refuse_change()",
            # Column-level grants: the app may change a team's counters, not its name.
            "UPDATE teams SET name = 'x'",
        ):
            with pytest.raises(psycopg.errors.InsufficientPrivilege) as refused:
                app.execute(statement)
            assert refused.value.sqlstate == "42501", statement
        rights = app.execute(
            "SELECT has_table_privilege('audit_events', 'UPDATE'), has_table_privilege('audit_events', 'DELETE'),"
            " has_table_privilege('audit_events', 'TRUNCATE'), has_table_privilege('audit_events', 'TRIGGER')"
        ).fetchone()
        assert rights == (False, False, False, False)
        # The table isn't the app role's, nor any role's it belongs to.
        owner, member = app.execute(
            "SELECT r.rolname, pg_has_role('ft_app', c.relowner, 'MEMBER') FROM pg_class c"
            " JOIN pg_roles r ON r.oid = c.relowner WHERE c.oid = 'public.audit_events'::regclass"
        ).fetchone()
        assert owner != "ft_app" and member is False
