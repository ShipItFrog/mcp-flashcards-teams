"""Postgres only: what one SQLite connection behind a lock can't show. Several
connections at once, a connection dropped by the server, startup against a real
database, and the database password staying out of logs and errors. The stores here
connect as the app role, like the hosted server (see conftest.pg_cluster)."""

import logging
import socket
import time

import anyio
import psycopg
import pytest
from helpers import actor, as_superuser, fresh_postgres_store, raw, set_up_as_owner, waiting_for_a_lock

from flashcards_teams import limits
from flashcards_teams import store as store_module
from flashcards_teams.app import ConfigError, load_settings, open_store
from flashcards_teams.store import APPLICATION_NAME, PostgresCardStore, StoreFullError, StoreUnavailableError

pytestmark = [pytest.mark.anyio, pytest.mark.postgres]

ALICE = actor("alice")
SENTINEL = "pw-SENTINEL-4711"


@pytest.fixture
def pg_store(pg_cluster):
    s = fresh_postgres_store(pg_cluster.admin_url, pg_cluster.app_url)
    yield s
    s.close()


async def total(store) -> int:
    return (await store.list_page(ALICE, None, "", 50, 0)).value["total"]


def settings_for(url: str):
    return load_settings(
        {
            "FLASHCARDS_ISSUER": "https://auth.example.test",
            "FLASHCARDS_JWKS_URL": "https://auth.example.test/.well-known/jwks.json",
            "FLASHCARDS_RESOURCE_URL": "http://localhost:8000/mcp",
            "FLASHCARDS_DATABASE_URL": url,
        }
    )


async def test_simultaneous_adds_cannot_go_past_the_card_limit(pg_store, pg_url, pg_cluster, monkeypatch):
    # Deterministic, not a race left to chance: the team's row is held until all four
    # adds are queued behind it, then released. A store that counted cards before taking
    # the lock would let all four through.
    monkeypatch.setattr(limits, "MAX_CARDS_PER_TEAM", 3)
    await pg_store.add(ALICE, None, "q1", "a", "t")
    await pg_store.add(ALICE, None, "q2", "a", "t")
    [(team_id,)] = raw(pg_store, "SELECT team_id FROM teams")
    results = []

    async def add(i):
        outcome = await pg_store.add(ALICE, None, f"c{i}", "a", "t")
        results.append(outcome.value["id"] if outcome.kind == "ok" else outcome.reason)

    with psycopg.connect(pg_cluster.admin_url) as holder:
        holder.execute("SELECT 1 FROM teams WHERE team_id = %s FOR UPDATE", (team_id,))
        async with anyio.create_task_group() as tg:
            for i in range(4):
                tg.start_soon(add, i)
            try:
                # Shorter than the adds' own lock wait (LOCK_WAIT_SECONDS), so a hang shows
                # up as this failure rather than as four "unavailable" adds.
                deadline = time.monotonic() + store_module.LOCK_WAIT_SECONDS - 2
                while waiting_for_a_lock(pg_url) < 4:
                    assert time.monotonic() < deadline, "the four adds never queued up behind the lock"
                    await anyio.sleep(0.05)
            finally:
                # Release the row whatever happened, or a failing add would leave the
                # others waiting on it forever and the test would hang instead of fail.
                holder.commit()
    assert sorted(results, key=str) == [3, "deck_full", "deck_full", "deck_full"]


async def test_a_connection_dropped_by_the_server_is_replaced(pg_store, pg_url):
    # Neon's free tier closes connections when it pauses after 5 idle minutes.
    await pg_store.add(ALICE, None, "q", "a", "t")  # the pool now holds an open connection
    with psycopg.connect(pg_url, autocommit=True) as admin:
        dropped = admin.execute(
            "SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity WHERE application_name = %s",
            (APPLICATION_NAME,),
        ).fetchone()[0]
    assert dropped >= 1
    assert await total(pg_store) == 1


async def test_a_database_lost_mid_service_is_reported_as_unavailable(pg_store, pg_url, monkeypatch, caplog):
    # The pool's connection is dropped and no new one can be made: the call must end in
    # StoreUnavailableError (which the tools turn into "temporarily unavailable"), not in
    # the driver's own error.
    await total(pg_store)
    with psycopg.connect(pg_url, autocommit=True) as admin:
        admin.execute(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name = %s", (APPLICATION_NAME,)
        )

    def refuse(cls, *args, **kwargs):
        raise psycopg.OperationalError("connection refused (test)")

    monkeypatch.setattr(psycopg.Connection, "connect", classmethod(refuse))
    monkeypatch.setattr(pg_store._pool, "timeout", 1.0)  # don't wait the full POOL_WAIT_SECONDS
    with caplog.at_level(logging.WARNING, logger="flashcards_teams.store"), pytest.raises(StoreUnavailableError):
        await total(pg_store)
    assert "The card database is unavailable" in caplog.text


async def test_running_out_of_space_is_not_reported_as_a_temporary_outage(pg_store):
    # Neon's storage limit raises DiskFull, which psycopg also counts as an OperationalError.
    with pytest.raises(StoreFullError), pg_store.map_errors():
        raise psycopg.errors.DiskFull("could not extend file (test)")
    # Too many connections is in the same SQLSTATE class but does pass with time.
    with pytest.raises(StoreUnavailableError), pg_store.map_errors():
        raise psycopg.errors.TooManyConnections("too many clients (test)")


def test_the_pool_is_set_up_for_neon(pg_store):
    # Things only a pooled Neon connection would expose, so the local tests can't see them break.
    kwargs = pg_store._pool.kwargs
    assert kwargs["prepare_threshold"] is None  # no server-side prepared statements through PgBouncer
    assert kwargs["connect_timeout"] and kwargs["keepalives_idle"]
    assert pg_store._pool.max_size >= 4  # the concurrency test needs four connections at once


async def test_a_failed_statement_rolls_back_and_uses_no_number(pg_store):
    with pytest.raises(psycopg.Error):
        await pg_store.add(ALICE, None, "nul \x00 inside", "a", "t")  # Postgres text can't hold NUL
    # Nothing of the failed call was kept: not the personal team it created, nor a number.
    assert raw(pg_store, "SELECT COUNT(*) FROM teams") == [(0,)]
    assert (await pg_store.add(ALICE, None, "q", "a", "t")).value["id"] == 1
    await pg_store.add(ALICE, None, "q2", "a", "t")
    with pytest.raises(psycopg.Error):
        await pg_store.add(ALICE, None, "nul \x00 inside", "a", "t")
    assert (await pg_store.add(ALICE, None, "q3", "a", "t")).value["id"] == 3


def test_every_transaction_has_its_own_timeouts(pg_store):
    # A stuck transaction holds back VACUUM: Postgres ends one that idles or runs a statement
    # too long. Set for each transaction only, so they never reach another call (Neon's
    # transaction-mode pooler hands one connection to many).
    timeouts = (
        "SELECT current_setting('idle_in_transaction_session_timeout') AS idle,"
        " current_setting('statement_timeout') AS statement, current_setting('lock_timeout') AS lock,"
        " current_setting('search_path') AS search_path, pg_backend_pid() AS pid"
    )
    wanted = (store_module.PG_IDLE_IN_TRANSACTION_TIMEOUT, store_module.PG_STATEMENT_TIMEOUT)
    with pg_store._pool.connection() as conn:
        default = conn.execute(timeouts).fetchone()
    assert (default["idle"], default["statement"]) != wanted
    inside = {}
    for read_only in (False, True):
        with pg_store.tx(read_only=read_only) as q:
            inside[read_only] = q(timeouts).fetchone()
    for read_only, seen in inside.items():
        assert (seen["idle"], seen["statement"]) == wanted == ("30s", "30s"), read_only
        assert seen["search_path"] == store_module.PG_SEARCH_PATH, read_only  # pinned too
        assert seen["pid"] == default["pid"]  # the pool's one connection, every time
    assert inside[False]["lock"] == f"{store_module.LOCK_WAIT_SECONDS}s"
    # Afterwards the same connection is back to the server's own settings.
    with pg_store._pool.connection() as conn:
        assert conn.execute(timeouts).fetchone() == default


def test_a_transaction_ended_for_idling_is_reported_as_unavailable(pg_store):
    # Postgres ends a transaction left idle too long with SQLSTATE 25P03, which psycopg
    # files under InternalError, not OperationalError. Whether a call sees that error or
    # only the closed connection depends on timing, so the mapping is checked on its own.
    with pytest.raises(StoreUnavailableError):
        with pg_store.map_errors():
            raise psycopg.errors.IdleInTransactionSessionTimeout("terminating connection due to idle-in-transaction timeout")


async def test_a_stuck_call_is_ended_and_reported_as_unavailable(pg_store, monkeypatch):
    # The timeouts lowered, a write that sits idle inside its transaction and one whose
    # statement runs too long: Postgres ends each, and the store reports the database as
    # temporarily unavailable. Nothing of either is kept, and the next call works.
    monkeypatch.setattr(store_module, "PG_IDLE_IN_TRANSACTION_TIMEOUT", "300ms")
    monkeypatch.setattr(store_module, "PG_STATEMENT_TIMEOUT", "300ms")
    real = store_module._Ops._add_card

    def idles(self, c, *args):
        time.sleep(1.5)  # no statement running: the transaction sits idle
        return real(self, c, *args)

    def runs_long(self, c, *args):
        c.q("SELECT pg_sleep(1.5)")
        return real(self, c, *args)

    for stuck in (idles, runs_long):
        monkeypatch.setattr(store_module._Ops, "_add_card", stuck)
        with pytest.raises(StoreUnavailableError):
            await pg_store.add(ALICE, None, "q", "a", "t")
    monkeypatch.setattr(store_module._Ops, "_add_card", real)
    monkeypatch.setattr(store_module, "PG_IDLE_IN_TRANSACTION_TIMEOUT", "30s")
    monkeypatch.setattr(store_module, "PG_STATEMENT_TIMEOUT", "30s")
    assert await total(pg_store) == 0
    assert (await pg_store.add(ALICE, None, "q", "a", "t")).kind == "ok"
    assert await total(pg_store) == 1


async def test_a_schema_named_after_the_app_role_cant_take_the_tables_place(scratch_db):
    # Postgres' default search path starts with "$user": a schema named after the app role,
    # holding tables of the same names, would stand in for the server's own. The store
    # pins the path for every transaction, the read-only ones included, so the records
    # still land in public and only public's rows are read.
    set_up_as_owner(scratch_db.admin_url, scratch_db.role)
    shadow = scratch_db.role
    tables = ("teams", "members", "cards", "audit_events")
    as_superuser(
        scratch_db.admin_url,
        f"CREATE SCHEMA {shadow} AUTHORIZATION {shadow}",
        f"SET ROLE {shadow}",  # the app role's own tables, in its own schema
        *(f"CREATE TABLE {shadow}.{table} (LIKE public.{table} INCLUDING ALL)" for table in tables),
    )
    with psycopg.connect(scratch_db.url) as app:
        # Without the pin, an unqualified name would mean the app role's table.
        assert app.execute(f"SELECT 'teams'::regclass = '{shadow}.teams'::regclass").fetchone()[0] is True
    store = PostgresCardStore(scratch_db.url, verify_schema=False)
    try:
        dave = actor("dave")
        team = await store.create_team(dave, "Team A")
        assert team.kind == "ok"
        team_id = team.value["team_id"]
        assert (await store.add(dave, team_id, "q?", "a", "t")).kind == "ok"
        counts = {}
        with psycopg.connect(scratch_db.admin_url) as conn:
            for schema_name in ("public", shadow):
                for table in tables:
                    counts[schema_name, table] = conn.execute(f"SELECT count(*) FROM {schema_name}.{table}").fetchone()[0]
        assert counts == {
            **{("public", table): n for table, n in zip(tables, (1, 1, 1, 2))},
            **{(shadow, table): 0 for table in tables},
        }
        # Forged rows in the shadow tables only: dave's team under another name, a team of
        # his that doesn't exist, a card and a record that were never made.
        as_superuser(
            scratch_db.admin_url,
            f"SET ROLE {shadow}",
            f"INSERT INTO {shadow}.teams (team_id, name, created_at) SELECT team_id, 'FORGED', created_at FROM public.teams",
            f"INSERT INTO {shadow}.teams (team_id, name, created_at) VALUES ('forged', 'FORGED', '2026-01-01')",
            f"INSERT INTO {shadow}.members SELECT * FROM public.members",
            f"INSERT INTO {shadow}.members (team_id, member_no, principal, role, joined_at)"
            " SELECT 'forged', 1, principal, 'owner', '2026-01-01' FROM public.members",
            f"INSERT INTO {shadow}.cards (team_id, card_no, question, answer, topic, topic_key, created_at)"
            " SELECT team_id, card_no + 1, 'FORGED?', 'FORGED', topic, topic_key, '2000-01-01' FROM public.cards",
            f"INSERT INTO {shadow}.audit_events (team_id, seq, at, member_no, client_id, action, target, result, reason)"
            " SELECT team_id, seq, at, member_no, 'FORGED', action, target, result, reason FROM public.audit_events",
        )
        teams = (await store.list_teams(dave)).value
        page = (await store.list_page(dave, team_id, "", 11, 0)).value
        review = (await store.least_recently_reviewed(dave, team_id, "")).value
        log = (await store.read_audit_log(dave, team_id, 11, 0)).value
    finally:
        store.close()
    assert [(t["team_id"], t["name"]) for t in teams] == [(team_id, "Team A")]
    assert [card["question"] for card in page["cards"]] == ["q?"] and page["total"] == 1
    assert review["question"] == "q?"
    assert [(e["action"], e["client_id"]) for e in log["events"]] == [("team.create", "client-dave"), ("card.add", "client-dave")]
    assert "FORGED" not in repr((teams, page, review, log))


async def test_a_temporary_table_cant_take_the_tables_place(scratch_db, monkeypatch):
    # Unlisted, a session's temporary schema is searched first for table names. Through a
    # transaction-mode pooler backends are shared, so whoever holds the app role's
    # credentials could leave temporary tables named like the server's in one. The store
    # lists pg_temp last, so its writes and reads still go to public's tables. One pooled
    # connection here: the backend that holds the temporary tables serves every call.
    set_up_as_owner(scratch_db.admin_url, scratch_db.role)
    monkeypatch.setattr(store_module, "POOL_MIN_SIZE", 1)
    monkeypatch.setattr(store_module, "POOL_MAX_SIZE", 1)
    tables = ("teams", "audit_events")
    store = PostgresCardStore(scratch_db.url)
    try:
        with store._pool.connection() as conn:
            for table in tables:
                conn.execute(f"CREATE TEMP TABLE {table} (LIKE public.{table} INCLUDING ALL)")
            backend = conn.execute("SELECT pg_backend_pid() AS pid").fetchone()["pid"]
        dave = actor("dave")
        team = await store.create_team(dave, "Team A")
        assert team.kind == "ok"
        team_id = team.value["team_id"]
        assert (await store.add(dave, team_id, "q?", "a", "t")).kind == "ok"
        teams = (await store.list_teams(dave)).value
        log = (await store.read_audit_log(dave, team_id, 11, 0)).value
        with store._pool.connection() as conn:
            assert conn.execute("SELECT pg_backend_pid() AS pid").fetchone()["pid"] == backend
            temporary = {table: conn.execute(f"SELECT count(*) AS n FROM pg_temp.{table}").fetchone()["n"] for table in tables}
    finally:
        store.close()
    assert temporary == {"teams": 0, "audit_events": 0}
    with psycopg.connect(scratch_db.admin_url) as conn:
        assert {table: conn.execute(f"SELECT count(*) FROM public.{table}").fetchone()[0] for table in tables} == {
            "teams": 1, "audit_events": 3,  # team.create, card.add, and the read of the log
        }
    assert [(t["team_id"], t["name"]) for t in teams] == [(team_id, "Team A")]
    assert [e["action"] for e in log["events"]] == ["team.create", "card.add"]


def test_the_database_password_stays_out_of_logs_and_errors(pg_store, pg_cluster, caplog, monkeypatch):
    # pg_store has set the tables up. The local server trusts every connection, so it
    # accepts this password for the app role without needing it.
    with_password = pg_cluster.app_url.replace("postgresql://ft_app@", f"postgresql://ft_app:{SENTINEL}@")
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        closed_port = s.getsockname()[1]
    unreachable = f"postgresql://postgres:{SENTINEL}@127.0.0.1:{closed_port}/postgres"
    monkeypatch.setattr(store_module, "POOL_OPEN_SECONDS", 1.0)
    with caplog.at_level(logging.DEBUG):
        settings = settings_for(with_password)
        open_store(settings).close()
        with pytest.raises(ConfigError) as stopped:
            open_store(settings_for(unreachable))
    assert "Could not reach the Postgres database" in str(stopped.value)
    for text in (caplog.text, str(stopped.value), repr(settings)):
        assert SENTINEL not in text
