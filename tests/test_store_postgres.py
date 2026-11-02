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
from helpers import actor, fresh_postgres_store, raw, waiting_for_a_lock

from flashcards_teams import limits
from flashcards_teams import store as store_module
from flashcards_teams.app import ConfigError, load_settings, open_store
from flashcards_teams.store import APPLICATION_NAME, StoreFullError, StoreUnavailableError

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
