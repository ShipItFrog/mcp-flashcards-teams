"""Test helpers: a fake token verifier, and ways to talk to the real ASGI app over
HTTP in-process (no network), as different users.

The fake verifier maps test tokens straight to users, so the isolation tests can
focus on what happens after sign-in. The real verifier (signature, issuer,
audience, expiry) is tested with real signed JWTs in test_verifier.py and
test_jwt_end_to_end.py. Everything after the verifier - the SDK's auth
middleware, the MCP protocol, the tools and the database - is the real code.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Coroutine
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any

import anyio
import httpx2
import pytest
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp_types.version import MODERN_PROTOCOL_VERSIONS

from flashcards_teams import ids, schema
from flashcards_teams import store as store_module
from flashcards_teams.server import create_server
from flashcards_teams.store import APPLICATION_NAME, Actor, PostgresCardStore, SqliteCardStore

ISSUER = "https://auth.example.test"
BASE = "http://127.0.0.1:8000"
RESOURCE = f"{BASE}/mcp"
SCOPE = "flashcards"


def _token(
    value: str,
    subject: str | None,
    *,
    resource: str = RESOURCE,
    scopes: tuple[str, ...] = (SCOPE,),
    issuer: str = ISSUER,
    client_id: str = "test-client",
) -> AccessToken:
    return AccessToken(
        token=value,
        client_id=client_id,
        scopes=list(scopes),
        resource=resource,
        subject=subject,
        claims={"iss": issuer, "sub": subject},
    )


TOKENS = {
    "alice-1": _token("alice-1", "alice"),
    "alice-2": _token("alice-2", "alice"),  # same person, another token (refresh, second client)
    "bob-1": _token("bob-1", "bob"),
    "other-audience": _token("other-audience", "mallory", resource="https://other.example.test/mcp"),
    "no-scope": _token("no-scope", "carol", scopes=()),
    "no-subject": _token("no-subject", None),
    # Same `sub` as alice, but from a different identity provider: a different person.
    "other-issuer": _token("other-issuer", "alice", issuer="https://other-idp.example.test"),
    # The team tests' people, each with a client_id of their own.
    **{f"{name}-1": _token(f"{name}-1", name, client_id=f"client-{name}") for name in ("dave", "erin", "frank", "gina", "henry")},
}


def actor(name: str) -> Actor:
    """The store's view of the person behind TOKENS[f"{name}-1"] (for dave to henry; the
    older tokens all share the client_id "test-client")."""
    client_id = f"client-{name}" if name in ("dave", "erin", "frank", "gina", "henry") else "test-client"
    return Actor(f"{ISSUER}|{name}", client_id)


class FakeVerifier(TokenVerifier):
    async def verify_token(self, token: str) -> AccessToken | None:
        return TOKENS.get(token)


# Every combination the server can be reached with: the 2026-07-28 protocol or the
# 2025-era initialize handshake (what claude.ai connectors use today), each against
# an app with or without per-connection sessions.
TRANSPORTS = [
    pytest.param(("auto", False), id="modern"),
    pytest.param(("legacy", False), id="legacy"),
    pytest.param(("auto", True), id="modern-stateless"),
    pytest.param(("legacy", True), id="legacy-stateless"),
]


@asynccontextmanager
async def running_app(
    store,
    *,
    stateless: bool = False,
    rate_limit: tuple[int, float] | None = None,
    token_verifier: TokenVerifier | None = None,
):
    extra = {} if rate_limit is None else {"rate_limit": rate_limit}
    mcp = create_server(
        store=store,
        token_verifier=token_verifier or FakeVerifier(),
        issuer_url=ISSUER,
        resource_url=RESOURCE,
        required_scopes=[SCOPE],
        **extra,
    )
    app = mcp.streamable_http_app(stateless_http=stateless)
    # ASGITransport doesn't run the app's lifespan, so start the session manager here.
    async with mcp.session_manager.run():
        yield app


# For raw HTTP requests (status codes and headers), without an MCP client in between.
INITIALIZE = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "raw-test", "version": "0"}},
}
HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}


@asynccontextmanager
async def http(app, token: str | None = None):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), base_url=BASE, headers=headers) as hc:
        yield hc


@asynccontextmanager
async def mcp_client(app, token: str, mode: str):
    """mode="auto" must end up on the 2026-07-28 protocol, mode="legacy" on the 2025-era
    handshake. The SDK's auto mode silently falls back to legacy on errors, so this is
    asserted - otherwise a broken modern path would just test legacy twice."""
    async with http(app, token) as hc:
        async with Client(streamable_http_client(RESOURCE, http_client=hc), mode=mode) as client:
            modern = client.protocol_version in MODERN_PROTOCOL_VERSIONS
            assert modern == (mode == "auto"), f"mode={mode!r} negotiated {client.protocol_version!r}"
            yield client


@dataclass(frozen=True)
class PgCluster:
    """The test Postgres database: ``admin_url`` connects as the superuser, ``app_url``
    as the app role (see conftest.pg_cluster)."""

    admin_url: str
    app_url: str


# One superuser connection per database for the whole run, for rebuilding the tables and
# for raw(): on Windows every new Postgres connection starts a server process, which
# costs more than the rebuild itself.
_ADMIN_CONNECTIONS: dict[str, Any] = {}


def admin_connection(url: str):
    """The run's autocommit superuser connection to ``url``, reconnected if it was lost."""
    import psycopg

    conn = _ADMIN_CONNECTIONS.get(url)
    if conn is None or conn.closed or conn.broken:
        conn = _ADMIN_CONNECTIONS[url] = psycopg.connect(url, autocommit=True)
        # A test that leaves a lock behind makes the next one fail within seconds (its
        # DROP TABLE can't get the lock), instead of hanging until the runner's timeout.
        conn.execute("SET lock_timeout = '10s'")
    return conn


def close_admin_connections() -> None:
    while _ADMIN_CONNECTIONS:
        _ADMIN_CONNECTIONS.popitem()[1].close()


def fresh_postgres_store(admin_url: str, app_url: str) -> PostgresCardStore:
    """A Postgres store on newly built, empty tables, connected as the app role.

    The tables are dropped and set up again, as the database owner would, every time:
    mutations are applied when a test starts, so tables built once for the whole run
    would never see a mutation of their definitions. DROP fires no triggers."""
    conn = admin_connection(admin_url)
    conn.execute("DROP TABLE IF EXISTS audit_events, invites, members, cards, teams, schema_info")
    conn.execute("SET ROLE ft_owner")
    try:
        schema.setup_database(conn, "ft_app")
    finally:
        conn.execute("RESET ROLE")
    # verify_schema=False: a mutation that breaks the tables must be caught by a test,
    # not make this fixture fail (run_mutations.py counts a setup error as INVALID).
    store = PostgresCardStore(app_url, verify_schema=False)
    store._admin_url = admin_url  # for raw(): tests read the tables as the superuser
    return store


@contextmanager
def _reader(store):
    """A function that runs SELECTs straight on the database (see raw), for one or more
    queries over the same connection."""
    if isinstance(store, SqliteCardStore):
        with store._lock:
            yield lambda sql, params=(): [tuple(row) for row in store._conn.execute(sql, params).fetchall()]
        return
    conn = admin_connection(store._admin_url)
    with conn.transaction():
        conn.execute("SET TRANSACTION READ ONLY")
        yield lambda sql, params=(): conn.execute(sql.replace("?", "%s"), params).fetchall()


def raw(store, sql: str, params: tuple = ()) -> list[tuple]:
    """Rows straight from the database, whatever team they belong to, as tuples. For
    tests only, and SELECT only: on Postgres it runs in a read-only transaction as the
    superuser. Placeholders are "?" for both databases."""
    with _reader(store) as run:
        return run(sql, params)


def rows(store, table: str) -> int:
    """How many rows a table has, across every team."""
    return raw(store, f"SELECT COUNT(*) FROM {table}")[0][0]


def snapshot(store) -> dict[str, Any]:
    """What a refused call must leave exactly as it was."""
    with _reader(store) as run:  # one connection for all five
        return {
            "cards": sorted(run("SELECT team_id, card_no, review_count FROM cards")),
            "members": sorted(run("SELECT team_id, member_no, role FROM members")),
            "invites": sorted((t, n, bool(unused)) for t, n, unused in run("SELECT team_id, invite_no, used_at IS NULL FROM invites")),
            "teams": sorted(run("SELECT team_id, next_card_no, next_member_no, next_invite_no FROM teams")),
            "audit": dict(run("SELECT team_id, COUNT(*) FROM audit_events GROUP BY team_id")),
        }


def without_audit(snap: dict[str, Any]) -> dict[str, Any]:
    """A snapshot without its audit counts, for comparing everything else."""
    return {key: value for key, value in snap.items() if key != "audit"}


def team_part(snap: dict[str, Any], team_id: str) -> dict[str, Any]:
    """The part of a snapshot that belongs to one team."""
    return {
        key: ({team_id: value[team_id]} if team_id in value else {}) if key == "audit" else [r for r in value if r[0] == team_id]
        for key, value in snap.items()
    }


async def team_fixture(store) -> SimpleNamespace:
    """A shared team set up through the store directly (faster than the tools):

    dave owner #1, erin editor #2, frank viewer #3, henry editor #4 (the one to change
    or remove), gina #5 joined as an editor and was removed; card #1; one unused editor
    invite (``code``). Bob owns another team, created last: nobody joined team A while
    already in another team, so a membership check that ignores the team can't make
    this setup fail."""
    dave = actor("dave")

    async def ok(call):
        outcome = await call
        assert outcome.kind == "ok", outcome
        return outcome.value

    team = (await ok(store.create_team(dave, "Team A")))["team_id"]
    numbers = {"dave": 1}
    for name, role in (("erin", "editor"), ("frank", "viewer"), ("henry", "editor"), ("gina", "editor")):
        code = ids.new_invite_code()
        await ok(store.create_invite(dave, team, role, ids.hash_invite(code)))
        numbers[name] = (await ok(store.join_team(actor(name), ids.hash_invite(code))))["member_no"]
    await ok(store.remove_member(dave, team, numbers["gina"]))
    card_no = (await ok(store.add(dave, team, "Fixture question?", "Fixture answer", "fixture")))["id"]
    code = ids.new_invite_code()
    invite_no = (await ok(store.create_invite(dave, team, "editor", ids.hash_invite(code))))["invite_no"]
    other_team = (await ok(store.create_team(actor("bob"), "Team B")))["team_id"]
    return SimpleNamespace(
        team=team, other_team=other_team, numbers=numbers, card_no=card_no, code=code, invite_no=invite_no
    )


def payload(result) -> Any:
    assert not result.is_error, f"unexpected tool error: {result.content}"
    if result.structured_content is not None:
        return result.structured_content
    return json.loads(result.content[0].text)


def error_text(result) -> str:
    assert result.is_error, f"expected a tool error, got {result.content}"
    return result.content[0].text


def refusal(result) -> str:
    """A tool error's own message, exactly, without the "Error executing tool <name>: "
    the SDK puts in front of it."""
    text = error_text(result)
    prefix, sep, message = text.partition(": ")
    assert sep and prefix.startswith("Error executing tool "), text
    return message


# --- Postgres: calls queued behind a lock --------------------------------------------


def waiting_for_a_lock(url: str) -> int:
    """How many of the store's connections are blocked on a lock right now."""
    return admin_connection(url).execute(
        "SELECT count(*) FROM pg_stat_activity WHERE application_name = %s AND wait_event_type = 'Lock'",
        (APPLICATION_NAME,),
    ).fetchone()[0]


async def queued_behind(
    store,
    hold: Callable[[Any], None],
    calls: list[Coroutine[Any, Any, Any]],
    *,
    waiting: int,
    before_release: Callable[[Any], None] | None = None,
) -> list[Any]:
    """Run store calls at once while another connection holds a lock, deterministically:
    ``hold(conn)`` takes the lock in an open transaction, the calls start, and only when
    exactly ``waiting`` of them are blocked on a lock does ``before_release(conn)`` run
    and the transaction commit. Returns the calls' results in order."""
    import psycopg

    results: list[Any] = [None] * len(calls)

    async def run(i, call):
        results[i] = await call

    with psycopg.connect(store._admin_url) as holder:
        hold(holder)
        async with anyio.create_task_group() as tg:
            for i, call in enumerate(calls):
                tg.start_soon(run, i, call)
            try:
                # Shorter than the calls' own lock wait (LOCK_WAIT_SECONDS), so a hang shows
                # up as this failure rather than as "unavailable" calls.
                deadline = time.monotonic() + store_module.LOCK_WAIT_SECONDS - 2
                while (n := waiting_for_a_lock(store._admin_url)) < waiting:
                    assert time.monotonic() < deadline, f"only {n} of the calls queued up behind the lock"
                    await anyio.sleep(0.05)
                assert n == waiting, f"{n} connections wait on a lock, not {waiting}"
                if before_release is not None:
                    before_release(holder)
            finally:
                # Release whatever happened, or the queued calls would wait until they time out.
                holder.commit()
    return results
