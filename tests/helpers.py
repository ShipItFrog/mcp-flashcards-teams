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
import uuid
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
    # Client ids an audit record must clean up: control characters and far too long; just
    # too long; none at all.
    "weird-client-1": _token("weird-client-1", "weird", client_id="bad\nclient\x1b" + "x" * 500),
    "long-client-1": _token("long-client-1", "long", client_id="".join(chr(ord("a") + i % 26) for i in range(100))),
    "no-client-1": _token("no-client-1", "noclient", client_id=""),
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
    issuer: str = ISSUER,
):
    extra = {} if rate_limit is None else {"rate_limit": rate_limit}
    mcp = create_server(
        store=store,
        token_verifier=token_verifier or FakeVerifier(),
        issuer_url=issuer,
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


@contextmanager
def scratch_database(pg_url: str):
    """A new, empty database owned by ft_owner, and a new login role to connect to it as,
    both made for one test and removed after it. Roles and role memberships belong to the
    whole server, not to a database, so a test that changes them uses a role of its own.

    Yields ``name``, ``role``, ``admin_url`` (the superuser, on this database), ``url``
    (the role, on this database) and ``extra_roles``, a list the test may add roles to
    that are dropped too."""
    import psycopg
    from psycopg import sql

    tag = uuid.uuid4().hex[:12]
    name, role = f"ft_s_{tag}", f"ft_app_{tag}"
    server = pg_url.rsplit("/", 1)[0].split("@", 1)[1]  # 127.0.0.1:port
    admin = admin_connection(pg_url)
    admin.execute(sql.SQL("CREATE DATABASE {} OWNER ft_owner").format(sql.Identifier(name)))
    db = SimpleNamespace(
        name=name, role=role, extra_roles=[],
        admin_url=f"postgresql://postgres@{server}/{name}", url=f"postgresql://{role}@{server}/{name}",
    )
    try:
        admin.execute(sql.SQL("CREATE ROLE {} LOGIN").format(sql.Identifier(role)))
        yield db
    finally:
        # The database first: the rights granted in it go with it, so the roles can go.
        admin.execute(sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(name)))
        for r in (role, *db.extra_roles):
            admin.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(r)))


def as_superuser(admin_url: str, *statements: str) -> None:
    """Run statements on a scratch database as the superuser, each committed on its own."""
    import psycopg

    with psycopg.connect(admin_url, autocommit=True) as conn:
        for statement in statements:
            conn.execute(statement)


def set_up_as_owner(admin_url: str, app_role: str) -> bool:
    """schema.setup_database on a scratch database, run as its owner like the real setup."""
    import psycopg

    with psycopg.connect(admin_url, autocommit=True) as conn:
        conn.execute("SET ROLE ft_owner")
        return schema.setup_database(conn, app_role)


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


AUDIT_FIELDS = ("seq", "at", "member_no", "client_id", "action", "target", "result", "reason", "old_role", "new_role")


def audit_rows(store, team_id: str) -> list[dict[str, Any]]:
    """One team's audit records, oldest first, each as {column: value}."""
    return [
        dict(zip(AUDIT_FIELDS, row))
        for row in raw(store, f"SELECT {', '.join(AUDIT_FIELDS)} FROM audit_events WHERE team_id = ? ORDER BY seq", (team_id,))
    ]


def audit_counters(store, team_id: str) -> tuple[int, int, int]:
    """One team's (next_audit_seq, audit_writes, audit_reads)."""
    [row] = raw(store, "SELECT next_audit_seq, audit_writes, audit_reads FROM teams WHERE team_id = ?", (team_id,))
    return tuple(row)


def assert_audit_counts_agree(store) -> None:
    """The invariant behind the audit allowance, for every team: each record took the
    next number and one place of the write or the read allowance, so
    next_audit_seq - 1 = audit_writes + audit_reads = the team's records."""
    with _reader(store) as run:
        teams = run("SELECT team_id, next_audit_seq, audit_writes, audit_reads FROM teams")
        recorded = dict(run("SELECT team_id, COUNT(*) FROM audit_events GROUP BY team_id"))
    for team_id, next_seq, writes, reads in teams:
        assert next_seq - 1 == writes + reads == recorded.get(team_id, 0), (team_id, next_seq, writes, reads, recorded)
    assert set(recorded) <= {team_id for team_id, *_ in teams}  # no record of a team that doesn't exist


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
