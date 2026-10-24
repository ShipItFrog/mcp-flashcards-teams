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
from contextlib import asynccontextmanager
from typing import Any

import httpx2
import pytest
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp_types.version import MODERN_PROTOCOL_VERSIONS

from flashcards_teams.server import create_server
from flashcards_teams.store import PostgresCardStore, SqliteCardStore

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
) -> AccessToken:
    return AccessToken(
        token=value,
        client_id="test-client",
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
}


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


def empty_postgres_store(url: str) -> PostgresCardStore:
    """A Postgres store whose tables exist and hold nothing."""
    import psycopg

    store = PostgresCardStore(url)
    with psycopg.connect(url, autocommit=True) as conn:
        conn.execute("TRUNCATE owners, cards")
    return store


def total_cards(store) -> int:
    """Every card in the database, whoever owns it. For tests only: the stores
    themselves have no way to count across owners."""
    if isinstance(store, SqliteCardStore):
        return store._conn.execute("SELECT COUNT(*) FROM cards").fetchone()[0]
    with store._pool.connection() as conn:
        return conn.execute("SELECT COUNT(*) AS n FROM cards").fetchone()["n"]


def payload(result) -> Any:
    assert not result.is_error, f"unexpected tool error: {result.content}"
    if result.structured_content is not None:
        return result.structured_content
    return json.loads(result.content[0].text)


def error_text(result) -> str:
    assert result.is_error, f"expected a tool error, got {result.content}"
    return result.content[0].text
