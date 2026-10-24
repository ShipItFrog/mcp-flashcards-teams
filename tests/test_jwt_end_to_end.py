"""The whole stack with real signed JWTs: the real verifier, the SDK's auth
middleware, the MCP protocol, the tools and the database. Only the network fetch
of the provider's public keys is replaced (see jwt_helpers.py)."""

import time

import pytest
from helpers import HEADERS, INITIALIZE, TRANSPORTS, error_text, http, mcp_client, payload, running_app
from jwt_helpers import ATTACKER_KEY, DROP, PROJECT_ID, descope_token, make_verifier, sign

pytestmark = pytest.mark.anyio

CARD = {"question": "What does HTTP 401 mean?", "answer": "Not authenticated", "topic": "web"}

# Plain test tokens, and tokens shaped like Descope's (aud list, several scopes, azp).
TOKEN_SHAPES = [pytest.param(sign, id="plain"), pytest.param(descope_token, id="descope-shaped")]


@pytest.mark.parametrize("make", TOKEN_SHAPES)
@pytest.mark.parametrize("transport", TRANSPORTS)
async def test_signed_in_users_only_see_their_own_cards(store, transport, make):
    mode, stateless = transport
    alice, bob = make(sub="U2alice"), make(sub="U2bob")
    # The same person later, with a different token (e.g. after a refresh).
    alice_again = make(sub="U2alice", exp=int(time.time()) + 900)
    assert alice_again != alice
    async with running_app(store, stateless=stateless, token_verifier=make_verifier()) as app:
        async with mcp_client(app, alice, mode) as client:
            card_id = payload(await client.call_tool("add_card", CARD))["card"]["id"]

        async with mcp_client(app, bob, mode) as client:
            assert payload(await client.call_tool("list_cards", {}))["total"] == 0
            assert error_text(await client.call_tool("delete_card", {"card_id": card_id})).endswith(
                f"No card with id {card_id}"
            )

        async with mcp_client(app, alice_again, mode) as client:
            assert payload(await client.call_tool("list_cards", {}))["total"] == 1


BAD_TOKENS = {
    "signed-by-another-key": lambda: sign(key=ATTACKER_KEY),
    "issued-for-another-server": lambda: sign(aud="https://other.example.test/mcp"),
    "session-token-for-the-project": lambda: sign(aud=PROJECT_ID),
    "wrong-issuer": lambda: sign(iss="https://evil.example.test"),
    "expired": lambda: sign(exp=int(time.time()) - 120),
    "no-subject": lambda: sign(sub=DROP),
    "subject-overridden-dsub-present": lambda: sign(sub="acme", dsub="U2victim"),
}


@pytest.mark.parametrize("make_token", BAD_TOKENS.values(), ids=BAD_TOKENS.keys())
async def test_bad_tokens_get_401(store, make_token):
    async with running_app(store, token_verifier=make_verifier()) as app, http(app, make_token()) as hc:
        r = await hc.post("/mcp", json=INITIALIZE, headers=HEADERS)
    assert r.status_code == 401
    assert "resource_metadata=" in r.headers["www-authenticate"]


async def test_token_without_the_required_scope_gets_403(store):
    async with running_app(store, token_verifier=make_verifier()) as app, http(app, sign(scope=DROP)) as hc:
        r = await hc.post("/mcp", json=INITIALIZE, headers=HEADERS)
    assert r.status_code == 403


@pytest.mark.parametrize("make", TOKEN_SHAPES)
async def test_valid_token_gets_200(store, make):
    async with running_app(store, token_verifier=make_verifier()) as app, http(app, make()) as hc:
        r = await hc.post("/mcp", json=INITIALIZE, headers=HEADERS)
    assert r.status_code == 200
