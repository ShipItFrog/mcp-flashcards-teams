"""The HTTP layer, checked with raw requests (status codes and headers) rather than
through an MCP client, so the client can't hide or retry anything."""

import pytest
from helpers import BASE, HEADERS, INITIALIZE, ISSUER, RESOURCE, http, running_app

pytestmark = pytest.mark.anyio

# The auth check runs before the server looks at which protocol generation a request
# uses; check both anyway, so a regression on either path shows up.
PROTOCOL_HEADERS = {"legacy": {}, "modern": {"MCP-Protocol-Version": "2026-07-28"}}
METADATA_URL = f"{BASE}/.well-known/oauth-protected-resource/mcp"


async def test_protected_resource_metadata_points_at_the_issuer(store):
    async with running_app(store) as app, http(app) as hc:
        r = await hc.get("/.well-known/oauth-protected-resource/mcp")
    assert r.status_code == 200
    body = r.json()
    assert body["resource"] == RESOURCE
    # Must match the identity provider's issuer string exactly - clients compare it.
    assert body["authorization_servers"] == [ISSUER]


@pytest.mark.parametrize("protocol", ["legacy", "modern"])
@pytest.mark.parametrize("token", [None, "not-a-real-token", "other-audience"])
async def test_missing_unknown_or_foreign_tokens_get_401(store, token, protocol):
    async with running_app(store) as app, http(app, token) as hc:
        r = await hc.post("/mcp", json=INITIALIZE, headers={**HEADERS, **PROTOCOL_HEADERS[protocol]})
    assert r.status_code == 401
    # Tells the client where to start the login flow.
    assert f'resource_metadata="{METADATA_URL}"' in r.headers["www-authenticate"]


@pytest.mark.parametrize("protocol", ["legacy", "modern"])
async def test_token_without_the_required_scope_gets_403(store, protocol):
    async with running_app(store) as app, http(app, "no-scope") as hc:
        r = await hc.post("/mcp", json=INITIALIZE, headers={**HEADERS, **PROTOCOL_HEADERS[protocol]})
    assert r.status_code == 403
    assert "insufficient_scope" in r.headers["www-authenticate"]


async def test_valid_token_is_accepted(store):
    async with running_app(store) as app, http(app, "alice-1") as hc:
        r = await hc.post("/mcp", json=INITIALIZE, headers=HEADERS)
    assert r.status_code == 200
