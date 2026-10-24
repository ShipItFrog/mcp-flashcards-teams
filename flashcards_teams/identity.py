"""Who is calling.

The only trusted source of identity is the access token the SDK has already
verified (signature, issuer, audience, expiry - see the token verifier). Tool
arguments, request metadata and headers are never used as identity: a client can
put anything in them.
"""

from __future__ import annotations

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.mcpserver.exceptions import ToolError


def _normalize_issuer(issuer: str) -> str:
    # Used only for comparing and for the storage key, so that adding or removing a
    # trailing slash in configuration can't silently orphan everyone's data.
    return issuer.rstrip("/")


def current_owner(issuer: str) -> str:
    """Storage key for the signed-in user: issuer plus the token's subject (sub).

    `sub` is only unique within one issuer, so the issuer is part of the key, and
    the token's own `iss` claim must match the configured issuer. The token
    verifier is expected to enforce that already; this is a second line of
    defence, so a verifier that ever accepts a second issuer can't merge two
    different people who share a `sub`.
    """
    token = get_access_token()
    if token is None or not token.subject:
        # The HTTP layer already rejects requests without a valid token.
        raise ToolError("Not signed in.")
    token_issuer = (token.claims or {}).get("iss")
    if not isinstance(token_issuer, str) or _normalize_issuer(token_issuer) != _normalize_issuer(issuer):
        raise ToolError("Not signed in.")
    return f"{_normalize_issuer(issuer)}|{token.subject}"
