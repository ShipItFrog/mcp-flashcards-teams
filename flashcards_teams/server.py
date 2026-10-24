"""Hosted, multi-user flashcards MCP server.

Each signed-in user has their own deck. Identity comes from the verified access
token (see identity.py); storage is always scoped to that user (see store.py).

Limits exist because this runs on free-tier hosting with open sign-up: per-user
card count and total size, short text fields, paginated listing, and a per-user
rate limit, so one account can't exhaust memory, storage or the event loop.
"""

from __future__ import annotations

import time
from collections import deque
from collections.abc import Callable
from typing import Annotated, Any

from mcp.server import MCPServer
from mcp.server.auth.provider import TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.server.mcpserver.exceptions import ToolError
from pydantic import Field

from .identity import current_owner
from .store import (
    MAX_CARDS_PER_OWNER,
    MAX_CHARS_PER_OWNER,
    CardLimitError,
    CardStore,
    StoreFullError,
    StoreUnavailableError,
)

MAX_QUESTION = 500
MAX_ANSWER = 1000
MAX_TOPIC = 50
DEFAULT_PAGE = 50
MAX_PAGE = 100
# Default per-user rate limit: this many tool calls per window.
RATE_LIMIT = (120, 60.0)

# Strict ints: rejects booleans and out-of-range numbers before they reach the database.
CardId = Annotated[int, Field(strict=True, ge=1, le=2**53)]
PageSize = Annotated[int, Field(strict=True, ge=1, le=MAX_PAGE)]
AfterId = Annotated[int, Field(strict=True, ge=0, le=2**53)]

INSTRUCTIONS = (
    "A personal flashcard deck. Add cards, quiz the user with review (it returns the "
    "question only), then record the result with grade_card. list_cards is paginated: "
    "pass next_after_id back as after_id to get the next page. Each user sees only "
    "their own cards."
)


def _check_characters(value: str, field: str) -> None:
    """Text both databases can store: valid UTF-8 (no lone surrogates) and no NUL,
    which Postgres text can't hold."""
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise ToolError(f"{field} contains invalid characters") from None
    if "\x00" in value:
        raise ToolError(f"{field} contains invalid characters")


def _text(value: str, field: str, limit: int) -> str:
    value = value.strip()
    if not value:
        raise ToolError(f"{field} must not be empty")
    if len(value) > limit:
        raise ToolError(f"{field} is too long (max {limit} characters)")
    _check_characters(value, field)
    return value


def _topic_filter(topic: str) -> str:
    """A topic filter: empty means all topics. Matching is case-insensitive (store.topic_key)."""
    topic = topic.strip()
    if len(topic) > MAX_TOPIC:
        raise ToolError(f"topic is too long (max {MAX_TOPIC} characters)")
    _check_characters(topic, "topic")
    return topic


async def _stored(call):
    """Await a store call; a database problem becomes a message the user can act on."""
    try:
        return await call
    except StoreUnavailableError:
        raise ToolError("The card database is temporarily unavailable. Please try again in a minute.") from None
    except StoreFullError:
        raise ToolError("The card database is out of space. Please let the server's owner know.") from None


class RateLimiter:
    """Sliding-window limit per user. In-process: fine for a single instance."""

    def __init__(self, max_calls: int, per_seconds: float, clock: Callable[[], float] = time.monotonic) -> None:
        self.max_calls = max_calls
        self.per_seconds = per_seconds
        self._clock = clock
        self._calls: dict[str, deque[float]] = {}

    def check(self, key: str) -> None:
        now = self._clock()
        calls = self._calls.setdefault(key, deque())
        while calls and now - calls[0] >= self.per_seconds:
            calls.popleft()
        if len(calls) >= self.max_calls:
            raise ToolError("Too many requests. Please wait a minute and try again.")
        calls.append(now)


def create_server(
    *,
    store: CardStore,
    token_verifier: TokenVerifier,
    issuer_url: str,
    resource_url: str,
    required_scopes: list[str] | None = None,
    rate_limit: tuple[int, float] = RATE_LIMIT,
) -> MCPServer:
    """Build the server. Everything it depends on is passed in, so tests can use a
    fake token verifier and a throwaway database."""

    mcp = MCPServer(
        name="flashcards-teams",
        instructions=INSTRUCTIONS,
        # Nothing here changes on its own, so there is nothing to subscribe to; the
        # 2026-07-28 subscriptions/listen stream would only be held open for nothing.
        subscriptions=False,
        token_verifier=token_verifier,
        auth=AuthSettings(
            issuer_url=issuer_url,
            resource_server_url=resource_url,
            # None rather than [] so the metadata leaves out scopes_supported entirely.
            required_scopes=required_scopes or None,
            # Only accept tokens issued for this server (RFC 8707). Set explicitly:
            # the SDK default changes in a future major version.
            validate_token_resource=True,
        ),
    )
    limiter = RateLimiter(*rate_limit)

    def owner() -> str:
        who = current_owner(issuer_url)
        limiter.check(who)
        return who

    @mcp.tool()
    async def add_card(question: str, answer: str, topic: str) -> dict[str, Any]:
        """Add a flashcard. Returns the new card, including its number."""
        who = owner()
        q = _text(question, "question", MAX_QUESTION)
        a = _text(answer, "answer", MAX_ANSWER)
        t = _text(topic, "topic", MAX_TOPIC)
        try:
            card = await _stored(store.add(who, q, a, t))
        except CardLimitError:
            raise ToolError(
                f"Deck is full (max {MAX_CARDS_PER_OWNER} cards or {MAX_CHARS_PER_OWNER:,} characters). "
                "Delete some cards first."
            ) from None
        return {"ok": True, "message": f"Added card #{card['id']}", "card": card}

    @mcp.tool()
    async def list_cards(topic: str = "", limit: PageSize = DEFAULT_PAGE, after_id: AfterId = 0) -> dict[str, Any]:
        """List your cards, a page at a time, optionally only one topic. To get the
        next page, call again with after_id set to next_after_id."""
        who = owner()
        t = _topic_filter(topic)
        # Fetch one extra card only to learn whether another page exists.
        cards = await _stored(store.list(who, t, limit + 1, after_id))
        has_more = len(cards) > limit
        cards = cards[:limit]
        total = await _stored(store.count(who, t))
        next_after_id = cards[-1]["id"] if has_more else None
        return {"ok": True, "total": total, "count": len(cards), "cards": cards, "next_after_id": next_after_id}

    @mcp.tool()
    async def review(topic: str = "") -> dict[str, Any]:
        """Draw the card you have gone longest without reviewing. Returns the question
        only, never the answer."""
        who = owner()
        card = await _stored(store.least_recently_reviewed(who, _topic_filter(topic)))
        if card is None:
            return {"ok": True, "card_id": None, "message": "No cards to review"}
        return {
            "ok": True,
            "card_id": card["id"],
            "topic": card["topic"],
            "question": card["question"],
            "hint": "After answering, call grade_card(card_id, correct) to record the result",
        }

    @mcp.tool()
    async def grade_card(card_id: CardId, correct: bool) -> dict[str, Any]:
        """Record a right or wrong answer and update the card's review time."""
        card = await _stored(store.record_review(owner(), card_id, correct))
        if card is None:
            # Same message whether the card doesn't exist or belongs to someone
            # else, so the reply never reveals another user's card numbers.
            raise ToolError(f"No card with id {card_id}")
        return {"ok": True, "message": f"Card #{card_id} marked {'correct' if correct else 'wrong'}", "card": card}

    @mcp.tool()
    async def delete_card(card_id: CardId) -> dict[str, Any]:
        """Delete one of your cards."""
        if not await _stored(store.delete(owner(), card_id)):
            raise ToolError(f"No card with id {card_id}")
        return {"ok": True, "message": f"Deleted card #{card_id}"}

    return mcp
