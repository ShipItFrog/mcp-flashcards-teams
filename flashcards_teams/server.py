"""Hosted flashcards MCP server for people and their teams.

Identity comes from the verified access token (see identity.py) and nothing else.
Each card belongs to a team; without a team_id the tools use the caller's personal
team, so a single user sees the same tools and replies as a personal deck. Roles live
in the database and are checked by the store on every call (see store.py and
permissions.py); a refusal is a tool error, never an HTTP 403 (that is kept for a
token without the required scope), and tools/list is the same for everyone.

Limits exist because this runs on free-tier hosting with open sign-up: per-team card
count and total size, short text fields, paginated listing, a cap on teams, members
and audit records, and a per-user rate limit, so one account can't exhaust memory,
storage or the event loop.
"""

from __future__ import annotations

import logging
import time
from collections import deque
from collections.abc import Callable
from typing import Annotated, Any, Literal

from mcp.server import MCPServer
from mcp.server.auth.provider import TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.server.mcpserver.exceptions import ToolError
from pydantic import Field

from . import ids, limits, permissions
from .identity import current_client_id, current_owner
from .store import Actor, AuditFullError, CardStore, Outcome, StoreFullError, StoreUnavailableError

logger = logging.getLogger(__name__)

MAX_QUESTION = 500
MAX_ANSWER = 1000
MAX_TOPIC = 50
DEFAULT_PAGE = 50
MAX_PAGE = 100
DEFAULT_AUDIT_PAGE = 100
MAX_AUDIT_PAGE = 500
# Default per-user rate limit: this many tool calls per window.
RATE_LIMIT = (120, 60.0)

# Strict ints: rejects booleans and out-of-range numbers before they reach the database.
CardId = Annotated[int, Field(strict=True, ge=1, le=2**53)]
PageSize = Annotated[int, Field(strict=True, ge=1, le=MAX_PAGE)]
AfterId = Annotated[int, Field(strict=True, ge=0, le=2**53)]
# The format is checked by the server (ids.TEAM_ID_RE): a malformed id is "no team".
TeamId = Annotated[str, Field(min_length=1, max_length=64)]
MemberNo = Annotated[int, Field(strict=True, ge=1, le=2**53)]
# limits.MAX_INVITE_CODE, written out because a type is fixed when this module loads
# (test_tool_schemas checks that the two agree).
InviteCode = Annotated[str, Field(min_length=1, max_length=100)]
Role = Literal["owner", "editor", "viewer"]
InviteRole = Literal["editor", "viewer"]
# Reading the audit log uses up its own allowance, so a page may be large.
AuditPageSize = Annotated[int, Field(strict=True, ge=1, le=MAX_AUDIT_PAGE)]

M_NO_TEAM = "No team with that id."
M_DENIED = "Permission denied: {tool} needs at least the {role} role in this team."
M_NO_CARD = "No card with id {card_id}"
M_DECK_FULL = "Deck is full (max {cards} cards or {chars:,} characters). Delete some cards first."
M_NO_MEMBER = "No member with number {member_no} in this team."
M_LAST_OWNER = "A team needs at least one owner. Make another member an owner first."
M_PERSONAL = "Your personal team can't have other members. Use create_team for a shared team."
M_PERSONAL_LEAVE = "You can't leave your personal team."
M_INVITE = "That invite code is not valid. Ask a team owner for a new one."
M_ALREADY = "You are already a member of this team (member #{member_no})."
M_TEAM_FULL = "This team already has {n} members, the most allowed."
M_TOO_MANY_TEAMS = "You are already in {n} shared teams, the most allowed."
M_AUDIT_NEARLY_FULL = (
    "This team's audit log is nearly full, so this change can't be recorded and was not made. Owners can still "
    "read the log and change or remove members, and members can still leave the team. Reading cards still works."
)
M_AUDIT_FULL = (
    "This team's audit log is full, so this change can't be recorded and was not made. Owners can still read "
    "the log. Reading cards still works."
)
M_AUDIT_READS_FULL = (
    "This team's audit log has reached its limit of recorded reads, so it can't be read through the server any "
    "more. The server's owner can still read it in the database."
)
M_SERVER_FULL = "This server has reached its limit of teams. Please let the server's owner know."
M_REFUSED = "The card database refused the change. Please let the server's owner know."

INSTRUCTIONS = (
    "Flashcard decks for you and your teams. Without team_id, tools use your personal deck. In a team, viewers "
    "can list and review cards; editors can also add, grade and delete them; owners can also invite people, "
    "change or remove members, and read the team's audit log. Any member can leave a team with leave_team, "
    "except its last owner. Use list_teams to see your teams and, for teams you own, the member numbers. "
    "join_team takes an invite code from a team owner; codes are shown once, so pass them on privately. review "
    "returns the question only; record the result with grade_card. list_cards is paginated: pass next_after_id "
    "back as after_id."
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


async def _outcome(tool: str, call) -> Outcome:
    """Await a store call that writes. A change the audit log can't take was not made."""
    try:
        return await _stored(call)
    except AuditFullError as e:
        logger.warning("Refused %s: the team's audit log can't take another record", tool)
        message = {"nearly": M_AUDIT_NEARLY_FULL, "full": M_AUDIT_FULL, "reads": M_AUDIT_READS_FULL}[e.kind]
        raise ToolError(message) from None


def _result(outcome: Outcome, tool: str, **ctx: Any) -> Any:
    """The value of a successful outcome; anything else becomes the tool error for it.
    ``ctx`` holds what the messages quote (card_id, member_no)."""
    if outcome.kind == "ok":
        return outcome.value
    if outcome.kind == "not_member":
        # Nothing that identifies the caller or the team: a stranger's attempt.
        logger.info("Refused %s: caller is not a member of the requested team", tool)
        raise ToolError(M_NO_TEAM)
    if outcome.kind == "denied":
        raise ToolError(M_DENIED.format(tool=tool, role=permissions.REQUIRED.get(tool, "owner")))
    reason = outcome.reason
    if reason == "server_full":
        logger.warning("Refused %s: the server's team limit is reached", tool)
        raise ToolError(M_SERVER_FULL)
    if reason == "invite_invalid":
        logger.info("Refused join_team: invite code not valid")
        raise ToolError(M_INVITE)
    if reason == "team_full":
        logger.info("Refused join_team: the team is full")
        raise ToolError(M_TEAM_FULL.format(n=limits.MAX_MEMBERS_PER_TEAM))
    messages = {
        "no_card": lambda: M_NO_CARD.format(card_id=ctx["card_id"]),
        "deck_full": lambda: M_DECK_FULL.format(cards=limits.MAX_CARDS_PER_TEAM, chars=limits.MAX_CHARS_PER_TEAM),
        "no_member": lambda: M_NO_MEMBER.format(member_no=ctx["member_no"]),
        "last_owner": lambda: M_LAST_OWNER,
        "personal_team": lambda: M_PERSONAL_LEAVE if tool == "leave_team" else M_PERSONAL,
        "already_member": lambda: M_ALREADY.format(member_no=outcome.value),
        "too_many_teams": lambda: M_TOO_MANY_TEAMS.format(n=limits.MAX_SHARED_TEAMS_PER_PERSON),
    }
    raise ToolError(messages[reason]())


def _check_team_id(team_id: str | None, tool: str) -> None:
    """A team id that can't exist is "no team", without asking the database."""
    if team_id is not None and ids.TEAM_ID_RE.fullmatch(team_id) is None:
        _result(Outcome("not_member"), tool)


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

    def caller() -> Actor:
        who = owner()
        return Actor(who, current_client_id())

    @mcp.tool()
    async def add_card(question: str, answer: str, topic: str, team_id: TeamId | None = None) -> dict[str, Any]:
        """Add a flashcard to your personal deck, or to a team's deck with team_id
        (editors and owners). Returns the new card, including its number."""
        actor = caller()
        q = _text(question, "question", MAX_QUESTION)
        a = _text(answer, "answer", MAX_ANSWER)
        t = _text(topic, "topic", MAX_TOPIC)
        _check_team_id(team_id, "add_card")
        card = _result(await _outcome("add_card", store.add(actor, team_id, q, a, t)), "add_card")
        return {"ok": True, "message": f"Added card #{card['id']}", "card": card}

    @mcp.tool()
    async def list_cards(
        topic: str = "", limit: PageSize = DEFAULT_PAGE, after_id: AfterId = 0, team_id: TeamId | None = None
    ) -> dict[str, Any]:
        """List the cards in your personal deck (or a team's, with team_id), a page at a
        time, optionally only one topic. To get the next page, call again with after_id
        set to next_after_id."""
        actor = caller()
        t = _topic_filter(topic)
        _check_team_id(team_id, "list_cards")
        # Fetch one extra card only to learn whether another page exists.
        page = _result(await _stored(store.list_page(actor, team_id, t, limit + 1, after_id)), "list_cards")
        cards = page["cards"]
        has_more = len(cards) > limit
        cards = cards[:limit]
        next_after_id = cards[-1]["id"] if has_more else None
        return {"ok": True, "total": page["total"], "count": len(cards), "cards": cards, "next_after_id": next_after_id}

    @mcp.tool()
    async def review(topic: str = "", team_id: TeamId | None = None) -> dict[str, Any]:
        """Draw the card you have gone longest without reviewing, from your personal
        deck or a team's. Returns the question only, never the answer."""
        actor = caller()
        t = _topic_filter(topic)
        _check_team_id(team_id, "review")
        card = _result(await _stored(store.least_recently_reviewed(actor, team_id, t)), "review")
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
    async def grade_card(card_id: CardId, correct: bool, team_id: TeamId | None = None) -> dict[str, Any]:
        """Record a right or wrong answer and update the card's review time (in a team:
        editors and owners)."""
        actor = caller()
        _check_team_id(team_id, "grade_card")
        # Same message whether the card doesn't exist or is in another team, so the
        # reply never reveals another team's card numbers.
        card = _result(
            await _outcome("grade_card", store.record_review(actor, team_id, card_id, correct)), "grade_card",
            card_id=card_id,
        )
        return {"ok": True, "message": f"Card #{card_id} marked {'correct' if correct else 'wrong'}", "card": card}

    @mcp.tool()
    async def delete_card(card_id: CardId, team_id: TeamId | None = None) -> dict[str, Any]:
        """Delete a card from your personal deck or a team's (editors and owners)."""
        actor = caller()
        _check_team_id(team_id, "delete_card")
        _result(await _outcome("delete_card", store.delete(actor, team_id, card_id)), "delete_card", card_id=card_id)
        return {"ok": True, "message": f"Deleted card #{card_id}"}

    @mcp.tool()
    async def create_team(name: str) -> dict[str, Any]:
        """Create a shared team with its own deck. You become its owner (member #1)."""
        actor = caller()
        n = _text(name, "name", limits.MAX_TEAM_NAME)
        team = _result(await _outcome("create_team", store.create_team(actor, n)), "create_team")
        return {"ok": True, **team}

    @mcp.tool()
    async def list_teams() -> dict[str, Any]:
        """List your teams, your personal team first, with your role and member number.
        For teams you own, also the members (by number only) and the audit log's use."""
        actor = caller()
        teams = _result(await _stored(store.list_teams(actor)), "list_teams")
        return {"ok": True, "teams": teams}

    @mcp.tool()
    async def create_invite(team_id: TeamId, role: InviteRole) -> dict[str, Any]:
        """Create a one-time invite code for a team (owners only). The code is shown
        only in this reply and expires after 72 hours."""
        actor = caller()
        _check_team_id(team_id, "create_invite")
        # The store only ever sees the code's hash.
        code = ids.new_invite_code()
        invite = _result(
            await _outcome("create_invite", store.create_invite(actor, team_id, role, ids.hash_invite(code))),
            "create_invite",
        )
        return {
            "ok": True,
            "code": code,
            **invite,
            "message": (
                f"Give this code to one person, privately. It works once and expires at {invite['expires_at']}. "
                "It won't be shown again."
            ),
        }

    @mcp.tool()
    async def join_team(code: InviteCode) -> dict[str, Any]:
        """Join a team with an invite code from one of its owners."""
        actor = caller()
        try:
            code_hash = ids.hash_invite(code)
        except UnicodeEncodeError:  # a lone surrogate: no code looks like this
            return _result(Outcome("failed", reason="invite_invalid", logged=False), "join_team")
        team = _result(await _outcome("join_team", store.join_team(actor, code_hash)), "join_team")
        return {"ok": True, **team}

    @mcp.tool()
    async def set_member_role(team_id: TeamId, member_no: MemberNo, role: Role) -> dict[str, Any]:
        """Change a member's role (owners only). Member numbers are in list_teams."""
        actor = caller()
        _check_team_id(team_id, "set_member_role")
        changed = _result(
            await _outcome("set_member_role", store.set_member_role(actor, team_id, member_no, role)),
            "set_member_role", member_no=member_no,
        )
        return {"ok": True, **changed, "message": f"Member #{member_no} is now {role}"}

    @mcp.tool()
    async def remove_member(team_id: TeamId, member_no: MemberNo) -> dict[str, Any]:
        """Remove a member from a team (owners only). To come back they need a new invite."""
        actor = caller()
        _check_team_id(team_id, "remove_member")
        _result(
            await _outcome("remove_member", store.remove_member(actor, team_id, member_no)),
            "remove_member", member_no=member_no,
        )
        return {"ok": True, "message": f"Removed member #{member_no}"}

    @mcp.tool()
    async def read_audit_log(
        team_id: TeamId, limit: AuditPageSize = DEFAULT_AUDIT_PAGE, after_seq: AfterId = 0
    ) -> dict[str, Any]:
        """Read a team's audit log, oldest first, a page at a time (owners only). To get
        the next page, call again with after_seq set to next_after_seq."""
        actor = caller()
        _check_team_id(team_id, "read_audit_log")
        page = _result(
            await _outcome("read_audit_log", store.read_audit_log(actor, team_id, limit + 1, after_seq)),
            "read_audit_log",
        )
        return {"ok": True, **page}

    @mcp.tool()
    async def leave_team(team_id: TeamId) -> dict[str, Any]:
        """Leave a team. Its last owner can't leave, and nobody can leave their personal team."""
        actor = caller()
        _check_team_id(team_id, "leave_team")
        _result(await _outcome("leave_team", store.leave_team(actor, team_id)), "leave_team")
        return {"ok": True, "message": "You left the team."}

    return mcp
