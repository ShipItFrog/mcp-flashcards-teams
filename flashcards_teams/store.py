"""Card storage, teams, roles and the audit log.

Every card belongs to a team, and every call names the team (or, without a team id,
the caller's personal team). Membership and role are read from the database inside
the same transaction as the action, every time: nothing comes from the token but who
the caller is, and nothing is cached. A team the caller isn't in looks exactly like
one that doesn't exist.

Every write to an existing team goes through ``_Ops._guarded``, one transaction in a
fixed order: find the team, check membership without a lock, lock the team's row, read
the member again, check the permission, check the member's daily limit, check the
request, allocate an audit number, act, record the audit row, count the change toward
the daily limit, commit. Creating a team, joining one, and the first add_card
(which creates the caller's personal team) take their locks themselves, always in the
order person, site, team row. Refusals and failures are returned as an ``Outcome``
rather than raised, so their audit rows commit too (a refusal the audit log has no room
for is only counted). Only a change the audit log can't record, or a database error,
raises, and then nothing at all is kept.

Card numbers, member numbers and invite numbers are per team, start at 1 and are
never reused, so a number someone remembers can't silently point at something new.

Topics are matched case-insensitively: each card stores the topic as typed, plus a
normalized ``topic_key`` used for filtering (see ``topic_key``).

Two stores behave the same way and run the same tests: ``SqliteCardStore`` for local
development, and ``PostgresCardStore`` for the hosted server, where the disk is wiped
on every restart. They share all SQL and all transaction logic (``_Ops``); each one
only supplies a few hooks (transactions, locks, error mapping).
"""

from __future__ import annotations

import logging
import sqlite3
import threading
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, Protocol

import anyio.to_thread

from . import ids, limits, permissions, schema

logger = logging.getLogger(__name__)

# Postgres connections. The server runs as one process, so a few connections are
# plenty, and a short wait for a free one fails fast instead of piling requests up.
POOL_MIN_SIZE = 1
POOL_MAX_SIZE = 4
POOL_WAIT_SECONDS = 10.0
# How long startup waits for the database: Neon's free tier pauses after 5 minutes
# idle and usually wakes in under a second.
POOL_OPEN_SECONDS = 30.0
CONNECT_TIMEOUT_SECONDS = 10
# Longest a write waits for its team's row lock before giving up ("temporarily unavailable").
LOCK_WAIT_SECONDS = 10
# Longest a transaction may sit idle, and one statement may run, before Postgres ends it
# ("temporarily unavailable"). A stuck transaction holds back VACUUM, so every write
# meanwhile leaves an old row version behind; this way none lives past half a minute.
PG_IDLE_IN_TRANSACTION_TIMEOUT = "30s"
PG_STATEMENT_TIMEOUT = "30s"
# The search path for every transaction. Postgres' default starts with "$user", so a
# schema named after the app role, if one existed and the role could create tables in
# it, would take the place of the server's tables for every unqualified name. pg_temp is
# listed last because, unlisted, a session's temporary schema is searched first for table
# names: through a transaction-mode pooler (Neon's -pooler URLs) backends are shared, so a
# temporary table named audit_events (or teams) left in one by anyone holding the app
# role's credentials would take the place of the server's table, diverting or hiding records.
PG_SEARCH_PATH = "public, pg_temp"
# Shown in Postgres' own views (pg_stat_activity), so this server's connections can be told apart.
APPLICATION_NAME = "mcp-flashcards-teams"


@dataclass(frozen=True)
class Actor:
    """Who is calling: ``principal`` is identity.current_owner's "issuer|sub" and is never
    shown or recorded; ``client_id`` is the app's own claim, cleaned, for the audit log."""

    principal: str
    client_id: str


@dataclass(frozen=True)
class Outcome:
    """What a store call came to. ``denied`` carries the tool name as its value;
    ``failed`` carries a reason code. For those two, ``logged`` is False when no audit
    row was written; a ``not_member`` outcome never has one."""

    kind: Literal["ok", "not_member", "denied", "failed"]
    value: Any = None
    reason: str = ""
    logged: bool = True


class StoreUnavailableError(Exception):
    """The database can't be reached right now. Raised instead of the driver's own
    error, whose text may name the host or the database user."""


class StoreFullError(Exception):
    """The database is out of space or over a resource limit: retrying won't help."""


class StoreRefusedError(Exception):
    """The database refused a change: a constraint, an append-only trigger or a missing
    right. Nothing of the call was kept. Raised instead of the driver's own error, whose
    text may quote the row (card content included)."""


class AuditFullError(Exception):
    """The team's audit allowance has no room for the record of this change, so the
    change was not made.

    ``kind`` is "nearly" (only the reserved part is left), "full" (writes) or "reads"."""

    def __init__(self, kind: Literal["nearly", "full", "reads"]) -> None:
        super().__init__(kind)
        self.kind = kind


class SchemaNotReadyError(Exception):
    """The Postgres tables are missing or not as setup_database leaves them."""


class AppRoleTooPowerfulError(Exception):
    """The role the server connects as could change or remove audit records."""


def topic_key(topic: str) -> str:
    """Normalized form used to match topics: trimmed and case-folded."""
    return topic.strip().casefold()


class CardStore(Protocol):
    async def add(self, actor: Actor, team_id: str | None, question: str, answer: str, topic: str) -> Outcome: ...

    async def list_page(
        self, actor: Actor, team_id: str | None, topic: str, limit_plus_one: int, after_id: int
    ) -> Outcome: ...

    async def least_recently_reviewed(self, actor: Actor, team_id: str | None, topic: str) -> Outcome: ...

    async def record_review(self, actor: Actor, team_id: str | None, card_no: int, correct: bool) -> Outcome: ...

    async def delete(self, actor: Actor, team_id: str | None, card_no: int) -> Outcome: ...

    async def create_team(self, actor: Actor, name: str) -> Outcome: ...

    async def list_teams(self, actor: Actor) -> Outcome: ...

    async def create_invite(self, actor: Actor, team_id: str, role: str, code_hash: str) -> Outcome: ...

    async def join_team(self, actor: Actor, code_hash: str) -> Outcome: ...

    async def set_member_role(self, actor: Actor, team_id: str, member_no: int, role: str) -> Outcome: ...

    async def remove_member(self, actor: Actor, team_id: str, member_no: int) -> Outcome: ...

    async def leave_team(self, actor: Actor, team_id: str) -> Outcome: ...

    async def read_audit_log(self, actor: Actor, team_id: str, limit_plus_one: int, after_seq: int) -> Outcome: ...

    def close(self) -> None: ...


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


# --- shared SQL --------------------------------------------------------------
# Both databases run these. Placeholders are "?" (the Postgres store turns them into
# "%s"), so no statement may contain "%". Values always travel as parameters.

# The team_id column is never selected for a card: it is a key, not card data.
_CARD_COLUMNS = "card_no, question, answer, topic, created_at, last_reviewed, review_count, correct_count, wrong_count"
_AUDIT_COLUMNS = "seq, at, member_no, client_id, action, target, result, reason, old_role, new_role"

_SQL_PERSONAL = "SELECT team_id FROM teams WHERE personal_of = ?"
_SQL_COUNT_TEAMS = "SELECT COUNT(*) AS n FROM teams"
_SQL_INSERT_PERSONAL = (
    "INSERT INTO teams (team_id, name, personal_of, created_at, next_member_no) VALUES (?, ?, ?, ?, 2)"
    " ON CONFLICT (personal_of) DO NOTHING RETURNING team_id"
)
_SQL_INSERT_TEAM = "INSERT INTO teams (team_id, name, created_at, next_member_no) VALUES (?, ?, ?, 2)"
_SQL_MEMBER = (
    "SELECT member_no, role, refused_count, writes_day, writes_today FROM members WHERE team_id = ? AND principal = ?"
)
# The Postgres store appends " FOR UPDATE": every write to a team queues on this row.
_SQL_LOCK_TEAM = (
    "SELECT name, personal_of, next_card_no, next_member_no, next_invite_no, next_audit_seq, audit_writes, audit_reads"
    " FROM teams WHERE team_id = ?"
)
_SQL_INSERT_MEMBER = (
    "INSERT INTO members (team_id, member_no, principal, role, joined_at, via_invite_no) VALUES (?, ?, ?, ?, ?, ?)"
)
_SQL_NEXT_MEMBER_NO = "UPDATE teams SET next_member_no = next_member_no + 1 WHERE team_id = ?"
_SQL_COUNT_SHARED = (
    "SELECT COUNT(*) AS n FROM members m JOIN teams t ON t.team_id = m.team_id"
    " WHERE m.principal = ? AND t.personal_of IS NULL"
)
_SQL_COUNT_MEMBERS = "SELECT COUNT(*) AS n FROM members WHERE team_id = ?"
_SQL_COUNT_OWNERS = "SELECT COUNT(*) AS n FROM members WHERE team_id = ? AND role = 'owner'"
_SQL_TARGET_MEMBER = "SELECT role FROM members WHERE team_id = ? AND member_no = ?"
_SQL_SET_ROLE = "UPDATE members SET role = ? WHERE team_id = ? AND member_no = ?"
_SQL_REMOVE = "DELETE FROM members WHERE team_id = ? AND member_no = ?"
_SQL_LEAVE = "DELETE FROM members WHERE team_id = ? AND member_no = ?"
_SQL_COUNT_REFUSAL = "UPDATE members SET refused_count = refused_count + 1 WHERE team_id = ? AND member_no = ?"
# One more change today, or the first of a new UTC day. Both sides of SET read the row as
# it was before this UPDATE, in both databases.
_SQL_COUNT_WRITE = (
    "UPDATE members SET writes_today = CASE WHEN writes_day = ? THEN writes_today + 1 ELSE 1 END, writes_day = ?"
    " WHERE team_id = ? AND member_no = ?"
)
_SQL_MY_TEAMS = (
    "SELECT t.team_id, t.name, t.personal_of IS NOT NULL AS personal, m.role, m.member_no, t.audit_writes, t.audit_reads"
    " FROM members m JOIN teams t ON t.team_id = m.team_id WHERE m.principal = ?"
    " ORDER BY t.personal_of IS NULL, t.created_at, t.team_id"
)
_SQL_TEAM_MEMBERS = (
    "SELECT member_no, role, joined_at, via_invite_no, refused_count FROM members WHERE team_id = ? ORDER BY member_no"
)

_SQL_USAGE = (
    "SELECT COUNT(*) AS cards, COALESCE(SUM(LENGTH(question) + LENGTH(answer) + LENGTH(topic)), 0) AS chars"
    " FROM cards WHERE team_id = ?"
)
_SQL_NEXT_CARD_NO = "UPDATE teams SET next_card_no = next_card_no + 1 WHERE team_id = ?"
_SQL_INSERT_CARD = (
    "INSERT INTO cards (team_id, card_no, question, answer, topic, topic_key, created_at)"
    f" VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING {_CARD_COLUMNS}"
)
_SQL_CARD_EXISTS = "SELECT card_no FROM cards WHERE team_id = ? AND card_no = ?"
_SQL_GRADE = (
    "UPDATE cards SET last_reviewed = ?, review_count = review_count + 1,"
    " correct_count = correct_count + ?, wrong_count = wrong_count + ?"
    f" WHERE team_id = ? AND card_no = ? RETURNING {_CARD_COLUMNS}"
)
_SQL_DELETE = "DELETE FROM cards WHERE team_id = ? AND card_no = ?"
# The topic filter takes the topic key twice: an empty key means every topic.
_SQL_LIST = (
    f"SELECT {_CARD_COLUMNS} FROM cards WHERE team_id = ? AND card_no > ?"
    " AND (CAST(? AS TEXT) = '' OR topic_key = ?) ORDER BY card_no LIMIT ?"
)
_SQL_COUNT = "SELECT COUNT(*) AS n FROM cards WHERE team_id = ? AND (CAST(? AS TEXT) = '' OR topic_key = ?)"
# Never-reviewed cards first (Postgres sorts NULL last by default), then oldest review first.
_SQL_REVIEW = (
    f"SELECT {_CARD_COLUMNS} FROM cards WHERE team_id = ? AND (CAST(? AS TEXT) = '' OR topic_key = ?)"
    " ORDER BY last_reviewed IS NOT NULL, last_reviewed, card_no LIMIT 1"
)

_SQL_INVITE_TEAM = "SELECT team_id FROM invites WHERE code_hash = ?"
# Valid means unused, unexpired, and made by someone who is an owner right now.
_SQL_INVITE = (
    "SELECT invite_no, role FROM invites WHERE team_id = ? AND code_hash = ? AND used_at IS NULL AND expires_at > ?"
    " AND EXISTS (SELECT 1 FROM members WHERE members.team_id = invites.team_id"
    " AND members.member_no = invites.created_by AND members.role = 'owner')"
)
_SQL_USE_INVITE = "UPDATE invites SET used_at = ?, used_by = ? WHERE team_id = ? AND invite_no = ?"
_SQL_NEXT_INVITE_NO = "UPDATE teams SET next_invite_no = next_invite_no + 1 WHERE team_id = ?"
_SQL_INSERT_INVITE = (
    "INSERT INTO invites (team_id, invite_no, code_hash, role, created_by, created_at, expires_at)"
    " VALUES (?, ?, ?, ?, ?, ?, ?)"
)

# Allocate the next audit number and use up one place of the allowance, in one
# statement under the team's row lock: no gap between checking and counting. The
# RETURNING value is the next unused number, so the new row's is one less.
_SQL_ALLOC_SEQ = (
    "UPDATE teams SET next_audit_seq = next_audit_seq + 1, audit_writes = audit_writes + 1"
    " WHERE team_id = ? AND audit_writes < ? RETURNING next_audit_seq"
)
_SQL_ALLOC_READ_SEQ = (
    "UPDATE teams SET next_audit_seq = next_audit_seq + 1, audit_reads = audit_reads + 1"
    " WHERE team_id = ? AND audit_reads < ? RETURNING next_audit_seq"
)
_SQL_AUDIT_WRITES = "SELECT audit_writes FROM teams WHERE team_id = ?"
_SQL_INSERT_AUDIT = f"INSERT INTO audit_events (team_id, {_AUDIT_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
_SQL_AUDIT_PAGE = f"SELECT {_AUDIT_COLUMNS} FROM audit_events WHERE team_id = ? AND seq > ? ORDER BY seq LIMIT ?"


def _row_to_card(row: Any) -> dict[str, Any]:
    card = dict(row)
    card["id"] = card.pop("card_no")
    return card


def _one(cursor: Any) -> Any:
    """The first row, or None. Reads every row, so the statement is finished before
    the transaction ends (SQLite won't commit around an unfinished write)."""
    rows = cursor.fetchall()
    return rows[0] if rows else None


def _iso(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat()


# --- shared transaction logic -------------------------------------------------


@dataclass(frozen=True)
class _Call:
    """One guarded write, after the team's row is locked and the member read again."""

    q: Callable[..., Any]
    tool: str
    actor: Actor
    team_id: str
    target: str  # what the audit row names: "team", "card:N", "member:N", "invite:N" or "log:N"
    team: Any  # the locked team row
    member: Any  # the caller's members row, read under the lock


class _Ops:
    """The transaction logic both stores share. ``x`` is the store, which supplies the
    hooks: ``tx(read_only)``, ``lock_team_suffix``, ``lock_person``, ``lock_site``,
    ``map_errors`` and the clock."""

    def __init__(self, x: Any) -> None:
        self.x = x

    def _now(self) -> str:
        return self.x._clock().isoformat()

    def _member(self, q: Callable[..., Any], team_id: str, principal: str) -> Any:
        return _one(q(_SQL_MEMBER, (team_id, principal)))

    # --- the guarded write ---------------------------------------------------

    def _guarded(
        self, tool: str, actor: Actor, team_id: str | None, target: str | None, action: Callable[[_Call], Outcome]
    ) -> Outcome:
        """Run one team write in the fixed order (see the module docstring). ``action``
        does the checks that need the lock, then allocates, acts and records.
        ``target`` None means the caller's own member number."""
        x = self.x
        with x.tx(read_only=False) as q:
            if team_id is None:
                found = self._personal_team(q, actor, tool)
                if isinstance(found, Outcome):
                    return found
                team_id = found
            # Checked before taking the lock, so a stranger can't queue on a team's row.
            if self._member(q, team_id, actor.principal) is None:
                return Outcome("not_member")
            team = _one(q(_SQL_LOCK_TEAM + x.lock_team_suffix, (team_id,)))
            # Read again under the lock: this is the role that counts.
            member = self._member(q, team_id, actor.principal)
            if team is None or member is None:
                return Outcome("not_member")
            c = _Call(q, tool, actor, team_id, target or f"member:{member['member_no']}", team, member)
            # The permission comes before any check that could tell what exists.
            if not permissions.allowed(member["role"], tool):
                return self._refuse(c, "denied", "role", tool)
            capped = tool in permissions.DAILY_CAPPED_TOOLS
            # So does the daily limit. The member row was read under the lock, so calls at
            # the same time can't pass it together.
            if capped and self._daily_limit_reached(c):
                return self._refuse(c, "failed", "daily_limit")
            outcome = action(c)
            if capped and outcome.kind == "ok":
                today = self._today()
                q(_SQL_COUNT_WRITE, (today, today, team_id, member["member_no"]))
            return outcome

    def _today(self) -> str:
        """Today's UTC date, which the daily limit counts by."""
        return self.x._clock().astimezone(timezone.utc).date().isoformat()

    def _daily_limit_reached(self, c: _Call) -> bool:
        """Whether the caller has made all the changes one member may make in this team today."""
        return (
            c.member["writes_day"] == self._today()
            and c.member["writes_today"] >= limits.MAX_WRITES_PER_MEMBER_PER_DAY
        )

    def _personal_team(self, q: Callable[..., Any], actor: Actor, tool: str) -> str | Outcome:
        """The caller's personal team. Only add_card creates it; grading or deleting
        without one is simply "no such card", with no team to record it in."""
        row = _one(q(_SQL_PERSONAL, (actor.principal,)))
        if row is not None:
            return row["team_id"]
        if tool != "add_card":
            return Outcome("failed", reason="no_card", logged=False)
        self.x.lock_site(q)
        # Again under the lock: a first add that ran at the same time may have made it
        # while this one waited, and it must not count as one team too many.
        row = _one(q(_SQL_PERSONAL, (actor.principal,)))
        if row is not None:
            return row["team_id"]
        return self._create_personal_team(q, actor)

    def _create_personal_team(self, q: Callable[..., Any], actor: Actor) -> str | Outcome:
        """Make the caller's personal team, under the site lock, if the server has room."""
        if _one(q(_SQL_COUNT_TEAMS, ()))["n"] >= limits.MAX_TEAMS_TOTAL:
            return Outcome("failed", reason="server_full", logged=False)
        now = self._now()
        created = _one(q(_SQL_INSERT_PERSONAL, (ids.new_team_id(), limits.PERSONAL_TEAM_NAME, actor.principal, now)))
        if created is None:
            # A second line of defence: this store always looks again under the site lock,
            # so only a row inserted without that lock (by other code) can get here.
            return _one(q(_SQL_PERSONAL, (actor.principal,)))["team_id"]
        team_id = created["team_id"]
        q(_SQL_INSERT_MEMBER, (team_id, 1, actor.principal, "owner", now, None))
        c = _Call(q, "create_team", actor, team_id, "team", None, {"member_no": 1})
        seq = self._alloc_seq(q, team_id, "create_team")
        self._insert_audit(c, seq, "ok", new_role="owner")
        return team_id

    def _next_seq(self, q: Callable[..., Any], team_id: str, tool: str, *, ok: bool) -> int | None:
        """The next audit number for a write record, or None if the allowance has no room
        for it. Only the successful calls of RESERVE_TOOLS may use the reserved last part
        of the allowance."""
        cap = limits.AUDIT_CAP_PER_TEAM
        if not (ok and tool in permissions.RESERVE_TOOLS):
            cap -= limits.AUDIT_OWNER_RESERVE
        row = _one(q(_SQL_ALLOC_SEQ, (team_id, cap)))
        return None if row is None else row["next_audit_seq"] - 1

    def _alloc_seq(self, q: Callable[..., Any], team_id: str, tool: str) -> int:
        """The next audit number for a change that is being made. Raises AuditFullError,
        which rolls the whole call back: a change the audit log can't record is not made.
        (Refusals and failures take theirs in _refuse, and never raise.)"""
        seq = self._next_seq(q, team_id, tool, ok=True)
        if seq is None:
            used = _one(q(_SQL_AUDIT_WRITES, (team_id,)))["audit_writes"]
            raise AuditFullError("nearly" if used < limits.AUDIT_CAP_PER_TEAM else "full")
        return seq

    def _insert_audit(
        self,
        c: _Call,
        seq: int,
        result: str,
        reason: str = "",
        *,
        target: str | None = None,
        old_role: str | None = None,
        new_role: str | None = None,
    ) -> None:
        c.q(
            _SQL_INSERT_AUDIT,
            (
                c.team_id, seq, self._now(), c.member["member_no"], c.actor.client_id,
                permissions.AUDIT_ACTION[c.tool], target or c.target, result, reason, old_role, new_role,
            ),
        )

    def _refuse(self, c: _Call, kind: Literal["denied", "failed"], reason: str, value: Any = None) -> Outcome:
        """Record a refusal or failure and return it, never raise: the caller is told the
        real reason, and the record commits. Each member's first
        MAX_REFUSALS_LOGGED_PER_MEMBER in a team are recorded one by one; later ones, and
        any the team's audit allowance has no room for, are only counted, so refusals
        alone can't fill the audit log."""
        member_no = c.member["member_no"]
        c.q(_SQL_COUNT_REFUSAL, (c.team_id, member_no))
        if c.member["refused_count"] < limits.MAX_REFUSALS_LOGGED_PER_MEMBER:
            seq = self._next_seq(c.q, c.team_id, c.tool, ok=False)
            if seq is not None:
                self._insert_audit(c, seq, kind, reason)
                return Outcome(kind, value, reason)
            why = "the team's audit log can't take another record"
        else:
            why = "this member's refusal records are used up"
        # Logged here rather than by the server, which doesn't know a personal team's id.
        logger.warning("Refused %s in team %s for member #%s: %s", c.tool, c.team_id, member_no, why)
        return Outcome(kind, value, reason, logged=False)

    def _is_last_owner(self, c: _Call, role: str) -> bool:
        """Whether taking away ``role`` would leave the team without an owner."""
        return role == "owner" and _one(c.q(_SQL_COUNT_OWNERS, (c.team_id,)))["n"] == 1

    # --- cards -------------------------------------------------------------------

    def add(self, actor: Actor, team_id: str | None, question: str, answer: str, topic: str) -> Outcome:
        return self._guarded("add_card", actor, team_id, "team", lambda c: self._add_card(c, question, answer, topic))

    def _add_card(self, c: _Call, question: str, answer: str, topic: str) -> Outcome:
        # Under the team's lock, so every card already committed is counted.
        usage = _one(c.q(_SQL_USAGE, (c.team_id,)))
        if (
            usage["cards"] >= limits.MAX_CARDS_PER_TEAM
            or usage["chars"] + len(question) + len(answer) + len(topic) > limits.MAX_CHARS_PER_TEAM
        ):
            return self._refuse(c, "failed", "deck_full")
        seq = self._alloc_seq(c.q, c.team_id, c.tool)
        card_no = c.team["next_card_no"]
        c.q(_SQL_NEXT_CARD_NO, (c.team_id,))
        row = _one(c.q(_SQL_INSERT_CARD, (c.team_id, card_no, question, answer, topic, topic_key(topic), self._now())))
        self._insert_audit(c, seq, "ok", target=f"card:{card_no}")
        return Outcome("ok", _row_to_card(row))

    def record_review(self, actor: Actor, team_id: str | None, card_no: int, correct: bool) -> Outcome:
        return self._guarded(
            "grade_card", actor, team_id, f"card:{card_no}", lambda c: self._grade_card(c, card_no, correct)
        )

    def _grade_card(self, c: _Call, card_no: int, correct: bool) -> Outcome:
        if _one(c.q(_SQL_CARD_EXISTS, (c.team_id, card_no))) is None:
            return self._refuse(c, "failed", "no_card")
        seq = self._alloc_seq(c.q, c.team_id, c.tool)
        row = _one(c.q(_SQL_GRADE, (self._now(), 1 if correct else 0, 0 if correct else 1, c.team_id, card_no)))
        self._insert_audit(c, seq, "ok")
        return Outcome("ok", _row_to_card(row))

    def delete(self, actor: Actor, team_id: str | None, card_no: int) -> Outcome:
        return self._guarded("delete_card", actor, team_id, f"card:{card_no}", lambda c: self._delete_card(c, card_no))

    def _delete_card(self, c: _Call, card_no: int) -> Outcome:
        if _one(c.q(_SQL_CARD_EXISTS, (c.team_id, card_no))) is None:
            return self._refuse(c, "failed", "no_card")
        seq = self._alloc_seq(c.q, c.team_id, c.tool)
        c.q(_SQL_DELETE, (c.team_id, card_no))
        self._insert_audit(c, seq, "ok")
        return Outcome("ok")

    def _readable_team(self, q: Callable[..., Any], actor: Actor, team_id: str | None, tool: str) -> str | Outcome | None:
        """For the read tools: the team to read, an Outcome refusing the call, or None
        when the caller has no personal team yet (nothing to read, and nothing created)."""
        if team_id is None:
            row = _one(q(_SQL_PERSONAL, (actor.principal,)))
            if row is None:
                return None
            team_id = row["team_id"]
        member = self._member(q, team_id, actor.principal)
        if member is None:
            return Outcome("not_member")
        if not permissions.allowed(member["role"], tool):
            # A read-only transaction can't record it; only a broken permission table gets here.
            return Outcome("denied", tool, logged=False)
        return team_id

    def list_page(self, actor: Actor, team_id: str | None, topic: str, limit_plus_one: int, after_id: int) -> Outcome:
        key = topic_key(topic)
        # One transaction (one snapshot on Postgres), so the page and the total agree.
        with self.x.tx(read_only=True) as q:
            found = self._readable_team(q, actor, team_id, "list_cards")
            if found is None:
                return Outcome("ok", {"cards": [], "total": 0})
            if isinstance(found, Outcome):
                return found
            rows = q(_SQL_LIST, (found, after_id, key, key, limit_plus_one)).fetchall()
            total = _one(q(_SQL_COUNT, (found, key, key)))["n"]
        return Outcome("ok", {"cards": [_row_to_card(r) for r in rows], "total": total})

    def least_recently_reviewed(self, actor: Actor, team_id: str | None, topic: str) -> Outcome:
        key = topic_key(topic)
        with self.x.tx(read_only=True) as q:
            found = self._readable_team(q, actor, team_id, "review")
            if found is None:
                return Outcome("ok", None)
            if isinstance(found, Outcome):
                return found
            row = _one(q(_SQL_REVIEW, (found, key, key)))
        return Outcome("ok", _row_to_card(row) if row else None)

    # --- teams and members ---------------------------------------------------------

    def create_team(self, actor: Actor, name: str) -> Outcome:
        x = self.x
        with x.tx(read_only=False) as q:
            x.lock_person(q, actor.principal)
            if _one(q(_SQL_COUNT_SHARED, (actor.principal,)))["n"] >= limits.MAX_SHARED_TEAMS_PER_PERSON:
                return Outcome("failed", reason="too_many_teams", logged=False)
            x.lock_site(q)
            if _one(q(_SQL_COUNT_TEAMS, ()))["n"] >= limits.MAX_TEAMS_TOTAL:
                return Outcome("failed", reason="server_full", logged=False)
            team_id = ids.new_team_id()
            now = self._now()
            q(_SQL_INSERT_TEAM, (team_id, name, now))
            q(_SQL_INSERT_MEMBER, (team_id, 1, actor.principal, "owner", now, None))
            # The new row is this transaction's own, so it is already locked.
            c = _Call(q, "create_team", actor, team_id, "team", None, {"member_no": 1})
            seq = self._alloc_seq(q, team_id, "create_team")
            self._insert_audit(c, seq, "ok", new_role="owner")  # the team's name is never recorded
        return Outcome("ok", {"team_id": team_id, "name": name, "role": "owner", "member_no": 1})

    def list_teams(self, actor: Actor) -> Outcome:
        teams = []
        with self.x.tx(read_only=True) as q:
            for row in q(_SQL_MY_TEAMS, (actor.principal,)).fetchall():
                team = {
                    "team_id": row["team_id"],
                    "name": row["name"],
                    "personal": bool(row["personal"]),
                    "role": row["role"],
                    "member_no": row["member_no"],
                }
                if row["role"] == "owner":
                    team["members"] = [dict(m) for m in q(_SQL_TEAM_MEMBERS, (row["team_id"],)).fetchall()]
                    team["refusals_logged_limit"] = limits.MAX_REFUSALS_LOGGED_PER_MEMBER
                    team["audit_writes_used"] = row["audit_writes"]
                    team["audit_writes_limit"] = limits.AUDIT_CAP_PER_TEAM
                    team["audit_reads_used"] = row["audit_reads"]
                    team["audit_reads_limit"] = limits.AUDIT_READS_CAP_PER_TEAM
                teams.append(team)
        return Outcome("ok", teams)

    def create_invite(self, actor: Actor, team_id: str, role: str, code_hash: str) -> Outcome:
        return self._guarded("create_invite", actor, team_id, "team", lambda c: self._create_invite(c, role, code_hash))

    def _create_invite(self, c: _Call, role: str, code_hash: str) -> Outcome:
        if c.team["personal_of"] is not None:
            return self._refuse(c, "failed", "personal_team")
        # next_invite_no is the next number to hand out, so one less have been made.
        if c.team["next_invite_no"] > limits.MAX_INVITES_PER_TEAM:
            return self._refuse(c, "failed", "invites_used_up")
        seq = self._alloc_seq(c.q, c.team_id, c.tool)
        invite_no = c.team["next_invite_no"]
        c.q(_SQL_NEXT_INVITE_NO, (c.team_id,))
        now = self.x._clock()
        expires_at = int(now.timestamp()) + limits.INVITE_TTL_SECONDS
        c.q(_SQL_INSERT_INVITE, (c.team_id, invite_no, code_hash, role, c.member["member_no"], now.isoformat(), expires_at))
        self._insert_audit(c, seq, "ok", target=f"invite:{invite_no}", new_role=role)
        return Outcome("ok", {"invite_no": invite_no, "role": role, "expires_at": _iso(expires_at)})

    def join_team(self, actor: Actor, code_hash: str) -> Outcome:
        x = self.x
        with x.tx(read_only=False) as q:
            x.lock_person(q, actor.principal)
            found = _one(q(_SQL_INVITE_TEAM, (code_hash,)))
            if found is None:
                return Outcome("failed", reason="invite_invalid", logged=False)
            team_id = found["team_id"]
            # Whether the code still works is decided under the team's lock, so anyone holding
            # a real code, even a used or expired one, waits here briefly (as often as the rate
            # limit lets them); a made-up code never gets this far.
            team = _one(q(_SQL_LOCK_TEAM + x.lock_team_suffix, (team_id,)))
            now = x._clock()
            invite = _one(q(_SQL_INVITE, (team_id, code_hash, int(now.timestamp()))))
            if team is None or invite is None:
                return Outcome("failed", reason="invite_invalid", logged=False)
            target = f"invite:{invite['invite_no']}"
            member = self._member(q, team_id, actor.principal)
            if member is not None:
                # Recorded, and the invite stays unused for the person it was meant for.
                c = _Call(q, "join_team", actor, team_id, target, team, member)
                return self._refuse(c, "failed", "already_member", member["member_no"])
            if _one(q(_SQL_COUNT_SHARED, (actor.principal,)))["n"] >= limits.MAX_SHARED_TEAMS_PER_PERSON:
                return Outcome("failed", reason="too_many_teams", logged=False)
            if _one(q(_SQL_COUNT_MEMBERS, (team_id,)))["n"] >= limits.MAX_MEMBERS_PER_TEAM:
                return Outcome("failed", reason="team_full", logged=False)
            member_no = team["next_member_no"]
            # Checked unused and unexpired above, under the same team lock.
            q(_SQL_USE_INVITE, (now.isoformat(), member_no, team_id, invite["invite_no"]))
            seq = self._alloc_seq(q, team_id, "join_team")
            q(_SQL_INSERT_MEMBER, (team_id, member_no, actor.principal, invite["role"], now.isoformat(), invite["invite_no"]))
            q(_SQL_NEXT_MEMBER_NO, (team_id,))
            c = _Call(q, "join_team", actor, team_id, target, team, {"member_no": member_no})
            self._insert_audit(c, seq, "ok", new_role=invite["role"])
        return Outcome("ok", {"team_id": team_id, "name": team["name"], "role": invite["role"], "member_no": member_no})

    def set_member_role(self, actor: Actor, team_id: str, member_no: int, role: str) -> Outcome:
        return self._guarded(
            "set_member_role", actor, team_id, f"member:{member_no}", lambda c: self._set_member_role(c, member_no, role)
        )

    def _set_member_role(self, c: _Call, member_no: int, role: str) -> Outcome:
        target = _one(c.q(_SQL_TARGET_MEMBER, (c.team_id, member_no)))
        if target is None:
            return self._refuse(c, "failed", "no_member")
        if role != "owner" and self._is_last_owner(c, target["role"]):
            return self._refuse(c, "failed", "last_owner")
        seq = self._alloc_seq(c.q, c.team_id, c.tool)
        c.q(_SQL_SET_ROLE, (role, c.team_id, member_no))
        self._insert_audit(c, seq, "ok", old_role=target["role"], new_role=role)
        return Outcome("ok", {"member_no": member_no, "role": role})

    def remove_member(self, actor: Actor, team_id: str, member_no: int) -> Outcome:
        return self._guarded(
            "remove_member", actor, team_id, f"member:{member_no}", lambda c: self._remove_member(c, member_no)
        )

    def _remove_member(self, c: _Call, member_no: int) -> Outcome:
        target = _one(c.q(_SQL_TARGET_MEMBER, (c.team_id, member_no)))
        if target is None:
            return self._refuse(c, "failed", "no_member")
        if self._is_last_owner(c, target["role"]):
            return self._refuse(c, "failed", "last_owner")
        seq = self._alloc_seq(c.q, c.team_id, c.tool)
        # The row goes: a removed member is a stranger, and comes back with a new number.
        c.q(_SQL_REMOVE, (c.team_id, member_no))
        self._insert_audit(c, seq, "ok", old_role=target["role"])
        return Outcome("ok", {"member_no": member_no})

    def leave_team(self, actor: Actor, team_id: str) -> Outcome:
        return self._guarded("leave_team", actor, team_id, None, lambda c: self._leave_team(c))

    def _leave_team(self, c: _Call) -> Outcome:
        if c.team["personal_of"] is not None:
            return self._refuse(c, "failed", "personal_team")
        if self._is_last_owner(c, c.member["role"]):
            return self._refuse(c, "failed", "last_owner")
        seq = self._alloc_seq(c.q, c.team_id, c.tool)
        c.q(_SQL_LEAVE, (c.team_id, c.member["member_no"]))
        self._insert_audit(c, seq, "ok", old_role=c.member["role"])
        return Outcome("ok")

    def read_audit_log(self, actor: Actor, team_id: str, limit_plus_one: int, after_seq: int) -> Outcome:
        return self._guarded(
            "read_audit_log", actor, team_id, f"log:{after_seq}",
            lambda c: self._read_audit_log(c, limit_plus_one, after_seq),
        )

    def _read_audit_log(self, c: _Call, limit_plus_one: int, after_seq: int) -> Outcome:
        """A page of the team's audit log after ``after_seq``, oldest first. Every read is
        itself recorded (in the next page, not this one), and reads have an allowance of
        their own: a read it has no room for reads nothing."""
        seq = self._alloc_read_seq(c.q, c.team_id)
        events = [dict(row) for row in c.q(_SQL_AUDIT_PAGE, (c.team_id, after_seq, limit_plus_one)).fetchall()]
        self._insert_audit(c, seq, "ok")
        return Outcome("ok", {"events": events})

    def _alloc_read_seq(self, q: Callable[..., Any], team_id: str) -> int:
        """The next audit number for a successful read of the log, from the reads'
        allowance. Raises AuditFullError("reads"), which rolls the call back."""
        row = _one(q(_SQL_ALLOC_READ_SEQ, (team_id, limits.AUDIT_READS_CAP_PER_TEAM)))
        if row is None:
            raise AuditFullError("reads")
        return row["next_audit_seq"] - 1


# --- the two stores -------------------------------------------------------------


def _refused(e: Exception) -> None:
    """Raise StoreRefusedError for the database's refusal ``e``. Only its class and
    SQLSTATE are logged: the message may quote the whole row, card content included."""
    logger.error("The card database refused a change: %s %s", type(e).__name__, getattr(e, "sqlstate", ""))
    raise StoreRefusedError from None


class _ThreadedStore:
    """The async API the server calls. Each call runs the shared synchronous logic
    (``_Ops``) in a worker thread, so the event loop never waits on the database."""

    _ops: _Ops
    _clock: Callable[[], datetime]

    async def add(self, actor: Actor, team_id: str | None, question: str, answer: str, topic: str) -> Outcome:
        return await anyio.to_thread.run_sync(self._ops.add, actor, team_id, question, answer, topic)

    async def list_page(
        self, actor: Actor, team_id: str | None, topic: str, limit_plus_one: int, after_id: int
    ) -> Outcome:
        return await anyio.to_thread.run_sync(self._ops.list_page, actor, team_id, topic, limit_plus_one, after_id)

    async def least_recently_reviewed(self, actor: Actor, team_id: str | None, topic: str) -> Outcome:
        return await anyio.to_thread.run_sync(self._ops.least_recently_reviewed, actor, team_id, topic)

    async def record_review(self, actor: Actor, team_id: str | None, card_no: int, correct: bool) -> Outcome:
        return await anyio.to_thread.run_sync(self._ops.record_review, actor, team_id, card_no, correct)

    async def delete(self, actor: Actor, team_id: str | None, card_no: int) -> Outcome:
        return await anyio.to_thread.run_sync(self._ops.delete, actor, team_id, card_no)

    async def create_team(self, actor: Actor, name: str) -> Outcome:
        return await anyio.to_thread.run_sync(self._ops.create_team, actor, name)

    async def list_teams(self, actor: Actor) -> Outcome:
        return await anyio.to_thread.run_sync(self._ops.list_teams, actor)

    async def create_invite(self, actor: Actor, team_id: str, role: str, code_hash: str) -> Outcome:
        return await anyio.to_thread.run_sync(self._ops.create_invite, actor, team_id, role, code_hash)

    async def join_team(self, actor: Actor, code_hash: str) -> Outcome:
        return await anyio.to_thread.run_sync(self._ops.join_team, actor, code_hash)

    async def set_member_role(self, actor: Actor, team_id: str, member_no: int, role: str) -> Outcome:
        return await anyio.to_thread.run_sync(self._ops.set_member_role, actor, team_id, member_no, role)

    async def remove_member(self, actor: Actor, team_id: str, member_no: int) -> Outcome:
        return await anyio.to_thread.run_sync(self._ops.remove_member, actor, team_id, member_no)

    async def leave_team(self, actor: Actor, team_id: str) -> Outcome:
        return await anyio.to_thread.run_sync(self._ops.leave_team, actor, team_id)

    async def read_audit_log(self, actor: Actor, team_id: str, limit_plus_one: int, after_seq: int) -> Outcome:
        return await anyio.to_thread.run_sync(self._ops.read_audit_log, actor, team_id, limit_plus_one, after_seq)


class SqliteCardStore(_ThreadedStore):
    """SQLite-backed store for local development and tests.

    One connection, and a lock held for each call's whole transaction, so calls run
    one at a time: that lock stands in for every row and advisory lock Postgres takes.
    There is no ``await`` inside the lock, so it can't deadlock the event loop.
    """

    lock_team_suffix = ""

    def __init__(self, path: str | Path, *, clock: Callable[[], datetime] = _utc_now) -> None:
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        self._clock = clock
        self._ops = _Ops(self)
        with self._lock:
            self._conn.executescript(schema.SQLITE_SCHEMA)
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    @contextmanager
    def map_errors(self):
        try:
            yield
        except sqlite3.IntegrityError as e:  # a constraint or an append-only trigger
            _refused(e)

    @contextmanager
    def tx(self, read_only: bool):
        # Leaving the block commits, or rolls back on an exception, before errors are mapped.
        with self.map_errors(), self._lock, self._conn:
            yield lambda sql, params=(): self._conn.execute(sql, params)

    def lock_person(self, q: Callable[..., Any], principal: str) -> None:
        pass  # the store-wide lock already runs one call at a time

    def lock_site(self, q: Callable[..., Any]) -> None:
        pass  # the store-wide lock already runs one call at a time


class PostgresCardStore(_ThreadedStore):
    """Postgres-backed store for the hosted server.

    Each call borrows its own connection from a small pool and runs as one
    transaction: committed when the call returns, rolled back if it raises. The pool
    checks a connection before handing it out, because Neon's free tier closes idle
    connections when it pauses.

    The server never creates tables here: the database's owner runs setup_database
    (see schema.py), and the server connects as an app role with fewer rights.
    """

    lock_team_suffix = " FOR UPDATE"

    def __init__(self, url: str, *, verify_schema: bool = True, clock: Callable[[], datetime] = _utc_now) -> None:
        # Imported here so the SQLite store works without the Postgres driver installed.
        import psycopg
        from psycopg.rows import dict_row
        from psycopg_pool import ConnectionPool

        # OperationalError also covers the pool's PoolTimeout and a statement Postgres cancels
        # after PG_STATEMENT_TIMEOUT. A transaction it ends for idling past
        # PG_IDLE_IN_TRANSACTION_TIMEOUT comes as SQLSTATE 25P03, which psycopg files under
        # InternalError; retrying works for it too.
        self._unavailable = (psycopg.OperationalError, psycopg.errors.IdleInTransactionSessionTimeout)
        # A constraint, an append-only trigger (RAISE EXCEPTION), or a right the app role lacks.
        self._refusals = (psycopg.IntegrityError, psycopg.errors.RaiseException, psycopg.errors.InsufficientPrivilege)
        self._clock = clock
        self._ops = _Ops(self)
        # verify_schema checks the tables and this role's rights once the pool is open
        # (schema.verify_app_role). Tests pass False, so that a broken table will still
        # fail a test rather than the setup of every test.
        self._verify_schema = verify_schema
        self._pool = ConnectionPool(
            url,
            min_size=POOL_MIN_SIZE,
            max_size=POOL_MAX_SIZE,
            timeout=POOL_WAIT_SECONDS,
            check=ConnectionPool.check_connection,
            name=APPLICATION_NAME,
            open=False,
            kwargs={
                "connect_timeout": CONNECT_TIMEOUT_SECONDS,
                # Notice a connection that died without closing (a dropped NAT entry, say)
                # within about a minute, instead of the operating system's two hours.
                "keepalives_idle": 30,
                "keepalives_interval": 10,
                "keepalives_count": 3,
                "tcp_user_timeout": 30_000,  # milliseconds; ignored where unsupported
                "application_name": APPLICATION_NAME,
                "row_factory": dict_row,
                # No server-side prepared statements: through Neon's transaction-mode
                # pooler they need libpq 17 or newer and a pooler set up for them, and
                # these short queries gain nothing from them.
                "prepare_threshold": None,
            },
        )
        try:
            with self.map_errors():
                self._pool.open(wait=True, timeout=POOL_OPEN_SECONDS)
            if verify_schema:
                with self._connection() as conn:
                    schema.verify_app_role(conn)
        except BaseException:
            self._pool.close()
            raise

    def close(self) -> None:
        self._pool.close()

    @contextmanager
    def map_errors(self):
        # libpq never puts the password in a message; the host and user name may be there.
        try:
            yield
        except self._refusals as e:
            _refused(e)
        except self._unavailable as e:
            # Disk full (SQLSTATE 53100, which Neon's storage limit is expected to raise)
            # won't pass by retrying, unlike the rest of the class: too many connections,
            # out of memory, a lock wait that timed out. psycopg files all of them under
            # OperationalError.
            if getattr(e, "sqlstate", None) == "53100":
                logger.error("The card database is out of space or over a limit: %s: %.300s", type(e).__name__, str(e))
                raise StoreFullError from None
            logger.warning("The card database is unavailable: %s: %.300s", type(e).__name__, str(e))
            raise StoreUnavailableError from None

    @contextmanager
    def _connection(self):
        with self.map_errors(), self._pool.connection() as conn:
            yield conn

    @contextmanager
    def tx(self, read_only: bool):
        with self._connection() as conn:
            # set_config(..., true) lasts only for this transaction, so it also works through
            # Neon's transaction-mode pooler and never reaches another call.
            if read_only:
                # One snapshot for the whole call: the membership check, a page and its total
                # agree. This must be the transaction's first statement.
                conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
                conn.execute(
                    "SELECT set_config('search_path', %s, true),"
                    " set_config('idle_in_transaction_session_timeout', %s, true),"
                    " set_config('statement_timeout', %s, true)",
                    (PG_SEARCH_PATH, PG_IDLE_IN_TRANSACTION_TIMEOUT, PG_STATEMENT_TIMEOUT),
                )
            else:
                conn.execute(
                    "SELECT set_config('search_path', %s, true),"
                    " set_config('lock_timeout', %s, true),"
                    " set_config('idle_in_transaction_session_timeout', %s, true),"
                    " set_config('statement_timeout', %s, true)",
                    (PG_SEARCH_PATH, f"{LOCK_WAIT_SECONDS}s", PG_IDLE_IN_TRANSACTION_TIMEOUT, PG_STATEMENT_TIMEOUT),
                )
            yield lambda sql, params=(): conn.execute(sql.replace("?", "%s"), params)

    def lock_person(self, q: Callable[..., Any], principal: str) -> None:
        # One person's team changes (creating, joining) run one at a time, so the limit
        # on their teams can't be passed by two calls at once. 20261025 is any fixed number.
        q("SELECT pg_advisory_xact_lock(20261025, hashtext(?))", (principal,))

    def lock_site(self, q: Callable[..., Any]) -> None:
        # Calls that add a team run one at a time, so the server-wide team count holds.
        q("SELECT pg_advisory_xact_lock(20261030)")
