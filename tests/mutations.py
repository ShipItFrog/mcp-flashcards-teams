"""Deliberately broken variants of the server, used only to prove the tests catch
real mistakes. Each one is applied with monkeypatch at test time (see conftest.py);
the source files are never modified.

Run all of them with:  python tests/run_mutations.py  (add --fast to stop each run at
its first failing test, for checks while working)
Every mutation must make at least one test fail.

Both stores share their SQL and their transaction logic (store._Ops), so most store
mutations break both databases at once. The pg- ones break the Postgres store only
(see _on_postgres): what they get wrong only shows with real concurrent connections.
"""

from __future__ import annotations

import threading
import time
from contextlib import contextmanager
from dataclasses import replace

import anyio
import jwt
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken
from mcp.server.auth.settings import AuthSettings

from flashcards_teams import app as app_module
from flashcards_teams import identity, ids, limits, permissions, schema, server, setup_db
from flashcards_teams import store as store_module
from flashcards_teams import verifier as verifier_module

A = app_module
P = permissions
S = store_module
V = verifier_module


def _shared_deck(issuer: str) -> str:
    """Forgot the per-user key: everyone shares one deck."""
    return "everyone"


def _key_by_client_id(issuer: str) -> str:
    """Keys data by the OAuth client (the app) instead of the user."""
    return f"{issuer}|{get_access_token().client_id}"


def _no_subject_check(issuer: str) -> str:
    """Drops the 'token must have a subject' defence."""
    token = get_access_token()
    if (token.claims or {}).get("iss") != issuer:
        raise server.ToolError("Not signed in.")
    return f"{issuer}|{token.subject}"


def _no_issuer_check(issuer: str) -> str:
    """Trusts any issuer: the same `sub` from two identity providers becomes one person."""
    token = get_access_token()
    if token is None or not token.subject:
        raise server.ToolError("Not signed in.")
    return f"{issuer}|{token.subject}"


# --- the store: shared SQL ---


def _sql_variant(mp, name, old, new, *, module=S):
    """Change one shared SQL constant (or, with ``module=schema``, a table definition).
    The callers pass the parameters separately, so the placeholders must stay the same
    in number and order: a condition is made always true, never removed."""
    sql = getattr(module, name)
    assert old in sql, (name, old)
    assert old.count("?") == new.count("?"), (name, old, new)
    mp.setattr(module, name, sql.replace(old, new))


def _list_unpaginated(mp):
    """Listing that ignores the page size and cursor. Dropping the LIMIT alone would
    change nothing a user sees: the server fetches one card more than a page and cuts
    the page itself."""
    _sql_variant(mp, "_SQL_LIST", "LIMIT ?", "LIMIT ? + 1000000")
    _sql_variant(mp, "_SQL_LIST", "card_no > ?", "(card_no > ? OR 1 = 1)")


def _invite_stored_raw(mp):
    """The server hands the store the invite code itself instead of its hash (and the
    table takes a value of any length, so nothing else stops it)."""
    mp.setattr(ids, "hash_invite", lambda code: code.strip())
    for name in ("SQLITE_SCHEMA", "PG_TABLES"):
        _sql_variant(mp, name, "CHECK (length(code_hash) = 64)", "CHECK (length(code_hash) > 0)", module=schema)


# --- the store: permissions and the shared transaction logic (_Ops) ---


def _required(**changes):
    """The permission table with other minimum roles: tool=role."""

    def change(mp):
        for tool, role in changes.items():
            mp.setitem(P.REQUIRED, tool, role)

    return change


def _default_allow(mp):
    """allowed() lets through a tool the table doesn't name, and the table has lost remove_member."""

    def allowed(role, tool):
        need = P.REQUIRED.get(tool)
        if need is None:
            return True
        return role in P.ROLE_RANK and P.ROLE_RANK[role] >= P.ROLE_RANK[need]

    mp.setattr(P, "allowed", allowed)
    mp.delitem(P.REQUIRED, "remove_member")


def _role_cached(mp):
    """Remembers a member's row, role and all, the first time it is read (one cache for
    the whole process, as a module-level dict would be)."""
    original = S._Ops._member
    cache = {}

    def _member(self, q, team_id, principal):
        key = (team_id, principal)
        if key not in cache:
            row = original(self, q, team_id, principal)
            if row is None:
                return None  # only members are remembered
            cache[key] = row
        return cache[key]

    mp.setattr(S._Ops, "_member", _member)


def _nonmember_distinguishable(mp):
    """Tells a team the caller isn't in apart from one that doesn't exist: "permission denied"."""
    exists = "SELECT 1 AS found FROM teams WHERE team_id = ?"
    guarded, readable = S._Ops._guarded, S._Ops._readable_team

    def _guarded(self, tool, actor, team_id, target, action):
        outcome = guarded(self, tool, actor, team_id, target, action)
        if outcome.kind == "not_member" and team_id is not None:
            with self.x.tx(read_only=True) as q:
                if S._one(q(exists, (team_id,))) is not None:
                    return S.Outcome("denied", tool)
        return outcome

    def _readable_team(self, q, actor, team_id, tool):
        found = readable(self, q, actor, team_id, tool)
        if isinstance(found, S.Outcome) and found.kind == "not_member" and S._one(q(exists, (team_id,))) is not None:
            return S.Outcome("denied", tool)
        return found

    mp.setattr(S._Ops, "_guarded", _guarded)
    mp.setattr(S._Ops, "_readable_team", _readable_team)


def _last_owner_unchecked(tools):
    """Lets ``tools`` take a team's last owner away; the other tools still check."""

    def change(mp):
        original = S._Ops._is_last_owner
        mp.setattr(S._Ops, "_is_last_owner", lambda self, c, role: False if c.tool in tools else original(self, c, role))

    return change


def _on_postgres(mp, name, patched):
    """Replace ``_Ops.<name>`` for the Postgres store only; the SQLite store keeps the
    real one."""
    original = getattr(S._Ops, name)

    def method(self, *args, **kwargs):
        return (patched if isinstance(self.x, S.PostgresCardStore) else original)(self, *args, **kwargs)

    mp.setattr(S._Ops, name, method)


def _personal_team_looked_for_once(self, q, actor, tool):
    """_Ops._personal_team that looks for the caller's personal team only before taking
    the site lock, not again once it holds it."""
    row = S._one(q(S._SQL_PERSONAL, (actor.principal,)))
    if row is not None:
        return row["team_id"]
    if tool != "add_card":
        return S.Outcome("failed", reason="no_card", logged=False)
    self.x.lock_site(q)
    return self._create_personal_team(q, actor)


def _personal_team_duplicated(mp):
    """The personal team is looked for once, then inserted without ON CONFLICT: two first
    adds at once both insert."""
    _on_postgres(mp, "_personal_team", _personal_team_looked_for_once)
    _sql_variant(mp, "_SQL_INSERT_PERSONAL", " ON CONFLICT (personal_of) DO NOTHING", "")


def _refusal_needs_audit_room(mp):
    """A refusal the audit log has no room for stops the call as a change would: the
    caller is told the log is full instead of the real reason, and it isn't counted."""
    original = S._Ops._next_seq

    def _next_seq(self, q, team_id, tool, *, ok):
        seq = original(self, q, team_id, tool, ok=ok)
        if seq is None and not ok:
            raise S.AuditFullError("nearly")
        return seq

    mp.setattr(S._Ops, "_next_seq", _next_seq)


def _no_owner_reserve(mp):
    """The last part of the audit allowance is kept for nobody: once only it is left,
    owners can't change roles or remove members, and members can't leave."""
    original = S._Ops._next_seq

    def _next_seq(self, q, team_id, tool, *, ok):
        return original(self, q, team_id, tool, ok=False)

    mp.setattr(S._Ops, "_next_seq", _next_seq)


# The team's audit count as a guarded write read it before locking the team's row (see
# _audit_cap_outside_lock); None outside such a write. Each store call runs in one thread.
_audit_writes_before_lock = threading.local()


def _pg_guarded(*, cards_counted_before_lock=False, role_from_before_lock=False, unlocked=(), audit_counted_before_lock=False):
    """A Postgres _Ops._guarded with one mistake about its lock: the deck's card count
    taken before the team's row is locked, the permission judged on the role read
    before the lock, ``unlocked`` tools that don't lock the row at all, or the team's
    audit count read before the lock (for _audit_cap_outside_lock to judge by)."""

    def _guarded(self, tool, actor, team_id, target, action):
        x = self.x
        _audit_writes_before_lock.n = None
        try:
            with x.tx(read_only=False) as q:
                if team_id is None:
                    found = self._personal_team(q, actor, tool)
                    if isinstance(found, S.Outcome):
                        return found
                    team_id = found
                before = self._member(q, team_id, actor.principal)
                if before is None:
                    return S.Outcome("not_member")
                full = False
                if cards_counted_before_lock and tool == "add_card":
                    full = S._one(q(S._SQL_USAGE, (team_id,)))["cards"] >= limits.MAX_CARDS_PER_TEAM
                if audit_counted_before_lock:
                    _audit_writes_before_lock.n = S._one(q(S._SQL_AUDIT_WRITES, (team_id,)))["audit_writes"]
                suffix = "" if tool in unlocked else x.lock_team_suffix
                team = S._one(q(S._SQL_LOCK_TEAM + suffix, (team_id,)))
                member = before if role_from_before_lock else self._member(q, team_id, actor.principal)
                if team is None or member is None:
                    return S.Outcome("not_member")
                c = S._Call(q, tool, actor, team_id, target or f"member:{member['member_no']}", team, member)
                if not P.allowed(member["role"], tool):
                    return self._refuse(c, "denied", "role", tool)
                capped = tool in P.DAILY_CAPPED_TOOLS
                if capped and self._daily_limit_reached(c):
                    return self._refuse(c, "failed", "daily_limit")
                if full:
                    return self._refuse(c, "failed", "deck_full")
                outcome = action(c)
                if capped and outcome.kind == "ok":
                    today = self._today()
                    q(S._SQL_COUNT_WRITE, (today, today, team_id, member["member_no"]))
                return outcome
        finally:
            _audit_writes_before_lock.n = None

    return _guarded


def _pg_add(*, max_numbering=False, limit_before_lock=False, number_in_own_transaction=False):
    """A Postgres add with one ordering or transaction mistake."""

    def _add_card(self, c, question, answer, topic, card_no=None):
        usage = S._one(c.q(S._SQL_USAGE, (c.team_id,)))
        too_many = usage["cards"] >= limits.MAX_CARDS_PER_TEAM and not limit_before_lock  # counted before the lock
        if too_many or usage["chars"] + len(question) + len(answer) + len(topic) > limits.MAX_CHARS_PER_TEAM:
            return self._refuse(c, "failed", "deck_full")
        seq = self._alloc_seq(c.q, c.team_id, c.tool)
        if card_no is None:
            card_no = c.team["next_card_no"]
            c.q(S._SQL_NEXT_CARD_NO, (c.team_id,))
        if max_numbering:
            card_no = S._one(c.q("SELECT COALESCE(MAX(card_no), 0) + 1 AS n FROM cards WHERE team_id = ?", (c.team_id,)))["n"]
        row = S._one(
            c.q(S._SQL_INSERT_CARD, (c.team_id, card_no, question, answer, topic, S.topic_key(topic), self._now()))
        )
        self._insert_audit(c, seq, "ok", target=f"card:{card_no}")
        return S.Outcome("ok", S._row_to_card(row))

    def add(self, actor, team_id, question, answer, topic):
        # Committed at once, whatever happens next: the personal team too, if this made it.
        with self.x.tx(read_only=False) as q:
            found = self._personal_team(q, actor, "add_card") if team_id is None else team_id
            if isinstance(found, S.Outcome):
                return found
            taken = S._one(
                q("UPDATE teams SET next_card_no = next_card_no + 1 WHERE team_id = ? RETURNING next_card_no - 1 AS n", (found,))
            )
        card_no = taken["n"] if taken is not None else None
        return self._guarded(
            "add_card", actor, team_id, "team", lambda c: _add_card(self, c, question, answer, topic, card_no)
        )

    def change(mp):
        _on_postgres(mp, "_add_card", _add_card)
        if limit_before_lock:
            _on_postgres(mp, "_guarded", _pg_guarded(cards_counted_before_lock=True))
        if number_in_own_transaction:
            _on_postgres(mp, "add", add)

    return change


# --- module 3, step 3: the audit log and the limits ---


def _audit_params(self, c, seq, result, reason="", *, target=None, old_role=None, new_role=None):
    """The parameters _Ops._insert_audit gives _SQL_INSERT_AUDIT, for variants that write
    a record somewhere else."""
    return (
        c.team_id, seq, self._now(), c.member["member_no"], c.actor.client_id,
        P.AUDIT_ACTION[c.tool], target or c.target, result, reason, old_role, new_role,
    )


def _refuse_unrecorded(self, c, kind, reason, value=None):
    """_Ops._refuse that counts the refusal but never records it."""
    c.q(S._SQL_COUNT_REFUSAL, (c.team_id, c.member["member_no"]))
    return S.Outcome(kind, value, reason)


def _refuse_without_quota(self, c, kind, reason, value=None):
    """_Ops._refuse that records every refusal while the audit log has room, however many
    the member already has: refusals alone can fill the log."""
    c.q(S._SQL_COUNT_REFUSAL, (c.team_id, c.member["member_no"]))
    seq = self._next_seq(c.q, c.team_id, c.tool, ok=False)
    if seq is None:
        return S.Outcome(kind, value, reason, logged=False)
    self._insert_audit(c, seq, kind, reason)
    return S.Outcome(kind, value, reason)


def _deck_full_recorded_as_ok(mp):
    """A full deck is recorded as a success."""
    original = S._Ops._insert_audit

    def _insert_audit(self, c, seq, result, reason="", **kwargs):
        if (result, reason) == ("failed", "deck_full"):
            result, reason = "ok", ""
        original(self, c, seq, result, reason, **kwargs)

    mp.setattr(S._Ops, "_insert_audit", _insert_audit)


def _audit_before_action_committed(mp):
    """A guarded change's ok record is written as soon as its number is allocated, before
    the change is made, and committed at once: on SQLite by committing the transaction so
    far, on Postgres by another connection (audit_events has no foreign key, so that one
    doesn't wait for the team's row). If the change then fails, its record stays."""
    guarded, alloc, insert = S._Ops._guarded, S._Ops._alloc_seq, S._Ops._insert_audit
    now = threading.local()  # the guarded call running in this thread, and whether its record is written

    def _guarded(self, tool, actor, team_id, target, action):
        def act(c):
            now.c, now.written = c, False
            return action(c)

        try:
            return guarded(self, tool, actor, team_id, target, act)
        finally:
            now.c = now.written = None

    def _alloc_seq(self, q, team_id, tool):
        seq = alloc(self, q, team_id, tool)
        c = getattr(now, "c", None)
        if c is not None:
            params = _audit_params(self, c, seq, "ok")
            if isinstance(self.x, S.PostgresCardStore):
                with self.x._pool.connection() as other:
                    other.execute(S._SQL_INSERT_AUDIT.replace("?", "%s"), params)
            else:
                q(S._SQL_INSERT_AUDIT, params)
                self.x._conn.commit()
            now.written = True
        return seq

    def _insert_audit(self, c, seq, result, reason="", **kwargs):
        if result == "ok" and getattr(now, "written", None):
            return  # written already
        insert(self, c, seq, result, reason, **kwargs)

    mp.setattr(S._Ops, "_guarded", _guarded)
    mp.setattr(S._Ops, "_alloc_seq", _alloc_seq)
    mp.setattr(S._Ops, "_insert_audit", _insert_audit)


def _audit_after_commit_swallowed(mp):
    """A guarded change commits first; its ok records are written afterwards in a
    transaction of their own, and if that fails the change stays, unrecorded."""
    guarded, insert = S._Ops._guarded, S._Ops._insert_audit
    later = threading.local()

    def _insert_audit(self, c, seq, result, reason="", **kwargs):
        pending = getattr(later, "records", None)
        if result == "ok" and pending is not None:
            pending.append((c, seq, kwargs))
        else:
            insert(self, c, seq, result, reason, **kwargs)

    def _guarded(self, tool, actor, team_id, target, action):
        later.records = []
        try:
            outcome = guarded(self, tool, actor, team_id, target, action)
            pending = later.records
        finally:
            later.records = None
        for c, seq, kwargs in pending:
            try:
                with self.x.tx(read_only=False) as q:
                    insert(self, replace(c, q=q), seq, "ok", **kwargs)
            except Exception:
                pass  # the change is made all the same
        return outcome

    mp.setattr(S._Ops, "_insert_audit", _insert_audit)
    mp.setattr(S._Ops, "_guarded", _guarded)


def _card_content_in_target(mp):
    """A card's record names the card by its number and the start of its question."""
    original = S._Ops._insert_audit

    def _insert_audit(self, c, seq, result, reason="", *, target=None, **kwargs):
        target = target or c.target
        if result == "ok" and target.startswith("card:"):
            card = S._one(c.q("SELECT question FROM cards WHERE team_id = ? AND card_no = ?", (c.team_id, int(target[5:]))))
            if card is not None:
                target = f"{target}:{card['question'][:20]}"
        original(self, c, seq, result, reason, target=target, **kwargs)

    mp.setattr(S._Ops, "_insert_audit", _insert_audit)


def _read_unrecorded(self, c, limit_plus_one, after_seq):
    """_Ops._read_audit_log that uses up a place of the reads' allowance but writes no
    record of the read."""
    self._alloc_read_seq(c.q, c.team_id)
    events = [dict(row) for row in c.q(S._SQL_AUDIT_PAGE, (c.team_id, after_seq, limit_plus_one)).fetchall()]
    return S.Outcome("ok", {"events": events})


def _audit_cap_outside_lock(mp):
    """Postgres: the audit allowance is judged on the count read before the team's row
    was locked, and the place then taken whatever the count is by now. Writes queued on
    the lock all see the last free place."""
    original = S._Ops._next_seq

    def _next_seq(self, q, team_id, tool, *, ok):
        used = getattr(_audit_writes_before_lock, "n", None)
        if used is None:  # not a guarded write, or a team made in this call: nothing read before a lock
            return original(self, q, team_id, tool, ok=ok)
        cap = limits.AUDIT_CAP_PER_TEAM
        if not (ok and tool in P.RESERVE_TOOLS):
            cap -= limits.AUDIT_OWNER_RESERVE
        if used >= cap:
            return None
        row = S._one(q(
            "UPDATE teams SET next_audit_seq = next_audit_seq + 1, audit_writes = audit_writes + 1"
            " WHERE team_id = ? RETURNING next_audit_seq",
            (team_id,),
        ))
        return row["next_audit_seq"] - 1

    _on_postgres(mp, "_guarded", _pg_guarded(audit_counted_before_lock=True))
    _on_postgres(mp, "_next_seq", _next_seq)


def _sqlite_triggers_dropped(*names):
    """SQLITE_SCHEMA without the named audit_events triggers."""

    def change(mp):
        for name in names:
            sql = schema.SQLITE_SCHEMA
            start = sql.index(f"CREATE TRIGGER IF NOT EXISTS {name} ")
            end = sql.index("END;\n", start) + len("END;\n")
            _sql_variant(mp, "SQLITE_SCHEMA", sql[start:end], "", module=schema)

    return change


def _pg_trigger_row_level_only(mp):
    """Postgres: one per-row trigger for UPDATE and DELETE, and none for TRUNCATE. A
    statement that matches no row fires nothing, and TRUNCATE fires no DELETE trigger."""
    sql = schema.PG_AUDIT
    start = sql.index("CREATE OR REPLACE TRIGGER audit_events_no_update_delete")
    _sql_variant(
        mp, "PG_AUDIT", sql[start:],
        "CREATE OR REPLACE TRIGGER audit_events_no_update_delete\n"
        "    BEFORE UPDATE OR DELETE ON audit_events\n"
        "    FOR EACH ROW EXECUTE FUNCTION audit_events_refuse_change();\n",
        module=schema,
    )


def _app_owns_tables(mp):
    """Postgres: after setup, the superuser makes the app role the owner of every table,
    so it may drop the triggers or grant itself anything."""
    original = schema.setup_database

    def setup_database(conn, app_role):
        from psycopg import sql
        from psycopg.rows import tuple_row

        new = original(conn, app_role)
        role = conn.cursor(row_factory=tuple_row).execute("SELECT current_user").fetchone()[0]
        conn.execute("RESET ROLE")
        try:
            for table in ("schema_info", "teams", "members", "invites", "cards", "audit_events"):
                conn.execute(sql.SQL("ALTER TABLE {} OWNER TO {}").format(sql.Identifier(table), sql.Identifier(app_role)))
        finally:
            conn.execute(sql.SQL("SET ROLE {}").format(sql.Identifier(role)))
        return new

    mp.setattr(schema, "setup_database", setup_database)


@contextmanager
def _no_session_timeouts(self, read_only):
    """PostgresCardStore.tx without the idle and statement timeouts: a stuck transaction
    lives until someone ends it. The search path is still pinned."""
    with self._connection() as conn:
        if read_only:
            conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            conn.execute("SELECT set_config('search_path', %s, true)", (S.PG_SEARCH_PATH,))
        else:
            conn.execute(
                "SELECT set_config('search_path', %s, true), set_config('lock_timeout', %s, true)",
                (S.PG_SEARCH_PATH, f"{S.LOCK_WAIT_SECONDS}s"),
            )
        yield lambda sql, params=(): conn.execute(sql.replace("?", "%s"), params)


def _idle_timeout_unmapped(mp):
    """A transaction Postgres ends for idling (SQLSTATE 25P03, which psycopg files under
    InternalError) escapes the store's error mapping instead of being reported as the
    database being temporarily unavailable."""
    import psycopg

    original = S.PostgresCardStore.__init__

    def __init__(self, *args, **kwargs):
        original(self, *args, **kwargs)
        self._unavailable = psycopg.OperationalError

    mp.setattr(S.PostgresCardStore, "__init__", __init__)


def _reserve_tools_daily_capped(mp):
    """The daily limit stops member changes and leaving too, so an owner past it can't
    remove a runaway member."""
    original = S._Ops._guarded

    def _guarded(self, tool, actor, team_id, target, action):
        def act(c):
            if c.tool in P.RESERVE_TOOLS and self._daily_limit_reached(c):
                return self._refuse(c, "failed", "daily_limit")
            return action(c)

        return original(self, tool, actor, team_id, target, act)

    mp.setattr(S._Ops, "_guarded", _guarded)


def _create_invite(*, personal_checked=True, capped=True):
    """_Ops._create_invite without its personal-team check or without its lifetime cap."""

    def create(self, c, role, code_hash):
        if personal_checked and c.team["personal_of"] is not None:
            return self._refuse(c, "failed", "personal_team")
        if capped and c.team["next_invite_no"] > limits.MAX_INVITES_PER_TEAM:
            return self._refuse(c, "failed", "invites_used_up")
        seq = self._alloc_seq(c.q, c.team_id, c.tool)
        invite_no = c.team["next_invite_no"]
        c.q(S._SQL_NEXT_INVITE_NO, (c.team_id,))
        now = self.x._clock()
        expires_at = int(now.timestamp()) + limits.INVITE_TTL_SECONDS
        c.q(S._SQL_INSERT_INVITE, (c.team_id, invite_no, code_hash, role, c.member["member_no"], now.isoformat(), expires_at))
        self._insert_audit(c, seq, "ok", target=f"invite:{invite_no}", new_role=role)
        return S.Outcome("ok", {"invite_no": invite_no, "role": role, "expires_at": S._iso(expires_at)})

    return create


def _topic_index_restored(mp):
    """The (team_id, topic_key) index on cards is back, in both databases."""
    index = "CREATE INDEX IF NOT EXISTS cards_team_topic ON cards (team_id, topic_key);\n"
    _sql_variant(mp, "SQLITE_SCHEMA", "CREATE TABLE IF NOT EXISTS audit_events", index + "CREATE TABLE IF NOT EXISTS audit_events", module=schema)
    mp.setattr(schema, "PG_TABLES", schema.PG_TABLES + index)


# --- module 3: restored variants of step 2 and 3 (cut on 2026-10-30) ---


def _existence_before_permission(mp):
    """grade_card and delete_card say a card doesn't exist before they say the caller may
    not use them, so a viewer learns which card numbers exist."""
    original = S._Ops._refuse

    def _refuse(self, c, kind, reason, value=None):
        if kind == "denied" and c.tool in ("grade_card", "delete_card"):
            if S._one(c.q(S._SQL_CARD_EXISTS, (c.team_id, int(c.target.removeprefix("card:"))))) is None:
                return original(self, c, "failed", "no_card")
        return original(self, c, kind, reason, value)

    mp.setattr(S._Ops, "_refuse", _refuse)


def _reads_create_personal_team(mp):
    """list_cards without a team creates the caller's personal team, as add_card does."""
    original = S._Ops.list_page

    def list_page(self, actor, team_id, *args):
        if team_id is None:
            with self.x.tx(read_only=False) as q:
                self._personal_team(q, actor, "add_card")
        return original(self, actor, team_id, *args)

    mp.setattr(S._Ops, "list_page", list_page)


def _expired_invite_distinguishable(mp):
    """An expired invite is refused with a message of its own, so a code can be tested."""
    original = S._Ops.join_team

    def join_team(self, actor, code_hash):
        outcome = original(self, actor, code_hash)
        if outcome.reason == "invite_invalid":
            with self.x.tx(read_only=True) as q:
                row = S._one(q("SELECT expires_at FROM invites WHERE code_hash = ?", (code_hash,)))
            if row is not None and row["expires_at"] <= int(self.x._clock().timestamp()):
                raise server.ToolError("That invite code has expired.")
        return outcome

    mp.setattr(S._Ops, "join_team", join_team)


def _invite_creator_not_rechecked(mp):
    """An invite stays valid after its maker stops being an owner: still a member is enough."""
    _sql_variant(mp, "_SQL_INVITE", " AND members.role = 'owner')", ")")


def _invite_consumed_on_already_member(mp):
    """A member who uses an invite again is refused, and the invite is used up anyway."""
    original = S._Ops._refuse

    def _refuse(self, c, kind, reason, value=None):
        if reason == "already_member":
            invite_no = int(c.target.removeprefix("invite:"))
            c.q(S._SQL_USE_INVITE, (self._now(), c.member["member_no"], c.team_id, invite_no))
        return original(self, c, kind, reason, value)

    mp.setattr(S._Ops, "_refuse", _refuse)


def _member_with_team_id_in_text(self, q, team_id, principal):
    """_Ops._member with the team id written into the statement (one parameter fewer)."""
    return S._one(q(
        f"SELECT member_no, role, refused_count, writes_day, writes_today FROM members"
        f" WHERE team_id = '{team_id}' AND principal = ?",
        (principal,),
    ))


def _denied_raised_in_transaction(mp):
    """A member's refusal is raised inside the transaction, which rolls its record back."""
    original = S._Ops._refuse

    def _refuse(self, c, kind, reason, value=None):
        outcome = original(self, c, kind, reason, value)
        if kind == "denied":
            raise server.ToolError(server.M_DENIED.format(tool=c.tool, role=P.REQUIRED.get(c.tool, "owner")))
        return outcome

    mp.setattr(S._Ops, "_refuse", _refuse)


def _nonmember_audited(mp):
    """A stranger's attempt on a team that exists is recorded in it, as member 0."""
    original = S._Ops._guarded

    def _guarded(self, tool, actor, team_id, target, action):
        outcome = original(self, tool, actor, team_id, target, action)
        if outcome.kind == "not_member" and team_id is not None:
            with self.x.tx(read_only=False) as q:
                if S._one(q("SELECT 1 AS found FROM teams WHERE team_id = ?", (team_id,))) is not None:
                    c = S._Call(q, tool, actor, team_id, target or "member:0", None, {"member_no": 0})
                    seq = self._next_seq(q, team_id, tool, ok=False)
                    if seq is not None:
                        self._insert_audit(c, seq, "denied", "role")
        return outcome

    mp.setattr(S._Ops, "_guarded", _guarded)


def _principal_as_client_id(mp):
    """The record's client_id column holds who the caller is (issuer|sub), cut to fit."""
    original = S._Ops._insert_audit

    def _insert_audit(self, c, seq, result, reason="", **kwargs):
        who = c.actor.principal
        original(self, replace(c, actor=S.Actor(who, who[: limits.MAX_CLIENT_ID])), seq, result, reason, **kwargs)

    mp.setattr(S._Ops, "_insert_audit", _insert_audit)


def _refused_with_message(e):
    """Logs the database's own message, which may quote the whole row."""
    S.logger.error("The card database refused a change: %s %s", type(e).__name__, e)
    raise S.StoreRefusedError from None


def _outage_ok_rewritten(mp):
    """Postgres: when the connection is lost before the commit, the change's ok records
    are written again through a new connection, though the change itself is gone."""
    insert, mapped = S._Ops._insert_audit, S.PostgresCardStore.map_errors
    written = threading.local()  # this transaction's ok records

    def _insert_audit(self, c, seq, result, reason="", **kwargs):
        insert(self, c, seq, result, reason, **kwargs)
        records = getattr(written, "records", None)
        if result == "ok" and records is not None:
            records.append(_audit_params(self, c, seq, result, reason, **kwargs))

    @contextmanager
    def map_errors(self):
        written.records = []
        try:
            with mapped(self):
                yield
        except S.StoreUnavailableError:
            records, written.records = written.records, None
            with self._pool.connection() as conn:
                for params in records or ():
                    conn.execute(S._SQL_INSERT_AUDIT.replace("?", "%s"), params)
            raise
        finally:
            written.records = None

    mp.setattr(S._Ops, "_insert_audit", _insert_audit)
    mp.setattr(S.PostgresCardStore, "map_errors", map_errors)


# --- module 3, step 3: gaps found by the review (2026-11-07) ---


def _triggers_not_always(mp):
    """Postgres: setup leaves the triggers enabled the default way (ORIGIN), so they don't
    fire in a replica session, and the startup check takes that as set up."""
    sql = schema.PG_AUDIT
    start = sql.index("ALTER TABLE audit_events ENABLE ALWAYS TRIGGER")
    _sql_variant(mp, "PG_AUDIT", sql[start:], "", module=schema)
    _sql_variant(mp, "_SQL_TRIGGERS", "t.tgenabled = 'A'", "t.tgenabled IN ('O', 'A')", module=schema)


def _audit_page_off_by_one(mp):
    """The server takes a full page for a sign of more (has_more = len(events) >= limit):
    when exactly a page is left, it reports a next page, which is empty. Made in the store,
    whose page then holds one record more for the server to cut, so the server's own code
    stays as it is."""
    original = S._Ops._read_audit_log

    def _read_audit_log(self, c, limit_plus_one, after_seq):
        outcome = original(self, c, limit_plus_one, after_seq)
        events = outcome.value["events"]
        if len(events) == limit_plus_one - 1:
            events.append(events[-1])
        return outcome

    mp.setattr(S._Ops, "_read_audit_log", _read_audit_log)


def _daily_limit_before_permission(mp):
    """The day's limit is checked before the permission: a member at the limit who may not
    use the tool at all is told the limit is reached, and it is recorded as such."""
    original = S._Ops._refuse

    def _refuse(self, c, kind, reason, value=None):
        if (kind, reason) == ("denied", "role") and c.tool in P.DAILY_CAPPED_TOOLS and self._daily_limit_reached(c):
            return original(self, c, "failed", "daily_limit")
        return original(self, c, kind, reason, value)

    mp.setattr(S._Ops, "_refuse", _refuse)


def _card_checked_before_daily_limit(mp):
    """grade_card and delete_card look the card up before the day's limit: a member at the
    limit learns which card numbers don't exist."""
    original = S._Ops._daily_limit_reached

    def _daily_limit_reached(self, c):
        if c.tool in ("grade_card", "delete_card"):
            card_no = int(c.target.removeprefix("card:"))
            if S._one(c.q(S._SQL_CARD_EXISTS, (c.team_id, card_no))) is None:
                return False  # the action then says there is no such card
        return original(self, c)

    mp.setattr(S._Ops, "_daily_limit_reached", _daily_limit_reached)


# --- module 3, step 3: gaps found by the second review (2026-11-07) ---


def _trigger_names_only(mp):
    """The startup check sees, for every trigger it knows by name, the definition it
    expects, whatever the trigger really is: only the names are compared."""
    expected = " ".join(f"WHEN '{name}' THEN '{definition}'" for name, definition in schema._PG_TRIGGERS.items())
    _sql_variant(mp, "_SQL_TRIGGERS", "pg_get_triggerdef(t.oid)", f"CASE t.tgname {expected} END", module=schema)


def _rules_and_row_security_ignored(mp):
    """A rule on audit_events, or row security switched on, goes unseen."""
    _sql_variant(mp, "_SQL_AUDIT_EXTRAS", "EXISTS (SELECT 1 FROM pg_rewrite r WHERE r.ev_class = c.oid)", "false", module=schema)
    _sql_variant(mp, "_SQL_AUDIT_EXTRAS", "c.relrowsecurity", "false", module=schema)


def _setup_unpinned(mp):
    """setup_database as it was before the second review: the owner's session keeps
    Postgres' default path, "$user" first, and the lock call names no schema and passes
    the lock id as psycopg sends it (integer). An overload of pg_advisory_xact_lock(integer)
    planted in a schema named after the owner runs with the owner's rights (one planted in
    public runs too, but setup then refuses public's foreign objects and all of it is
    rolled back)."""
    _sql_variant(mp, "_SQL_SETUP_PIN", "pg_catalog.set_config('search_path', 'public, pg_temp', true)", "NULL", module=schema)
    _sql_variant(mp, "_SQL_SETUP_LOCK", "pg_catalog.pg_advisory_xact_lock(%s::bigint)", "pg_advisory_xact_lock(%s)", module=schema)


@contextmanager
def _read_search_path_not_pinned(self, read_only):
    """PostgresCardStore.tx whose read-only transactions keep the session's search path,
    "$user" first: a schema named after the app role stands in for the tables in every
    read. Writes are still pinned."""
    with self._connection() as conn:
        if read_only:
            conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            conn.execute(
                "SELECT set_config('idle_in_transaction_session_timeout', %s, true),"
                " set_config('statement_timeout', %s, true)",
                (S.PG_IDLE_IN_TRANSACTION_TIMEOUT, S.PG_STATEMENT_TIMEOUT),
            )
        else:
            conn.execute(
                "SELECT set_config('search_path', %s, true),"
                " set_config('lock_timeout', %s, true),"
                " set_config('idle_in_transaction_session_timeout', %s, true),"
                " set_config('statement_timeout', %s, true)",
                (S.PG_SEARCH_PATH, f"{S.LOCK_WAIT_SECONDS}s", S.PG_IDLE_IN_TRANSACTION_TIMEOUT, S.PG_STATEMENT_TIMEOUT),
            )
        yield lambda sql, params=(): conn.execute(sql.replace("?", "%s"), params)


# --- module 3, step 3: gaps found by the fourth review (2026-11-07) ---


def _setup_foreign_variant(mp, old, new):
    """Change setup's check for what it must not run into, both times setup runs it."""
    for name in ("_SQL_SETUP_FOREIGN", "_SQL_SETUP_RECHECK"):
        _sql_variant(mp, name, old, new, module=schema)


def _setup_extension_exemption(alias):
    """The part of setup's check that lets an extension's relation (alias r) or function
    (alias f) through."""
    return (
        " AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend e JOIN pg_catalog.pg_extension x"
        f" ON x.tableoid = e.refclassid AND x.oid = e.refobjid WHERE e.classid = {alias}.tableoid AND e.objid = {alias}.oid"
        " AND e.deptype = 'e')"
    )


def _setup_refuses_extensions(mp):
    """Setup counts what a trusted extension put in public as another role's objects (its
    relations, its functions, and its functions a trigger calls), and refuses every
    database with one, as on Neon."""
    for alias in ("r", "f", "p"):
        _setup_foreign_variant(mp, _setup_extension_exemption(alias), "")


# The relation kinds setup's check skips: composite types and indexes.
_SETUP_RELKIND_SKIP = " AND r.relkind NOT IN ('c', 'i', 'I')"


def _setup_ignores_foreign_relations(mp):
    """Setup's check looks at functions and triggers only: a table another role owns in
    public goes unseen, whatever its rules or constraints call."""
    relations = (
        "EXISTS (SELECT 1 FROM pg_catalog.pg_class r WHERE r.relnamespace = n.oid AND r.relowner <> u.oid"
        + _SETUP_RELKIND_SKIP + _setup_extension_exemption("r") + ")"
    )
    _setup_foreign_variant(mp, relations, "false")


# The trigger part of setup's check: a trigger on a table in public but audit_events whose
# function neither the role running setup nor an extension owns.
_SETUP_TRIGGER_CHECK = (
    " OR EXISTS (SELECT 1 FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_class c ON c.oid = t.tgrelid"
    " JOIN pg_catalog.pg_proc p ON p.oid = t.tgfoid"
    " WHERE c.relnamespace = n.oid AND NOT t.tgisinternal AND c.relname <> 'audit_events' AND p.proowner <> u.oid"
    + _setup_extension_exemption("p") + ")"
)


def _setup_refuses_owners_triggers(mp):
    """Setup's trigger check as it was before the fourth review was verified: any trigger
    on a table in public but audit_events is refused, even one that calls the owner's own
    function on a table setup never writes to."""
    _setup_foreign_variant(
        mp,
        _SETUP_TRIGGER_CHECK,
        " OR EXISTS (SELECT 1 FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_class c ON c.oid = t.tgrelid"
        " WHERE c.relnamespace = n.oid AND NOT t.tgisinternal AND c.relname <> 'audit_events')",
    )


def _setup_leaves_app_create(mp):
    """Setup no longer takes back CREATE on schema public and on the database from the app
    role, so running it again doesn't undo that mistake."""
    taken_back = ("REVOKE CREATE ON SCHEMA public FROM {app}", "REVOKE CREATE ON DATABASE {database} FROM {app}")
    assert all(statement in schema._PG_GRANTS for statement in taken_back)
    mp.setattr(schema, "_PG_GRANTS", tuple(s for s in schema._PG_GRANTS if s not in taken_back))


def _auth_without_audience_check(**kwargs):
    """Accepts tokens issued for any server."""
    kwargs["validate_token_resource"] = False
    return AuthSettings(**kwargs)


# --- the real JWT verifier ---


def _decode_without_signature(self, token):
    """Reads the token without checking its signature (every claim is still checked)."""
    return jwt.decode(
        token,
        issuer=self.issuer,
        audience=self.audience,
        leeway=V.LEEWAY_SECONDS,
        options={
            "verify_signature": False,
            **dict.fromkeys(["verify_exp", "verify_nbf", "verify_iat", "verify_iss", "verify_aud", "verify_sub"], True),
            "require": V.REQUIRED_CLAIMS,
        },
    )


def _decode_any_audience(self, token):
    """Forgot the audience check: accepts tokens the provider issued for other servers."""
    key = self._keys.get_signing_key_from_jwt(token)
    return jwt.decode(
        token, key, algorithms=V.ALGORITHMS, issuer=self.issuer, leeway=V.LEEWAY_SECONDS,
        options={"verify_aud": False, "require": ["iss", "sub", "exp"]},
    )


def _decode_any_issuer(self, token):
    """Forgot the issuer check."""
    key = self._keys.get_signing_key_from_jwt(token)
    return jwt.decode(
        token, key, algorithms=V.ALGORITHMS, audience=self.audience, leeway=V.LEEWAY_SECONDS,
        options={"require": V.REQUIRED_CLAIMS},
    )


def _decode_ignoring_expiry(self, token):
    """Forgot the expiry check."""
    key = self._keys.get_signing_key_from_jwt(token)
    return jwt.decode(
        token, key, algorithms=V.ALGORITHMS, issuer=self.issuer, audience=self.audience, leeway=V.LEEWAY_SECONDS,
        options={"verify_exp": False, "require": ["iss", "sub", "aud"]},
    )


async def _verify_subject_optional(self, token):
    """Accepts a token that doesn't name a user."""

    def decode():
        key = self._keys.get_signing_key_from_jwt(token)
        return jwt.decode(
            token, key, algorithms=V.ALGORITHMS, issuer=self.issuer, audience=self.audience,
            leeway=V.LEEWAY_SECONDS, options={"require": ["iss", "aud", "exp"]},
        )

    try:
        claims = await anyio.to_thread.run_sync(decode)
    except Exception:
        return None
    return AccessToken(
        token=token, client_id="", scopes=V._scopes(claims), expires_at=int(claims["exp"]),
        resource=self.audience, subject=claims.get("sub"), claims={"iss": claims["iss"], "sub": claims.get("sub")},
    )


def _rs256_only(mp):
    """Hard-codes RS256, as Descope's metadata suggests, though a project run by Descope itself signs with ES384."""
    mp.setattr(V, "ALGORITHMS", ["RS256"])


def _unverified(token):
    return jwt.decode(token, options={"verify_signature": False})


def _rewrap_verify_token(mp, change):
    """Run the real verify_token, then apply `change(result, claims)` to what it accepted."""
    original = V.JwtTokenVerifier.verify_token

    async def patched(self, token):
        result = await original(self, token)
        return change(result, _unverified(token)) if result is not None else None

    mp.setattr(V.JwtTokenVerifier, "verify_token", patched)


def _resource_from_first_aud(mp):
    """Takes the resource from the token's aud (its first entry) instead of the configured URL."""
    _rewrap_verify_token(
        mp, lambda r, c: r.model_copy(update={"resource": c["aud"] if isinstance(c["aud"], str) else c["aud"][0]})
    )


def _client_id_without_azp(mp):
    """Reads the client ID only from client_id, which Descope's tokens don't have."""
    _rewrap_verify_token(mp, lambda r, c: r.model_copy(update={"client_id": str(c.get("client_id") or "")}))


def _scope_not_split(claims):
    """Treats the space-separated scope string as one scope."""
    scope = claims.get("scope")
    return [scope] if isinstance(scope, str) else (scope or [])


def _token_logged_on_mismatch(mp):
    """Logs the token itself when explaining an issuer or audience mismatch."""
    original = V._claimed

    def patched(token):
        V.logger.info("mismatched token: %s", token)
        return original(token)

    mp.setattr(V, "_claimed", patched)


class _InlineAnyio:
    """anyio stand-in whose to_thread.run_sync runs the function on the event loop."""

    class to_thread:
        @staticmethod
        async def run_sync(fn, *args):
            return fn(*args)


def _dsub_ignored(mp):
    """Ignores dsub, so a customized sub is trusted as the user's ID."""
    original = V.JwtTokenVerifier._decode

    def patched(self, token):
        claims = original(self, token)
        claims.pop("dsub", None)
        return claims

    mp.setattr(V.JwtTokenVerifier, "_decode", patched)


def _token_type_ignored(mp):
    """Accepts the same provider's refresh and ID tokens as access tokens."""
    original = V._kind_problem
    mp.setattr(V, "_kind_problem", lambda claims: original({k: v for k, v in claims.items() if k != "token_type"}))


def _lifetime_capped_only_with_iat(mp):
    """Checks the lifetime only when the token says when it was issued."""
    original = V._kind_problem
    mp.setattr(V, "_kind_problem", lambda claims: original(claims) if "iat" in claims else "")


def _lifetime_counted_from_now(mp):
    """Counts the lifetime from now, so a long-lived token close to expiry passes."""
    original = V._kind_problem
    mp.setattr(V, "_kind_problem", lambda claims: original({k: v for k, v in claims.items() if k != "iat"}))


def _empty_token_type_allowed(mp):
    """Treats a null or empty token_type as no token_type at all."""
    original = V._kind_problem
    mp.setattr(
        V, "_kind_problem",
        lambda claims: original({k: v for k, v in claims.items() if k != "token_type" or v}),
    )


# --- the provider's signing keys (SigningKeys) ---


def _after_init(mp, change):
    """Run the real SigningKeys.__init__, then `change(self)`."""
    original = V.SigningKeys.__init__

    def patched(self, *args, **kwargs):
        original(self, *args, **kwargs)
        change(self)

    mp.setattr(V.SigningKeys, "__init__", patched)


def _after_failure(mp, change):
    """Run the real SigningKeys._failed, then `change(self)`."""
    original = V.SigningKeys._failed

    def patched(self, e):
        original(self, e)
        change(self)

    mp.setattr(V.SigningKeys, "_failed", patched)


def _default_user_agent(store):
    """Fetches keys with Python's default User-Agent, which Descope's endpoint refuses."""
    store._client.headers = {}


def _token_in_key_warning(mp):
    """Logs a warning naming the token when no keys are young enough to check it."""
    original = V.SigningKeys.get_signing_key_from_jwt

    def patched(self, token):
        try:
            return original(self, token)
        except V.SigningKeysUnavailable:
            V.logger.warning("No signing keys to check the token %s", token)
            raise

    mp.setattr(V.SigningKeys, "get_signing_key_from_jwt", patched)


def _staleness_from_last_attempt(store):
    """Dates the kept keys from the failed attempt, so they never grow too old."""
    if store._snapshot is not None:
        store._snapshot = (store._snapshot[0], store._clock())


def _failed_fetch_drops_keys(store):
    """Throws the last good keys away when a fetch fails."""
    store._snapshot = None


def _empty_set_replaces_keys(mp):
    """Takes a response with no usable keys as an empty key set that replaces the good one."""
    original = V.SigningKeys._download

    def patched(self):
        try:
            return original(self)
        except jwt.PyJWKSetError:  # no usable keys at all, or none for the allowed algorithms
            return {}
        except jwt.PyJWKClientError as e:
            if "did not contain any signing keys" in str(e):  # only encryption keys
                return {}
            raise  # unreachable, not an object: still a failed fetch

    mp.setattr(V.SigningKeys, "_download", patched)


def _key_age_from_fetch_end(mp):
    """Dates the keys from the end of their fetch, so a slow fetch makes them last longer."""
    original = V.SigningKeys._succeeded
    mp.setattr(V.SigningKeys, "_succeeded", lambda self, keys, started: original(self, keys, self._clock()))


def _download_any_algorithm(self):
    """Keeps keys for algorithms the verifier doesn't allow."""
    keys = {}
    for key in self._client.get_signing_keys():
        keys.setdefault(key.key_id, key)
    if not keys:
        raise jwt.PyJWKSetError("The key endpoint published no signing keys")
    return keys


def _removed_keys_kept(mp):
    """Merges a new key set into the old one, so a key the provider dropped keeps working."""
    original = V.SigningKeys._succeeded

    def patched(self, keys, started):
        old = self._snapshot[0] if self._snapshot is not None else {}
        original(self, {**old, **keys}, started)

    mp.setattr(V.SigningKeys, "_succeeded", patched)


def _fetch_catching_only_jwt_errors(self):
    """Treats only PyJWT's errors as a failed fetch; anything else escapes."""
    started = self._clock()
    self._last_attempt = started
    try:
        keys = self._download()
    except jwt.PyJWTError as e:
        self._failed(e)
        return
    self._succeeded(keys, started)


def _back_off_not_reset(mp):
    """Keeps counting failures after a success, so the next outage starts with long waits."""
    original = V.SigningKeys._succeeded

    def patched(self, keys, started):
        failures, failing_since = self._failures, self._failing_since
        original(self, keys, started)
        self._failures, self._failing_since = failures, failing_since

    mp.setattr(V.SigningKeys, "_succeeded", patched)


def _back_off_from_attempt_start(store):
    """Counts the wait from the start of the failed attempt, so a slow timeout eats it."""
    store._retry_at -= store._clock() - store._last_attempt


def _gate_counts_only_successes(store):
    """Counts the unknown-key-id gap from the last successful fetch only (PyJWT's cooldown)."""
    store._last_attempt = store._snapshot[1] if store._snapshot is not None else None


def _wants_fetch_ignoring_back_off_for_unknown_kids(self, kid):
    """Lets a token with an unknown key id fetch during back-off."""
    now = self._clock()
    in_back_off = self._retry_at is not None and now < self._retry_at
    snap = self._snapshot
    if snap is None or now - snap[1] >= V.KEYS_CACHE_SECONDS:
        return not in_back_off
    if kid in snap[0]:
        return False
    return self._last_attempt is None or now - self._last_attempt >= V.KEYS_UNKNOWN_KID_GAP_SECONDS


def _get_key(*, no_kid_shortcut=True, wait_with_keys=False, wait_without_keys=True):
    """A SigningKeys.get_key with one mistake about tokens without a kid or about waiting."""

    def get_key(self, kid):
        if no_kid_shortcut and (not isinstance(kid, str) or not kid):
            raise V.UnknownKeyId("The token names no key id")
        if self._wants_fetch(kid):
            wait = wait_without_keys if self._usable() is None else wait_with_keys
            if wait:
                acquired = self._fetch_lock.acquire(timeout=V.KEYS_WAIT_SECONDS)
            else:
                acquired = self._fetch_lock.acquire(blocking=False)
            if acquired:
                try:
                    if self._wants_fetch(kid):
                        self._fetch()
                finally:
                    self._fetch_lock.release()
        keys = self._usable()
        if keys is None:
            raise V.SigningKeysUnavailable("No signing keys young enough to trust")
        key = keys.get(kid)
        if key is None:
            raise V.UnknownKeyId("No published key matches the token's key id")
        return key

    return get_key


class _NoLock:
    """A lock that never stops anyone, so every request runs its own fetch."""

    def acquire(self, blocking=True, timeout=-1):
        return True

    def release(self):
        pass


def _outage_warning_per_request(mp):
    """Logs a warning on every request refused for want of keys."""
    original = V.SigningKeys.get_key

    def patched(self, kid):
        try:
            return original(self, kid)
        except V.SigningKeysUnavailable:
            V.logger.warning("Could not check an access token: no signing keys")
            raise

    mp.setattr(V.SigningKeys, "get_key", patched)


def _recovery_not_logged(mp):
    """Forgets the failure count just before a success, so the recovery isn't logged."""
    original = V.SigningKeys._succeeded

    def patched(self, keys, started):
        self._failures = 0
        original(self, keys, started)

    mp.setattr(V.SigningKeys, "_succeeded", patched)


def _max_age_crossing_not_logged(mp):
    """Doesn't log the moment an outage outlasts the kept keys."""
    original = V.SigningKeys._failed

    def patched(self, e):
        self._said_refusing = True
        original(self, e)

    mp.setattr(V.SigningKeys, "_failed", patched)


def _key_outage_logged_as_info(mp):
    """Logs a key outage at INFO, where it hides among token rejections."""
    original = V.SigningKeys._failed

    def patched(self, e):
        V.logger.warning = V.logger.info  # for this call only: other warnings stay warnings
        try:
            original(self, e)
        finally:
            del V.logger.warning

    mp.setattr(V.SigningKeys, "_failed", patched)


def _unknown_key_id_silent(mp):
    """Reports a key id the provider doesn't publish as a provider outage, so nothing is logged."""
    original = V.SigningKeys.get_key
    unavailable = V.SigningKeysUnavailable

    def patched(self, kid):
        try:
            return original(self, kid)
        except V.UnknownKeyId:
            raise unavailable("No signing keys young enough to trust") from None

    mp.setattr(V.SigningKeys, "get_key", patched)


def _lenient_url(env, name, errors):
    """The first version's URL check: present, http(s), https unless local. No standard form."""
    value = env.get(name, "").strip()
    if not value:
        errors.append(f"{name} is missing")
        return value
    parts = A.urlsplit(value)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        errors.append(f"{name} must be a full URL")
    elif parts.scheme == "http" and parts.hostname not in A.LOCAL_HOSTS:
        errors.append(f"{name} must use https")
    return value


async def _guard_allows_any_method(self, scope, receive, send):
    """The guard still names the scope in challenges, but lets GET through again."""
    if scope["type"] == "http" and scope["path"] == self.path and scope["method"] != "POST":
        await self.app(scope, receive, send)
        return
    await _ORIGINAL_GUARD_CALL(self, scope, receive, send)


_ORIGINAL_GUARD_CALL = A.McpEndpointGuard.__call__


def _challenge_without_scope(mp):
    """401 and 403 challenges no longer name the required scope."""
    original = A.McpEndpointGuard.__init__

    def patched(self, app, *, path, scopes):
        original(self, app, path=path, scopes=scopes)
        self.scope_param = b""

    mp.setattr(A.McpEndpointGuard, "__init__", patched)


def _pg_request_errors_unmapped(mp):
    """Requests hand the driver's own error on instead of StoreUnavailableError
    (startup still maps its errors)."""

    @contextmanager
    def connection(self):
        with self._pool.connection() as conn:
            yield conn

    mp.setattr(S.PostgresCardStore, "_connection", connection)


def _pg_prepared_statements(mp):
    """Leaves psycopg's server-side prepared statements on, which Neon's pooler may break."""
    original = S.PostgresCardStore.__init__

    def init(self, url, **kw):
        original(self, url, **kw)
        self._pool.kwargs.pop("prepare_threshold", None)

    mp.setattr(S.PostgresCardStore, "__init__", init)


def _pg_full_as_unavailable(mp):
    """Reports a full database as a passing outage ("try again in a minute")."""
    original = S.PostgresCardStore.map_errors

    @contextmanager
    def mapped(self):
        try:
            with original(self):
                yield
        except S.StoreFullError:
            raise S.StoreUnavailableError from None

    mp.setattr(S.PostgresCardStore, "map_errors", mapped)


def _pg_no_connection_check(mp):
    """The pool hands out connections without checking them, so one the server dropped
    (Neon pausing) fails the next request."""
    import psycopg_pool

    mp.setattr(psycopg_pool.ConnectionPool, "check_connection", staticmethod(lambda conn: None))


def _database_url_echoed(value, errors):
    """Puts the database URL, password and all, into the error message."""
    if not value.startswith(("postgresql://", "postgres://")) or "sslmode=require" not in value:
        errors.append(f"FLASHCARDS_DATABASE_URL is not usable: {value!r}")


def _database_url_lenient(value, errors):
    """Only checks the scheme: no host, port or TLS checks."""
    if not value.startswith(("postgresql://", "postgres://")):
        errors.append("FLASHCARDS_DATABASE_URL must be a postgresql:// URL (value not shown)")


def _sqlite_allowed_on_render(mp):
    """Lets the server start on Render with a SQLite file that every restart wipes."""
    original = A._database
    mp.setattr(A, "_database", lambda env, on_render, errors: original(env, False, errors))


def _characters_unchecked(value, field):
    """Only rejects text that isn't valid UTF-8; NUL passes and Postgres then fails."""
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise server.ToolError(f"{field} contains invalid characters") from None


async def _outage_unexplained(call):
    """A database outage reaches the user as the SDK's generic error."""
    return await call


class _ServerWithListen(server.MCPServer):
    """Leaves subscriptions/listen on (the SDK default)."""

    def __init__(self, *args, **kwargs):
        kwargs.pop("subscriptions", None)
        super().__init__(*args, **kwargs)


class _StatefulServer(server.MCPServer):
    """Runs the app with per-connection sessions, which have a global cap."""

    def streamable_http_app(self, **kwargs):
        return super().streamable_http_app(**{**kwargs, "stateless_http": False})


MUTATIONS = {
    "shared-deck": lambda mp: mp.setattr(server, "current_owner", _shared_deck),
    "key-by-client-id": lambda mp: mp.setattr(server, "current_owner", _key_by_client_id),
    "no-subject-check": lambda mp: mp.setattr(server, "current_owner", _no_subject_check),
    "no-issuer-check": lambda mp: mp.setattr(server, "current_owner", _no_issuer_check),
    # One query that forgot its team filter (both databases: the SQL is shared).
    "unscoped-grade": lambda mp: _sql_variant(mp, "_SQL_GRADE", "team_id = ?", "(team_id = ? OR 1 = 1)"),
    # Was pg-unscoped-grade, before the two stores shared their SQL.
    "unscoped-delete": lambda mp: _sql_variant(mp, "_SQL_DELETE", "team_id = ?", "(team_id = ? OR 1 = 1)"),
    "no-audience-check": lambda mp: mp.setattr(server, "AuthSettings", _auth_without_audience_check),
    # Review order by card number alone, not by when each card was last reviewed.
    "review-ignores-time": lambda mp: _sql_variant(
        mp, "_SQL_REVIEW", "ORDER BY last_reviewed IS NOT NULL, last_reviewed, card_no", "ORDER BY card_no"
    ),
    "unpaginated-list": _list_unpaginated,
    "topic-not-normalized": lambda mp: mp.setattr(S, "topic_key", lambda topic: topic),
    "no-rate-limit": lambda mp: mp.setattr(server.RateLimiter, "check", lambda self, key: None),
    "jwt-signature-not-checked": lambda mp: mp.setattr(V.JwtTokenVerifier, "_decode", _decode_without_signature),
    "jwt-audience-not-checked": lambda mp: mp.setattr(V.JwtTokenVerifier, "_decode", _decode_any_audience),
    "jwt-issuer-not-checked": lambda mp: mp.setattr(V.JwtTokenVerifier, "_decode", _decode_any_issuer),
    "jwt-expiry-not-checked": lambda mp: mp.setattr(V.JwtTokenVerifier, "_decode", _decode_ignoring_expiry),
    "jwt-subject-optional": lambda mp: mp.setattr(V.JwtTokenVerifier, "verify_token", _verify_subject_optional),
    "jwt-keys-not-cached": lambda mp: mp.setattr(V, "KEYS_CACHE_SECONDS", 0),
    "jwt-default-user-agent": lambda mp: _after_init(mp, _default_user_agent),
    "jwt-rs256-only": _rs256_only,
    "jwt-resource-from-first-aud": _resource_from_first_aud,
    "jwt-scope-not-split": lambda mp: mp.setattr(V, "_scopes", _scope_not_split),
    "jwt-client-id-without-azp": _client_id_without_azp,
    "jwt-token-logged-on-mismatch": _token_logged_on_mismatch,
    "jwt-token-in-key-warning": _token_in_key_warning,
    "jwt-decode-on-event-loop": lambda mp: mp.setattr(V, "anyio", _InlineAnyio),
    "jwt-dsub-ignored": _dsub_ignored,
    # A provider outage reported as a token problem.
    "jwt-key-errors-look-like-token-errors": lambda mp: mp.setattr(V, "SigningKeysUnavailable", V.UnknownKeyId),
    "jwt-token-type-ignored": _token_type_ignored,
    "jwt-lifetime-uncapped": lambda mp: mp.setattr(V, "MAX_LIFETIME_SECONDS", 10**12),
    "jwt-lifetime-capped-only-with-iat": _lifetime_capped_only_with_iat,
    "jwt-lifetime-counted-from-now": _lifetime_counted_from_now,
    "jwt-empty-token-type-allowed": _empty_token_type_allowed,
    # The provider's signing keys during an outage (SigningKeys).
    "jwt-no-stale-keys": lambda mp: mp.setattr(V, "KEYS_MAX_AGE_SECONDS", V.KEYS_CACHE_SECONDS),
    "jwt-stale-keys-forever": lambda mp: mp.setattr(V, "KEYS_MAX_AGE_SECONDS", 10**12),
    "jwt-staleness-from-last-attempt": lambda mp: _after_failure(mp, _staleness_from_last_attempt),
    "jwt-failed-fetch-drops-keys": lambda mp: _after_failure(mp, _failed_fetch_drops_keys),
    "jwt-empty-set-replaces-keys": _empty_set_replaces_keys,
    "jwt-disallowed-algorithm-keys-kept": lambda mp: mp.setattr(V.SigningKeys, "_download", _download_any_algorithm),
    "jwt-removed-keys-kept": _removed_keys_kept,
    "jwt-fetch-error-escapes": lambda mp: mp.setattr(V.SigningKeys, "_fetch", _fetch_catching_only_jwt_errors),
    "jwt-no-back-off": lambda mp: mp.setattr(V, "KEYS_RETRY_FIRST_SECONDS", 0),
    "jwt-back-off-uncapped": lambda mp: mp.setattr(V, "KEYS_RETRY_MAX_SECONDS", 10**9),
    "jwt-back-off-not-reset": _back_off_not_reset,
    "jwt-back-off-from-attempt-start": lambda mp: _after_failure(mp, _back_off_from_attempt_start),
    "jwt-unknown-kid-refresh-unlimited": lambda mp: mp.setattr(V, "KEYS_UNKNOWN_KID_GAP_SECONDS", 0),
    "jwt-unknown-kid-gate-counts-only-successes": lambda mp: _after_failure(mp, _gate_counts_only_successes),
    "jwt-unknown-kid-ignores-back-off": lambda mp: mp.setattr(
        V.SigningKeys, "_wants_fetch", _wants_fetch_ignoring_back_off_for_unknown_kids
    ),
    "jwt-no-kid-fetches": lambda mp: mp.setattr(V.SigningKeys, "get_key", _get_key(no_kid_shortcut=False)),
    "jwt-concurrent-fetches": lambda mp: _after_init(mp, lambda store: setattr(store, "_fetch_lock", _NoLock())),
    "jwt-refresh-waits-for-in-flight-fetch": lambda mp: mp.setattr(V.SigningKeys, "get_key", _get_key(wait_with_keys=True)),
    "jwt-waiters-never-wait": lambda mp: mp.setattr(V.SigningKeys, "get_key", _get_key(wait_without_keys=False)),
    "jwt-no-wait-limit": lambda mp: mp.setattr(V, "KEYS_WAIT_SECONDS", -1),
    "jwt-outage-warning-per-attempt": lambda mp: mp.setattr(V.logger, "debug", V.logger.warning),
    "jwt-outage-warning-per-request": _outage_warning_per_request,
    "jwt-recovery-not-logged": _recovery_not_logged,
    "jwt-max-age-crossing-not-logged": _max_age_crossing_not_logged,
    "jwt-key-outage-logged-as-info": _key_outage_logged_as_info,
    "jwt-key-age-from-fetch-end": _key_age_from_fetch_end,
    "jwt-fetch-timeout-unbounded": lambda mp: mp.setattr(V, "KEYS_FETCH_TIMEOUT_SECONDS", None),
    # A token problem reported as a provider outage.
    "jwt-unknown-key-id-silent": _unknown_key_id_silent,
    "jwt-keys-aged-by-wall-clock": lambda mp: _after_init(mp, lambda store: setattr(store, "_clock", time.time)),
    "app-urls-not-standard-form": lambda mp: mp.setattr(A, "_url", _lenient_url),
    "app-key-url-on-any-host": lambda mp: mp.setattr(A, "_same_host", lambda url, other: True),
    "app-get-allowed": lambda mp: mp.setattr(A.McpEndpointGuard, "__call__", _guard_allows_any_method),
    "app-challenge-without-scope": _challenge_without_scope,
    "app-listen-enabled": lambda mp: mp.setattr(server, "MCPServer", _ServerWithListen),
    "app-stateful": lambda mp: mp.setattr(server, "MCPServer", _StatefulServer),
    "app-default-keep-alive": lambda mp: mp.setattr(A, "KEEP_ALIVE_SECONDS", 5),
    "app-no-connection-limit": lambda mp: mp.setattr(A, "MAX_CONNECTIONS", None),
    "app-workers-from-environment": lambda mp: mp.setattr(A, "WORKERS", None),
    "app-sqlite-allowed-on-render": _sqlite_allowed_on_render,
    "app-database-url-echoed": lambda mp: mp.setattr(A, "_database_url", _database_url_echoed),
    "app-database-url-unchecked": lambda mp: mp.setattr(A, "_database_url", _database_url_lenient),
    "app-database-url-in-repr": lambda mp: mp.setattr(A.Settings, "__repr__", lambda self: f"Settings({self.database_url!r})"),
    "app-allowed-origins-ignored": lambda mp: mp.setattr(A, "_origins", lambda env, errors: []),
    "app-settings-not-stripped": lambda mp: mp.setattr(A, "_setting", lambda env, name: env.get(name)),
    "app-stray-url-characters-unexplained": lambda mp: mp.setattr(A, "NOT_IN_URLS", frozenset()),
    "store-on-event-loop": lambda mp: mp.setattr(S, "anyio", _InlineAnyio),
    "text-nul-allowed": lambda mp: mp.setattr(server, "_check_characters", _characters_unchecked),
    "outage-unexplained": lambda mp: mp.setattr(server, "_stored", _outage_unexplained),
    # Postgres only: run_mutations.py skips these when no local Postgres is available.
    "pg-number-from-max": _pg_add(max_numbering=True),
    "pg-limit-checked-before-lock": _pg_add(limit_before_lock=True),
    "pg-number-in-own-transaction": _pg_add(number_in_own_transaction=True),
    # Orders by review time alone: Postgres puts never-reviewed cards (NULL) last, SQLite first.
    "pg-review-nulls-last": lambda mp: _sql_variant(
        mp, "_SQL_REVIEW", "ORDER BY last_reviewed IS NOT NULL, last_reviewed", "ORDER BY last_reviewed"
    ),
    "pg-no-connection-check": _pg_no_connection_check,
    "pg-request-errors-unmapped": _pg_request_errors_unmapped,
    "pg-prepared-statements": _pg_prepared_statements,
    "pg-full-as-unavailable": _pg_full_as_unavailable,
    "app-origins-not-standardized": lambda mp: mp.setattr(A, "_standard_origin", lambda origin: origin),
    # --- Teams, roles and invites (module 3, step 2). ---
    "perm-viewer-can-delete": _required(delete_card="viewer"),
    "perm-viewer-can-grade": _required(grade_card="viewer"),
    "perm-default-allow": _default_allow,
    "perm-members-by-editor": _required(set_member_role="editor", remove_member="editor"),
    # Membership in any team counts as membership in this one.
    "perm-any-team": lambda mp: _sql_variant(
        mp, "_SQL_MEMBER", "team_id = ? AND principal = ?", "(team_id = ? OR 1 = 1) AND principal = ?"
    ),
    "perm-role-cached": _role_cached,
    "pg-perm-checked-before-lock": lambda mp: _on_postgres(mp, "_guarded", _pg_guarded(role_from_before_lock=True)),
    # Everyone who joins becomes an editor, whatever the invite says.
    "join-role-not-from-invite": lambda mp: _sql_variant(
        mp, "_SQL_INVITE", "SELECT invite_no, role FROM", "SELECT invite_no, 'editor' AS role FROM"
    ),
    # A removed member stays in the team, as a viewer.
    "remove-keeps-row": lambda mp: _sql_variant(mp, "_SQL_REMOVE", "DELETE FROM members", "UPDATE members SET role = 'viewer'"),
    "nonmember-distinguishable": _nonmember_distinguishable,
    "pg-personal-team-duplicated": _personal_team_duplicated,
    # A first add that waited behind another one counts the personal team that one made
    # as a team too many: at the server's last free place it is told the server is full.
    "pg-personal-team-not-rechecked": lambda mp: _on_postgres(mp, "_personal_team", _personal_team_looked_for_once),
    "invite-reusable": lambda mp: _sql_variant(mp, "_SQL_INVITE", "used_at IS NULL", "(used_at IS NULL OR 1 = 1)"),
    "invite-never-expires": lambda mp: _sql_variant(mp, "_SQL_INVITE", "expires_at > ?", "(expires_at > ? OR 1 = 1)"),
    "invite-stored-raw": _invite_stored_raw,
    "last-owner-unchecked": _last_owner_unchecked({"set_member_role", "remove_member"}),
    "leave-last-owner-unchecked": _last_owner_unchecked({"leave_team"}),
    "pg-last-owner-without-lock": lambda mp: _on_postgres(
        mp, "_guarded", _pg_guarded(unlocked=("set_member_role", "remove_member"))
    ),
    # Counts no shared teams, so MAX_SHARED_TEAMS_PER_PERSON never stops anyone.
    "team-cap-unchecked": lambda mp: _sql_variant(mp, "_SQL_COUNT_SHARED", "SELECT COUNT(*) AS n", "SELECT 0 * COUNT(*) AS n"),
    "refusal-needs-audit-room": _refusal_needs_audit_room,
    "no-owner-reserve": _no_owner_reserve,
    # --- The audit log, its limits, and the database's own defences (module 3, step 3). ---
    "audit-denied-not-recorded": lambda mp: mp.setattr(S._Ops, "_refuse", _refuse_unrecorded),
    "audit-failed-as-ok": _deck_full_recorded_as_ok,
    "audit-before-action-committed": _audit_before_action_committed,
    "audit-after-commit-swallowed": _audit_after_commit_swallowed,
    "audit-records-card-content": _card_content_in_target,
    "audit-read-not-recorded": lambda mp: mp.setattr(S._Ops, "_read_audit_log", _read_unrecorded),
    # Reads the log of every team.
    "audit-cross-team-read": lambda mp: _sql_variant(mp, "_SQL_AUDIT_PAGE", "team_id = ?", "(team_id = ? OR 1 = 1)"),
    # Takes a place of the write allowance even when none is left.
    "audit-cap-unchecked": lambda mp: _sql_variant(mp, "_SQL_ALLOC_SEQ", "audit_writes < ?", "(audit_writes < ? OR 1 = 1)"),
    # A read of the log takes a place of the write allowance (short of the reserve), not of its own.
    "audit-reads-share-write-counter": lambda mp: mp.setattr(
        S._Ops, "_alloc_read_seq", lambda self, q, team_id: self._alloc_seq(q, team_id, "read_audit_log")
    ),
    "pg-audit-cap-outside-lock": _audit_cap_outside_lock,
    "refusal-quota-ignored": lambda mp: mp.setattr(S._Ops, "_refuse", _refuse_without_quota),
    # Counts no teams, so MAX_TEAMS_TOTAL never stops a new team or a new personal team.
    "server-cap-unchecked": lambda mp: _sql_variant(mp, "_SQL_COUNT_TEAMS", "SELECT COUNT(*) AS n", "SELECT 0 * COUNT(*) AS n"),
    "sqlite-no-append-only-triggers": _sqlite_triggers_dropped("audit_events_no_update", "audit_events_no_delete"),
    "pg-trigger-row-level-only": _pg_trigger_row_level_only,
    # The app role may change and remove audit records.
    "pg-app-granted-rewrite": lambda mp: mp.setattr(
        schema, "_PG_GRANTS", (*schema._PG_GRANTS, "GRANT UPDATE, DELETE ON audit_events TO {app}")
    ),
    "pg-startup-check-skipped": lambda mp: mp.setattr(schema, "verify_app_role", lambda conn: None),
    "daily-cap-unchecked": lambda mp: mp.setattr(S._Ops, "_daily_limit_reached", lambda self, c: False),
    "daily-cap-blocks-reserve-tools": _reserve_tools_daily_capped,
    # Every change counts on from yesterday's: the day's count never starts again.
    "daily-cap-never-resets": lambda mp: _sql_variant(
        mp, "_SQL_COUNT_WRITE", "CASE WHEN writes_day = ? THEN", "CASE WHEN (writes_day = ? OR 1 = 1) THEN"
    ),
    "invite-cap-unchecked": lambda mp: mp.setattr(S._Ops, "_create_invite", _create_invite(capped=False)),
    "topic-index-restored": _topic_index_restored,
    "pg-no-session-timeouts": lambda mp: mp.setattr(S.PostgresCardStore, "tx", _no_session_timeouts),
    "pg-idle-timeout-unmapped": _idle_timeout_unmapped,
    # --- Cut on 2026-10-30 to save time, restored in step 3. ---
    "perm-rank-flat": lambda mp: mp.setitem(P.ROLE_RANK, "viewer", 2),
    # Any member may use any tool: only membership is checked.
    "perm-membership-only": lambda mp: mp.setattr(P, "allowed", lambda role, tool: role in P.ROLE_RANK),
    "perm-invite-by-editor": _required(create_invite="editor"),
    "perm-check-after-lookup": _existence_before_permission,
    "reads-create-personal-team": _reads_create_personal_team,
    "personal-team-shareable": lambda mp: mp.setattr(S._Ops, "_create_invite", _create_invite(personal_checked=False)),
    "invite-errors-distinguishable": _expired_invite_distinguishable,
    "invite-creator-not-rechecked": _invite_creator_not_rechecked,
    "invite-consumed-on-already-member": _invite_consumed_on_already_member,
    "sql-interpolated-team-id": lambda mp: mp.setattr(S._Ops, "_member", _member_with_team_id_in_text),
    "denied-raised-in-transaction": _denied_raised_in_transaction,
    "nonmember-audited": _nonmember_audited,
    "audit-records-principal": _principal_as_client_id,
    # The client's claim is stored as it came: any characters, any length.
    "client-id-unsanitized": lambda mp: mp.setattr(identity, "clean_client_id", lambda raw: raw or ""),
    "refused-error-logs-message": lambda mp: mp.setattr(S, "_refused", _refused_with_message),
    "sqlite-replace-overwrites": _sqlite_triggers_dropped("audit_events_no_replace"),
    "pg-app-owns-tables": _app_owns_tables,
    "outage-ok-rewritten": _outage_ok_rewritten,
    # Only table-wide UPDATE counts: a column-level grant on audit_events goes unseen.
    "verify-table-privilege-only": lambda mp: _sql_variant(
        mp, "_SQL_APP_ROLE", "has_any_column_privilege(g.oid, c.oid, 'UPDATE')",
        "has_table_privilege(g.oid, c.oid, 'UPDATE')", module=schema,
    ),
    # Superuser, CREATEROLE, BYPASSRLS and neon_superuser are looked for on the app role
    # only, never on the roles it belongs to.
    "verify-ignores-inherited-roles": lambda mp: _sql_variant(
        mp, "_SQL_APP_ROLE", "EXISTS (SELECT 1 FROM g WHERE (g.rolsuper",
        "EXISTS (SELECT 1 FROM g WHERE g.rolname = current_user AND (g.rolsuper", module=schema,
    ),
    # --- The startup check's gaps found by the step 3 review (2026-11-07). ---
    # Owning a schema, audit_events' own included, goes unseen (the database and what is in
    # audit_events' schema still count).
    "verify-ignores-owned-schemas": lambda mp: _sql_variant(
        mp, "_SQL_APP_ROLE", "g.oid IN (SELECT nspowner FROM pg_namespace)", "false", module=schema
    ),
    # Owning the database goes unseen.
    "verify-ignores-database-owner": lambda mp: _sql_variant(mp, "_SQL_APP_ROLE", "g.oid = d.datdba", "false", module=schema),
    # Owning a table in the schema, audit_events itself included, goes unseen.
    "verify-ignores-owned-tables": lambda mp: _sql_variant(
        mp, "_SQL_APP_ROLE", "g.oid IN (SELECT r.relowner FROM pg_class r WHERE r.relnamespace = n.oid)", "false",
        module=schema,
    ),
    # Owning a function in the schema, the one the triggers call included, goes unseen.
    "verify-ignores-owned-functions": lambda mp: _sql_variant(
        mp, "_SQL_APP_ROLE", "g.oid IN (SELECT f.proowner FROM pg_proc f WHERE f.pronamespace = n.oid)", "false",
        module=schema,
    ),
    # The rights on audit_events are asked of the app role only (with what it inherits),
    # never of the roles it may SET ROLE to.
    "verify-inherited-privileges-only": lambda mp: _sql_variant(
        mp, "_SQL_APP_ROLE", "EXISTS (SELECT 1 FROM g WHERE (has_any_column_privilege",
        "EXISTS (SELECT 1 FROM g WHERE g.rolname = current_user AND (has_any_column_privilege", module=schema,
    ),
    # Only superusers count as powerful: CREATEROLE and BYPASSRLS go unseen.
    "verify-ignores-role-attributes": lambda mp: _sql_variant(
        mp, "_SQL_APP_ROLE", "(g.rolsuper OR g.rolcreaterole OR g.rolbypassrls OR g.rolname = 'neon_superuser')",
        "(g.rolsuper OR g.rolname = 'neon_superuser')", module=schema,
    ),
    # Any function will do: one whose body lets every change through passes.
    "verify-ignores-trigger-function": lambda mp: _sql_variant(
        mp, "_SQL_TRIGGERS",
        "p.prosrc = %s AND l.lanname = 'plpgsql' AND p.proconfig = ARRAY['search_path=pg_catalog'] AND NOT p.prosecdef",
        "%s::text IS NOT NULL", module=schema,
    ),
    "triggers-not-always": _triggers_not_always,
    "setup-db-accepts-reserved-role": lambda mp: mp.setattr(setup_db, "reserved_role", lambda name: False),
    # The role is made without a password; the one shown was never set.
    "create-app-role-without-password": lambda mp: mp.setattr(
        setup_db, "_CREATE_ROLE", setup_db._CREATE_ROLE.replace("PASSWORD {password}", "PASSWORD NULL")
    ),
    "audit-page-off-by-one": _audit_page_off_by_one,
    "daily-cap-before-permission": _daily_limit_before_permission,
    "daily-cap-after-card-check": _card_checked_before_daily_limit,
    # Each transaction keeps Postgres' default search path, "$user" first.
    "pg-search-path-not-pinned": lambda mp: mp.setattr(S, "PG_SEARCH_PATH", '"$user", public'),
    # --- The startup check's and setup's gaps found by the second step 3 review (2026-11-07). ---
    # Only the triggers' names are compared: one that fires per row passes.
    "verify-trigger-names-only": _trigger_names_only,
    # Any function with the same body will do, whatever its search_path setting or rights.
    "verify-function-body-only": lambda mp: _sql_variant(
        mp, "_SQL_TRIGGERS",
        "p.prosrc = %s AND l.lanname = 'plpgsql' AND p.proconfig = ARRAY['search_path=pg_catalog'] AND NOT p.prosecdef",
        "p.prosrc = %s", module=schema,
    ),
    # A trigger setup never made, beside the two it did, goes unseen.
    "verify-allows-extra-triggers": lambda mp: _sql_variant(
        mp, "_SQL_AUDIT_EXTRAS",
        "EXISTS (SELECT 1 FROM pg_trigger t WHERE t.tgrelid = c.oid AND NOT t.tgisinternal"
        " AND t.tgname::text <> ALL (%s::text[]))",
        "%s::text[] IS NULL", module=schema,
    ),
    "verify-ignores-rules-and-row-security": _rules_and_row_security_ignored,
    # The roles that read and write the server's files or run programs on it go unseen.
    "verify-ignores-file-roles": lambda mp: _sql_variant(
        mp, "_SQL_APP_ROLE",
        " OR g.rolname IN ('pg_read_server_files', 'pg_write_server_files', 'pg_execute_server_program')", "",
        module=schema,
    ),
    # CREATE on the database or on a schema goes unseen (PUBLIC's still counts, on its own).
    "verify-ignores-create": lambda mp: _sql_variant(
        mp, "_SQL_APP_ROLE",
        "has_database_privilege(g.oid, d.oid, 'CREATE')"
        " OR EXISTS (SELECT 1 FROM pg_namespace s WHERE s.nspname !~ '^pg_(temp|toast_temp)_'::text"
        " AND has_schema_privilege(g.oid, s.oid, 'CREATE'))",
        "false", module=schema,
    ),
    # Belonging to any other role counts as too powerful, however harmless that role.
    "verify-overbroad": lambda mp: _sql_variant(
        mp, "_SQL_APP_ROLE", "EXISTS (SELECT 1 FROM g WHERE (g.rolsuper",
        "EXISTS (SELECT 1 FROM g WHERE g.rolname <> current_user OR (g.rolsuper", module=schema,
    ),
    "setup-unpinned": _setup_unpinned,
    "pg-read-search-path-not-pinned": lambda mp: mp.setattr(S.PostgresCardStore, "tx", _read_search_path_not_pinned),
    # --- The startup check's and setup's gaps found by the third step 3 review (2026-11-07). ---
    # Only the role the session is now counts: a login role whose default is to become the
    # app role goes unseen, though it may RESET ROLE and act as any role it belongs to.
    "verify-ignores-session-user": lambda mp: _sql_variant(
        mp, "_SQL_APP_ROLE", "pg_has_role(session_user, oid, 'MEMBER') OR pg_has_role(current_user, oid, 'MEMBER')",
        "pg_has_role(current_user, oid, 'MEMBER')", module=schema,
    ),
    # A SECURITY DEFINER function in public, of a role the session can't act as, goes unseen.
    "verify-ignores-definer-functions": lambda mp: _sql_variant(
        mp, "_SQL_APP_ROLE", "AND x.prosecdef", "AND false", module=schema
    ),
    # The session's own temporary schema counts as a place it may create in.
    "verify-counts-temp-schemas": lambda mp: _sql_variant(
        mp, "_SQL_APP_ROLE", "s.nspname !~ '^pg_(temp|toast_temp)_'::text AND ", "", module=schema
    ),
    # CREATE granted to PUBLIC is reported as a role too powerful, whose remedy (connect as
    # another role) can't help.
    "verify-public-create-as-too-powerful": lambda mp: _sql_variant(
        mp, "_SQL_APP_ROLE",
        "has_database_privilege('public', d.oid, 'CREATE') OR EXISTS (SELECT 1 FROM pg_namespace p"
        " WHERE p.nspname !~ '^pg_(temp|toast_temp)_'::text AND has_schema_privilege('public', p.oid, 'CREATE'))",
        "false", module=schema,
    ),
    # A parent or child table of audit_events, partitions included, goes unseen.
    "verify-ignores-inheritance": lambda mp: _sql_variant(
        mp, "_SQL_AUDIT_EXTRAS",
        "(EXISTS (SELECT 1 FROM pg_inherits i WHERE i.inhrelid = c.oid OR i.inhparent = c.oid) OR c.relispartition)",
        "false", module=schema,
    ),
    # Belonging to a role named neon_superuser goes unseen.
    "verify-ignores-neon-superuser": lambda mp: _sql_variant(
        mp, "_SQL_APP_ROLE", " OR g.rolname = 'neon_superuser'", "", module=schema
    ),
    # Setup goes ahead over tables and functions another role put in public, and over
    # triggers it didn't make, firing them with the owner's rights (neither check runs).
    "setup-adopts-foreign-objects": lambda mp: (
        mp.setattr(schema, "_SQL_SETUP_FOREIGN", "SELECT false"), mp.setattr(schema, "_SQL_SETUP_RECHECK", "SELECT false")
    ),
    # Setup succeeds though every role may still create in the database.
    "setup-ignores-public-create": lambda mp: mp.setattr(schema, "_SQL_SETUP_PUBLIC_CREATE", "SELECT false"),
    # Setup keeps the session's path, "$user" first (its calls still name pg_catalog): the
    # tables go into a schema named after the owner, and the rights are reset there.
    "setup-search-path-not-pinned": lambda mp: _sql_variant(
        mp, "_SQL_SETUP_PIN", "pg_catalog.set_config('search_path', 'public, pg_temp', true)", "NULL", module=schema
    ),
    # Run in the caller's transaction, setup leaves its own path behind.
    "setup-keeps-its-search-path": lambda mp: _sql_variant(
        mp, "_SQL_SETUP_RESTORE", "pg_catalog.set_config('search_path', %s, true)", "%s::text", module=schema
    ),
    # --- The startup check's and setup's gaps found by the fourth step 3 review (2026-11-07). ---
    "setup-refuses-extensions": _setup_refuses_extensions,
    # An extension's SECURITY DEFINER function counts as a way to act as its owner.
    "verify-flags-extension-definers": lambda mp: _sql_variant(
        mp, "_SQL_APP_ROLE",
        " AND NOT EXISTS (SELECT 1 FROM pg_depend e JOIN pg_extension m ON m.tableoid = e.refclassid"
        " AND m.oid = e.refobjid WHERE e.classid = x.tableoid AND e.objid = x.oid AND e.deptype = 'e')",
        "", module=schema,
    ),
    # A trigger that calls another role's function, on one of the tables setup writes to,
    # goes unseen.
    "setup-ignores-foreign-triggers": lambda mp: _setup_foreign_variant(mp, _SETUP_TRIGGER_CHECK, ""),
    # Setup checks only once, before it creates anything: what is planted after that check
    # is fired by the INSERT.
    "setup-no-recheck": lambda mp: mp.setattr(schema, "_SQL_SETUP_RECHECK", "SELECT false"),
    # Setup doesn't lock its tables before the second check: a trigger can still be added.
    "setup-unlocked": lambda mp: mp.setattr(schema, "_SQL_SETUP_LOCK_TABLES", "SELECT 1"),
    # The advisory lock call names no schema and passes the lock id as psycopg sends it
    # (integer); the path is still pinned.
    "setup-lock-unqualified": lambda mp: _sql_variant(
        mp, "_SQL_SETUP_LOCK", "pg_catalog.pg_advisory_xact_lock(%s::bigint)", "pg_advisory_xact_lock(%s)", module=schema
    ),
    "setup-ignores-foreign-relations": _setup_ignores_foreign_relations,
    # A session that made a temporary table can't set up: its own temporary schema counts
    # as one PUBLIC may create in.
    "setup-counts-temp-schemas": lambda mp: _sql_variant(
        mp, "_SQL_SETUP_PUBLIC_CREATE", "s.nspname !~ '^pg_(temp|toast_temp)_'::text AND ", "", module=schema
    ),
    # The same in the startup check's PUBLIC column: a session that made a temporary table
    # is told every role may create.
    "verify-public-create-counts-temp-schemas": lambda mp: _sql_variant(
        mp, "_SQL_APP_ROLE", "p.nspname !~ '^pg_(temp|toast_temp)_'::text AND ", "", module=schema
    ),
    "setup-leaves-app-create": _setup_leaves_app_create,
    # Each transaction searches the session's temporary schema first (pg_temp unlisted).
    "pg-temp-tables-searched-first": lambda mp: mp.setattr(S, "PG_SEARCH_PATH", "public"),
    # --- Setup's and the startup check's gaps found verifying the fourth review (2026-11-07). ---
    # Setup counts composite types and indexes as relations another role owns: an
    # extension's composite type (tablefunc's) or its table's primary key index isn't an
    # extension member itself, so every database with one is refused.
    "setup-counts-types-and-indexes": lambda mp: _setup_foreign_variant(mp, _SETUP_RELKIND_SKIP, ""),
    # Only an extension's relations count as another role's: its functions still pass.
    "setup-refuses-extension-relations": lambda mp: _setup_foreign_variant(mp, _setup_extension_exemption("r"), ""),
    "setup-refuses-owners-triggers": _setup_refuses_owners_triggers,
    # The startup check's path without pg_temp, which is then searched first: a temporary
    # pg_roles or schema_info stands in for the real one.
    "verify-temp-searched-first": lambda mp: mp.setattr(schema, "_CHECK_SEARCH_PATH", "pg_catalog, public"),
    # The same in setup's pin: a temporary audit_events in the owner's session gets the
    # triggers and the rights instead of public's.
    "setup-temp-searched-first": lambda mp: _sql_variant(mp, "_SQL_SETUP_PIN", "'public, pg_temp'", "'public'", module=schema),
}
