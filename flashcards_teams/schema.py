"""The tables, for both databases.

SQLite: the store creates them itself when it opens the file.

Postgres: the server never creates tables. ``setup_database`` does, run once by the
database's owner role; it also grants the app role (the role the server connects as)
only the rights the server needs. The app role owns nothing, so it can't change what
it was granted.

There are no foreign keys: teams are never deleted, and the audit records must never
be removed along with anything else. Every write locks its team's row first instead.
"""

from __future__ import annotations

from typing import Any

SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS teams (
    team_id        TEXT    PRIMARY KEY,
    name           TEXT    NOT NULL,
    personal_of    TEXT    UNIQUE,
    created_at     TEXT    NOT NULL,
    next_card_no   INTEGER NOT NULL DEFAULT 1,
    next_member_no INTEGER NOT NULL DEFAULT 1,
    next_invite_no INTEGER NOT NULL DEFAULT 1,
    next_audit_seq INTEGER NOT NULL DEFAULT 1 CHECK (next_audit_seq >= 1),
    audit_writes   INTEGER NOT NULL DEFAULT 0 CHECK (audit_writes >= 0),
    audit_reads    INTEGER NOT NULL DEFAULT 0 CHECK (audit_reads >= 0)
);
CREATE TABLE IF NOT EXISTS members (
    team_id       TEXT    NOT NULL,
    member_no     INTEGER NOT NULL,
    principal     TEXT    NOT NULL,
    role          TEXT    NOT NULL CHECK (role IN ('owner', 'editor', 'viewer')),
    joined_at     TEXT    NOT NULL,
    via_invite_no INTEGER,
    refused_count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (team_id, member_no),
    UNIQUE (team_id, principal)
);
CREATE INDEX IF NOT EXISTS members_principal ON members (principal);
CREATE TABLE IF NOT EXISTS invites (
    team_id    TEXT    NOT NULL,
    invite_no  INTEGER NOT NULL,
    code_hash  TEXT    NOT NULL UNIQUE CHECK (length(code_hash) = 64),
    role       TEXT    NOT NULL CHECK (role IN ('editor', 'viewer')),
    created_by INTEGER NOT NULL,
    created_at TEXT    NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at    TEXT,
    used_by    INTEGER,
    CHECK ((used_at IS NULL) = (used_by IS NULL)),
    PRIMARY KEY (team_id, invite_no)
);
CREATE TABLE IF NOT EXISTS cards (
    team_id       TEXT    NOT NULL,
    card_no       INTEGER NOT NULL,
    question      TEXT    NOT NULL,
    answer        TEXT    NOT NULL,
    topic         TEXT    NOT NULL,
    topic_key     TEXT    NOT NULL,
    created_at    TEXT    NOT NULL,
    last_reviewed TEXT,
    review_count  INTEGER NOT NULL DEFAULT 0,
    correct_count INTEGER NOT NULL DEFAULT 0,
    wrong_count   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (team_id, card_no)
);
CREATE INDEX IF NOT EXISTS cards_team_topic ON cards (team_id, topic_key);
CREATE TABLE IF NOT EXISTS audit_events (
    team_id   TEXT    NOT NULL,
    seq       INTEGER NOT NULL,
    at        TEXT    NOT NULL,
    member_no INTEGER NOT NULL,
    client_id TEXT    NOT NULL CHECK (length(client_id) <= 200),
    action    TEXT    NOT NULL CHECK (action IN ('team.create', 'card.add', 'card.grade', 'card.delete',
                                                 'invite.create', 'member.join', 'member.role', 'member.remove',
                                                 'member.leave', 'audit.read')),
    target    TEXT    NOT NULL CHECK (length(target) <= 40),
    result    TEXT    NOT NULL CHECK (result IN ('ok', 'denied', 'failed')),
    reason    TEXT    NOT NULL CHECK (reason IN ('', 'role', 'no_card', 'deck_full', 'no_member', 'last_owner',
                                                 'personal_team', 'already_member')),
    old_role  TEXT    CHECK (old_role IN ('owner', 'editor', 'viewer')),
    new_role  TEXT    CHECK (new_role IN ('owner', 'editor', 'viewer')),
    CHECK ((result = 'ok') = (reason = '')),
    PRIMARY KEY (team_id, seq)
);
"""

# Times are ISO 8601 strings, as in SQLite; the "C" collation sorts them byte by byte
# whatever the database's locale, so the review order matches SQLite's.
PG_TABLES = """
CREATE TABLE IF NOT EXISTS schema_info (version INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS teams (
    team_id        TEXT   PRIMARY KEY,
    name           TEXT   NOT NULL,
    personal_of    TEXT   UNIQUE,
    created_at     TEXT   COLLATE "C" NOT NULL,
    next_card_no   BIGINT NOT NULL DEFAULT 1,
    next_member_no BIGINT NOT NULL DEFAULT 1,
    next_invite_no BIGINT NOT NULL DEFAULT 1,
    next_audit_seq BIGINT NOT NULL DEFAULT 1 CHECK (next_audit_seq >= 1),
    audit_writes   BIGINT NOT NULL DEFAULT 0 CHECK (audit_writes >= 0),
    audit_reads    BIGINT NOT NULL DEFAULT 0 CHECK (audit_reads >= 0)
);
CREATE TABLE IF NOT EXISTS members (
    team_id       TEXT    NOT NULL,
    member_no     BIGINT  NOT NULL,
    principal     TEXT    NOT NULL,
    role          TEXT    NOT NULL CHECK (role IN ('owner', 'editor', 'viewer')),
    joined_at     TEXT    COLLATE "C" NOT NULL,
    via_invite_no BIGINT,
    refused_count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (team_id, member_no),
    UNIQUE (team_id, principal)
);
CREATE INDEX IF NOT EXISTS members_principal ON members (principal);
CREATE TABLE IF NOT EXISTS invites (
    team_id    TEXT   NOT NULL,
    invite_no  BIGINT NOT NULL,
    code_hash  TEXT   NOT NULL UNIQUE CHECK (length(code_hash) = 64),
    role       TEXT   NOT NULL CHECK (role IN ('editor', 'viewer')),
    created_by BIGINT NOT NULL,
    created_at TEXT   COLLATE "C" NOT NULL,
    expires_at BIGINT NOT NULL,
    used_at    TEXT   COLLATE "C",
    used_by    BIGINT,
    CHECK ((used_at IS NULL) = (used_by IS NULL)),
    PRIMARY KEY (team_id, invite_no)
);
CREATE TABLE IF NOT EXISTS cards (
    team_id       TEXT    NOT NULL,
    card_no       BIGINT  NOT NULL,
    question      TEXT    NOT NULL,
    answer        TEXT    NOT NULL,
    topic         TEXT    NOT NULL,
    topic_key     TEXT    NOT NULL,
    created_at    TEXT    COLLATE "C" NOT NULL,
    last_reviewed TEXT    COLLATE "C",
    review_count  INTEGER NOT NULL DEFAULT 0,
    correct_count INTEGER NOT NULL DEFAULT 0,
    wrong_count   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (team_id, card_no)
);
CREATE INDEX IF NOT EXISTS cards_team_topic ON cards (team_id, topic_key);
INSERT INTO schema_info (version) SELECT 1 WHERE NOT EXISTS (SELECT 1 FROM schema_info);
"""

PG_AUDIT = """
CREATE TABLE IF NOT EXISTS audit_events (
    team_id   TEXT   NOT NULL,
    seq       BIGINT NOT NULL,
    at        TEXT   COLLATE "C" NOT NULL,
    member_no BIGINT NOT NULL,
    client_id TEXT   NOT NULL CHECK (length(client_id) <= 200),
    action    TEXT   NOT NULL CHECK (action IN ('team.create', 'card.add', 'card.grade', 'card.delete',
                                                'invite.create', 'member.join', 'member.role', 'member.remove',
                                                'member.leave', 'audit.read')),
    target    TEXT   NOT NULL CHECK (length(target) <= 40),
    result    TEXT   NOT NULL CHECK (result IN ('ok', 'denied', 'failed')),
    reason    TEXT   NOT NULL CHECK (reason IN ('', 'role', 'no_card', 'deck_full', 'no_member', 'last_owner',
                                                'personal_team', 'already_member')),
    old_role  TEXT   CHECK (old_role IN ('owner', 'editor', 'viewer')),
    new_role  TEXT   CHECK (new_role IN ('owner', 'editor', 'viewer')),
    CHECK ((result = 'ok') = (reason = '')),
    PRIMARY KEY (team_id, seq)
);
"""

# The app role's rights, and nothing more. REVOKE ALL also takes back column-level
# grants, so running this again resets the rights to exactly this list. No UPDATE,
# DELETE, TRUNCATE, TRIGGER or REFERENCES on audit_events.
_PG_GRANTS = (
    "REVOKE ALL ON schema_info, teams, members, invites, cards, audit_events FROM PUBLIC",
    "REVOKE ALL ON schema_info, teams, members, invites, cards, audit_events FROM {app}",
    "REVOKE CREATE ON SCHEMA public FROM PUBLIC",
    "GRANT USAGE ON SCHEMA public TO {app}",
    "GRANT SELECT ON schema_info TO {app}",
    "GRANT SELECT, INSERT ON teams TO {app}",
    "GRANT UPDATE (next_card_no, next_member_no, next_invite_no, next_audit_seq, audit_writes, audit_reads) ON teams TO {app}",
    "GRANT SELECT, INSERT, DELETE ON members TO {app}",
    "GRANT UPDATE (role, refused_count) ON members TO {app}",
    "GRANT SELECT, INSERT ON invites TO {app}",
    "GRANT UPDATE (used_at, used_by) ON invites TO {app}",
    "GRANT SELECT, INSERT, DELETE ON cards TO {app}",
    "GRANT UPDATE (last_reviewed, review_count, correct_count, wrong_count) ON cards TO {app}",
    "GRANT SELECT, INSERT ON audit_events TO {app}",
)
# Any fixed number: two setups started at once take turns.
_SETUP_LOCK_ID = 20261024


def pg_grants(app_role: str) -> list[Any]:
    """The grant statements for ``app_role``, its name quoted as an identifier."""
    from psycopg import sql

    return [sql.SQL(statement).format(app=sql.Identifier(app_role)) for statement in _PG_GRANTS]


def setup_database(conn: Any, app_role: str) -> bool:
    """Create any missing tables and reset the app role's rights; True if the database
    had no tables yet. Run as the tables' owner. All of it is one transaction (a
    savepoint when ``conn`` is already in one), so a failure leaves nothing half done."""
    from psycopg.rows import tuple_row

    with conn.transaction():
        conn.execute("SELECT pg_advisory_xact_lock(%s)", (_SETUP_LOCK_ID,))
        new = conn.cursor(row_factory=tuple_row).execute("SELECT to_regclass('public.teams') IS NULL").fetchone()[0]
        conn.execute(PG_TABLES)
        conn.execute(PG_AUDIT)
        for statement in pg_grants(app_role):
            conn.execute(statement)
    return new
