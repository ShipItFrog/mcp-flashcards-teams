"""The tables, for both databases.

SQLite: the store creates them itself when it opens the file.

Postgres: the server never creates tables. ``setup_database`` does, run once by the
database's owner role; it also grants the app role (the role the server connects as)
only the rights the server needs. The app role owns nothing, so it can't change what
it was granted. Setup refuses, changing nothing, a database where another role's objects
in public, triggers it didn't make, or every role's CREATE could turn the owner's rights
against it.

There are no foreign keys: teams are never deleted, and the audit records must never
be removed along with anything else. Every write locks its team's row first instead.
"""

from __future__ import annotations

from typing import Any

from . import limits

# No (team_id, topic_key) index on cards: churning cards with ever new topics leaves
# half-empty pages in it that VACUUM can't reclaim.
#
# audit_events is append-only: its triggers refuse every UPDATE and DELETE (RAISE(ABORT)
# surfaces as sqlite3.IntegrityError), and a DELETE without WHERE fires them too, since a
# table with triggers skips the truncate optimization. The third trigger refuses a row
# whose key is taken: a REPLACE conflict deletes the old row without firing the delete
# trigger unless recursive_triggers is on.
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
    writes_day    TEXT    NOT NULL DEFAULT '',
    writes_today  INTEGER NOT NULL DEFAULT 0,
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
CREATE TABLE IF NOT EXISTS audit_events (
    team_id   TEXT    NOT NULL,
    seq       INTEGER NOT NULL,
    at        TEXT    NOT NULL,
    member_no INTEGER NOT NULL,
    client_id TEXT    NOT NULL CHECK (length(client_id) <= 64),
    action    TEXT    NOT NULL CHECK (action IN ('team.create', 'card.add', 'card.grade', 'card.delete',
                                                 'invite.create', 'member.join', 'member.role', 'member.remove',
                                                 'member.leave', 'audit.read')),
    target    TEXT    NOT NULL CHECK (length(target) <= 40),
    result    TEXT    NOT NULL CHECK (result IN ('ok', 'denied', 'failed')),
    reason    TEXT    NOT NULL CHECK (reason IN ('', 'role', 'no_card', 'deck_full', 'no_member', 'last_owner',
                                                 'personal_team', 'already_member', 'daily_limit',
                                                 'invites_used_up')),
    old_role  TEXT    CHECK (old_role IN ('owner', 'editor', 'viewer')),
    new_role  TEXT    CHECK (new_role IN ('owner', 'editor', 'viewer')),
    CHECK ((result = 'ok') = (reason = '')),
    PRIMARY KEY (team_id, seq)
);
CREATE TRIGGER IF NOT EXISTS audit_events_no_update BEFORE UPDATE ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_events_no_delete BEFORE DELETE ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_events_no_replace BEFORE INSERT ON audit_events
WHEN EXISTS (SELECT 1 FROM audit_events WHERE team_id = NEW.team_id AND seq = NEW.seq)
BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;
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
    writes_day    TEXT    COLLATE "C" NOT NULL DEFAULT '',
    writes_today  INTEGER NOT NULL DEFAULT 0,
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
"""

PG_AUDIT = """
CREATE TABLE IF NOT EXISTS audit_events (
    team_id   TEXT   NOT NULL,
    seq       BIGINT NOT NULL,
    at        TEXT   COLLATE "C" NOT NULL,
    member_no BIGINT NOT NULL,
    client_id TEXT   NOT NULL CHECK (length(client_id) <= 64),
    action    TEXT   NOT NULL CHECK (action IN ('team.create', 'card.add', 'card.grade', 'card.delete',
                                                'invite.create', 'member.join', 'member.role', 'member.remove',
                                                'member.leave', 'audit.read')),
    target    TEXT   NOT NULL CHECK (length(target) <= 40),
    result    TEXT   NOT NULL CHECK (result IN ('ok', 'denied', 'failed')),
    reason    TEXT   NOT NULL CHECK (reason IN ('', 'role', 'no_card', 'deck_full', 'no_member', 'last_owner',
                                                'personal_team', 'already_member', 'daily_limit',
                                                'invites_used_up')),
    old_role  TEXT   CHECK (old_role IN ('owner', 'editor', 'viewer')),
    new_role  TEXT   CHECK (new_role IN ('owner', 'editor', 'viewer')),
    CHECK ((result = 'ok') = (reason = '')),
    PRIMARY KEY (team_id, seq)
);
CREATE OR REPLACE FUNCTION audit_events_refuse_change() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only (% refused)', TG_OP;
END $$;
CREATE OR REPLACE TRIGGER audit_events_no_update_delete
    BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH STATEMENT EXECUTE FUNCTION audit_events_refuse_change();
CREATE OR REPLACE TRIGGER audit_events_no_truncate
    BEFORE TRUNCATE ON audit_events
    FOR EACH STATEMENT EXECUTE FUNCTION audit_events_refuse_change();
ALTER TABLE audit_events ENABLE ALWAYS TRIGGER audit_events_no_update_delete;
ALTER TABLE audit_events ENABLE ALWAYS TRIGGER audit_events_no_truncate;
"""
# Append-only for every role, the table's owner and superusers included, and in every
# session: a trigger enabled the default way doesn't fire where session_replication_role
# is replica (which a superuser, or a role granted SET on that setting, may choose), one
# enabled ALWAYS does. CREATE OR REPLACE TRIGGER enables a trigger the default way again,
# so the ALTERs run on every setup. This holds until someone who owns the table, its
# schema, the database or the trigger function, or a superuser, drops or changes the
# triggers or the function; the startup check then reports the tables as not set up.
# Statement-level triggers fire even when no row is affected; TRUNCATE fires no DELETE
# trigger, and a TRUNCATE trigger can only be statement-level, so it is a trigger of its
# own. CREATE OR REPLACE TRIGGER needs PostgreSQL 14 or newer.

# The trigger function's body as PG_AUDIT writes it, which pg_proc.prosrc keeps exactly.
_REFUSE_CHANGE_BODY = PG_AUDIT.split("AS $$", 1)[1].split("$$", 1)[0]

# The two triggers exactly as pg_get_triggerdef shows them when PG_AUDIT made them. The
# startup check compares the whole definition, so a trigger of the same name that fires
# per row, on fewer statements, or calls something else counts as missing; so does one
# that isn't enabled ALWAYS, or whose function isn't the one PG_AUDIT made.
_PG_TRIGGERS = {
    "audit_events_no_update_delete": (
        "CREATE TRIGGER audit_events_no_update_delete BEFORE DELETE OR UPDATE ON public.audit_events"
        " FOR EACH STATEMENT EXECUTE FUNCTION audit_events_refuse_change()"
    ),
    "audit_events_no_truncate": (
        "CREATE TRIGGER audit_events_no_truncate BEFORE TRUNCATE ON public.audit_events"
        " FOR EACH STATEMENT EXECUTE FUNCTION audit_events_refuse_change()"
    ),
}

# The app role's rights, and nothing more. REVOKE ALL also takes back column-level
# grants, so running this again resets the rights to exactly this list. No UPDATE,
# DELETE, TRUNCATE, TRIGGER or REFERENCES on audit_events. CREATE on schema public or on
# the database ({database}: the current one), which the startup check refuses the app
# role, is taken back too, so running setup again undoes that mistake as well.
_PG_GRANTS = (
    "REVOKE ALL ON schema_info, teams, members, invites, cards, audit_events FROM PUBLIC",
    "REVOKE ALL ON schema_info, teams, members, invites, cards, audit_events FROM {app}",
    "REVOKE CREATE ON SCHEMA public FROM PUBLIC",
    "REVOKE CREATE ON SCHEMA public FROM {app}",
    "REVOKE CREATE ON DATABASE {database} FROM {app}",
    "GRANT USAGE ON SCHEMA public TO {app}",
    "GRANT SELECT ON schema_info TO {app}",
    "GRANT SELECT, INSERT ON teams TO {app}",
    "GRANT UPDATE (next_card_no, next_member_no, next_invite_no, next_audit_seq, audit_writes, audit_reads) ON teams TO {app}",
    "GRANT SELECT, INSERT, DELETE ON members TO {app}",
    "GRANT UPDATE (role, refused_count, writes_day, writes_today) ON members TO {app}",
    "GRANT SELECT, INSERT ON invites TO {app}",
    "GRANT UPDATE (used_at, used_by) ON invites TO {app}",
    "GRANT SELECT, INSERT, DELETE ON cards TO {app}",
    "GRANT UPDATE (last_reviewed, review_count, correct_count, wrong_count) ON cards TO {app}",
    "GRANT SELECT, INSERT ON audit_events TO {app}",
)
# Any fixed number: two setups started at once take turns.
_SETUP_LOCK_ID = 20261024

# Setup's own statements, run with the owner's rights (see setup_database), in the order
# it runs them. Every call names pg_catalog and matches its argument types exactly; the
# operators are oid = oid, oid <> oid, name = name, name <> name, name !~ text,
# "char" = "char" and "char" <> "char", which pg_catalog has exact matches for.
_SQL_SETUP_PATH = "SELECT pg_catalog.current_setting('search_path')"
# pg_temp last, as in store.PG_SEARCH_PATH: unlisted, a session's temporary schema is
# searched first for table names.
_SQL_SETUP_PIN = "SELECT pg_catalog.set_config('search_path', 'public, pg_temp', true)"
_SQL_SETUP_LOCK = "SELECT pg_catalog.pg_advisory_xact_lock(%s::bigint)"
# Whether schema public holds what setup must not run into with the owner's rights:
# - a table (or any other relation) or a function that the role running setup doesn't
#   own, unless it belongs to an extension (pg_depend's 'e'), as what a trusted extension
#   installs in public on Neon belongs to the bootstrap superuser: an extension's objects
#   come from its files on the database server, not from another role, and installing one
#   takes CREATE on the database, which the startup check refuses the app role.
#   CREATE TABLE IF NOT EXISTS would leave another role's table as it is, and setup's
#   INSERT into schema_info would fire its triggers with the owner's rights. A composite
#   type ('c') holds no rows and takes no trigger or rule, and an extension records its
#   membership on the type's pg_type row, not on its pg_class row (tablefunc, which Neon
#   offers as trusted, dblink, pldbgapi and PostGIS have such types, so they would make
#   every database with them look foreign). An index ('i', 'I') always has its table's
#   owner, and the table is checked itself (an extension table's primary key index, such
#   as PostGIS's spatial_ref_sys_pkey, is not an extension member);
# - a trigger on any table but audit_events whose function the role running setup
#   doesn't own and no extension owns either: another role's function may live anywhere,
#   even in the temporary schema of a session that role keeps open, and adding a trigger
#   takes only the TRIGGER right on the table. Setup fires triggers only by its INSERT
#   into schema_info, and a trigger that calls the owner's own function runs the owner's
#   own code, so the owner's triggers on its other tables (in a database it shares with
#   something else) don't stop setup. Setup replaces audit_events' two triggers itself and
#   changes no rows there.
_SQL_SETUP_FOREIGN = (
    "SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_class r WHERE r.relnamespace = n.oid AND r.relowner <> u.oid"
    " AND r.relkind NOT IN ('c', 'i', 'I')"
    " AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend e JOIN pg_catalog.pg_extension x"
    " ON x.tableoid = e.refclassid AND x.oid = e.refobjid WHERE e.classid = r.tableoid AND e.objid = r.oid"
    " AND e.deptype = 'e'))"
    " OR EXISTS (SELECT 1 FROM pg_catalog.pg_proc f WHERE f.pronamespace = n.oid AND f.proowner <> u.oid"
    " AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend e JOIN pg_catalog.pg_extension x"
    " ON x.tableoid = e.refclassid AND x.oid = e.refobjid WHERE e.classid = f.tableoid AND e.objid = f.oid"
    " AND e.deptype = 'e'))"
    " OR EXISTS (SELECT 1 FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_class c ON c.oid = t.tgrelid"
    " JOIN pg_catalog.pg_proc p ON p.oid = t.tgfoid"
    " WHERE c.relnamespace = n.oid AND NOT t.tgisinternal AND c.relname <> 'audit_events' AND p.proowner <> u.oid"
    " AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend e JOIN pg_catalog.pg_extension x"
    " ON x.tableoid = e.refclassid AND x.oid = e.refobjid WHERE e.classid = p.tableoid AND e.objid = p.oid"
    " AND e.deptype = 'e'))"
    " FROM pg_catalog.pg_namespace n JOIN pg_catalog.pg_roles u ON u.rolname = current_user"
    " WHERE n.nspname = 'public'"
)
_SQL_SETUP_NEW = "SELECT pg_catalog.to_regclass('public.teams') IS NULL"
# Then PG_TABLES, which only creates. The check above is a statement of its own, so
# another role may since have put a table in public, or a trigger on one of setup's
# tables. Locked in this mode, which conflicts with CREATE TRIGGER, ALTER and DROP, the
# tables can't be added to or swapped until setup commits, and the same check run again
# sees what the INSERT will fire. On a table another role owns, the LOCK fails, or the
# check refuses it.
_SQL_SETUP_LOCK_TABLES = "LOCK TABLE schema_info, teams, members, invites, cards IN SHARE ROW EXCLUSIVE MODE"
_SQL_SETUP_RECHECK = _SQL_SETUP_FOREIGN
_SQL_SETUP_VERSION = "INSERT INTO schema_info (version) SELECT 1 WHERE NOT EXISTS (SELECT 1 FROM schema_info)"
# Then PG_AUDIT, and the grants on the current database.
_SQL_SETUP_DATABASE = "SELECT pg_catalog.current_database()"
# Whether PUBLIC may still create in the database or in any schema that isn't temporary
# (see _SQL_APP_ROLE). The grants' REVOKE CREATE ON SCHEMA public FROM PUBLIC only warns
# when the role running setup doesn't own public, as on a database made by Postgres 14.
_SQL_SETUP_PUBLIC_CREATE = (
    "SELECT pg_catalog.has_database_privilege('public', d.oid, 'CREATE')"
    " OR EXISTS (SELECT 1 FROM pg_catalog.pg_namespace s WHERE s.nspname !~ '^pg_(temp|toast_temp)_'::text"
    " AND pg_catalog.has_schema_privilege('public', s.oid, 'CREATE'))"
    " FROM pg_catalog.pg_database d WHERE d.datname = pg_catalog.current_database()"
)
_SQL_SETUP_RESTORE = "SELECT pg_catalog.set_config('search_path', %s, true)"

SETUP_FOREIGN_OBJECTS = (
    "Schema public holds tables or functions another role owns, or triggers that call another role's functions, "
    "so setup won't touch it: remove them or run setup as their owner (see README)."
)
SETUP_PUBLIC_MAY_CREATE = (
    "Every role may still create objects in this database (CREATE granted to PUBLIC). Only the owner of that "
    "schema or database, or a superuser, can take it back: have them run REVOKE CREATE ON SCHEMA public FROM "
    "PUBLIC (and the same for any other schema or the database) and GRANT CREATE ON SCHEMA public to the role "
    "that runs setup, then run setup again (see README)."
)


class SetupRefusedError(Exception):
    """setup_database found the database unsafe to set up and changed nothing. The
    message is one of the fixed ones above: it names no URL, host or role."""


def pg_grants(app_role: str, database: str) -> list[Any]:
    """The grant statements for ``app_role`` in ``database``, both names quoted as identifiers."""
    from psycopg import sql

    return [
        sql.SQL(statement).format(app=sql.Identifier(app_role), database=sql.Identifier(database))
        for statement in _PG_GRANTS
    ]


def setup_database(conn: Any, app_role: str) -> bool:
    """Create any missing tables and reset the app role's rights; True if the database
    had no tables yet. Run as the tables' owner. All of it is one transaction (a
    savepoint when ``conn`` is already in one), so a failure leaves nothing half done.

    Raises SetupRefusedError, having changed nothing, when schema public holds tables or
    functions another role owns, or triggers that call another role's functions
    (SETUP_FOREIGN_OBJECTS), or when PUBLIC may still create in the database afterwards
    (SETUP_PUBLIC_MAY_CREATE)."""
    from psycopg.rows import tuple_row

    with conn.transaction():
        cur = conn.cursor(row_factory=tuple_row)
        # The caller's path, put back at the end: set_config(..., true) lasts until the
        # end of the whole transaction, not of the savepoint this runs in when the caller
        # is already in one.
        path = cur.execute(_SQL_SETUP_PATH).fetchone()[0]
        # Everything here runs with the owner's rights, so no name may resolve to an object
        # another role made. The path is pinned to public, then pg_temp: Postgres' default
        # starts with "$user", a schema named after the owner. pg_catalog is searched first
        # anyway, but a function in public with a closer argument type still wins: psycopg
        # sends the lock id as integer, and public.pg_advisory_xact_lock(integer) would beat
        # pg_catalog's (bigint). So the calls here name pg_catalog and match its argument
        # types exactly. PG_TABLES, PG_AUDIT and the grants call nothing pg_catalog lacks an
        # exact match for (length(text), and operators such as bigint >= integer).
        cur.execute(_SQL_SETUP_PIN)
        cur.execute(_SQL_SETUP_LOCK, (_SETUP_LOCK_ID,))
        if cur.execute(_SQL_SETUP_FOREIGN).fetchone() == (True,):
            raise SetupRefusedError(SETUP_FOREIGN_OBJECTS)
        new = cur.execute(_SQL_SETUP_NEW).fetchone()[0]
        conn.execute(PG_TABLES)
        # Nothing can be added to or swapped under the tables from here until commit; the
        # check again sees anything put there since the first one.
        cur.execute(_SQL_SETUP_LOCK_TABLES)
        if cur.execute(_SQL_SETUP_RECHECK).fetchone() == (True,):
            raise SetupRefusedError(SETUP_FOREIGN_OBJECTS)
        conn.execute(_SQL_SETUP_VERSION)
        conn.execute(PG_AUDIT)
        database = cur.execute(_SQL_SETUP_DATABASE).fetchone()[0]
        for statement in pg_grants(app_role, database):
            conn.execute(statement)
        if cur.execute(_SQL_SETUP_PUBLIC_CREATE).fetchone()[0]:
            raise SetupRefusedError(SETUP_PUBLIC_MAY_CREATE)
        cur.execute(_SQL_SETUP_RESTORE, (path,))
    return new


NOT_READY = (
    "The database isn't set up for this server yet. Run python -m flashcards_teams.setup_db as the database "
    "owner first (see README)."
)
TOO_POWERFUL = (
    "The database role this server connects as is too powerful: it can change or remove audit records. "
    "Connect as the app role created for this server (see README)."
)
PUBLIC_MAY_CREATE = (
    "The database lets every role create objects in it (CREATE granted to PUBLIC), which this server refuses. "
    "Have the owner of that schema or database, or a superuser, revoke it and, on a database set up like "
    "Postgres 14's, also grant CREATE on schema public to the role that runs setup (see README)."
)

# The startup check's path. The trigger definitions name the function unqualified only
# while it is on the path. pg_temp last (see store.PG_SEARCH_PATH): unlisted, it is
# searched first, even before pg_catalog, so a temporary table named like schema_info or
# a catalog (pg_roles), left in a pooled backend, would stand in for it here.
_CHECK_SEARCH_PATH = "pg_catalog, public, pg_temp"
_SQL_READY = (
    "SELECT to_regclass('public.schema_info') IS NOT NULL AND to_regclass('public.audit_events') IS NOT NULL AS ready"
)
# First, whether PUBLIC, every role, may create in the database or in any schema that
# isn't temporary (public_may_create). Postgres 14 makes schema public that way, owned by
# the bootstrap superuser, and a database upgraded from it keeps it: only that schema's
# owner or a superuser can take it back, so connecting as another role can't help, and
# the message says so.
#
# Then what every role this session can act as could do to the audit records: g is the
# role it logged in as (session_user) and the role it is now (current_user), and every
# role either belongs to, directly or through others, whether it inherits that role's
# rights or must SET ROLE to use them (pg_has_role's 'MEMBER'; has_table_privilege on
# current_user alone would count only the inherited rights). The login role counts: one
# whose default is to become the app role (ALTER ROLE ... SET role, or options=-c role=)
# may RESET ROLE and SET ROLE to any role it belongs to. None of them may:
# - be a superuser, have CREATEROLE or BYPASSRLS, or be Neon's neon_superuser, or one of
#   pg_read_server_files, pg_write_server_files and pg_execute_server_program, which
#   Postgres' documentation says can be used to gain superuser-level access (COPY ... TO
#   PROGRAM runs any command as the server's operating system user). A superuser has
#   every right, so can_rewrite and can_create count it too: rolsuper stays as plain
#   insurance;
# - own the database, any schema of it (a schema's owner may grant itself CREATE there
#   again), or any table or function in audit_events' schema (an owner may drop or change
#   it): that takes in audit_events itself and the triggers' function, which the trigger
#   check proves is the one in public;
# - be able to call a SECURITY DEFINER function in audit_events' schema that none of them
#   owns (definer): it runs with its owner's rights. Setup leaves none there
#   (audit_events_refuse_change is SECURITY INVOKER). An extension's own functions don't
#   count (see _SQL_SETUP_FOREIGN): its SECURITY DEFINER ones are its designed interface;
# - have CREATE on the database or on any of its schemas that isn't temporary: either
#   lets the role put objects where a session, the owner's running setup included, may
#   resolve names (has_database_privilege and has_schema_privilege count PUBLIC's grants
#   too). A temporary schema is searched only by its own session, and a session that has
#   made a temporary table reports CREATE on its own (through a transaction-mode pooler,
#   another client's session may have);
# - have UPDATE on any column of audit_events (has_any_column_privilege), DELETE,
#   TRUNCATE or TRIGGER.
# The direction matters: since PostgreSQL 16 a role's creator becomes a member of the new
# role, which gives the new role nothing. The patterns are cast to text so that the
# operator is pg_catalog's name !~ text, an exact match nothing in public can beat.
_SQL_APP_ROLE = (
    "WITH g AS (SELECT oid, rolname, rolsuper, rolcreaterole, rolbypassrls FROM pg_roles"
    " WHERE pg_has_role(session_user, oid, 'MEMBER') OR pg_has_role(current_user, oid, 'MEMBER'))"
    " SELECT (SELECT version FROM schema_info LIMIT 1) AS version,"
    " has_database_privilege('public', d.oid, 'CREATE') OR EXISTS (SELECT 1 FROM pg_namespace p"
    " WHERE p.nspname !~ '^pg_(temp|toast_temp)_'::text AND has_schema_privilege('public', p.oid, 'CREATE'))"
    " AS public_may_create,"
    " EXISTS (SELECT 1 FROM g WHERE (g.rolsuper OR g.rolcreaterole OR g.rolbypassrls OR g.rolname = 'neon_superuser')"
    " OR g.rolname IN ('pg_read_server_files', 'pg_write_server_files', 'pg_execute_server_program')) AS powerful,"
    " EXISTS (SELECT 1 FROM g WHERE g.oid = d.datdba OR g.oid IN (SELECT nspowner FROM pg_namespace)"
    " OR g.oid IN (SELECT r.relowner FROM pg_class r WHERE r.relnamespace = n.oid)"
    " OR g.oid IN (SELECT f.proowner FROM pg_proc f WHERE f.pronamespace = n.oid)) AS owns,"
    " EXISTS (SELECT 1 FROM pg_proc x WHERE x.pronamespace = n.oid AND x.prosecdef"
    " AND x.proowner NOT IN (SELECT oid FROM g)"
    " AND NOT EXISTS (SELECT 1 FROM pg_depend e JOIN pg_extension m ON m.tableoid = e.refclassid"
    " AND m.oid = e.refobjid WHERE e.classid = x.tableoid AND e.objid = x.oid AND e.deptype = 'e')"
    " AND EXISTS (SELECT 1 FROM g WHERE has_function_privilege(g.oid, x.oid, 'EXECUTE'))) AS definer,"
    " EXISTS (SELECT 1 FROM g WHERE has_database_privilege(g.oid, d.oid, 'CREATE')"
    " OR EXISTS (SELECT 1 FROM pg_namespace s WHERE s.nspname !~ '^pg_(temp|toast_temp)_'::text"
    " AND has_schema_privilege(g.oid, s.oid, 'CREATE'))) AS can_create,"
    " EXISTS (SELECT 1 FROM g WHERE (has_any_column_privilege(g.oid, c.oid, 'UPDATE')"
    " OR has_table_privilege(g.oid, c.oid, 'DELETE') OR has_table_privilege(g.oid, c.oid, 'TRUNCATE')"
    " OR has_table_privilege(g.oid, c.oid, 'TRIGGER'))) AS can_rewrite"
    " FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace"
    " JOIN pg_database d ON d.datname = current_database()"
    " WHERE c.oid = 'public.audit_events'::regclass"
)
# Every trigger on audit_events: its definition, whether it is enabled ALWAYS (disabled
# ones are 'D', and fail that too), and whether its function is exactly the one PG_AUDIT
# made (the parameter is _REFUSE_CHANGE_BODY): the same body, language and search_path
# setting, and not SECURITY DEFINER.
_SQL_TRIGGERS = (
    "SELECT t.tgname, pg_get_triggerdef(t.oid), t.tgenabled = 'A',"
    " p.prosrc = %s AND l.lanname = 'plpgsql' AND p.proconfig = ARRAY['search_path=pg_catalog'] AND NOT p.prosecdef"
    " FROM pg_trigger t JOIN pg_proc p ON p.oid = t.tgfoid JOIN pg_language l ON l.oid = p.prolang"
    " WHERE t.tgrelid = 'public.audit_events'::regclass AND NOT t.tgisinternal"
)
# What setup never puts on audit_events, each true when found: a trigger other than the
# two in _PG_TRIGGERS (the parameter is their names; a BEFORE INSERT trigger could rewrite
# or drop the records), a rule (ON INSERT DO INSTEAD NOTHING drops them), row security,
# and a parent or child table, partitions included: a DELETE on a parent reaches its
# children's rows yet fires only the parent's statement triggers and checks only the
# rights on the parent.
_SQL_AUDIT_EXTRAS = (
    "SELECT EXISTS (SELECT 1 FROM pg_trigger t WHERE t.tgrelid = c.oid AND NOT t.tgisinternal"
    " AND t.tgname::text <> ALL (%s::text[])) AS other_triggers,"
    " EXISTS (SELECT 1 FROM pg_rewrite r WHERE r.ev_class = c.oid) AS rules,"
    " c.relrowsecurity AS row_security,"
    " (EXISTS (SELECT 1 FROM pg_inherits i WHERE i.inhrelid = c.oid OR i.inhparent = c.oid) OR c.relispartition)"
    " AS inheritance"
    " FROM pg_class c WHERE c.oid = 'public.audit_events'::regclass"
)


def verify_app_role(conn: Any) -> None:
    """Check, as the server starts, that the tables are exactly as setup_database leaves
    them (the schema version; both triggers as PG_AUDIT makes them, enabled ALWAYS and
    calling its function; no other trigger, no rule, no row security and no parent or
    child table on audit_events); that PUBLIC may create nothing in the database; and that
    no role the session can act as (the role it logged in as, the role it is now, and
    every role either belongs to) could change or remove audit records, the triggers that
    stop that, or what the owner's setup runs (see _SQL_APP_ROLE). Raises
    SchemaNotReadyError, or AppRoleTooPowerfulError with PUBLIC_MAY_CREATE or
    TOO_POWERFUL, in that order; the messages name no URL, host or role. Reads only."""
    from psycopg import errors
    from psycopg.rows import tuple_row

    from .store import AppRoleTooPowerfulError, SchemaNotReadyError

    with conn.transaction():
        cur = conn.cursor(row_factory=tuple_row)
        cur.execute("SELECT pg_catalog.set_config('search_path', %s, true)", (_CHECK_SEARCH_PATH,))
        try:
            if not cur.execute(_SQL_READY).fetchone()[0]:
                raise SchemaNotReadyError(NOT_READY)
            version, public_may_create, *powers = cur.execute(_SQL_APP_ROLE).fetchone()
        except errors.InsufficientPrivilege:  # no USAGE on schema public, or no SELECT on schema_info
            raise SchemaNotReadyError(NOT_READY) from None
        triggers = sum(
            _PG_TRIGGERS.get(name) == definition and always is True and ours is True
            for name, definition, always, ours in cur.execute(_SQL_TRIGGERS, (_REFUSE_CHANGE_BODY,))
        )
        extras = cur.execute(_SQL_AUDIT_EXTRAS, (list(_PG_TRIGGERS),)).fetchone()
    if version != limits.SCHEMA_VERSION or triggers != len(_PG_TRIGGERS) or any(extras):
        raise SchemaNotReadyError(NOT_READY)
    if public_may_create:
        raise AppRoleTooPowerfulError(PUBLIC_MAY_CREATE)
    if any(powers):
        raise AppRoleTooPowerfulError(TOO_POWERFUL)
