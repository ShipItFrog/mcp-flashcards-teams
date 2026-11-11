"""Setting up the Postgres database (schema.setup_database, run by the tables' owner) and
the server's startup check (schema.verify_app_role): setup refuses a database where
another role's objects or every role's CREATE could turn its own rights against it, and
the server won't start on tables that aren't set up as setup_database leaves them, where
every role may create objects, nor as a role that could change or remove audit records.

Each test has a database of its own and an app role of its own (conftest.scratch_db):
roles and memberships belong to the whole Postgres server, so a test that grants its
app role more must not grant it to the role the other tests use.
"""

import base64
import hashlib
import hmac
from contextlib import contextmanager

import psycopg
import pytest
from helpers import as_superuser, set_up_as_owner

from flashcards_teams import limits, schema, setup_db
from flashcards_teams.store import AppRoleTooPowerfulError, PostgresCardStore, SchemaNotReadyError

pytestmark = pytest.mark.postgres


def opens(url: str) -> None:
    """Open a store with the startup check on, as the server does, and close it again."""
    PostgresCardStore(url, verify_schema=True).close()


def as_the_owner(db) -> str:
    """A URL that connects to ``db`` as the superuser and becomes ft_owner, the database's
    owner (not a superuser), for setup_db, which takes a URL."""
    return db.admin_url + "?options=-c%20role%3Dft_owner"


def assert_says_nothing_about_where(message: str, db) -> None:
    host, port = db.url.split("@", 1)[1].split("/", 1)[0].split(":")
    for text in (host, port, db.role, db.name, "ft_owner", "postgres@"):
        assert text not in message, text


def test_setup_creates_the_tables_once_and_can_run_again(scratch_db):
    assert set_up_as_owner(scratch_db.admin_url, scratch_db.role) is True
    assert set_up_as_owner(scratch_db.admin_url, scratch_db.role) is False
    opens(scratch_db.url)


def test_a_failed_setup_leaves_nothing_behind(scratch_db):
    # The grants fail (no such role) after the tables were created: all of it is undone.
    with psycopg.connect(scratch_db.admin_url, autocommit=True) as conn:
        conn.execute("SET ROLE ft_owner")
        with pytest.raises(psycopg.errors.UndefinedObject):
            schema.setup_database(conn, "no_such_role_" + scratch_db.role)
        assert conn.execute("SELECT to_regclass('public.teams') IS NULL").fetchone()[0] is True


def test_running_setup_again_takes_back_rights_granted_since(scratch_db):
    set_up_as_owner(scratch_db.admin_url, scratch_db.role)
    as_superuser(scratch_db.admin_url, f"GRANT UPDATE ON audit_events TO {scratch_db.role}")

    def can_update():
        with psycopg.connect(scratch_db.admin_url) as conn:
            return conn.execute(
                "SELECT has_table_privilege(%s, 'public.audit_events', 'UPDATE')", (scratch_db.role,)
            ).fetchone()[0]

    assert can_update() is True
    set_up_as_owner(scratch_db.admin_url, scratch_db.role)
    assert can_update() is False
    opens(scratch_db.url)


# Tables that aren't set up as setup_database leaves them: each one is SchemaNotReadyError.
NOT_READY = {
    "not-set-up": (),
    "wrong-version": ("UPDATE schema_info SET version = 0",),
    "no-truncate-trigger": ("DROP TRIGGER audit_events_no_truncate ON audit_events",),
    "update-delete-trigger-disabled": ("ALTER TABLE audit_events DISABLE TRIGGER audit_events_no_update_delete",),
    # Same name, but per row: an UPDATE or DELETE that matches no row wouldn't fire it.
    # Enabled ALWAYS again, so only the definition differs from what setup leaves.
    "update-delete-trigger-per-row": (
        "CREATE OR REPLACE TRIGGER audit_events_no_update_delete BEFORE UPDATE OR DELETE ON audit_events"
        " FOR EACH ROW EXECUTE FUNCTION audit_events_refuse_change()",
        "ALTER TABLE audit_events ENABLE ALWAYS TRIGGER audit_events_no_update_delete",
    ),
    # Same name, language and setting: only the body differs, and it lets everything through.
    "trigger-function-replaced": (
        "CREATE OR REPLACE FUNCTION audit_events_refuse_change() RETURNS trigger LANGUAGE plpgsql"
        " SET search_path = pg_catalog AS $$ BEGIN RETURN NULL; END $$",
    ),
    # The same body, but its names resolve through whatever path the session has.
    "trigger-function-search-path-reset": ("ALTER FUNCTION audit_events_refuse_change() RESET search_path",),
    # The same body, run with its owner's rights.
    "trigger-function-security-definer": ("ALTER FUNCTION audit_events_refuse_change() SECURITY DEFINER",),
    # Enabled the default way: it doesn't fire where session_replication_role is replica.
    "update-delete-trigger-origin-only": ("ALTER TABLE audit_events ENABLE TRIGGER audit_events_no_update_delete",),
    # A trigger setup never makes: one that fires before each insert could rewrite or drop
    # the records. This one changes nothing, yet the tables aren't as setup left them.
    "extra-trigger": (
        "CREATE FUNCTION audit_events_extra() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$",
        "ALTER FUNCTION audit_events_extra() OWNER TO ft_owner",
        "CREATE TRIGGER audit_events_extra BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION audit_events_extra()",
    ),
    # A rule could turn every insert into nothing (DO INSTEAD NOTHING); any rule counts.
    "a-rule": ("CREATE RULE audit_events_also AS ON INSERT TO audit_events DO ALSO NOTHING",),
    # Without a policy, row security hides the records from the app role and refuses its inserts.
    "row-security": ("ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY",),
    # The app role can't even look the tables up.
    "no-usage-on-public": (
        "REVOKE USAGE ON SCHEMA public FROM PUBLIC",
        "REVOKE USAGE ON SCHEMA public FROM {role}",
    ),
    # The app role can't read the schema version.
    "no-select-on-schema-info": ("REVOKE SELECT ON schema_info FROM {role}",),
    # A DELETE on the parent reaches audit_events' rows, yet fires only the parent's
    # statement triggers and checks only the rights on the parent.
    "child-of-another-table": (
        "CREATE TABLE audit_parent (LIKE audit_events)",
        "ALTER TABLE audit_parent OWNER TO ft_owner",
        "ALTER TABLE audit_events INHERIT audit_parent",
    ),
    "partition-of-another-table": (
        "CREATE TABLE audit_parent (LIKE audit_events) PARTITION BY LIST (action)",
        "ALTER TABLE audit_parent OWNER TO ft_owner",
        "ALTER TABLE audit_parent ATTACH PARTITION audit_events DEFAULT",
    ),
    # A child's rows show up in every read of audit_events, yet its triggers and rights
    # don't cover them.
    "parent-of-another-table": ("SET ROLE ft_owner", "CREATE TABLE audit_child () INHERITS (audit_events)"),
}


@pytest.mark.parametrize("case", NOT_READY)
def test_the_server_wont_start_on_tables_not_set_up(scratch_db, case):
    if case != "not-set-up":
        set_up_as_owner(scratch_db.admin_url, scratch_db.role)
        as_superuser(scratch_db.admin_url, *(s.format(role=scratch_db.role) for s in NOT_READY[case]))
    with pytest.raises(SchemaNotReadyError) as stopped:
        opens(scratch_db.url)
    assert str(stopped.value) == schema.NOT_READY
    assert_says_nothing_about_where(str(stopped.value), scratch_db)


def test_running_setup_again_gives_back_the_use_of_schema_public(scratch_db):
    set_up_as_owner(scratch_db.admin_url, scratch_db.role)
    as_superuser(scratch_db.admin_url, *(s.format(role=scratch_db.role) for s in NOT_READY["no-usage-on-public"]))
    with pytest.raises(SchemaNotReadyError):
        opens(scratch_db.url)
    set_up_as_owner(scratch_db.admin_url, scratch_db.role)
    opens(scratch_db.url)


@contextmanager
def owner_session(db, notices: list[str]):
    """A connection to ``db`` that has become ft_owner, as set_up_as_owner's does, and
    keeps the text of every notice the server sends it: a planted function's RAISE NOTICE
    arrives even when setup then refuses and all it did is rolled back."""
    with psycopg.connect(db.admin_url, autocommit=True) as conn:
        conn.add_notice_handler(lambda diagnostic: notices.append(diagnostic.message_primary))
        conn.execute("SET ROLE ft_owner")
        yield conn


def planted_ran(notices: list[str]) -> list[str]:
    """The notices a planted function or rule sent (setup's own say nothing of the kind)."""
    return [notice for notice in notices if "planted" in notice]


class Interrupted:
    """A connection for setup_database that runs ``action`` once, just before setup runs
    the statement named ``before`` in schema (looked up when setup runs it, so a variant's
    statement counts): another role acting between two of setup's statements, at a moment
    a real one would have to be lucky to hit."""

    def __init__(self, conn, before: str, action):
        self._conn, self._before, self._action = conn, before, action
        self.acted = False

    def at(self, query) -> None:
        if not self.acted and isinstance(query, str) and query == getattr(schema, self._before):
            self.acted = True
            self._action()

    def execute(self, query, params=None):
        self.at(query)
        return self._conn.execute(query, params)

    def cursor(self, *args, **kwargs):
        return _InterruptedCursor(self._conn.cursor(*args, **kwargs), self)

    def __getattr__(self, name):
        return getattr(self._conn, name)


class _InterruptedCursor:
    def __init__(self, cur, conn: Interrupted):
        self._cur, self._conn = cur, conn

    def execute(self, query, params=None):
        self._conn.at(query)
        return self._cur.execute(query, params)

    def __getattr__(self, name):
        return getattr(self._cur, name)


AUDIT_RECORD = (
    "INSERT INTO audit_events (team_id, seq, at, member_no, client_id, action, target, result, reason)"
    " VALUES ('t', 1, '2026-11-07T00:00:00+00:00', 1, 'c', 'team.create', 'team', 'ok', '')"
)


def audit_records(db) -> int:
    with psycopg.connect(db.admin_url) as conn:
        return conn.execute("SELECT count(*) FROM public.audit_events").fetchone()[0]


# A setup run stands in for a function another role planted where the owner's session
# looks for names: public, or a schema named after the owner ("$user", first on Postgres'
# default path). psycopg sends the lock id as integer, so an overload taking integer beats
# pg_catalog's pg_advisory_xact_lock(bigint) wherever it is on the path. This one would
# run with the owner's rights: switch the triggers off, empty audit_events, switch them on.
PLANTED_LOCK = """
CREATE FUNCTION {where}.pg_advisory_xact_lock(integer) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    RAISE NOTICE 'planted pg_advisory_xact_lock ran';
    INSERT INTO planted.ran VALUES ('{where}');
    ALTER TABLE public.audit_events DISABLE TRIGGER USER;
    DELETE FROM public.audit_events;
    ALTER TABLE public.audit_events ENABLE ALWAYS TRIGGER audit_events_no_update_delete;
    ALTER TABLE public.audit_events ENABLE ALWAYS TRIGGER audit_events_no_truncate;
    PERFORM pg_catalog.pg_advisory_xact_lock($1::bigint);
END $$
"""


@pytest.mark.parametrize("where", ["public", "ft_owner"])
def test_setup_runs_nothing_another_role_planted(scratch_db, where):
    set_up_as_owner(scratch_db.admin_url, scratch_db.role)
    planted = [
        AUDIT_RECORD,
        # Outside public, which must hold nothing of another role's for setup to run.
        "CREATE SCHEMA planted",
        "CREATE TABLE planted.ran (place TEXT)",
        "GRANT USAGE ON SCHEMA planted TO ft_owner",
        "GRANT INSERT ON planted.ran TO ft_owner",
        # A right setup must take back from the table in public, not from one of the same
        # name in the owner's schema.
        f"GRANT UPDATE ON public.audit_events TO {scratch_db.role}",
    ]
    if where == "ft_owner":
        planted.append("CREATE SCHEMA ft_owner AUTHORIZATION ft_owner")
    as_superuser(scratch_db.admin_url, *planted, PLANTED_LOCK.format(where=where))
    notices = []
    with owner_session(scratch_db, notices) as conn:
        if where == "public":
            # Another role's function in public: setup refuses before it creates anything.
            with pytest.raises(schema.SetupRefusedError) as refused:
                schema.setup_database(conn, scratch_db.role)
            assert str(refused.value) == schema.SETUP_FOREIGN_OBJECTS
        else:
            assert schema.setup_database(conn, scratch_db.role) is False
    # The planted function never ran, not even before the refusal (which would roll back
    # what it did, but not what it may have sent out): the lock call names pg_catalog.
    assert planted_ran(notices) == []
    with psycopg.connect(scratch_db.admin_url) as conn:
        assert conn.execute("SELECT count(*) FROM planted.ran").fetchone()[0] == 0
        assert conn.execute("SELECT count(*) FROM public.audit_events").fetchone()[0] == 1
        if where == "ft_owner":
            # The path is pinned to public: the schema named after the owner, which it may
            # create in and which comes first on Postgres' default path, got no table or
            # function, and the rights reset are the ones on public's tables.
            assert conn.execute(
                "SELECT (SELECT count(*) FROM pg_class WHERE relnamespace = 'ft_owner'::regnamespace),"
                " (SELECT count(*) FROM pg_proc WHERE pronamespace = 'ft_owner'::regnamespace)"
            ).fetchone() == (0, 1)  # the planted lock function only
            assert conn.execute(
                "SELECT has_table_privilege(%s, 'public.audit_events', 'UPDATE')", (scratch_db.role,)
            ).fetchone()[0] is False


# Planted before the first setup by a role that was given CREATE on public (or by anyone,
# on a database made by Postgres 14): a schema_info whose trigger, fired by setup's INSERT
# with the owner's rights, would leave a SECURITY DEFINER function of the owner's behind.
PLANTED_SCHEMA_INFO = """
CREATE FUNCTION public.plant() RETURNS trigger LANGUAGE plpgsql AS $p$
BEGIN
    EXECUTE 'CREATE FUNCTION public.planted_helper() RETURNS integer LANGUAGE sql SECURITY DEFINER AS ''SELECT 1''';
    RETURN NULL;
END $p$;
CREATE TABLE public.schema_info (version INTEGER NOT NULL);
CREATE TRIGGER plant BEFORE INSERT ON public.schema_info FOR EACH ROW EXECUTE FUNCTION public.plant();
GRANT SELECT, INSERT ON public.schema_info TO PUBLIC;
"""


def test_setup_refuses_tables_another_role_planted_before_it(scratch_db, capsys):
    as_superuser(scratch_db.admin_url, f"GRANT CREATE ON SCHEMA public TO {scratch_db.role}")
    with psycopg.connect(scratch_db.url, autocommit=True) as conn:
        conn.execute(PLANTED_SCHEMA_INFO)
    env = {"FLASHCARDS_SETUP_DATABASE_URL": as_the_owner(scratch_db), "FLASHCARDS_APP_ROLE": scratch_db.role}
    assert setup_db.main([], env) == 1
    out, err = capsys.readouterr()
    assert out == "" and err.splitlines() == [schema.SETUP_FOREIGN_OBJECTS]
    with psycopg.connect(scratch_db.admin_url) as conn:
        # The trigger never ran, and setup made nothing.
        assert conn.execute(
            "SELECT to_regproc('public.planted_helper') IS NULL, to_regclass('public.teams') IS NULL,"
            " to_regclass('public.audit_events') IS NULL"
        ).fetchone() == (True, True, True)


# Planted before the first setup by a role given CREATE on the database and on public: a
# schema_info whose rule calls, with the rights of whoever inserts, a function in the
# planting role's own schema. Nothing else in public and no trigger: only the table's
# owner gives it away.
PLANTED_RULE = (
    "CREATE SCHEMA planter",
    "CREATE FUNCTION planter.planted() RETURNS integer LANGUAGE plpgsql AS $$"
    " BEGIN RAISE NOTICE 'planted rule ran as %', current_user; RETURN 1; END $$",
    "GRANT USAGE ON SCHEMA planter TO PUBLIC",
    "CREATE TABLE public.schema_info (version INTEGER NOT NULL)",
    "CREATE RULE planted AS ON INSERT TO public.schema_info DO ALSO SELECT planter.planted()",
    "GRANT ALL ON public.schema_info TO PUBLIC",
)


def test_setup_refuses_a_table_another_role_owns_whatever_it_calls(scratch_db):
    as_superuser(
        scratch_db.admin_url,
        f"GRANT CREATE ON DATABASE {scratch_db.name} TO {scratch_db.role}",
        f"GRANT CREATE ON SCHEMA public TO {scratch_db.role}",
    )
    with psycopg.connect(scratch_db.url, autocommit=True) as conn:
        for statement in PLANTED_RULE:
            conn.execute(statement)
    notices = []
    with owner_session(scratch_db, notices) as conn, pytest.raises(schema.SetupRefusedError) as refused:
        schema.setup_database(conn, scratch_db.role)
    assert str(refused.value) == schema.SETUP_FOREIGN_OBJECTS
    assert planted_ran(notices) == []
    with psycopg.connect(scratch_db.admin_url) as conn:
        assert conn.execute("SELECT to_regclass('public.teams') IS NULL").fetchone()[0] is True


# Made by the app role in its own session's temporary schema: the function a trigger it
# adds to schema_info calls. Setup's INSERT into schema_info fires that table's triggers
# with the owner's rights, so this would switch the triggers off, empty audit_events and
# switch them on again.
PLANTED_TEMPORARY_FUNCTION = """
CREATE FUNCTION pg_temp.planted() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE NOTICE 'planted trigger ran as %', current_user;
    ALTER TABLE public.audit_events DISABLE TRIGGER USER;
    DELETE FROM public.audit_events;
    ALTER TABLE public.audit_events ENABLE ALWAYS TRIGGER audit_events_no_update_delete;
    ALTER TABLE public.audit_events ENABLE ALWAYS TRIGGER audit_events_no_truncate;
    RETURN NULL;
END $$
"""
# The same, before setup has made audit_events: it only says that it ran.
PLANTED_TEMPORARY_NOTICE = """
CREATE FUNCTION pg_temp.planted() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE NOTICE 'planted trigger ran as %', current_user;
    RETURN NULL;
END $$
"""
# Per statement: it fires even when setup's INSERT adds no row, as on every run after the
# first.
PLANTED_TRIGGER = "CREATE TRIGGER planted BEFORE INSERT ON public.schema_info FOR EACH STATEMENT EXECUTE FUNCTION pg_temp.planted()"


def test_setup_refuses_a_trigger_it_didnt_make(scratch_db):
    # One mistake (GRANT ALL ON ALL TABLES IN SCHEMA public TO the app role, say) gives the
    # app role TRIGGER on schema_info. The startup check refuses such a role, and its
    # message asks for setup to be run again, which would fire the trigger.
    set_up_as_owner(scratch_db.admin_url, scratch_db.role)
    as_superuser(scratch_db.admin_url, AUDIT_RECORD, f"GRANT TRIGGER ON schema_info TO {scratch_db.role}")
    notices = []
    with psycopg.connect(scratch_db.url, autocommit=True) as app:
        app.execute(PLANTED_TEMPORARY_FUNCTION)
        app.execute(PLANTED_TRIGGER)
        with owner_session(scratch_db, notices) as conn, pytest.raises(schema.SetupRefusedError) as refused:
            schema.setup_database(conn, scratch_db.role)
    assert str(refused.value) == schema.SETUP_FOREIGN_OBJECTS
    assert planted_ran(notices) == []
    assert audit_records(scratch_db) == 1


def test_setup_sees_a_table_planted_after_its_first_check(scratch_db):
    # The app role, given CREATE on public before the first setup, makes schema_info just
    # after setup's first check and before its CREATE TABLE IF NOT EXISTS, which then
    # leaves that table as it is, and lets every role use it, setup's owner included.
    as_superuser(scratch_db.admin_url, f"GRANT CREATE ON SCHEMA public TO {scratch_db.role}")
    notices = []
    with psycopg.connect(scratch_db.url, autocommit=True) as app:
        app.execute(PLANTED_TEMPORARY_NOTICE)

        def plant():
            app.execute("CREATE TABLE public.schema_info (version INTEGER NOT NULL)")
            app.execute(PLANTED_TRIGGER)
            app.execute("GRANT ALL ON public.schema_info TO PUBLIC")

        with owner_session(scratch_db, notices) as conn:
            interrupted = Interrupted(conn, "PG_TABLES", plant)
            with pytest.raises(schema.SetupRefusedError) as refused:
                schema.setup_database(interrupted, scratch_db.role)
            assert interrupted.acted
    assert str(refused.value) == schema.SETUP_FOREIGN_OBJECTS
    assert planted_ran(notices) == []
    with psycopg.connect(scratch_db.admin_url) as conn:
        # Setup made nothing; the planted table is still there, the app role's.
        assert conn.execute(
            "SELECT to_regclass('public.teams') IS NULL, to_regclass('public.audit_events') IS NULL,"
            " pg_get_userbyid(relowner) FROM pg_class WHERE oid = 'public.schema_info'::regclass"
        ).fetchone() == (True, True, scratch_db.role)


def test_no_trigger_can_be_added_once_setup_has_checked(scratch_db):
    # Setup locks its tables before it checks them again: the app role, given TRIGGER on
    # schema_info, tries to add a trigger after that check and before the INSERT, and
    # can't get the lock.
    set_up_as_owner(scratch_db.admin_url, scratch_db.role)
    as_superuser(scratch_db.admin_url, f"GRANT TRIGGER ON schema_info TO {scratch_db.role}")
    notices, tried = [], []
    with psycopg.connect(scratch_db.url, autocommit=True) as app:
        app.execute(PLANTED_TEMPORARY_NOTICE)
        app.execute("SET lock_timeout = '2s'")

        def plant():
            try:
                app.execute(PLANTED_TRIGGER)
                tried.append("created")
            except psycopg.errors.LockNotAvailable:
                tried.append("no lock")

        with owner_session(scratch_db, notices) as conn:
            interrupted = Interrupted(conn, "_SQL_SETUP_VERSION", plant)
            assert schema.setup_database(interrupted, scratch_db.role) is False
    assert tried == ["no lock"]
    assert planted_ran(notices) == []
    with psycopg.connect(scratch_db.admin_url) as conn:
        assert conn.execute(
            "SELECT count(*) FROM pg_trigger WHERE tgrelid = 'public.schema_info'::regclass AND NOT tgisinternal"
        ).fetchone()[0] == 0
    opens(scratch_db.url)  # and setup took TRIGGER back


# Every role may create in the database: Postgres 14 makes schema public that way, owned
# by the bootstrap superuser. Only that schema's owner or a superuser can take it back,
# so the message doesn't tell the operator to connect as another role.
PUBLIC_MAY_CREATE = {
    "public-as-on-postgres-14": ("ALTER SCHEMA public OWNER TO postgres", "GRANT CREATE ON SCHEMA public TO PUBLIC"),
    "the-database": ("GRANT CREATE ON DATABASE {db} TO PUBLIC",),
}
# What SETUP_PUBLIC_MAY_CREATE asks a superuser to do in each case.
PUBLIC_MAY_CREATE_REMEDY = {
    "public-as-on-postgres-14": ("REVOKE CREATE ON SCHEMA public FROM PUBLIC", "GRANT CREATE ON SCHEMA public TO ft_owner"),
    "the-database": ("REVOKE CREATE ON DATABASE {db} FROM PUBLIC",),
}


@pytest.mark.parametrize("case", PUBLIC_MAY_CREATE)
def test_setup_refuses_a_database_where_every_role_may_create(scratch_db, capsys, case):
    # A database as Postgres 14 makes it (and one upgraded from it keeps): public belongs
    # to the bootstrap superuser, and PUBLIC may create there. The owner, not a superuser,
    # can't take that back: the setup's REVOKE only warns. Setup doesn't take back CREATE
    # that PUBLIC was given on the database either.
    as_superuser(scratch_db.admin_url, *(s.format(db=scratch_db.name) for s in PUBLIC_MAY_CREATE[case]))
    env = {"FLASHCARDS_SETUP_DATABASE_URL": as_the_owner(scratch_db), "FLASHCARDS_APP_ROLE": scratch_db.role}
    assert setup_db.main([], env) == 1
    out, err = capsys.readouterr()
    assert out == "" and err.splitlines() == [schema.SETUP_PUBLIC_MAY_CREATE]
    with psycopg.connect(scratch_db.admin_url) as conn:
        assert conn.execute(
            "SELECT (SELECT count(*) FROM pg_class WHERE relnamespace = 'public'::regnamespace),"
            " (SELECT count(*) FROM pg_proc WHERE pronamespace = 'public'::regnamespace)"
        ).fetchone() == (0, 0)
    # What the message asks a superuser to do; then setup runs and the server starts.
    as_superuser(scratch_db.admin_url, *(s.format(db=scratch_db.name) for s in PUBLIC_MAY_CREATE_REMEDY[case]))
    assert setup_db.main([], env) == 0
    out, err = capsys.readouterr()
    assert out.splitlines() == [setup_db.CREATED] and err == ""
    opens(scratch_db.url)


@pytest.mark.parametrize("path", [None, "custom_path, public"], ids=["default-path", "set-local-path"])
def test_setup_in_a_transaction_leaves_its_search_path_as_it_was(scratch_db, path):
    # In a transaction already, setup runs in a savepoint, and what set_config(..., true)
    # sets there lasts until the whole transaction ends: whatever path the caller had,
    # the session's default or one it set for this transaction only, is put back.
    with psycopg.connect(scratch_db.admin_url) as conn:
        conn.execute("SET ROLE ft_owner")
        if path is not None:
            conn.execute(f"SET LOCAL search_path TO {path}")
        before = conn.execute("SHOW search_path").fetchone()[0]
        assert schema.setup_database(conn, scratch_db.role) is True
        assert conn.execute("SHOW search_path").fetchone()[0] == before == (path or '"$user", public')


def test_setup_runs_in_a_session_that_made_a_temporary_table(scratch_db):
    # As in the startup check: the session's own temporary schema reports CREATE for
    # PUBLIC once the session has made a temporary table, yet only that session searches it.
    with psycopg.connect(scratch_db.admin_url, autocommit=True) as conn:
        conn.execute("SET ROLE ft_owner")
        conn.execute("CREATE TEMP TABLE scratch_temporary (x INTEGER)")
        conn.execute("DROP TABLE scratch_temporary")
        assert schema.setup_database(conn, scratch_db.role) is True
    opens(scratch_db.url)


def test_setup_ignores_the_owners_temporary_tables(scratch_db):
    # A temporary audit_events in the owner's session: unlisted, the session's temporary
    # schema is searched first, and setup would put the triggers and the rights on that
    # table instead of on public's. Public's are put wrong first, so setup must mend them.
    set_up_as_owner(scratch_db.admin_url, scratch_db.role)
    as_superuser(
        scratch_db.admin_url,
        "ALTER TABLE audit_events ENABLE TRIGGER audit_events_no_update_delete",
        "ALTER TABLE audit_events DISABLE TRIGGER audit_events_no_truncate",
        f"REVOKE INSERT ON audit_events FROM {scratch_db.role}",
    )
    with psycopg.connect(scratch_db.admin_url, autocommit=True) as conn:
        conn.execute("SET ROLE ft_owner")
        conn.execute("CREATE TEMP TABLE audit_events (LIKE public.audit_events)")
        assert schema.setup_database(conn, scratch_db.role) is False
    with psycopg.connect(scratch_db.admin_url) as conn:
        assert conn.execute(
            "SELECT tgname, tgenabled FROM pg_trigger WHERE tgrelid = 'public.audit_events'::regclass"
            " AND NOT tgisinternal ORDER BY tgname"
        ).fetchall() == [("audit_events_no_truncate", "A"), ("audit_events_no_update_delete", "A")]
        assert conn.execute(
            "SELECT has_table_privilege(%s, 'public.audit_events', 'SELECT'),"
            " has_table_privilege(%s, 'public.audit_events', 'INSERT')",
            (scratch_db.role, scratch_db.role),
        ).fetchone() == (True, True)
    opens(scratch_db.url)


@pytest.mark.parametrize(
    ("extension", "when"), [("pgcrypto", "before"), ("pg_trgm", "after"), ("tablefunc", "before"), ("tablefunc", "after")]
)
def test_a_trusted_extension_in_public_is_no_foreign_object(scratch_db, capsys, extension, when):
    # On Neon the owner, not a superuser, may install a trusted extension in public; what
    # it installs there belongs to the bootstrap superuser. Setup still runs, before and
    # after the extension came, and the server starts. tablefunc also makes composite
    # types, whose pg_class rows aren't extension members (their pg_type rows are).
    owner, app = f"{scratch_db.role}_owner", f"{scratch_db.role}_made"
    scratch_db.extra_roles.extend([app, owner])  # the made role first: its creator's membership goes with it
    as_superuser(
        scratch_db.admin_url,
        f"CREATE ROLE {owner} CREATEROLE LOGIN",
        f"ALTER DATABASE {scratch_db.name} OWNER TO {owner}",
    )
    owner_url = scratch_db.url.replace(f"//{scratch_db.role}@", f"//{owner}@")
    env = {"FLASHCARDS_SETUP_DATABASE_URL": owner_url, "FLASHCARDS_APP_ROLE": app}

    def install():
        with psycopg.connect(owner_url, autocommit=True) as conn:
            conn.execute(f"CREATE EXTENSION {extension}")
            assert conn.execute(
                "SELECT count(*) FROM pg_proc WHERE pronamespace = 'public'::regnamespace AND proowner <> %s::regrole",
                (owner,),
            ).fetchone()[0] > 0

    assert setup_db.main(["--create-app-role"], env) == 0
    if when == "before":
        install()
    assert setup_db.main([], env) == 0
    if when == "after":
        install()
    assert setup_db.main([], env) == 0
    out, err = capsys.readouterr()
    assert out.splitlines()[-2:] == [setup_db.CREATED, setup_db.RESET] and err == ""
    opens(scratch_db.url.replace(f"//{scratch_db.role}@", f"//{app}@"))


def test_an_extension_table_with_a_primary_key_is_no_foreign_object(scratch_db):
    # As PostGIS's spatial_ref_sys: a table in public that belongs to an extension and has
    # a primary key. The table is an extension member, its index isn't. None of the
    # extensions the test server has comes with one, so a superuser makes one part of
    # pgcrypto, which the owner installed, as an extension script would.
    as_superuser(
        scratch_db.admin_url,
        "SET ROLE ft_owner",
        "CREATE EXTENSION pgcrypto",
        "RESET ROLE",
        "CREATE TABLE public.extension_table (id INTEGER PRIMARY KEY, v TEXT)",
        "ALTER EXTENSION pgcrypto ADD TABLE public.extension_table",
    )
    with psycopg.connect(scratch_db.admin_url) as conn:
        # The index has the table's owner, the superuser, and isn't an extension member.
        assert conn.execute(
            "SELECT pg_get_userbyid(i.relowner), NOT EXISTS (SELECT 1 FROM pg_depend e"
            " WHERE e.classid = 'pg_class'::regclass AND e.objid = i.oid AND e.deptype = 'e')"
            " FROM pg_class i WHERE i.oid = 'public.extension_table_pkey'::regclass"
        ).fetchone() == ("postgres", True)
    assert set_up_as_owner(scratch_db.admin_url, scratch_db.role) is True
    assert set_up_as_owner(scratch_db.admin_url, scratch_db.role) is False
    opens(scratch_db.url)


# The owner's own trigger on a table of its own in public, calling a function the owner
# owns, or one an extension the owner installed brings (tcn, trusted, so the bootstrap
# superuser owns its function). Setup fires neither, and either runs no other role's code.
OWNERS_TRIGGERS = {
    "owners-function": (
        "CREATE FUNCTION public.owners_touch() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$",
        "CREATE TRIGGER owners_touch BEFORE INSERT ON public.owners_table FOR EACH ROW EXECUTE FUNCTION public.owners_touch()",
    ),
    "extensions-function": (
        "CREATE EXTENSION tcn",
        "CREATE TRIGGER owners_notify AFTER INSERT ON public.owners_table FOR EACH ROW"
        " EXECUTE FUNCTION public.triggered_change_notification()",
    ),
}


@pytest.mark.parametrize("case", OWNERS_TRIGGERS)
def test_setup_runs_beside_the_owners_own_triggers(scratch_db, case):
    # A database the owner shares with something else: its other tables may have triggers.
    as_superuser(
        scratch_db.admin_url,
        "SET ROLE ft_owner",
        "CREATE TABLE public.owners_table (id INTEGER PRIMARY KEY)",
        *OWNERS_TRIGGERS[case],
    )
    assert set_up_as_owner(scratch_db.admin_url, scratch_db.role) is True
    assert set_up_as_owner(scratch_db.admin_url, scratch_db.role) is False
    opens(scratch_db.url)


def test_running_setup_again_takes_back_create_given_to_the_app_role(scratch_db):
    # One mistake: CREATE on public and on the database. The server refuses the role, and
    # running setup again, as its message says, takes both back.
    set_up_as_owner(scratch_db.admin_url, scratch_db.role)
    as_superuser(
        scratch_db.admin_url,
        f"GRANT CREATE ON SCHEMA public TO {scratch_db.role}",
        f"GRANT CREATE ON DATABASE {scratch_db.name} TO {scratch_db.role}",
    )
    with pytest.raises(AppRoleTooPowerfulError) as stopped:
        opens(scratch_db.url)
    assert str(stopped.value) == schema.TOO_POWERFUL
    set_up_as_owner(scratch_db.admin_url, scratch_db.role)
    opens(scratch_db.url)


# A role that could change or remove audit records, itself or as a role it may act as
# (inherited or only through SET ROLE): each one is AppRoleTooPowerfulError.
TOO_POWERFUL = {
    "superuser": (),  # connects as the superuser instead of the app role
    "member-of-the-owner": ("GRANT ft_owner TO {role}",),
    "set-only-member-of-the-owner": ("GRANT ft_owner TO {role} WITH INHERIT FALSE, SET TRUE",),
    # ft_owner owns the database too, and an owner has every right on its table unless it
    # gives them up: this owner owns only the table and has given up its rights, yet it
    # may still drop the triggers or grant itself the rights again.
    "owner-of-the-table-without-rights": (
        "CREATE ROLE {power} NOLOGIN",
        "ALTER TABLE audit_events OWNER TO {power}",
        "REVOKE ALL ON audit_events FROM {power}",
        "GRANT {power} TO {role}",
    ),
    # Since PostgreSQL 15 the database's owner is a member of pg_database_owner, which owns
    # schema public unless someone else is made its owner, as here. An owner may create in
    # what it owns unless it gives that up: these owners have, so only owning counts.
    "owner-of-the-database": (
        "ALTER SCHEMA public OWNER TO ft_owner",
        "ALTER DATABASE {db} OWNER TO {role}",
        "REVOKE CREATE ON DATABASE {db} FROM {role}",
    ),
    "owner-of-the-schema": ("ALTER SCHEMA public OWNER TO {role}", "REVOKE CREATE ON SCHEMA public FROM {role}"),
    # Any schema: its owner may grant itself CREATE there again.
    "owns-another-schema": (
        "CREATE SCHEMA extra_owned",
        "ALTER SCHEMA extra_owned OWNER TO {role}",
        "REVOKE CREATE ON SCHEMA extra_owned FROM {role}",
    ),
    # The server logs in as {power}, whose default is to become the app role: it may
    # RESET ROLE, and then SET ROLE to the owner.
    "login-role-defaulting-to-the-app-role": (
        "CREATE ROLE {power} LOGIN",
        "GRANT ft_owner TO {power}",
        "GRANT {role} TO {power}",
        "ALTER ROLE {power} SET role = {role}",
    ),
    # Calling it acts as its owner (EXECUTE stays with PUBLIC, as by default).
    "a-definer-function-in-public": (
        "CREATE FUNCTION public.extra_definer() RETURNS INTEGER LANGUAGE sql SECURITY DEFINER AS 'SELECT 1'",
        "ALTER FUNCTION public.extra_definer() OWNER TO ft_owner",
    ),
    # Whoever owns the function may change what the triggers do.
    "owner-of-the-trigger-function": (
        "CREATE ROLE {power} NOLOGIN",
        "ALTER FUNCTION audit_events_refuse_change() OWNER TO {power}",
        "GRANT {power} TO {role}",
    ),
    # Whoever owns anything in the tables' schema may drop it, or change what it does.
    "owns-a-table-in-public": ("CREATE TABLE public.extra_table (x INTEGER)", "ALTER TABLE extra_table OWNER TO {role}"),
    "owns-a-function-in-public": (
        "CREATE FUNCTION public.extra_function() RETURNS INTEGER LANGUAGE sql AS 'SELECT 1'",
        "ALTER FUNCTION extra_function() OWNER TO {role}",
    ),
    # Objects the role makes where a session may look for names could stand in for what
    # that session means to call: an overload in public, or a schema named after the owner.
    "create-on-the-database": ("GRANT CREATE ON DATABASE {db} TO {role}",),
    "create-on-schema-public": ("GRANT CREATE ON SCHEMA public TO {role}",),
    "create-on-another-schema": ("CREATE SCHEMA extra_schema", "GRANT CREATE ON SCHEMA extra_schema TO {role}"),
    # Postgres' documentation: these roles can be used to gain superuser-level access.
    "member-of-pg-execute-server-program": ("GRANT pg_execute_server_program TO {role}",),
    "set-only-member-of-pg-write-server-files": ("GRANT pg_write_server_files TO {role} WITH INHERIT FALSE, SET TRUE",),
    "member-of-pg-read-server-files": ("GRANT pg_read_server_files TO {role}",),
    "update-on-the-table": ("GRANT UPDATE ON audit_events TO {role}",),
    "update-on-one-column": ("GRANT UPDATE (result) ON audit_events TO {role}",),
    "delete-on-the-table": ("GRANT DELETE ON audit_events TO {role}",),
    "truncate-on-the-table": ("GRANT TRUNCATE ON audit_events TO {role}",),
    "trigger-on-the-table": ("GRANT TRIGGER ON audit_events TO {role}",),
    "set-only-member-of-a-role-that-can-delete": (
        "CREATE ROLE {power} NOLOGIN",
        "GRANT DELETE ON audit_events TO {power}",
        "GRANT {power} TO {role} WITH INHERIT FALSE, SET TRUE",
    ),
    "set-only-member-of-pg-write-all-data": ("GRANT pg_write_all_data TO {role} WITH INHERIT FALSE, SET TRUE",),
    "member-of-a-superuser-role": ("CREATE ROLE {power} SUPERUSER NOLOGIN", "GRANT {power} TO {role}"),
    # No rights on the table at all: only the role's attributes give it away.
    "member-of-a-createrole-role": ("CREATE ROLE {power} CREATEROLE NOLOGIN", "GRANT {power} TO {role}"),
    "createrole": ("ALTER ROLE {role} CREATEROLE",),
    "bypassrls": ("ALTER ROLE {role} BYPASSRLS",),
    # A plain role that has nothing, but whose name means a superuser's powers on Neon:
    # only the name gives it away.
    "member-of-neon-superuser": ("CREATE ROLE neon_superuser NOLOGIN", "GRANT neon_superuser TO {role}"),
}


@pytest.mark.parametrize("case", TOO_POWERFUL)
def test_the_server_wont_start_as_a_role_that_could_rewrite_records(scratch_db, case):
    set_up_as_owner(scratch_db.admin_url, scratch_db.role)
    power = f"{scratch_db.role}_power"
    scratch_db.extra_roles.append(power)  # dropped after the test, whether made or not
    if case == "member-of-neon-superuser":
        scratch_db.extra_roles.append("neon_superuser")  # roles belong to the whole server
    statements = (s.format(role=scratch_db.role, power=power, db=scratch_db.name) for s in TOO_POWERFUL[case])
    as_superuser(scratch_db.admin_url, *statements)
    url = {
        "superuser": scratch_db.admin_url,
        "login-role-defaulting-to-the-app-role": scratch_db.url.replace(f"//{scratch_db.role}@", f"//{power}@"),
    }.get(case, scratch_db.url)
    with pytest.raises(AppRoleTooPowerfulError) as stopped:
        opens(url)
    assert str(stopped.value) == schema.TOO_POWERFUL
    assert_says_nothing_about_where(str(stopped.value), scratch_db)


@pytest.mark.parametrize("case", PUBLIC_MAY_CREATE)
def test_the_server_wont_start_where_every_role_may_create(scratch_db, case):
    set_up_as_owner(scratch_db.admin_url, scratch_db.role)  # before PUBLIC was given CREATE
    as_superuser(scratch_db.admin_url, *(s.format(db=scratch_db.name) for s in PUBLIC_MAY_CREATE[case]))
    with pytest.raises(AppRoleTooPowerfulError) as stopped:
        opens(scratch_db.url)
    assert str(stopped.value) == schema.PUBLIC_MAY_CREATE
    assert_says_nothing_about_where(str(stopped.value), scratch_db)


def test_the_server_starts_in_a_session_that_made_a_temporary_table(scratch_db):
    # A session's own temporary schema reports CREATE for every role that may make
    # temporary tables (PUBLIC, by default) once the session has made one; through a
    # transaction-mode pooler that may be another client's doing. Only that session
    # searches it, so it doesn't count.
    set_up_as_owner(scratch_db.admin_url, scratch_db.role)
    with psycopg.connect(scratch_db.url, autocommit=True) as conn:
        conn.execute("CREATE TEMP TABLE scratch_temporary (x INTEGER)")
        conn.execute("DROP TABLE scratch_temporary")
        schema.verify_app_role(conn)


def test_the_startup_check_ignores_a_temporary_catalog_table(scratch_db):
    # A temporary table named like a catalog, left in a pooled backend: unlisted, the
    # session's temporary schema is searched even before pg_catalog, and an empty pg_roles
    # there would hide every role the session can act as.
    set_up_as_owner(scratch_db.admin_url, scratch_db.role)
    as_superuser(scratch_db.admin_url, f"ALTER ROLE {scratch_db.role} CREATEROLE")
    with psycopg.connect(scratch_db.url, autocommit=True) as conn:
        conn.execute("CREATE TEMP TABLE pg_roles (LIKE pg_catalog.pg_roles)")
        with pytest.raises(AppRoleTooPowerfulError) as stopped:
            schema.verify_app_role(conn)
    assert str(stopped.value) == schema.TOO_POWERFUL


def test_the_startup_check_ignores_a_temporary_schema_info(scratch_db):
    # The same for the tables: a temporary schema_info with the right version can't stand
    # in for public's.
    set_up_as_owner(scratch_db.admin_url, scratch_db.role)
    as_superuser(scratch_db.admin_url, "UPDATE schema_info SET version = 0")
    with psycopg.connect(scratch_db.url, autocommit=True) as conn:
        conn.execute("CREATE TEMP TABLE schema_info (version INTEGER NOT NULL)")
        conn.execute("INSERT INTO pg_temp.schema_info (version) VALUES (%s)", (limits.SCHEMA_VERSION,))
        with pytest.raises(SchemaNotReadyError) as stopped:
            schema.verify_app_role(conn)
    assert str(stopped.value) == schema.NOT_READY


def test_the_server_starts_as_a_role_that_belongs_to_harmless_roles(scratch_db):
    # Belonging to other roles isn't power in itself: a monitoring role, and a group that
    # may only read the cards.
    set_up_as_owner(scratch_db.admin_url, scratch_db.role)
    group = f"{scratch_db.role}_readers"
    scratch_db.extra_roles.append(group)
    as_superuser(
        scratch_db.admin_url,
        f"GRANT pg_monitor TO {scratch_db.role}",
        f"CREATE ROLE {group} NOLOGIN",
        f"GRANT SELECT ON cards TO {group}",
        f"GRANT {group} TO {scratch_db.role} WITH INHERIT TRUE",
    )
    opens(scratch_db.url)


def test_the_server_starts_beside_a_definer_function_it_may_not_call(scratch_db):
    # A SECURITY DEFINER function of the owner's in public, which only its owner may call:
    # the app role can't run it, so it gives the app role nothing.
    set_up_as_owner(scratch_db.admin_url, scratch_db.role)
    as_superuser(
        scratch_db.admin_url,
        "CREATE FUNCTION public.owner_only() RETURNS INTEGER LANGUAGE sql SECURITY DEFINER AS 'SELECT 1'",
        "ALTER FUNCTION public.owner_only() OWNER TO ft_owner",
        "REVOKE EXECUTE ON FUNCTION public.owner_only() FROM PUBLIC",
    )
    opens(scratch_db.url)


def test_the_server_starts_beside_an_extensions_definer_function(scratch_db):
    # An extension's SECURITY DEFINER functions are its designed interface. None of the
    # extensions the test server has comes with one, so a superuser makes one part of
    # pgcrypto, as an extension script would. Setup accepts it too: it is the extension's.
    set_up_as_owner(scratch_db.admin_url, scratch_db.role)
    as_superuser(
        scratch_db.admin_url,
        "CREATE EXTENSION pgcrypto",
        "CREATE FUNCTION public.extension_definer() RETURNS INTEGER LANGUAGE sql SECURITY DEFINER AS 'SELECT 1'",
        "ALTER EXTENSION pgcrypto ADD FUNCTION public.extension_definer()",
    )
    opens(scratch_db.url)
    assert set_up_as_owner(scratch_db.admin_url, scratch_db.role) is False
    opens(scratch_db.url)


# --- python -m flashcards_teams.setup_db ------------------------------------------------


def test_the_command_sets_up_and_says_only_what_it_did(scratch_db, capsys):
    env = {"FLASHCARDS_SETUP_DATABASE_URL": scratch_db.admin_url, "FLASHCARDS_APP_ROLE": scratch_db.role}
    assert setup_db.main([], env) == 0
    assert setup_db.main([], env) == 0
    out, err = capsys.readouterr()
    assert out.splitlines() == [setup_db.CREATED, setup_db.RESET] and err == ""


def scram_made_from(verifier: str, password: str) -> bool:
    """Whether a SCRAM-SHA-256 verifier as Postgres stores it,
    "SCRAM-SHA-256$<iterations>:<salt>$<StoredKey>:<ServerKey>" (base64), was made from
    ``password`` (RFC 5802)."""
    method, params, keys = verifier.split("$")
    iterations, salt = params.split(":")
    stored_key, server_key = (base64.b64decode(k) for k in keys.split(":"))
    salted = hashlib.pbkdf2_hmac("sha256", password.encode(), base64.b64decode(salt), int(iterations))
    client_key = hmac.new(salted, b"Client Key", "sha256").digest()
    return (
        method == "SCRAM-SHA-256"
        and hashlib.sha256(client_key).digest() == stored_key
        and hmac.new(salted, b"Server Key", "sha256").digest() == server_key
    )


def test_the_command_creates_the_app_role_and_shows_its_password_once(scratch_db, capsys):
    role = f"{scratch_db.role}_new"
    scratch_db.extra_roles.append(role)
    env = {"FLASHCARDS_SETUP_DATABASE_URL": scratch_db.admin_url, "FLASHCARDS_APP_ROLE": role}
    assert setup_db.main(["--create-app-role"], env) == 0
    out, err = capsys.readouterr()
    explanation, password = out.splitlines()
    assert explanation == "Created the app role. Its password, shown only this once:" and err == ""
    assert len(password) >= 32  # 24 random bytes
    with psycopg.connect(scratch_db.admin_url) as conn:
        assert conn.execute("SELECT rolcanlogin, rolsuper FROM pg_roles WHERE rolname = %s", (role,)).fetchone() == (True, False)
        # Only the role: the tables are set up by a run without the flag.
        assert conn.execute("SELECT to_regclass('public.teams') IS NULL").fetchone()[0] is True
        # The password shown is the one the role was given, stored only as a SCRAM verifier.
        [verifier] = conn.execute("SELECT rolpassword FROM pg_authid WHERE rolname = %s", (role,)).fetchone()
    assert verifier is not None and verifier.startswith("SCRAM-SHA-256$")
    assert scram_made_from(verifier, password)
    assert not scram_made_from(verifier, password + "x")


def test_the_command_refuses_a_reserved_app_role(scratch_db, capsys):
    # In GRANT even the quoted identifier "public" means PUBLIC, every role: setup would
    # give every role the app role's rights, and say it had succeeded.
    tables_public_may_read = (
        "SELECT count(*) FROM pg_class c WHERE c.relnamespace = 'public'::regnamespace"
        " AND has_table_privilege('public', c.oid, 'SELECT')"
    )
    with psycopg.connect(scratch_db.admin_url) as conn:
        schema_rights = conn.execute("SELECT nspacl FROM pg_namespace WHERE nspname = 'public'").fetchone()
    for name in ("public", "PUBLIC", "none", "pg_monitor"):
        env = {"FLASHCARDS_SETUP_DATABASE_URL": scratch_db.admin_url, "FLASHCARDS_APP_ROLE": name}
        for argv in ([], ["--create-app-role"]):
            assert setup_db.main(argv, env) == 2, (name, argv)
            out, err = capsys.readouterr()
            assert out == "" and err.splitlines() == [setup_db.RESERVED], (name, argv)
    with psycopg.connect(scratch_db.admin_url) as conn:
        assert conn.execute("SELECT to_regclass('public.teams') IS NULL").fetchone()[0] is True
        assert conn.execute(tables_public_may_read).fetchone()[0] == 0
        assert conn.execute("SELECT nspacl FROM pg_namespace WHERE nspname = 'public'").fetchone() == schema_rights


def test_an_owner_that_isnt_a_superuser_sets_up_as_on_neon(scratch_db, capsys):
    # On Neon the database's owner has CREATEROLE and LOGIN but isn't a superuser. Since
    # PostgreSQL 16 it becomes a member of the role it creates; the new role belongs to
    # nothing, so the startup check accepts it.
    owner, app = f"{scratch_db.role}_owner", f"{scratch_db.role}_made"
    scratch_db.extra_roles.extend([app, owner])  # the made role first: its creator's membership goes with it
    as_superuser(
        scratch_db.admin_url,
        f"CREATE ROLE {owner} CREATEROLE LOGIN",
        f"ALTER DATABASE {scratch_db.name} OWNER TO {owner}",
    )
    owner_url = scratch_db.url.replace(f"//{scratch_db.role}@", f"//{owner}@")
    env = {"FLASHCARDS_SETUP_DATABASE_URL": owner_url, "FLASHCARDS_APP_ROLE": app}
    assert setup_db.main(["--create-app-role"], env) == 0
    assert setup_db.main([], env) == 0
    out, err = capsys.readouterr()
    assert out.splitlines()[-1] == setup_db.CREATED and err == ""
    with psycopg.connect(scratch_db.admin_url) as conn:
        assert conn.execute(
            "SELECT rolsuper, pg_has_role(%s, %s, 'MEMBER'), pg_has_role(%s, %s, 'MEMBER') FROM pg_roles WHERE rolname = %s",
            (owner, app, app, owner, owner),
        ).fetchone() == (False, True, False)
    opens(scratch_db.url.replace(f"//{scratch_db.role}@", f"//{app}@"))


def test_the_command_never_shows_the_url(scratch_db, capsys):
    secret = "pw-SENTINEL-4711"
    url = scratch_db.admin_url.replace("postgres@", f"postgres:{secret}@").replace(scratch_db.name, "no_such_database")
    assert setup_db.main([], {"FLASHCARDS_SETUP_DATABASE_URL": url}) == 1
    assert setup_db.main([], {}) == 2
    out, err = capsys.readouterr()
    for text in (secret, "no_such_database", "127.0.0.1"):
        assert text not in out + err, text
    assert err.splitlines()[0].startswith("The database refused or could not be reached: OperationalError")
