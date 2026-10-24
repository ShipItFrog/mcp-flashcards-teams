"""Card storage.

Every method takes an ``owner`` key and every SQL statement filters on it. There is
no way to read, change or delete a card without naming its owner, so one user can
never reach another user's cards through this module.

Card numbers are per owner (each user's first card is #1) and are never reused
after a delete, so a number someone remembers can't silently point at a new card.

Topics are matched case-insensitively: each card stores the topic as typed, plus a
normalized ``topic_key`` used for filtering (see ``topic_key``).

Two stores behave the same way and run the same tests: ``SqliteCardStore`` for local
development, and ``PostgresCardStore`` for the hosted server, where the disk is wiped
on every restart.
"""

from __future__ import annotations

import logging
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

import anyio.to_thread

logger = logging.getLogger(__name__)

MAX_CARDS_PER_OWNER = 1000
# Total characters (question + answer + topic) one owner may store. Bounds the
# database size per user on a free-tier database.
MAX_CHARS_PER_OWNER = 200_000

# Postgres connections. The server runs as one process, so a few connections are
# plenty, and a short wait for a free one fails fast instead of piling requests up.
POOL_MIN_SIZE = 1
POOL_MAX_SIZE = 4
POOL_WAIT_SECONDS = 10.0
# How long startup waits for the database: Neon's free tier pauses after 5 minutes
# idle and usually wakes in under a second.
POOL_OPEN_SECONDS = 30.0
CONNECT_TIMEOUT_SECONDS = 10
# Longest an add waits for the user's row lock before giving up ("temporarily unavailable").
LOCK_WAIT_SECONDS = 10
# Shown in Postgres' own views (pg_stat_activity), so this server's connections can be told apart.
APPLICATION_NAME = "mcp-flashcards-teams"


class CardLimitError(Exception):
    """The owner is at the card-count or total-size limit."""


class StoreUnavailableError(Exception):
    """The database can't be reached right now. Raised instead of the driver's own
    error, whose text may name the host or the database user."""


class StoreFullError(Exception):
    """The database is out of space or over a resource limit: retrying won't help."""


def topic_key(topic: str) -> str:
    """Normalized form used to match topics: trimmed and case-folded."""
    return topic.strip().casefold()


class CardStore(Protocol):
    async def add(self, owner: str, question: str, answer: str, topic: str) -> dict[str, Any]: ...

    async def list(self, owner: str, topic: str = "", limit: int = 50, after_id: int = 0) -> list[dict[str, Any]]: ...

    async def count(self, owner: str, topic: str = "") -> int: ...

    async def least_recently_reviewed(self, owner: str, topic: str = "") -> dict[str, Any] | None: ...

    async def record_review(self, owner: str, card_no: int, correct: bool) -> dict[str, Any] | None: ...

    async def delete(self, owner: str, card_no: int) -> bool: ...

    def close(self) -> None: ...


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


_SCHEMA = """
CREATE TABLE IF NOT EXISTS owners (
    owner   TEXT PRIMARY KEY,
    next_no INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS cards (
    owner         TEXT    NOT NULL,
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
    PRIMARY KEY (owner, card_no)
);
CREATE INDEX IF NOT EXISTS cards_owner_topic ON cards (owner, topic_key);
"""

# The owner column is never selected: it is an internal key, not card data.
_CARD_COLUMNS = "card_no, question, answer, topic, created_at, last_reviewed, review_count, correct_count, wrong_count"


def _row_to_card(row: Any) -> dict[str, Any]:
    card = dict(row)
    card["id"] = card.pop("card_no")
    return card


def _topic_clause(topic: str, placeholder: str = "?") -> tuple[str, list[Any]]:
    key = topic_key(topic)
    return (f" AND topic_key = {placeholder}", [key]) if key else ("", [])


class _ThreadedStore:
    """The async API the server calls. Each call runs the store's synchronous
    implementation in a worker thread, so the event loop never waits on the database."""

    async def add(self, owner: str, question: str, answer: str, topic: str) -> dict[str, Any]:
        return await anyio.to_thread.run_sync(self._add, owner, question, answer, topic)

    async def list(self, owner: str, topic: str = "", limit: int = 50, after_id: int = 0) -> list[dict[str, Any]]:
        return await anyio.to_thread.run_sync(self._list, owner, topic, limit, after_id)

    async def count(self, owner: str, topic: str = "") -> int:
        return await anyio.to_thread.run_sync(self._count, owner, topic)

    async def least_recently_reviewed(self, owner: str, topic: str = "") -> dict[str, Any] | None:
        return await anyio.to_thread.run_sync(self._least_recently_reviewed, owner, topic)

    async def record_review(self, owner: str, card_no: int, correct: bool) -> dict[str, Any] | None:
        return await anyio.to_thread.run_sync(self._record_review, owner, card_no, correct)

    async def delete(self, owner: str, card_no: int) -> bool:
        return await anyio.to_thread.run_sync(self._delete, owner, card_no)


class SqliteCardStore(_ThreadedStore):
    """SQLite-backed store for local development and tests.

    One connection, and a lock held for each call's whole read-modify-write. There is
    no ``await`` inside the lock, so it can't deadlock the event loop.
    """

    def __init__(self, path: str | Path) -> None:
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # --- synchronous implementations (run in a worker thread) --------------

    def _add(self, owner: str, question: str, answer: str, topic: str) -> dict[str, Any]:
        with self._lock, self._conn:
            count, chars = self._conn.execute(
                "SELECT COUNT(*), COALESCE(SUM(LENGTH(question) + LENGTH(answer) + LENGTH(topic)), 0)"
                " FROM cards WHERE owner = ?",
                (owner,),
            ).fetchone()
            if count >= MAX_CARDS_PER_OWNER or chars + len(question) + len(answer) + len(topic) > MAX_CHARS_PER_OWNER:
                raise CardLimitError
            self._conn.execute("INSERT OR IGNORE INTO owners (owner, next_no) VALUES (?, 1)", (owner,))
            (card_no,) = self._conn.execute("SELECT next_no FROM owners WHERE owner = ?", (owner,)).fetchone()
            self._conn.execute("UPDATE owners SET next_no = next_no + 1 WHERE owner = ?", (owner,))
            self._conn.execute(
                "INSERT INTO cards (owner, card_no, question, answer, topic, topic_key, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (owner, card_no, question, answer, topic, topic_key(topic), _now()),
            )
            row = self._conn.execute(
                f"SELECT {_CARD_COLUMNS} FROM cards WHERE owner = ? AND card_no = ?", (owner, card_no)
            ).fetchone()
        return _row_to_card(row)

    def _list(self, owner: str, topic: str, limit: int, after_id: int) -> list[dict[str, Any]]:
        clause, params = _topic_clause(topic)
        with self._lock:
            rows = self._conn.execute(
                f"SELECT {_CARD_COLUMNS} FROM cards WHERE owner = ? AND card_no > ?{clause} ORDER BY card_no LIMIT ?",
                [owner, after_id, *params, limit],
            ).fetchall()
        return [_row_to_card(r) for r in rows]

    def _count(self, owner: str, topic: str) -> int:
        clause, params = _topic_clause(topic)
        with self._lock:
            (n,) = self._conn.execute(f"SELECT COUNT(*) FROM cards WHERE owner = ?{clause}", [owner, *params]).fetchone()
        return n

    def _least_recently_reviewed(self, owner: str, topic: str) -> dict[str, Any] | None:
        clause, params = _topic_clause(topic)
        # Never-reviewed cards (NULL) first, then oldest review first.
        with self._lock:
            row = self._conn.execute(
                f"SELECT {_CARD_COLUMNS} FROM cards WHERE owner = ?{clause}"
                " ORDER BY last_reviewed IS NOT NULL, last_reviewed, card_no LIMIT 1",
                [owner, *params],
            ).fetchone()
        return _row_to_card(row) if row else None

    def _record_review(self, owner: str, card_no: int, correct: bool) -> dict[str, Any] | None:
        with self._lock, self._conn:
            cur = self._conn.execute(
                "UPDATE cards SET last_reviewed = ?, review_count = review_count + 1,"
                " correct_count = correct_count + ?, wrong_count = wrong_count + ?"
                " WHERE owner = ? AND card_no = ?",
                (_now(), 1 if correct else 0, 0 if correct else 1, owner, card_no),
            )
            if cur.rowcount == 0:
                return None
            row = self._conn.execute(
                f"SELECT {_CARD_COLUMNS} FROM cards WHERE owner = ? AND card_no = ?", (owner, card_no)
            ).fetchone()
        return _row_to_card(row)

    def _delete(self, owner: str, card_no: int) -> bool:
        with self._lock, self._conn:
            cur = self._conn.execute("DELETE FROM cards WHERE owner = ? AND card_no = ?", (owner, card_no))
        return cur.rowcount > 0


_PG_SCHEMA = (
    """CREATE TABLE IF NOT EXISTS owners (
    owner   TEXT   PRIMARY KEY,
    next_no BIGINT NOT NULL
)""",
    # Times are ISO 8601 strings, as in SQLite; the "C" collation sorts them byte by
    # byte whatever the database's locale, so the review order matches SQLite's.
    """CREATE TABLE IF NOT EXISTS cards (
    owner         TEXT    NOT NULL,
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
    PRIMARY KEY (owner, card_no)
)""",
    "CREATE INDEX IF NOT EXISTS cards_owner_topic ON cards (owner, topic_key)",
)
# Any fixed number. During a deploy Render runs the old and the new instance side by
# side, so two startups can create the tables at once; this makes them take turns.
_SCHEMA_LOCK_ID = 20261012


class PostgresCardStore(_ThreadedStore):
    """Postgres-backed store for the hosted server.

    Each call borrows its own connection from a small pool and runs as one
    transaction: committed when the call returns, rolled back if it raises. The pool
    checks a connection before handing it out, because Neon's free tier closes idle
    connections when it pauses.
    """

    def __init__(self, url: str) -> None:
        # Imported here so the SQLite store works without the Postgres driver installed.
        import psycopg
        from psycopg.rows import dict_row
        from psycopg_pool import ConnectionPool

        self._unavailable = psycopg.OperationalError  # also covers the pool's PoolTimeout
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
            with self._mapped_errors():
                self._pool.open(wait=True, timeout=POOL_OPEN_SECONDS)
            self.created_tables = self._create_tables()
        except BaseException:
            self._pool.close()
            raise

    def close(self) -> None:
        self._pool.close()

    @contextmanager
    def _mapped_errors(self):
        # libpq never puts the password in a message; the host and user name may be there.
        try:
            yield
        except self._unavailable as e:
            # Disk full (SQLSTATE 53100, which Neon's storage limit is expected to raise)
            # won't pass by retrying, unlike the rest of the class: too many connections,
            # out of memory. psycopg files all of them under OperationalError.
            if getattr(e, "sqlstate", None) == "53100":
                logger.error("The card database is out of space or over a limit: %s: %.300s", type(e).__name__, str(e))
                raise StoreFullError from None
            logger.warning("The card database is unavailable: %s: %.300s", type(e).__name__, str(e))
            raise StoreUnavailableError from None

    @contextmanager
    def _connection(self):
        with self._mapped_errors(), self._pool.connection() as conn:
            yield conn

    def _create_tables(self) -> bool:
        """Create any missing tables; True if the database had none yet."""
        with self._connection() as conn:
            conn.execute("SELECT pg_advisory_xact_lock(%s)", (_SCHEMA_LOCK_ID,))
            new = conn.execute("SELECT to_regclass('cards') IS NULL AS new").fetchone()["new"]
            for statement in _PG_SCHEMA:
                conn.execute(statement)
        return new

    # --- synchronous implementations (run in a worker thread) --------------

    def _add(self, owner: str, question: str, answer: str, topic: str) -> dict[str, Any]:
        with self._connection() as conn:
            # SET LOCAL lasts only for this transaction, so it also works through Neon's pooler.
            conn.execute(f"SET LOCAL lock_timeout = '{LOCK_WAIT_SECONDS}s'")
            # Hand out the next number. The upsert also locks this owner's row until the
            # transaction ends, so one owner's adds run one at a time: the limits checked
            # next see every card already committed, and two adds can't both slip under them.
            card_no = conn.execute(
                "INSERT INTO owners (owner, next_no) VALUES (%s, 2)"
                " ON CONFLICT (owner) DO UPDATE SET next_no = owners.next_no + 1"
                " RETURNING next_no - 1 AS card_no",
                (owner,),
            ).fetchone()["card_no"]
            usage = conn.execute(
                "SELECT COUNT(*) AS cards, COALESCE(SUM(length(question) + length(answer) + length(topic)), 0) AS chars"
                " FROM cards WHERE owner = %s",
                (owner,),
            ).fetchone()
            if usage["cards"] >= MAX_CARDS_PER_OWNER or usage["chars"] + len(question) + len(answer) + len(topic) > MAX_CHARS_PER_OWNER:
                # Leaving the block with an exception rolls back, so the number isn't used up.
                raise CardLimitError
            row = conn.execute(
                "INSERT INTO cards (owner, card_no, question, answer, topic, topic_key, created_at)"
                f" VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING {_CARD_COLUMNS}",
                (owner, card_no, question, answer, topic, topic_key(topic), _now()),
            ).fetchone()
        return _row_to_card(row)

    def _list(self, owner: str, topic: str, limit: int, after_id: int) -> list[dict[str, Any]]:
        clause, params = _topic_clause(topic, "%s")
        with self._connection() as conn:
            rows = conn.execute(
                f"SELECT {_CARD_COLUMNS} FROM cards WHERE owner = %s AND card_no > %s{clause} ORDER BY card_no LIMIT %s",
                [owner, after_id, *params, limit],
            ).fetchall()
        return [_row_to_card(r) for r in rows]

    def _count(self, owner: str, topic: str) -> int:
        clause, params = _topic_clause(topic, "%s")
        with self._connection() as conn:
            return conn.execute(f"SELECT COUNT(*) AS n FROM cards WHERE owner = %s{clause}", [owner, *params]).fetchone()["n"]

    def _least_recently_reviewed(self, owner: str, topic: str) -> dict[str, Any] | None:
        clause, params = _topic_clause(topic, "%s")
        # Never-reviewed cards first (Postgres sorts NULL last by default), then oldest review first.
        with self._connection() as conn:
            row = conn.execute(
                f"SELECT {_CARD_COLUMNS} FROM cards WHERE owner = %s{clause}"
                " ORDER BY last_reviewed IS NOT NULL, last_reviewed, card_no LIMIT 1",
                [owner, *params],
            ).fetchone()
        return _row_to_card(row) if row else None

    def _record_review(self, owner: str, card_no: int, correct: bool) -> dict[str, Any] | None:
        with self._connection() as conn:
            row = conn.execute(
                "UPDATE cards SET last_reviewed = %s, review_count = review_count + 1,"
                " correct_count = correct_count + %s, wrong_count = wrong_count + %s"
                f" WHERE owner = %s AND card_no = %s RETURNING {_CARD_COLUMNS}",
                (_now(), 1 if correct else 0, 0 if correct else 1, owner, card_no),
            ).fetchone()
        return _row_to_card(row) if row else None

    def _delete(self, owner: str, card_no: int) -> bool:
        with self._connection() as conn:
            return conn.execute("DELETE FROM cards WHERE owner = %s AND card_no = %s", (owner, card_no)).rowcount > 0
