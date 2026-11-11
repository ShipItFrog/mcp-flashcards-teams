"""Set up the Postgres database for the server:  python -m flashcards_teams.setup_db

Run by the database's owner, from the owner's own machine, never by the server: it
creates the tables and resets the app role's rights (see schema.setup_database). Safe
to run again.

  FLASHCARDS_SETUP_DATABASE_URL  the table owner's connection URL (secret; never put it
                                 on the hosting service or in the repository)
  FLASHCARDS_APP_ROLE            optional: the role the server connects as
                                 (default flashcards_app; never public, none or pg_...)

With --create-app-role it only creates that role, with a new random password shown
once, and sets up nothing; run it again without the flag to set up the tables.

When setup refuses the database (schema public holds tables or functions another role
owns, or triggers that call another role's functions, or every role may still create
objects in it: see schema.setup_database), it changes nothing, prints why on one line to
stderr and nothing to stdout, and exits 1.

Nothing it prints names the URL, the host or the database's own error text.
"""

from __future__ import annotations

import argparse
import os
import secrets
import sys
from collections.abc import Mapping

from . import schema

DEFAULT_APP_ROLE = "flashcards_app"
CREATED = "Created the team tables; granted the app role its rights."
RESET = "The team tables already exist; the app role's rights were reset."
RESERVED = "FLASHCARDS_APP_ROLE names a reserved role (public, none or pg_...): choose another name."
# The role and its password go in as an identifier and a literal (psycopg.sql), never as text.
_CREATE_ROLE = "CREATE ROLE {role} LOGIN PASSWORD {password}"


def reserved_role(name: str) -> bool:
    """Whether ``name`` can't be the app role. In GRANT even the quoted identifier "public"
    means PUBLIC, every role; "none" is refused as a role name, and names starting with
    pg_ belong to Postgres' own roles."""
    folded = name.casefold()
    return folded in ("public", "none") or folded.startswith("pg_")


def main(argv: list[str] | None = None, env: Mapping[str, str] | None = None) -> int:
    """Run the command; returns its exit status: 0 done, 2 not configured, 1 the database
    refused or couldn't be reached, or setup refused the database (schema.SetupRefusedError:
    its fixed message, one line, goes to stderr and nothing to stdout)."""
    env = os.environ if env is None else env
    parser = argparse.ArgumentParser(
        prog="python -m flashcards_teams.setup_db",
        description="Create the team tables and reset the app role's rights (run as the tables' owner).",
    )
    parser.add_argument(
        "--create-app-role", action="store_true",
        help="only create the app role, with a new password shown once",
    )
    args = parser.parse_args(argv)
    url = (env.get("FLASHCARDS_SETUP_DATABASE_URL") or "").strip()
    if not url:
        print("FLASHCARDS_SETUP_DATABASE_URL is not set: set it to the table owner's database URL.", file=sys.stderr)
        return 2
    role = (env.get("FLASHCARDS_APP_ROLE") or "").strip() or DEFAULT_APP_ROLE
    if reserved_role(role):
        print(RESERVED, file=sys.stderr)
        return 2

    import psycopg
    from psycopg import sql

    try:
        with psycopg.connect(url, autocommit=True) as conn:
            if args.create_app_role:
                # About 192 bits, well past the 60 Neon asks for.
                password = secrets.token_urlsafe(24)
                conn.execute(sql.SQL(_CREATE_ROLE).format(role=sql.Identifier(role), password=sql.Literal(password)))
                # The only time the password is shown; it is never written anywhere.
                print("Created the app role. Its password, shown only this once:")
                print(password)
                return 0
            new = schema.setup_database(conn, role)
    except schema.SetupRefusedError as e:
        print(e, file=sys.stderr)  # a fixed message: no URL, host or role
        return 1
    except psycopg.Error as e:
        # Only the kind of error: its text may name the host or the user.
        print(f"The database refused or could not be reached: {type(e).__name__} {e.sqlstate or ''}".rstrip(), file=sys.stderr)
        return 1
    print(CREATED if new else RESET)
    return 0


if __name__ == "__main__":
    sys.exit(main())
