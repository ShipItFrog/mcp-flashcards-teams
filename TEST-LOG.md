# Test log

Everything the README claims should be traceable to this log. Items listed under **Pending** have not been run yet.

## Environment

| Item | Value |
|---|---|
| MCP Python SDK | `mcp` 2.3.0 |
| PyJWT | 2.15.1 |
| Postgres driver | `psycopg` 3.3.6, `psycopg-pool` 3.3.3 |
| Local test database | Postgres 18.6 from `postgresql-binaries`, started by the tests on `127.0.0.1` |
| Python | 3.14 |
| OS | Windows 11 |

# Starting point (2026-10-24)

## 1. The inherited server and tests

This repo was created from [mcp-flashcards-cloud](https://github.com/ShipItFrog/mcp-flashcards-cloud) at commit `b52e664`, with `git archive`, so only committed files came across. The package was renamed from `flashcards_cloud` to `flashcards_teams`, and the server name, User-Agent and database application name from `mcp-flashcards-cloud` to `mcp-flashcards-teams`. That repo's TEST-LOG records how each inherited test and broken variant came about.

| Check | Result |
|---|---|
| The inherited test suite, with `FLASHCARDS_REQUIRE_PG=1` | **460 passed**, none skipped |
| The inherited broken variants (`tests/run_mutations.py`) | **all 89 caught** on 2026-10-24, the 9 Postgres-only ones included; none invalid |

- **Pending:**
  - teams, roles and the audit log, with their tests and broken variants;
  - a deployment of this repo (its own Render service, Neon project and Descope MCP server), tested with real owner, editor and viewer accounts.
