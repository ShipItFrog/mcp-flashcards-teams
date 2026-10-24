# mcp-flashcards-teams

A flashcards MCP server for teams, still being built. The aim: each person signs in with OAuth, teams share decks, every tool call is checked against the member's role (owner, editor or viewer), and every change and every denied attempt leaves an append-only audit record. Built on the official MCP Python SDK 2.x.

> **Status: work in progress.** This repo starts from [mcp-flashcards-cloud](https://github.com/ShipItFrog/mcp-flashcards-cloud) at commit `b52e664`: a hosted, multi-user server with OAuth sign-in, per-user isolation and Postgres storage. Teams, roles and the audit log are being added here. Until they are, the code behaves exactly like that server. See [TEST-LOG.md](TEST-LOG.md) for what has been verified.

## Plan

- **Teams and roles.** Three roles: owner, editor and viewer. Every tool goes through one deny-by-default permission check. Roles live in this server's database and are read on every call, so a role change applies to the next call. The access token only proves who the person is.
- **An append-only audit log.** Every write, every denied attempt by a team member, and every role change is recorded in the same database transaction as the change itself. Database triggers and a database role without UPDATE or DELETE rights stop the app from editing or deleting records. They don't stop the operator or anyone holding the database URL; the Security model will say so.
- **Tests that prove it.** These include a role-by-tool permission matrix, isolation between teams, a check that every write leaves exactly one record, a check that no secrets appear in the log, and deliberately broken variants the tests must catch.

## Run it and run the tests

For now, the same as [mcp-flashcards-cloud](https://github.com/ShipItFrog/mcp-flashcards-cloud#run-it), with `python -m flashcards_teams` as the start command.

```
python -m venv .venv
# Windows: .venv\Scripts\activate    macOS/Linux: source .venv/bin/activate
pip install -r requirements-dev.txt
python -m pytest
python tests/run_mutations.py   # checks that the tests catch deliberately broken variants
```

## License

MIT - see [LICENSE](LICENSE).
