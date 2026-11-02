# mcp-flashcards-teams

A flashcards MCP server for teams, still being built. The aim: each person signs in with OAuth, teams share decks, every team tool checks the caller's role (owner, editor or viewer), and every change leaves an append-only audit record, as do a member's refused attempts, up to a limit per member. Built on the official MCP Python SDK 2.x.

> **Status: work in progress. Don't deploy this version.** This repo starts from [mcp-flashcards-cloud](https://github.com/ShipItFrog/mcp-flashcards-cloud) at commit `b52e664`: a hosted, multi-user server with OAuth sign-in, per-user isolation and Postgres storage. Teams, roles and invites now work, tested on SQLite and on a local Postgres. The audit log is only partly built: records are written, but the database doesn't stop them from being changed or deleted yet, and the server can't show them yet. Postgres has no setup command yet: the code that creates the tables exists, but only the tests run it. See [TEST-LOG.md](TEST-LOG.md) for what has been verified.

## What works now

- **A personal deck and shared teams.** A person's first `add_card` creates their personal team, which the card tools use unless they're given a `team_id`. `create_team` makes a shared team with its own deck and its own card numbers, and its creator becomes its owner.
- **Roles, read on every call.** Roles live in this server's database and are read again in the same transaction as the action they allow, so a demotion or a removal counts from the very next call. The access token says who the person is (its issuer and subject); what they may do comes only from the database. One deny-by-default table decides:

  | Tool | owner | editor | viewer |
  |---|---|---|---|
  | `list_cards`, `review` | yes | yes | yes |
  | `add_card`, `grade_card`, `delete_card` | yes | yes | no |
  | `create_invite`, `set_member_role`, `remove_member`, `read_audit_log` | yes | no | no |
  | `leave_team` | yes, unless they're the last owner | yes | yes |

  Viewers can't grade, because a card's review count and time are shared by the whole team. `create_team`, `list_teams` and `join_team` belong to no team: being signed in is enough.
- **The same reply for every stranger.** Someone who isn't a member, a removed member, and a team that doesn't exist all get the same reply, and a card in another team looks just like a missing one.
- **Invites.** An owner's `create_invite` returns a code that's shown only in that reply; only its hash is stored. A code works once, expires after 72 hours, and gives the role it was made for, editor or viewer. It works only while the member who made it is an owner, and works again if that same member is made an owner again (someone who leaves and rejoins is a new member). A wrong, used or expired code all get the same reply. Codes can't be revoked; an owner can remove anyone who joined with a leaked one.
- **A team always keeps an owner.** Its last owner can't step down, be removed or leave. Anyone else can leave with `leave_team`; to come back they need a new invite. Nobody can leave their personal team.
- **Audit records, in part.** Changes, and members' refused attempts, write their audit records in the same transaction as the change or refusal. Each team has a lifetime allowance of records: every change uses up one place for good, grading a card included, and a change the allowance has no room for isn't made. The last part of it is kept for owners changing roles or removing members and for members leaving, so once only that part is left, the team's cards can still be read but not added, graded or deleted, and nobody can be invited or join. A member's refused attempts are recorded one by one, up to 100 per member in each team; after that, or once only the kept part is left, they're only counted. A non-member's attempts leave no record at all.
- **Limits:** 1,000 cards and 200,000 characters per team, 25 members per team, 10 shared teams per person. The audit log and the number of teams on the server have limits too, but their numbers are placeholders until the size of an audit record has been measured.

## Not built yet

- **Append-only enforcement:** database triggers, and on Postgres a database role that can't update or delete audit records, which the server checks at startup.
- **Reading the audit log:** `read_audit_log` checks that the caller is an owner, then returns no records.
- **The Postgres setup command** (`python -m flashcards_teams.setup_db`), run as the tables' owner, so this version can run on Neon.
- **The tests that check every tool's audit record,** and that no secret from any tool reaches the logs or the audit log.
- **The final audit and team limits,** set by measuring record sizes against Neon's free storage.
- **A Security model** in this README, and a deployment tested with real owner, editor and viewer accounts.

## Run it and run the tests

To try it locally, run it like [mcp-flashcards-cloud](https://github.com/ShipItFrog/mcp-flashcards-cloud#run-it) with a SQLite file (`FLASHCARDS_DB`), with `python -m flashcards_teams` as the start command.

```
python -m venv .venv
# Windows: .venv\Scripts\activate    macOS/Linux: source .venv/bin/activate
pip install -r requirements-dev.txt
python -m pytest
python tests/run_mutations.py   # checks that the tests catch deliberately broken variants (a full test run each: hours)
```

## License

MIT - see [LICENSE](LICENSE).
