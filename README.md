# mcp-flashcards-teams

A flashcards MCP server for teams, still being built. Each person signs in with OAuth, teams share decks, every team tool checks the caller's role (owner, editor or viewer), and every change leaves an append-only audit record, as do a member's refused attempts, up to a limit per member. Built on the official MCP Python SDK 2.x.

> **Status: work in progress, not deployed yet.** This repo starts from [mcp-flashcards-cloud](https://github.com/ShipItFrog/mcp-flashcards-cloud) at commit `b52e664`: a hosted, multi-user server with OAuth sign-in, per-user isolation and Postgres storage. Teams, roles, invites and the append-only audit log now work, tested on SQLite and on a local Postgres. What's left: running the Neon steps below on Neon, testing the server with real owner, editor and viewer accounts, and a Security model section in this README. See [TEST-LOG.md](TEST-LOG.md) for what has been verified.

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
- **Invites.** An owner's `create_invite` returns a code that's shown only in that reply; only its hash is stored. A code works once, expires after 72 hours, and gives the role it was made for, editor or viewer. It works only while the member who made it is an owner, and works again if that same member is made an owner again (someone who leaves and rejoins is a new member). A wrong, used or expired code all get the same reply. Codes can't be revoked; an owner can remove anyone who joined with a leaked one. A personal team can't have other members, so `create_invite` is refused there.
- **A team always keeps an owner.** Its last owner can't step down, be removed or leave. Anyone else can leave with `leave_team`; to come back they need a new invite. Nobody can leave their personal team.
- **An audit log of every change.** Each change writes its audit record in the same transaction as the change, so no change is kept without its record. A member's refused attempts are recorded the same way, up to a limit (see the allowance below). A record holds the member's number in the team, the time, the action, what it was done to (the team, or a card, member, invite or place in the log, by number), whether it worked and why not, the role given or taken away (for a new team, a join, an invite, a role change, a removal or leaving), and the client ID in the access token (its `client_id` or `azp` claim): a hint at which app made the call, not an identity, kept as printable ASCII and cut to its first 64 characters. It holds no card text, team name, sign-in identity or invite code. A non-member's attempts leave no record. Owners read the log with `read_audit_log`, oldest first, up to 500 records a page; every read is recorded too, and shows up in the pages after it.
- **Append-only, enforced by the database.** On SQLite, triggers refuse to update or delete an audit record, or to insert one in the place of another. On Postgres, triggers refuse every UPDATE, DELETE and TRUNCATE of the audit table, for every role and in every session, and the server connects as a role that may only insert and read audit records. Every transaction the server makes looks up table names in schema `public` only (temporary tables last), so no other schema or temporary table can take the place of its tables. When it starts on Postgres, the server checks the database, and stops with a fixed message naming no URL, host or role, unless:
  - the schema is the version this code expects, and the audit table has exactly the two triggers the setup command makes, enabled for every session and calling its own unchanged function, and nothing added to it: no other trigger, rule, row security, parent or child table. Its columns and constraints aren't compared, and the other tables aren't checked this way;
  - no role the server can act as (the role it connects as, the role it logged in as, and every role either belongs to or can switch to) could change or remove audit records, or gain the right to. None of them may:
    - be a superuser, have CREATEROLE or BYPASSRLS, be Neon's neon_superuser, or hold one of Postgres's roles that read or write the server's files or run programs on it;
    - own the database, any schema, or a table or function in `public`;
    - create objects in the database or in any of its schemas (temporary schemas aside);
    - call a security-definer function in `public` that isn't an extension's;
    - update, delete, truncate or add triggers to the audit table.

  This stops the server's own code paths from changing or removing audit records. It does not stop the database operator or anyone who holds the table owner's database URL: they can drop the triggers or the table. It also does not stop members of neon_superuser (roles created in the Neon Console, CLI or API): they can change teams, members and cards directly, and may be able to add triggers or grant rights. On SQLite there is no database role, so anyone with the file can do the same. The app role can still insert false records; append-only does not mean every record is true. The check covers the rights listed above, and only when the server starts: rights granted while it runs count from its next start.
- **A lifetime allowance of records per team.** Every record but a read of the log uses up one of a team's 100,000 places for good: each change, grading a card included, and each refused attempt that is recorded. A change the allowance has no room for isn't made. The last 200 places are kept for owners changing roles or removing members and for members leaving, so once only those are left, the team's cards can still be read but not added, graded or deleted, and nobody can be invited or join; once those are used up too, the team can only be read. Reads of the log have 2,000 places of their own, so a full log can still be read; after that, only the server's operator can read it, in the database. A member's refused attempts are recorded one by one, up to 100 per member in each team; after that, or once only the kept places are left, they're only counted. Owners see every member's count, and how much of both allowances is used, in `list_teams`.
- **A daily limit per member.** Each member can make 500 changes a day in each team (adding, grading or deleting cards, and creating invites; the day is UTC), so a runaway app can't use up a team's allowance in an afternoon. Changing roles, removing members, leaving and reading the log never count, so the daily limit never stops an owner from removing a runaway member.
- **Other limits:** 1,000 cards and 200,000 characters per team, 25 members per team, 1,000 invite codes per team for its whole life, and 2 shared teams per person besides their personal team. At most 12 teams on the server, personal ones included (see Capacity); once it's full, nobody can create a team or a personal deck.
- **One write at a time per team.** On Postgres, each write to a team locks the team's row before it checks the caller's role, so writes to one team never interleave. SQLite runs every call one at a time.
- **Postgres ends stuck transactions.** A transaction left idle for 30 seconds, or a statement running for 30 seconds, is ended by Postgres, and the call reports the database as temporarily unavailable, so a stuck call can't hold back Postgres's cleanup of old row versions for long. This covers the server's own connections only, not, for example, a transaction the operator leaves open in psql.

## Capacity

Every team may be filled to all its limits, so the number of teams comes from one team's worst case, measured on Postgres 18.6 with rows at the server's size limits (details in [TEST-LOG.md](TEST-LOG.md)):

| Part of one team | Bytes |
|---|---|
| 102,000 audit records (100,000 writes and 2,000 reads), 344.9 bytes each | 35,176,448 |
| 1,000 used invites, 456.3 bytes each | 456,294 |
| 1,000 cards at the size limit, after adding 16 cards and deleting 15 over and over on a shared server | 4,063,232 |
| 25 members, as the real store left them after 102,000 calls | 131,072 |
| the team's own row, as the real store left it after 102,000 calls | 139,264 |
| **worst case for one team** | **39,966,310 (about 40 MB)** |

Two things aren't in the table, estimated at about 0.35 MB a team: sign-in identities, whose length the server doesn't limit, and topic keys, which case-folding can make longer than their topics. The server plans for half of the database, so every team at its worst case fits with room to spare for them and for the rest of Postgres:

| Database size | Teams |
|---|---|
| 1 GB (Neon's free plan) | 12 |
| 5 GB | 62 |
| 10 GB | 125 |

The server is set for 1 GB: on a larger database, raise `MAX_TEAMS_TOTAL` in `flashcards_teams/limits.py` to the number in this table. The allowance is per team, and "normal use" was defined for one person: 50 card changes a day for five years. A team of five who each make that many changes every day would use up its places for card changes in about 13 months. After that its cards can only be read, though owners can still change roles and remove members, and members can still leave, until the kept places are used too. Its members can start a new shared team if the server has room and they are in fewer than 2 shared teams, that one included; a personal team can't be replaced, since each person has only one. When the demo server fills up, its operator will reset its database, deleting everything in it.

## Set it up on Postgres (Neon)

The server never creates tables on Postgres: the tables' owner sets them up with a command run from their own machine, never from the server. Setup needs Postgres 14 or later, and the tests and measurements ran on Postgres 18.6; use 15 or later (see below about 14). Neon counts the storage of every branch, so keep only one branch with data.

1. Note the empty project's storage in Neon's console, to compare with later.
2. Create the role the server will connect as, with `FLASHCARDS_SETUP_DATABASE_URL` set to the database owner's URL: `python -m flashcards_teams.setup_db --create-app-role`. It prints the new role's password once. The password goes to Postgres inside the CREATE ROLE statement, so a server set to log statements could log it; whether Neon accepts a password hashed beforehand is still to be tried (see TEST-LOG's Pending). Don't type the password into Neon's SQL Editor, which keeps a history of queries. If you have, give the role a new password from your own machine, for example with psql's `\password flashcards_app`: the command can't, since it only creates the role.
3. Create a test branch from main (after step 2: roles belong to a branch).
4. With `FLASHCARDS_SETUP_DATABASE_URL` set to the owner's URL for the test branch (each branch has its own host), run `python -m flashcards_teams.setup_db`. Then start the server against the branch with the app role's URL for it, to see the setup and the startup check pass, and try what a role made in the Neon Console can do to the audit table (see TEST-LOG's Pending).
5. Run `python -m flashcards_teams.setup_db` on main, then delete the test branch. If you ever restore main from its history, delete the backup branch Neon makes.
6. Give the hosting service only the app role's URL (`FLASHCARDS_DATABASE_URL`). The owner's URL never goes there, or into the repo. The server sets nothing that outlives a transaction, so it is meant to work through Neon's pooled (`-pooler`) URL; that is still to be tried on Neon (see TEST-LOG's Pending). Setup can use the owner's direct URL.

`FLASHCARDS_APP_ROLE` names the app role (default `flashcards_app`); a reserved name such as `public` is refused.

Setup runs with the owner's rights, so it guards against running code another role left in `public`. It looks up every name in `public`; its queries call Postgres's own functions by their full names, and its table definitions use only functions and operators Postgres has an exact match for. It stops, changing nothing, if `public` holds tables or functions another role owns (an extension's objects excepted), or a trigger on any table there but the audit table that calls another role's function (an extension's excepted). It also stops if every role may still create objects in the database: on Postgres 14, or a database upgraded from it, `public` belongs to a superuser and lets every role create objects there, so the owner of `public` or a superuser has to revoke that, and grant CREATE on `public` to the role that runs setup. Running setup again makes the audit table's two triggers and their function anew, resets the app role's rights on the server's tables, gives it back the use of `public`, and takes back its CREATE on the database and on `public`. It changes nothing else of the app role's: roles granted to it, its attributes, objects it owns, rights elsewhere, and rights another role passed on to it with its grant option stay until you remove them, and until then the server refuses to start if any of them could reach the audit records.

If the server stops at startup: "isn't set up" means run setup (as the owner) on this database or branch, and if it still says so afterwards, either the server's URL belongs to a role other than the one setup was run for (`FLASHCARDS_APP_ROLE`), or the audit table has something setup didn't make (another trigger, a rule, row security, a parent or child table), which the table's owner has to remove; "too powerful" means the URL isn't the app role's, or the app role was given more rights or roles since setup (roles made in the Neon Console belong to neon_superuser and are always refused); "every role" means every role may create objects in the database or in one of its schemas, usually the Postgres 14 case above. If setup stops, it has changed nothing: remove what its message names, or run it as that object's owner. The startup check hasn't been run on Neon yet.

## Not handled

- No hash chain or outside anchor for the audit log, and no third-party audit.
- Audit records never expire, and teams can't be deleted.
- Invite codes can't be revoked; they expire after 72 hours.
- A refused permission is an ordinary tool error, with no step-up sign-in (HTTP 403 is for a token without the required scope, and for a request whose Origin header isn't one the server allows).
- Neon also keeps 6 hours of change history, with a 1 GB limit of its own. Its documentation doesn't say what happens past that limit, or whether the history counts toward the 1 GB of storage. To be watched once the server is deployed.

## Not built yet

- A deployment of this repo (its own Render service, Neon project and Descope MCP server), tested with real owner, editor and viewer accounts.
- A Security model section in this README.

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
