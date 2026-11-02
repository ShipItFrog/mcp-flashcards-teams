# Test log

Everything the README claims should be traceable to this log. Items listed under **Pending** have not been run yet.

## Environment

| Item | Value |
|---|---|
| MCP Python SDK | `mcp` 2.3.0 |
| PyJWT | 2.15.1 |
| Postgres driver | `psycopg` 3.3.6, `psycopg-pool` 3.3.3 |
| Local test database | Postgres 18.6 from `postgresql-binaries`, started by the tests on `127.0.0.1` |
| SQLite | 3.50.4 (Python's built-in `sqlite3`) |
| Python | 3.14 |
| OS | Windows 11 |

# Starting point (2026-10-24)

## 1. The inherited server and tests

This repo was created from [mcp-flashcards-cloud](https://github.com/ShipItFrog/mcp-flashcards-cloud) at commit `b52e664`, with `git archive`, so only committed files came across. The package was renamed from `flashcards_cloud` to `flashcards_teams`, and the server name, User-Agent and database application name from `mcp-flashcards-cloud` to `mcp-flashcards-teams`. That repo's TEST-LOG records how each inherited test and broken variant came about.

| Check | Result |
|---|---|
| The inherited test suite, with `FLASHCARDS_REQUIRE_PG=1` | **460 passed**, none skipped |
| The inherited broken variants (`tests/run_mutations.py`) | **all 89 caught** on 2026-10-24, the 9 Postgres-only ones included; none invalid |

# Teams and roles (2026-10-31)

## 2. Teams, roles, invites and permission checks

Added in this step: personal and shared teams, the three roles with one deny-by-default permission table for every team tool, invites, `leave_team`, and audit records written with each change and with members' refused attempts. Reading the audit log and making it append-only come in step 3: `read_audit_log` is one of the 13 tools, but so far it only checks that the caller is an owner and returns no records, although its description, which MCP clients see, already describes the finished tool. On Postgres the server no longer creates tables: `schema.setup_database`, run as the tables' owner, creates them and gives the role the server connects as only the rights it needs. The tests set up their database that way; the command to run it comes in step 3. The code was written by AI agents from a written spec and reviewed by other AI agents (see Reviews below); no person has reviewed it line by line.

| Check | Result |
|---|---|
| The test suite, with `FLASHCARDS_REQUIRE_PG=1` | **1,027 passed**, none skipped: 362 on SQLite, 374 on Postgres, 291 that use no database; about 1 min 45 s |
| The broken variants (`tests/run_mutations.py`, the full run: no `--fast`) | **all 110 caught** in the run of 2026-10-31 (179 minutes from 21:51), the 12 Postgres-only ones included; none invalid. Another project's test runs shared the machine for part of it: see How the recorded run went |

### Inherited tests

- Five were rewritten for teams and renamed: in `test_store`, `test_card_limit_is_per_owner`, `test_total_size_limit_is_per_owner`, `test_numbers_are_per_owner_and_never_reused`, `test_every_method_is_scoped_to_its_owner` and `test_owner_key_never_appears_in_card_data` are now `test_card_limit_is_per_team`, `test_total_size_limit_is_per_team`, `test_numbers_are_per_team_and_never_reused`, `test_every_method_is_scoped_to_its_team` and `test_no_team_or_owner_key_appears_in_card_data`.
- Other inherited tests in `test_store`, `test_store_postgres`, `test_isolation` and `test_tools` kept their names but were adapted to the new store API, a few with extra checks: `test_store_calls_run_off_the_event_loop`, for one, now counts the store's transactions (exactly two, for a read and an add). The other five inherited test files are unchanged.
- One was removed: `test_store_postgres::test_startup_creates_the_tables_once_and_says_which_database`, since the server no longer creates tables on Postgres. Its other check, that the startup line names the database, isn't made on Postgres now (`test_the_database_password_stays_out_of_logs_and_errors` still checks that no password reaches the logs); it comes back with step 3's startup check.

### The broken variants

- **21 new ones** for this step's code:
  - the permission table: `perm-viewer-can-delete`, `perm-viewer-can-grade`, `perm-default-allow`, `perm-members-by-editor`, `perm-any-team`, `perm-role-cached`, `pg-perm-checked-before-lock`;
  - members and invites: `join-role-not-from-invite`, `remove-keeps-row`, `nonmember-distinguishable`, `invite-reusable`, `invite-never-expires`, `invite-stored-raw`;
  - the last owner: `last-owner-unchecked`, `leave-last-owner-unchecked`, `pg-last-owner-without-lock`;
  - the personal team: `pg-personal-team-duplicated`, `pg-personal-team-not-rechecked`;
  - limits and the audit allowance: `team-cap-unchecked`, `refusal-needs-audit-room`, and `no-owner-reserve`, which was planned for step 3 and moved here because the part of the allowance kept for role changes, removals and leaving was built in this step.
- **10 of the 89 inherited ones were rewritten** to fit the new code (cards now belong to teams, the two stores share their SQL and their transaction logic, and two store methods changed name or signature): `unscoped-grade`, `review-ignores-time`, `unpaginated-list`, `pg-number-from-max`, `pg-limit-checked-before-lock`, `pg-number-in-own-transaction`, `pg-review-nulls-last`, `pg-prepared-statements`, `pg-full-as-unavailable`, and one renamed:
  - **`pg-unscoped-grade` is now `unscoped-delete`.** The two stores now share their SQL, so `unscoped-grade` covers grading on both databases; the renamed variant removes the team condition from deleting a card instead, also on both.
- **`unscoped-grade` is caught by different tests now.** The inherited `test_isolation` tests, and `test_store::test_every_method_is_scoped_to_its_team`, no longer reach the grading statement: someone grading another user's card number has no personal team yet, so the call stops earlier. It's caught by `test_team_isolation::test_card_numbers_are_per_team_and_never_cross`, `test_store::test_a_shared_team_has_its_own_cards_and_numbers` and the new `test_isolation::test_grading_or_deleting_by_number_only_touches_your_own_card`.
- **`pg-personal-team-duplicated` was redefined.** It first only removed `ON CONFLICT` from creating the personal team. After the review fix below, the store looks for the personal team again under the server-wide lock, so removing `ON CONFLICT` alone broke nothing: all 10 personal-team tests passed with it. It now removes both the second look and `ON CONFLICT`.
- **12 planned variants were dropped** on 2026-10-30 to keep the full run shorter, and weren't run: `perm-rank-flat`, `perm-membership-only`, `perm-invite-by-editor`, `perm-check-after-lookup`, `reads-create-personal-team`, `personal-team-shareable`, `invite-errors-distinguishable`, `invite-creator-not-rechecked`, `invite-consumed-on-already-member`, `sql-interpolated-team-id`, `denied-raised-in-transaction`, `nonmember-audited`. Eight more, for step 3's code, were dropped too; all 20 are to be added back later (see Pending). One more, `leave-keeps-row` (leaving changes your own role instead of deleting your row), was never added.

### How the recorded run went

The run started at 21:51, once five checks a minute apart had each found no other mutation run on the machine and the CPU less than half busy, and a script noted the machine's state every minute until it ended. The baseline and the first 13 variants ran with nothing else. In 94 of the 178 checks made a minute apart, mutation runs of another project on this machine were going on at the same time, up to three at once; the CPU was never more than 76% busy over a minute.

- Each variant's failing tests were compared with the tests recorded as catching it when it was written: for every variant, every test function recorded for it failed (the run lists test functions, not their parameter cases).
- Some tests depend on timing, threads or several connections at once, so a busy machine could fail them. Each of them failed only with variants that change the code it exercises, and passed in every other variant run.
- Four new variants are caught only by such tests and had no earlier full run to compare with: `pg-personal-team-duplicated`, `pg-personal-team-not-rechecked`, `pg-perm-checked-before-lock` and `pg-last-owner-without-lock`. The tests that catch them hold a lock in another connection and release it only once Postgres shows exactly the expected number of the store's connections waiting on it, so the order of events doesn't depend on timing (only calls taking more than 8 seconds to queue up would fail them). The four were run again on their own on 2026-11-01, after another five quiet minutes, together with `pg-number-in-own-transaction`, which fails two such tests as well as seven others (the one written for it among them). All five failed the same tests, as many times, as in the full run. Another project's run started near the end of the second variant and went on to the end, with the CPU 26 to 35% busy.
- Compared with the two earlier full runs of the inherited variants (mcp-flashcards-cloud's of 2026-10-22 and this repo's of 2026-10-24), the differences are tests new or renamed in this step; tests that no longer reach the code (`unscoped-grade`, above); the removed startup test (Inherited tests, above); one inherited test that `pg-number-in-own-transaction` now fails: `test_store_calls_run_off_the_event_loop` now counts the store's transactions (Inherited tests, above), and the rewritten variant takes its extra transaction through the same method; and three key-handling tests that failed in those runs, some with variants that don't touch the keys, and passed in this one.
- An earlier attempt, started at 00:19 the same day, had other runs alongside from ten minutes in (five to eight at once from 00:53 on, the CPU 91 to 100% busy) and stopped after 29 variants when the session that started it was closed. Its 29 results were all caught, by the same failing tests apart from a test added since.

### Reviews (all by AI agents)

- **The code and the tests, 4 agents.** Two reviewed from two angles (the code, the tests), and two more tried to refute each finding. 6 findings, all confirmed, 1 of medium severity and 5 low (a reviewer rated one more as medium; the agent checking it lowered it to low):
  - medium: `test_isolation`'s grading and deleting tests never reached the card UPDATE or DELETE (see `unscoped-grade` above). Added `test_grading_or_deleting_by_number_only_touches_your_own_card`.
  - low: `test_an_invite_expires` counted the 72 hours from before the invite was made, so a much slower machine could have failed it (measured: 26 ms used of about 1.7 s of margin). Fixed: it now counts from the `expires_at` in the reply.
  - low: on Postgres, two first `add_card` calls by the same person at the same moment, with one team place left on the server: the second was refused as "server full" (SQLite runs one call at a time, so it can't happen there). The store now looks for the personal team again once it holds the server-wide lock. Added `test_first_adds_at_the_last_free_place_both_succeed` and the variant `pg-personal-team-not-rechecked`.
  - low: the static SQL scan (new in this step) missed values joined in with `+`, so its docstring claimed more than it checked. It now catches those too, matches `_SQL_*` names exactly, refuses a statement held in any other variable, and has test cases of its own (`test_the_scan_catches_values_put_into_a_statement`).
  - low: anyone holding a used or expired invite code makes the server lock that team's row for a moment on each `join_team` call. Kept as the spec has it, since the rate limit bounds how often; a comment in the code says so.
  - low: the spec contradicted itself about clearing tables between tests. Fixed in the spec; no code change.
- **The fixes, 1 agent.** 7 findings, all low, all fixed:
  - the first version of the scan change let any expression starting with `_SQL_` through, and missed statements kept in a variable;
  - the longest invite code was read from `limits` when the module loaded, so a test couldn't lower it (the type now spells out 100, and `test_tool_schemas` checks the two agree);
  - after the personal-team fix, no test could reach `ON CONFLICT` any more (it stays as a second line of defence, and `pg-personal-team-duplicated` now removes both), and one parameter was always `True` (removed);
  - docstrings that said more than the code does, and one assertion that depended on the machine's speed.
- **The README and this section, 4 agents.** Two checked every claim against the code, the tests and the records, and two more tried to refute each finding. 20 findings: 13 confirmed (2 medium, 11 low) and fixed, 7 refuted.
  - medium: the README's opening said every refused attempt would be recorded, which no part of the design does: a non-member's attempts never are, and a member's only up to a limit. Rewritten, and the package description no longer says the append-only audit log is there.
  - medium: the README didn't say a team's audit allowance is for life, and what happens once it's used up. It does now.
  - low: three README claims had no test behind them, so three tests were added: `test_limits::test_the_documented_limits` (the README's numbers), `test_limits::test_the_last_part_of_the_audit_allowance_is_kept_for_member_changes` (with the variant `no-owner-reserve`), and `test_sql_safety::test_no_statement_takes_back_an_audit_record`.
  - low: the README's sentence on invites made after their maker rejoins, and eight places where this section was inexact or left something out (the severities above, why ten variants were rewritten, the dropped variants coming back, and the claims table below).
- **The parts of this section written after that, and the commit message, 4 agents.** Two checked every claim in the run record (recomputing its figures from the run's own logs), the inherited tests and the commit message against the records, the code and the previous commit, and two more tried to refute each finding. 13 findings, all low (a reviewer rated one as medium; the agent checking it lowered it to low):
  - 6 confirmed and fixed: the run's length given two ways; a renamed test that `unscoped-grade` no longer reaches; `test_store_calls_run_off_the_event_loop` and other inherited tests changed without being listed; and in the commit message, the count of rewritten variants, and what the refusal limit and the kept part of the allowance apply to.
  - 7 refuted, six of which were taken up anyway as more exact wording, among them that `read_audit_log`'s description already describes the finished tool.
- **Those fixes, 1 agent.** Every finding was handled as described (12 fixed, the commit title kept by choice). 1 more finding, low: the refusal limit and the kept part of the allowance were worded more exactly in the commit message than in this section's variant list and claims table. Fixed.

### README claims and the tests behind them

| Claim | Tests |
|---|---|
| A person's first `add_card` creates their personal team, and reading creates nothing | `test_personal_team`: `test_the_first_add_creates_one_personal_team_with_its_owner`, `test_reading_creates_nothing`, `test_first_adds_race_for_personal_team`, `test_first_adds_at_the_last_free_place_both_succeed` |
| A shared team has its own deck and card numbers, and its creator is its owner | `test_store::test_a_shared_team_has_its_own_cards_and_numbers`, `test_team_isolation::test_card_numbers_are_per_team_and_never_cross`, `test_permission_matrix::test_team_free_tools` |
| Roles are read in the action's own transaction; a demotion or removal counts from the next call | `test_roles`: `test_a_demotion_counts_from_the_next_call`, `test_a_removal_counts_from_the_next_call`; `test_store::test_roles_decide_and_are_read_on_every_call`; `test_roles_postgres::test_write_rechecks_role_after_lock` |
| A person is the token's issuer and subject | `test_team_isolation::test_the_same_subject_from_another_issuer_is_not_a_member`, `test_isolation::test_same_subject_from_another_issuer_is_a_different_person` |
| The role table, deny by default | `test_permission_matrix::test_matrix` (each team tool, called by an owner, an editor, a viewer, a stranger and a removed member, over 4 transports, on both databases); `test_permissions`: `test_required_table_exact`, `test_deny_by_default` |
| The same reply for every stranger; a card in another team looks like a missing one | `test_team_isolation`: `test_another_teams_member_gets_no_team_for_every_tool`, `test_a_real_a_made_up_and_a_malformed_team_id_look_the_same`, `test_card_numbers_are_per_team_and_never_cross`; `test_roles::test_a_missing_and_a_removed_member_look_the_same`; `test_isolation`: `test_someone_elses_card_looks_exactly_like_a_missing_one`, `test_grading_or_deleting_by_number_only_touches_your_own_card` |
| Invites: only the hash stored, one use, 72 hours, the invite's role (editor or viewer), void while its maker isn't an owner, every invalid code the same reply; someone who rejoins is a new member | `test_invites`: `test_only_the_codes_hash_is_stored`, `test_an_invite_works_once`, `test_two_people_using_one_code_at_once`, `test_an_invite_expires`, `test_the_role_comes_from_the_invite`, `test_an_invite_works_again_once_its_maker_is_an_owner_again`, `test_every_invalid_invite_looks_the_same_and_leaves_no_record`; `test_tool_schemas` (the roles an invite can have); `test_roles::test_after_leaving_the_team_is_gone_until_a_new_invite` |
| Codes can't be revoked; an owner can remove anyone who joined | `test_tool_schemas` (the 13 tools, none of which revokes a code); `test_permission_matrix::test_matrix` (the `remove_member` cells); `test_roles::test_a_removal_counts_from_the_next_call` |
| A team always keeps an owner; anyone else can leave; nobody can leave their personal team | `test_roles`: `test_the_only_owner_cant_step_down_or_remove_themselves`, `test_the_only_owner_cant_leave`, `test_an_owner_may_remove_another_owner_but_not_the_last`, `test_with_two_owners_one_may_step_down`, `test_with_two_owners_one_may_leave`, `test_after_leaving_the_team_is_gone_until_a_new_invite`, `test_nobody_can_leave_their_personal_team`; `test_roles_postgres::test_mutual_demotion_waits_on_team_lock` |
| Audit records come with the change (so far the tests check the counters, the refusal records and the personal team's `team.create`; checking every tool's own record is step 3, see Pending) | `test_store::test_team_writes_are_audited_and_refusals_quota`, `test_personal_team::test_the_first_add_creates_one_personal_team_with_its_owner` |
| A lifetime allowance: places never come back, a change with no room for its record isn't made, and the last part is kept for owners changing roles or removing members and for members leaving | `test_sql_safety::test_no_statement_takes_back_an_audit_record` (static: no statement deletes or changes a record or lowers a counter), `test_limits`: `test_a_refusal_the_audit_log_has_no_room_for_still_gives_the_real_reason`, `test_the_last_part_of_the_audit_allowance_is_kept_for_member_changes` |
| Refusals one by one up to 100 per member in each team, then only counted; non-members leave no record | `test_store::test_team_writes_are_audited_and_refusals_quota`, `test_limits::test_a_refusal_the_audit_log_has_no_room_for_still_gives_the_real_reason`, `test_team_isolation::test_another_teams_member_gets_no_team_for_every_tool` |
| The limits (each reached with a lowered value; the README's numbers are checked on their own) | `test_store`: `test_card_limit_is_per_team`, `test_total_size_limit_is_per_team`; `test_limits`: `test_members_per_team`, `test_shared_teams_per_person`, `test_teams_on_the_whole_server`, `test_the_documented_limits`; `test_tools::test_a_full_deck_says_so` |

# Pending

- Step 3: the append-only triggers; `setup_db`, which runs `schema.setup_database` and can create the app role; the server's startup check of that role's rights (with a test that the startup line names the Postgres database, see Inherited tests); reading the audit log; the tests that check every tool's audit record and that no secret reaches the logs; and the final audit and team limits from measured record sizes, each with their broken variants.
- The 20 broken variants dropped on 2026-10-30, added back.
- A deployment of this repo (its own Render service, Neon project and Descope MCP server), tested with real owner, editor and viewer accounts.
