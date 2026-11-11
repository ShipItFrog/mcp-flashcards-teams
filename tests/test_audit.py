"""The audit log is complete: every change to a team adds exactly one record (in the same
transaction, so a change and its record are kept or lost together), every refusal of a
member and every failure one more, and nothing else; only owners read it, a page at a
time, and every read is recorded too.

In the fixture (helpers.team_fixture) dave is the only owner of team A, erin and henry
editors, frank a viewer; gina was removed; bob owns team B and is a stranger in team A.
"""

import logging
from contextlib import contextmanager
from datetime import datetime, timedelta

import psycopg
import pytest
from helpers import (
    AUDIT_FIELDS, ISSUER, actor, admin_connection, assert_audit_counts_agree, audit_counters, audit_rows,
    fresh_postgres_store, mcp_client, payload, raw, refusal, rows, running_app, snapshot, team_fixture,
)

from flashcards_teams import limits
from flashcards_teams import store as store_module
from flashcards_teams.server import (
    M_ALREADY, M_DECK_FULL, M_DENIED, M_LAST_OWNER, M_NO_CARD, M_NO_MEMBER, M_NO_TEAM, M_PERSONAL_LEAVE, M_REFUSED,
)
from flashcards_teams.store import SqliteCardStore

pytestmark = pytest.mark.anyio

CARD = {"question": "Audit question?", "answer": "Audit answer", "topic": "audit"}
UNAVAILABLE = "The card database is temporarily unavailable. Please try again in a minute."


async def call(app, token: str, tool: str, arguments: dict | None = None):
    async with mcp_client(app, token, "auto") as client:
        return await client.call_tool(tool, arguments or {})


def total_records(store) -> int:
    return rows(store, "audit_events")


# --- every change adds exactly one record -------------------------------------------


def change(action: str, f) -> tuple[str, str, dict, list[dict]]:
    """For each audited action: who calls (token), the tool, its arguments, and the records
    it must add (the fields that depend on the call; every one is "ok" with no reason)."""
    n, team = f.numbers, {"team_id": f.team}
    henry = f"member:{n['henry']}"
    return {
        "card.add": ("dave-1", "add_card", {**CARD, **team},
                     [{"member_no": n["dave"], "client_id": "client-dave", "action": "card.add", "target": "card:2",
                       "old_role": None, "new_role": None}]),
        "card.grade": ("erin-1", "grade_card", {"card_id": f.card_no, "correct": True, **team},
                       [{"member_no": n["erin"], "client_id": "client-erin", "action": "card.grade",
                         "target": f"card:{f.card_no}", "old_role": None, "new_role": None}]),
        "card.delete": ("erin-1", "delete_card", {"card_id": f.card_no, **team},
                        [{"member_no": n["erin"], "client_id": "client-erin", "action": "card.delete",
                          "target": f"card:{f.card_no}", "old_role": None, "new_role": None}]),
        "team.create": ("erin-1", "create_team", {"name": "Erin's team"},
                        [{"member_no": 1, "client_id": "client-erin", "action": "team.create", "target": "team",
                          "old_role": None, "new_role": "owner"}]),
        # The first add_card without a team creates the caller's personal team: two records.
        "team.create-personal": ("frank-1", "add_card", CARD,
                                 [{"member_no": 1, "client_id": "client-frank", "action": "team.create",
                                   "target": "team", "old_role": None, "new_role": "owner"},
                                  {"member_no": 1, "client_id": "client-frank", "action": "card.add",
                                   "target": "card:1", "old_role": None, "new_role": None}]),
        "invite.create": ("dave-1", "create_invite", {"role": "viewer", **team},
                          [{"member_no": n["dave"], "client_id": "client-dave", "action": "invite.create",
                            "target": f"invite:{f.invite_no + 1}", "old_role": None, "new_role": "viewer"}]),
        # The new member records their own joining, naming the invite they used.
        "member.join": ("bob-1", "join_team", {"code": f.code},
                        [{"member_no": 6, "client_id": "test-client", "action": "member.join",
                          "target": f"invite:{f.invite_no}", "old_role": None, "new_role": "editor"}]),
        "member.role": ("dave-1", "set_member_role", {"member_no": n["henry"], "role": "viewer", **team},
                        [{"member_no": n["dave"], "client_id": "client-dave", "action": "member.role",
                          "target": henry, "old_role": "editor", "new_role": "viewer"}]),
        "member.remove": ("dave-1", "remove_member", {"member_no": n["henry"], **team},
                          [{"member_no": n["dave"], "client_id": "client-dave", "action": "member.remove",
                            "target": henry, "old_role": "editor", "new_role": None}]),
        "member.leave": ("erin-1", "leave_team", team,
                         [{"member_no": n["erin"], "client_id": "client-erin", "action": "member.leave",
                           "target": f"member:{n['erin']}", "old_role": "editor", "new_role": None}]),
        "audit.read": ("dave-1", "read_audit_log", team,
                       [{"member_no": n["dave"], "client_id": "client-dave", "action": "audit.read",
                         "target": "log:0", "old_role": None, "new_role": None}]),
    }[action]


ACTIONS = [
    "card.add", "card.grade", "card.delete", "team.create", "team.create-personal", "invite.create",
    "member.join", "member.role", "member.remove", "member.leave", "audit.read",
]


@pytest.mark.parametrize("action", ACTIONS)
async def test_each_write_adds_exactly_one_ok_row(store, action):
    f = await team_fixture(store)
    token, tool, arguments, expected = change(action, f)
    creates = action.startswith("team.create")
    # A call that creates a team writes into that new team, from nothing.
    before = ([], (1, 0, 0)) if creates else (audit_rows(store, f.team), audit_counters(store, f.team))
    everywhere = total_records(store)
    async with running_app(store) as app:
        result = payload(await call(app, token, tool, arguments))
    if action == "team.create":
        team_id = result["team_id"]
    elif action == "team.create-personal":
        [(team_id,)] = raw(store, "SELECT team_id FROM teams WHERE personal_of = ?", (actor("frank").principal,))
    else:
        team_id = f.team
    records = audit_rows(store, team_id)
    assert records[: len(before[0])] == before[0]  # nothing earlier changed
    added = records[len(before[0]):]
    assert len(added) == len(expected) and total_records(store) == everywhere + len(expected)
    for i, (record, want) in enumerate(zip(added, expected)):
        assert record["seq"] == len(before[0]) + 1 + i  # numbers go on from the last record, no gaps
        at = datetime.fromisoformat(record["at"])
        assert at.utcoffset() == timedelta(0)
        assert {key: record[key] for key in want} == want
        assert (record["result"], record["reason"]) == ("ok", "")
    next_seq, writes, reads = before[1]
    k = len(expected)
    # A read of the log uses the reads' allowance, everything else the writes'; both take numbers.
    if action == "audit.read":
        assert audit_counters(store, team_id) == (next_seq + k, writes, reads + k)
    else:
        assert audit_counters(store, team_id) == (next_seq + k, writes + k, reads)
    assert_audit_counts_agree(store)


# --- refusals, failures and strangers -----------------------------------------------


async def test_member_denial_adds_exactly_one_denied_row(store):
    f = await team_fixture(store)
    n, team = f.numbers, {"team_id": f.team}
    async with running_app(store) as app:
        for token, tool, arguments, needs, action, target in (
            ("frank-1", "add_card", {**CARD, **team}, "editor", "card.add", "team"),
            ("frank-1", "delete_card", {"card_id": f.card_no, **team}, "editor", "card.delete", f"card:{f.card_no}"),
            ("erin-1", "create_invite", {"role": "viewer", **team}, "owner", "invite.create", "team"),
            ("erin-1", "remove_member", {"member_no": n["frank"], **team}, "owner", "member.remove", f"member:{n['frank']}"),
            ("erin-1", "read_audit_log", {**team, "after_seq": 3}, "owner", "audit.read", "log:3"),
        ):
            name = token.removesuffix("-1")
            before = audit_rows(store, f.team)
            reply = await call(app, token, tool, arguments)
            assert refusal(reply) == M_DENIED.format(tool=tool, role=needs)
            added = audit_rows(store, f.team)[len(before):]
            assert [{k: r[k] for k in AUDIT_FIELDS if k != "at"} for r in added] == [{
                "seq": len(before) + 1, "member_no": n[name], "client_id": f"client-{name}",
                "action": action, "target": target,
                "result": "denied", "reason": "role", "old_role": None, "new_role": None,
            }], tool
    assert_audit_counts_agree(store)


async def test_failed_write_records_failed_not_ok(store, monkeypatch):
    f = await team_fixture(store)
    n, team = f.numbers, {"team_id": f.team}
    dave_no = f"member:{n['dave']}"
    async with running_app(store) as app:
        payload(await call(app, "erin-1", "add_card", CARD))  # erin's personal team
        [(personal,)] = raw(store, "SELECT team_id FROM teams WHERE personal_of = ?", (actor("erin").principal,))
        monkeypatch.setattr(limits, "MAX_CARDS_PER_TEAM", 1)  # team A has one card
        for token, tool, arguments, team_id, message, action, target, reason in (
            ("dave-1", "add_card", {**CARD, **team}, f.team,
             M_DECK_FULL.format(cards=1, chars=limits.MAX_CHARS_PER_TEAM), "card.add", "team", "deck_full"),
            ("erin-1", "grade_card", {"card_id": 999, "correct": False, **team}, f.team,
             M_NO_CARD.format(card_id=999), "card.grade", "card:999", "no_card"),
            ("erin-1", "delete_card", {"card_id": 999, **team}, f.team,
             M_NO_CARD.format(card_id=999), "card.delete", "card:999", "no_card"),
            ("dave-1", "set_member_role", {"member_no": 999, "role": "viewer", **team}, f.team,
             M_NO_MEMBER.format(member_no=999), "member.role", "member:999", "no_member"),
            ("dave-1", "set_member_role", {"member_no": n["dave"], "role": "editor", **team}, f.team,
             M_LAST_OWNER, "member.role", dave_no, "last_owner"),
            ("dave-1", "remove_member", {"member_no": n["dave"], **team}, f.team,
             M_LAST_OWNER, "member.remove", dave_no, "last_owner"),
            ("dave-1", "leave_team", team, f.team, M_LAST_OWNER, "member.leave", dave_no, "last_owner"),
            ("frank-1", "join_team", {"code": f.code}, f.team,
             M_ALREADY.format(member_no=n["frank"]), "member.join", f"invite:{f.invite_no}", "already_member"),
            ("erin-1", "leave_team", {"team_id": personal}, personal,
             M_PERSONAL_LEAVE, "member.leave", "member:1", "personal_team"),
        ):
            before = audit_rows(store, team_id)
            everywhere = total_records(store)
            assert refusal(await call(app, token, tool, arguments)) == message, reason
            added = audit_rows(store, team_id)[len(before):]
            assert [(r["action"], r["target"], r["result"], r["reason"]) for r in added] == [
                (action, target, "failed", reason)
            ], (tool, reason)
            assert total_records(store) == everywhere + 1
    assert_audit_counts_agree(store)


async def test_non_member_attempt_writes_nothing_and_logs_anonymously(store, caplog):
    f = await team_fixture(store)
    team = {"team_id": f.team}
    before = snapshot(store)
    attempts = (
        ("list_cards", team), ("review", team), ("add_card", {**CARD, **team}),
        ("grade_card", {"card_id": f.card_no, "correct": True, **team}), ("delete_card", {"card_id": f.card_no, **team}),
        ("create_invite", {"role": "editor", **team}), ("set_member_role", {"member_no": 2, "role": "viewer", **team}),
        ("remove_member", {"member_no": 2, **team}), ("read_audit_log", team), ("leave_team", team),
    )
    with caplog.at_level(logging.INFO):
        async with running_app(store) as app:
            for token in ("bob-1", "gina-1"):  # a stranger, and a removed member
                for tool, arguments in attempts:
                    assert refusal(await call(app, token, tool, arguments)) == M_NO_TEAM, (token, tool)
    assert snapshot(store) == before  # no record anywhere, nothing else either
    lines = [r.getMessage() for r in caplog.records if r.name == "flashcards_teams.server"]
    assert lines == [f"Refused {tool}: caller is not a member of the requested team" for tool, _ in attempts] * 2
    for secret in ("bob", "gina", ISSUER, f.team, "test-client", "client-gina"):
        assert secret not in caplog.text, secret


# --- a change and its record are kept or lost together --------------------------------


@pytest.fixture
def pg_store(pg_cluster):
    s = fresh_postgres_store(pg_cluster.admin_url, pg_cluster.app_url)
    yield s
    s.close()


@pytest.mark.postgres
async def test_outage_before_commit_leaves_no_row(pg_store, monkeypatch):
    # The connection is lost after the change and its record were both written, before the
    # commit: the caller is told to try again, and neither is kept.
    f = await team_fixture(pg_store)
    original = pg_store.tx

    @contextmanager
    def tx(read_only):
        with original(read_only) as q:
            yield q
            if not read_only:
                raise psycopg.OperationalError("the connection was lost (test)")

    monkeypatch.setattr(pg_store, "tx", tx)
    before = snapshot(pg_store)
    team = {"team_id": f.team}
    async with running_app(pg_store) as app:
        assert refusal(await call(app, "dave-1", "add_card", {**CARD, **team})) == UNAVAILABLE
        assert refusal(await call(app, "dave-1", "set_member_role", {"member_no": f.numbers["henry"], "role": "viewer", **team})) == UNAVAILABLE
        assert refusal(await call(app, "alice-1", "add_card", CARD)) == UNAVAILABLE  # would create her personal team
    # Read through another connection.
    assert snapshot(pg_store) == before
    assert raw(pg_store, "SELECT COUNT(*) FROM cards") == [(1,)]
    assert raw(pg_store, "SELECT COUNT(*) FROM audit_events WHERE team_id = ?", (f.team,)) == [(before["audit"][f.team],)]


@contextmanager
def audit_inserts_fail(store, message: str):
    """A trigger for this test only: every new audit record is refused with ``message``."""
    if isinstance(store, SqliteCardStore):
        with store._lock, store._conn:
            store._conn.execute(
                f"CREATE TRIGGER test_audit_insert_fails BEFORE INSERT ON audit_events"
                f" BEGIN SELECT RAISE(ABORT, '{message}'); END"
            )
        yield
        return
    conn = admin_connection(store._admin_url)
    conn.execute(
        "CREATE OR REPLACE FUNCTION test_audit_insert_fails() RETURNS trigger LANGUAGE plpgsql AS"
        f" $$ BEGIN RAISE EXCEPTION '{message}'; END $$"
    )
    conn.execute(
        "CREATE TRIGGER test_audit_insert_fails BEFORE INSERT ON audit_events"
        " FOR EACH ROW EXECUTE FUNCTION test_audit_insert_fails()"
    )
    try:
        yield
    finally:
        conn.execute("DROP TRIGGER IF EXISTS test_audit_insert_fails ON audit_events")
        conn.execute("DROP FUNCTION IF EXISTS test_audit_insert_fails()")


async def test_audit_write_failure_rolls_back_action(store):
    # The record can't be written, so the change isn't made either: not the card, the role,
    # the invite, the member who joined or left; and the invite is still unused.
    f = await team_fixture(store)
    team = {"team_id": f.team}
    before = snapshot(store)
    with audit_inserts_fail(store, "test: audit insert fails"):
        async with running_app(store) as app:
            for token, tool, arguments in (
                ("dave-1", "add_card", {**CARD, **team}),
                ("dave-1", "delete_card", {"card_id": f.card_no, **team}),
                ("dave-1", "set_member_role", {"member_no": f.numbers["henry"], "role": "viewer", **team}),
                ("dave-1", "create_invite", {"role": "viewer", **team}),
                ("bob-1", "join_team", {"code": f.code}),
                ("erin-1", "leave_team", team),
            ):
                assert refusal(await call(app, token, tool, arguments)) == M_REFUSED, tool
                assert snapshot(store) == before, tool  # the invite's "unused" flag included
    [(unused,)] = raw(store, "SELECT used_at IS NULL FROM invites WHERE team_id = ? AND invite_no = ?", (f.team, f.invite_no))
    assert unused


async def test_action_failure_leaves_no_ok_row(store, monkeypatch):
    # The card can't be inserted: no record says it was.
    f = await team_fixture(store)
    monkeypatch.setattr(store_module, "_SQL_INSERT_CARD", store_module._SQL_INSERT_CARD.replace("INTO cards", "INTO no_such_cards"))
    before = snapshot(store)
    async with running_app(store) as app:
        assert (await call(app, "dave-1", "add_card", {**CARD, "team_id": f.team})).is_error
        assert (await call(app, "alice-1", "add_card", CARD)).is_error  # nor her personal team
    assert snapshot(store) == before
    assert rows(store, "teams") == 2


async def test_refused_error_logs_class_only(store, caplog):
    # The database's own message can quote the row; only the kind of error is logged.
    f = await team_fixture(store)
    sentinel = "SENTINEL-ERR-90210"
    with caplog.at_level(logging.DEBUG), audit_inserts_fail(store, sentinel):
        async with running_app(store) as app:
            assert refusal(await call(app, "dave-1", "add_card", {**CARD, "team_id": f.team})) == M_REFUSED
    assert sentinel not in caplog.text
    kind = "IntegrityError " if isinstance(store, SqliteCardStore) else "RaiseException P0001"
    assert f"The card database refused a change: {kind}" in [r.getMessage() for r in caplog.records]


# --- reading the log ----------------------------------------------------------------------


async def test_read_audit_log_paginates(store):
    dave = actor("dave")
    team = (await store.create_team(dave, "Team A")).value["team_id"]  # record 1
    for i in range(119):  # records 2 to 120
        assert (await store.add(dave, team, f"q{i}", "a", "t")).kind == "ok"
    async with running_app(store) as app, mcp_client(app, "dave-1", "auto") as client:

        async def read(after_seq):
            return payload(await client.call_tool("read_audit_log", {"team_id": team, "limit": 50, "after_seq": after_seq}))

        pages = [await read(0), await read(50), await read(100), await read(122)]
    assert [[e["seq"] for e in p["events"]] for p in pages] == [
        list(range(1, 51)), list(range(51, 101)), list(range(101, 123)), [123],
    ]
    assert [p["next_after_seq"] for p in pages] == [50, 100, None, None]
    assert all(set(e) == set(AUDIT_FIELDS) for p in pages for e in p["events"])
    # Each read is in the next one: records 121, 122 and 123 are the first three reads.
    reads = [e for p in pages for e in p["events"] if e["action"] == "audit.read"]
    assert [(e["seq"], e["target"], e["member_no"], e["result"]) for e in reads] == [
        (121, "log:0", 1, "ok"), (122, "log:50", 1, "ok"), (123, "log:100", 1, "ok"),
    ]
    assert audit_counters(store, team) == (125, 120, 4)
    assert_audit_counts_agree(store)


async def test_read_audit_log_next_page_only_when_more_remain(store):
    dave = actor("dave")
    team = (await store.create_team(dave, "Team A")).value["team_id"]  # record 1
    for i in range(9):  # records 2 to 10
        assert (await store.add(dave, team, f"q{i}", "a", "t")).kind == "ok"
    async with running_app(store) as app, mcp_client(app, "dave-1", "auto") as client:

        async def read():
            return payload(await client.call_tool("read_audit_log", {"team_id": team, "limit": 5, "after_seq": 5}))

        # Exactly a page left (6 to 10): no next page.
        exact = await read()
        # The read itself is record 11, so now one more than a page is left.
        more = await read()
    assert [e["seq"] for e in exact["events"]] == [6, 7, 8, 9, 10] and exact["next_after_seq"] is None
    assert [e["seq"] for e in more["events"]] == [6, 7, 8, 9, 10] and more["next_after_seq"] == 10


async def test_read_audit_log_only_this_team(store):
    f = await team_fixture(store)
    await store.add(actor("bob"), f.other_team, "B's question", "B's answer", "b")
    expected = {team: audit_rows(store, team) for team in (f.team, f.other_team)}
    assert expected[f.team] and expected[f.other_team]
    async with running_app(store) as app:
        for token, team in (("dave-1", f.team), ("bob-1", f.other_team)):
            page = payload(await call(app, token, "read_audit_log", {"team_id": team}))
            assert page["events"] == expected[team] and page["next_after_seq"] is None
        # Team A's owner can't read team B's log at all.
        assert refusal(await call(app, "dave-1", "read_audit_log", {"team_id": f.other_team})) == M_NO_TEAM
