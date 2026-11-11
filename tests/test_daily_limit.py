"""Each member's changes in each team are limited per UTC day
(limits.MAX_WRITES_PER_MEMBER_PER_DAY), so a runaway client can't use up a team's
lifetime audit allowance in an afternoon. Only the successful calls of
permissions.DAILY_CAPPED_TOOLS count; member changes, leaving and reading the log are
never limited, so an owner can always remove the runaway member.

The store's clock is fixed (``clock``), and the limit lowered with monkeypatch.
In the fixture (helpers.team_fixture) dave is the only owner of team A, erin and henry
editors, frank a viewer; bob owns team B.
"""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from helpers import (
    actor, audit_rows, fresh_postgres_store, mcp_client, payload, queued_behind, raw, refusal, running_app,
    snapshot, team_fixture, without_audit,
)

from flashcards_teams import ids, limits
from flashcards_teams.server import M_DAILY_LIMIT, M_DECK_FULL, M_DENIED, M_NO_CARD

pytestmark = pytest.mark.anyio

CARD = {"question": "Daily question?", "answer": "Daily answer", "topic": "daily"}
# A minute before midnight UTC on 2026-11-07.
LATE = datetime(2026, 11, 7, 23, 59, tzinfo=timezone.utc)
TODAY = "2026-11-07"


def fix_clock(monkeypatch, store, when: datetime) -> SimpleNamespace:
    """Fix the store's clock at ``when``; set the returned object's ``now`` to move it."""
    clock = SimpleNamespace(now=when)
    monkeypatch.setattr(store, "_clock", lambda: clock.now)
    return clock


@pytest.fixture
def clock(store, monkeypatch):
    return fix_clock(monkeypatch, store, LATE)


@pytest.fixture
def three_a_day(monkeypatch):
    """Call it to lower the limit to three changes a day: after the team fixture, whose
    owner makes six."""
    return lambda: monkeypatch.setattr(limits, "MAX_WRITES_PER_MEMBER_PER_DAY", 3)


def writes(store, team_id: str, member_no: int) -> tuple[str, int]:
    """A member's (writes_day, writes_today) in a team."""
    [row] = raw(store, "SELECT writes_day, writes_today FROM members WHERE team_id = ? AND member_no = ?", (team_id, member_no))
    return tuple(row)


def refused(store, team_id: str, member_no: int) -> int:
    [(count,)] = raw(store, "SELECT refused_count FROM members WHERE team_id = ? AND member_no = ?", (team_id, member_no))
    return count


LIMITED = M_DAILY_LIMIT.format(n=3)


async def test_a_member_is_stopped_at_the_days_limit(store, clock, three_a_day):
    f = await team_fixture(store)
    three_a_day()
    n, team = f.numbers, {"team_id": f.team}
    # The owner's five invites and one card in the fixture were all counted, together.
    assert writes(store, f.team, n["dave"]) == (TODAY, 6)
    async with running_app(store) as app:
        async with mcp_client(app, "erin-1", "auto") as erin:
            new = payload(await erin.call_tool("add_card", {**CARD, **team}))["card"]["id"]
            payload(await erin.call_tool("grade_card", {"card_id": f.card_no, "correct": True, **team}))
            payload(await erin.call_tool("delete_card", {"card_id": new, **team}))
            assert writes(store, f.team, n["erin"]) == (TODAY, 3)
            for tool, arguments in (
                ("add_card", {**CARD, **team}),
                ("grade_card", {"card_id": f.card_no, "correct": True, **team}),
                ("delete_card", {"card_id": f.card_no, **team}),
            ):
                before, records, count = snapshot(store), audit_rows(store, f.team), refused(store, f.team, n["erin"])
                assert refusal(await erin.call_tool(tool, arguments)) == LIMITED, tool
                # Nothing changed but one refusal counted and recorded.
                assert without_audit(snapshot(store)) == without_audit(before)
                added = audit_rows(store, f.team)[len(records):]
                assert [(r["member_no"], r["result"], r["reason"]) for r in added] == [(n["erin"], "failed", "daily_limit")]
                assert refused(store, f.team, n["erin"]) == count + 1
        async with mcp_client(app, "dave-1", "auto") as dave:
            assert refusal(await dave.call_tool("create_invite", {"role": "viewer", **team})) == LIMITED
        # Another member of the team isn't affected.
        async with mcp_client(app, "henry-1", "auto") as henry:
            payload(await henry.call_tool("add_card", {**CARD, **team}))
    assert writes(store, f.team, n["erin"]) == (TODAY, 3)


async def test_the_limit_comes_after_the_permission_and_before_any_lookup(store, clock, three_a_day):
    # The order of the checks: the permission, then the day's limit, then whether the card
    # exists. A member past the limit learns nothing about which cards exist, and one who
    # may not use a tool at all is told that, not that the day's changes are used up.
    f = await team_fixture(store)
    three_a_day()
    n, team = f.numbers, {"team_id": f.team}
    async with running_app(store) as app:
        async with mcp_client(app, "erin-1", "auto") as erin:
            for _ in range(3):
                payload(await erin.call_tool("add_card", {**CARD, **team}))
            for tool, arguments in (
                ("grade_card", {"card_id": 999, "correct": True, **team}),
                ("delete_card", {"card_id": 999, **team}),
            ):
                assert refusal(await erin.call_tool(tool, arguments)) == LIMITED, tool
        async with mcp_client(app, "dave-1", "auto") as dave:
            payload(await dave.call_tool("set_member_role", {"member_no": n["erin"], "role": "viewer", **team}))
        async with mcp_client(app, "erin-1", "auto") as erin:
            records = audit_rows(store, f.team)
            assert refusal(await erin.call_tool("add_card", {**CARD, **team})) == M_DENIED.format(
                tool="add_card", role="editor"
            )
    added = audit_rows(store, f.team)[len(records):]
    assert [(r["member_no"], r["action"], r["result"], r["reason"]) for r in added] == [
        (n["erin"], "card.add", "denied", "role")
    ]


async def test_the_limit_starts_again_each_utc_day(store, clock, three_a_day):
    f = await team_fixture(store)
    three_a_day()
    erin, team = f.numbers["erin"], {"team_id": f.team}
    async with running_app(store) as app, mcp_client(app, "erin-1", "auto") as client:
        for _ in range(3):
            payload(await client.call_tool("add_card", {**CARD, **team}))
        # Still 2026-11-07 in UTC, though the clock reads the 8th in UTC+8.
        clock.now = datetime(2026, 11, 8, 7, 59, 59, tzinfo=timezone(timedelta(hours=8)))
        assert refusal(await client.call_tool("add_card", {**CARD, **team})) == LIMITED
        # Just after midnight UTC.
        clock.now = datetime(2026, 11, 8, 8, 0, 1, tzinfo=timezone(timedelta(hours=8)))
        payload(await client.call_tool("add_card", {**CARD, **team}))
        assert writes(store, f.team, erin) == ("2026-11-08", 1)
        payload(await client.call_tool("add_card", {**CARD, **team}))
        payload(await client.call_tool("add_card", {**CARD, **team}))
        assert refusal(await client.call_tool("add_card", {**CARD, **team})) == LIMITED
    assert writes(store, f.team, erin) == ("2026-11-08", 3)


async def test_member_changes_leaving_and_reading_the_log_are_never_limited(store, clock, three_a_day):
    f = await team_fixture(store)
    three_a_day()
    n, team = f.numbers, {"team_id": f.team}
    async with running_app(store) as app:
        async with mcp_client(app, "erin-1", "auto") as erin:
            for _ in range(3):
                payload(await erin.call_tool("add_card", {**CARD, **team}))
            assert refusal(await erin.call_tool("add_card", {**CARD, **team})) == LIMITED
            payload(await erin.call_tool("leave_team", team))
        # dave is past the limit too (6 changes in the fixture).
        async with mcp_client(app, "dave-1", "auto") as dave:
            assert refusal(await dave.call_tool("add_card", {**CARD, **team})) == LIMITED
            payload(await dave.call_tool("set_member_role", {"member_no": n["henry"], "role": "viewer", **team}))
            payload(await dave.call_tool("remove_member", {"member_no": n["henry"], **team}))
            assert payload(await dave.call_tool("read_audit_log", team))["events"]
            assert payload(await dave.call_tool("list_cards", team))["total"] == 4
    assert writes(store, f.team, n["dave"]) == (TODAY, 6)


async def test_each_member_counts_in_each_team_on_their_own(store, clock, three_a_day):
    f = await team_fixture(store)
    three_a_day()
    n = f.numbers
    # erin joins bob's team B too.
    code = ids.new_invite_code()
    assert (await store.create_invite(actor("bob"), f.other_team, "editor", ids.hash_invite(code))).kind == "ok"
    erin_in_b = (await store.join_team(actor("erin"), ids.hash_invite(code))).value["member_no"]
    async with running_app(store) as app:
        async with mcp_client(app, "erin-1", "auto") as erin:
            for _ in range(3):
                payload(await erin.call_tool("add_card", {**CARD, "team_id": f.team}))
            assert refusal(await erin.call_tool("add_card", {**CARD, "team_id": f.team})) == LIMITED
            payload(await erin.call_tool("add_card", {**CARD, "team_id": f.other_team}))
        async with mcp_client(app, "henry-1", "auto") as henry:
            payload(await henry.call_tool("add_card", {**CARD, "team_id": f.team}))
    assert writes(store, f.team, n["erin"]) == (TODAY, 3)
    assert writes(store, f.other_team, erin_in_b) == (TODAY, 1)
    assert writes(store, f.team, n["henry"]) == (TODAY, 1)


async def test_what_doesnt_count(store, clock, three_a_day, monkeypatch):
    f = await team_fixture(store)
    three_a_day()
    n, team = f.numbers, {"team_id": f.team}
    # Joining (in the fixture) didn't count.
    assert writes(store, f.team, n["erin"]) == ("", 0) and writes(store, f.team, n["frank"]) == ("", 0)
    async with running_app(store) as app:
        async with mcp_client(app, "erin-1", "auto") as erin:
            mine = payload(await erin.call_tool("create_team", {"name": "Erin's"}))["team_id"]
            payload(await erin.call_tool("read_audit_log", {"team_id": mine}))
            assert writes(store, mine, 1) == ("", 0)
            # Failures don't count.
            assert refusal(await erin.call_tool("grade_card", {"card_id": 999, "correct": True, **team})) == (
                M_NO_CARD.format(card_id=999)
            )
            monkeypatch.setattr(limits, "MAX_CARDS_PER_TEAM", 1)
            assert refusal(await erin.call_tool("add_card", {**CARD, **team})) == M_DECK_FULL.format(
                cards=1, chars=limits.MAX_CHARS_PER_TEAM
            )
        # Nor do refusals.
        async with mcp_client(app, "frank-1", "auto") as frank:
            assert refusal(await frank.call_tool("add_card", {**CARD, **team})) == M_DENIED.format(
                tool="add_card", role="editor"
            )
    assert writes(store, f.team, n["erin"]) == ("", 0) and writes(store, f.team, n["frank"]) == ("", 0)


async def test_a_personal_team_has_the_limit_too(store, clock, three_a_day):
    three_a_day()
    async with running_app(store) as app, mcp_client(app, "alice-1", "auto") as alice:
        payload(await alice.call_tool("add_card", CARD))  # creates the personal team: one change, not two
        [(team_id,)] = raw(store, "SELECT team_id FROM teams")
        assert writes(store, team_id, 1) == (TODAY, 1)
        payload(await alice.call_tool("add_card", CARD))
        payload(await alice.call_tool("grade_card", {"card_id": 1, "correct": True}))
        assert refusal(await alice.call_tool("add_card", CARD)) == LIMITED
        assert refusal(await alice.call_tool("delete_card", {"card_id": 1})) == LIMITED
    assert writes(store, team_id, 1) == (TODAY, 3)


@pytest.fixture
def pg_store(pg_cluster):
    s = fresh_postgres_store(pg_cluster.admin_url, pg_cluster.app_url)
    yield s
    s.close()


@pytest.mark.postgres
async def test_daily_limit_waits_on_team_lock(pg_store, monkeypatch, three_a_day):
    # One change left today, and four adds held at the team's row until all four wait
    # there: exactly one gets it. The member row each one reads under the lock is the
    # one that counts.
    fix_clock(monkeypatch, pg_store, LATE)
    f = await team_fixture(pg_store)
    three_a_day()
    erin = actor("erin")
    for i in range(2):
        assert (await pg_store.add(erin, f.team, f"q{i}", "a", "t")).kind == "ok"

    def hold(conn):
        conn.execute("SELECT 1 FROM teams WHERE team_id = %s FOR UPDATE", (f.team,))

    outcomes = await queued_behind(pg_store, hold, [pg_store.add(erin, f.team, f"c{i}", "a", "t") for i in range(4)], waiting=4)
    assert sorted((o.kind, o.reason) for o in outcomes) == [("failed", "daily_limit")] * 3 + [("ok", "")]
    assert writes(pg_store, f.team, f.numbers["erin"]) == (TODAY, 3)
    assert raw(pg_store, "SELECT COUNT(*) FROM cards WHERE team_id = ?", (f.team,)) == [(4,)]
