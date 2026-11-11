"""Each team's audit log has a fixed allowance, and fails closed: a change it has no room
to record is not made. The last part of the write allowance is kept for member changes
(owners changing or removing members, members leaving); reads of the log have an
allowance of their own; refusals are recorded only up to each member's quota.

The limits are lowered with monkeypatch (``small_limits``) so they are quick to reach.
"""

import logging

import pytest
from helpers import (
    actor, assert_audit_counts_agree, audit_counters, audit_rows, fresh_postgres_store, mcp_client, payload,
    queued_behind, raw, refusal, running_app, snapshot, team_fixture,
)

from flashcards_teams import ids, limits
from flashcards_teams.server import (
    M_AUDIT_FULL, M_AUDIT_NEARLY_FULL, M_AUDIT_READS_FULL, M_DENIED, M_LAST_OWNER, M_NO_CARD,
)
from flashcards_teams.store import AuditFullError

pytestmark = pytest.mark.anyio

CARD = {"question": "Cap question?", "answer": "Cap answer", "topic": "cap"}
DENIED_ADD = M_DENIED.format(tool="add_card", role="editor")


@pytest.fixture
def small_limits(monkeypatch):
    """10 write records per team, the last 2 kept for member changes, 3 reads, and 2
    refusals recorded per member."""
    monkeypatch.setattr(limits, "AUDIT_CAP_PER_TEAM", 10)
    monkeypatch.setattr(limits, "AUDIT_OWNER_RESERVE", 2)
    monkeypatch.setattr(limits, "AUDIT_READS_CAP_PER_TEAM", 3)
    monkeypatch.setattr(limits, "MAX_REFUSALS_LOGGED_PER_MEMBER", 2)


async def small_team(store, *members: tuple[str, str], cards: int = 0) -> tuple[str, dict[str, int]]:
    """A new team of dave's, through the store: for each (name, role) an invite and that
    person joining, then ``cards`` cards. 1 + 2 × len(members) + cards write records."""
    dave = actor("dave")
    team = (await store.create_team(dave, "Small")).value["team_id"]
    numbers = {"dave": 1}
    for name, role in members:
        code = ids.new_invite_code()
        assert (await store.create_invite(dave, team, role, ids.hash_invite(code))).kind == "ok"
        numbers[name] = (await store.join_team(actor(name), ids.hash_invite(code))).value["member_no"]
    for i in range(cards):
        assert (await store.add(dave, team, f"q{i}", "a", "t")).kind == "ok"
    return team, numbers


def refused_counts(store, team_id: str) -> dict[int, int]:
    return dict(raw(store, "SELECT member_no, refused_count FROM members WHERE team_id = ?", (team_id,)))


async def test_writes_stop_at_the_cap_but_member_changes_use_the_reserve(store, small_limits):
    team_id, n = await small_team(store, ("erin", "editor"), ("frank", "viewer"), ("henry", "editor"), cards=1)
    team = {"team_id": team_id}
    assert audit_counters(store, team_id) == (9, 8, 0)  # only the reserve is left
    async with running_app(store) as app:
        async with mcp_client(app, "dave-1", "auto") as dave, mcp_client(app, "erin-1", "auto") as erin, \
                mcp_client(app, "frank-1", "auto") as frank:
            before = snapshot(store)
            assert refusal(await erin.call_tool("add_card", {**CARD, **team})) == M_AUDIT_NEARLY_FULL
            assert refusal(await dave.call_tool("add_card", {**CARD, **team})) == M_AUDIT_NEARLY_FULL
            assert snapshot(store) == before  # no card and no record
            # Records 9 and 10: an editor leaves, the owner changes a role.
            payload(await erin.call_tool("leave_team", team))
            payload(await dave.call_tool("set_member_role", {"member_no": n["frank"], "role": "editor", **team}))
            assert audit_counters(store, team_id) == (11, 10, 0)
            full = snapshot(store)
            # The 11th has no room left at all.
            assert refusal(await dave.call_tool("remove_member", {"member_no": n["henry"], **team})) == M_AUDIT_FULL
            assert refusal(await dave.call_tool("add_card", {**CARD, **team})) == M_AUDIT_FULL
            assert snapshot(store) == full
            # Reading the cards is never recorded, so it still works.
            assert payload(await frank.call_tool("list_cards", team))["total"] == 1
            assert payload(await frank.call_tool("review", team))["card_id"] == 1
    assert_audit_counts_agree(store)


async def test_owners_still_read_the_log_when_the_writes_are_full(store, small_limits):
    team_id, n = await small_team(store, ("erin", "editor"), ("frank", "viewer"), ("henry", "editor"), cards=1)
    dave = actor("dave")
    assert (await store.set_member_role(dave, team_id, n["frank"], "editor")).kind == "ok"
    assert (await store.remove_member(dave, team_id, n["henry"])).kind == "ok"
    assert audit_counters(store, team_id) == (11, 10, 0)  # the writes are full
    async with running_app(store) as app, mcp_client(app, "dave-1", "auto") as client:
        for i in range(2):
            events = payload(await client.call_tool("read_audit_log", {"team_id": team_id}))["events"]
            # Each read is one more record, the reads' own.
            assert len(events) == 10 + i and [e["action"] for e in events[10:]] == ["audit.read"] * i
            assert audit_counters(store, team_id) == (12 + i, 10, 1 + i)
    assert_audit_counts_agree(store)


async def test_reads_fail_closed_when_their_allowance_is_used_up(store, small_limits, caplog):
    team_id, _ = await small_team(store, ("erin", "editor"))
    async with running_app(store) as app, mcp_client(app, "dave-1", "auto") as client:
        for _ in range(3):
            payload(await client.call_tool("read_audit_log", {"team_id": team_id}))
        before = (snapshot(store), audit_counters(store, team_id))
        assert before[1] == (7, 3, 3)
        with caplog.at_level(logging.WARNING, logger="flashcards_teams.server"):
            assert refusal(await client.call_tool("read_audit_log", {"team_id": team_id})) == M_AUDIT_READS_FULL
    # Nothing read, so nothing recorded, and no counter moved.
    assert (snapshot(store), audit_counters(store, team_id)) == before
    assert [r.getMessage() for r in caplog.records if r.name == "flashcards_teams.server"] == [
        "Refused read_audit_log: the team's audit log can't take another record"
    ]


async def test_a_refused_read_uses_the_write_allowance_not_the_reads(store, small_limits):
    # Otherwise a viewer could use up the reads' allowance by being refused.
    team_id, n = await small_team(store, ("erin", "editor"))
    async with running_app(store) as app, mcp_client(app, "erin-1", "auto") as erin:
        assert refusal(await erin.call_tool("read_audit_log", {"team_id": team_id})) == M_DENIED.format(
            tool="read_audit_log", role="owner"
        )
    assert audit_counters(store, team_id) == (5, 4, 0)
    assert [(r["action"], r["member_no"], r["result"]) for r in audit_rows(store, team_id)[3:]] == [
        ("audit.read", n["erin"], "denied")
    ]


async def test_refusals_are_recorded_up_to_each_members_quota(store, small_limits, caplog):
    team_id, n = await small_team(store, ("frank", "viewer"))
    async with running_app(store) as app:
        with caplog.at_level(logging.WARNING, logger="flashcards_teams.store"):
            async with mcp_client(app, "frank-1", "auto") as frank:
                for _ in range(5):
                    assert refusal(await frank.call_tool("add_card", {**CARD, "team_id": team_id})) == DENIED_ADD
        async with mcp_client(app, "dave-1", "auto") as dave:
            [listed] = payload(await dave.call_tool("list_teams", {}))["teams"]
    records = audit_rows(store, team_id)
    assert len(records) == 3 + 2 and [r["result"] for r in records[3:]] == ["denied", "denied"]
    assert [r.getMessage() for r in caplog.records if r.name == "flashcards_teams.store"] == [
        f"Refused add_card in team {team_id} for member #{n['frank']}: this member's refusal records are used up"
    ] * 3
    # Every refusal is counted, and the owner sees the count.
    assert refused_counts(store, team_id)[n["frank"]] == 5
    assert [m["refused_count"] for m in listed["members"] if m["member_no"] == n["frank"]] == [5]
    assert listed["refusals_logged_limit"] == 2
    assert_audit_counts_agree(store)


async def test_a_refusal_with_only_the_reserve_left_is_counted_not_recorded(store, small_limits):
    team_id, n = await small_team(store, ("frank", "viewer"), cards=5)
    assert audit_counters(store, team_id) == (9, 8, 0)
    before = snapshot(store)
    async with running_app(store) as app:
        async with mcp_client(app, "frank-1", "auto") as frank:
            assert refusal(await frank.call_tool("add_card", {**CARD, "team_id": team_id})) == DENIED_ADD
        async with mcp_client(app, "dave-1", "auto") as dave:
            assert refusal(await dave.call_tool("leave_team", {"team_id": team_id})) == M_LAST_OWNER
    assert snapshot(store) == before
    assert refused_counts(store, team_id) == {n["dave"]: 1, n["frank"]: 1}


async def test_list_teams_shows_the_allowance_and_its_use(store, small_limits):
    team_id, n = await small_team(store, ("erin", "editor"), cards=2)
    async with running_app(store) as app, mcp_client(app, "dave-1", "auto") as dave:
        payload(await dave.call_tool("read_audit_log", {"team_id": team_id}))
        [listed] = payload(await dave.call_tool("list_teams", {}))["teams"]
    _, writes, reads = audit_counters(store, team_id)
    assert (writes, reads) == (5, 1)
    assert {k: listed[k] for k in ("audit_writes_used", "audit_writes_limit", "audit_reads_used", "audit_reads_limit")} == {
        "audit_writes_used": writes, "audit_writes_limit": 10, "audit_reads_used": reads, "audit_reads_limit": 3,
    }


async def test_personal_team_at_cap(store, small_limits):
    # A personal team has the same allowance; grading uses it too. Its owner can still
    # change their own role (to owner: the only member change a personal team has).
    async with running_app(store) as app, mcp_client(app, "alice-1", "auto") as alice:
        payload(await alice.call_tool("add_card", CARD))  # records 1 (team.create) and 2
        payload(await alice.call_tool("add_card", CARD))
        for _ in range(5):
            payload(await alice.call_tool("grade_card", {"card_id": 1, "correct": True}))
        [personal] = payload(await alice.call_tool("list_teams", {}))["teams"]
        team_id = personal["team_id"]
        assert audit_counters(store, team_id) == (9, 8, 0)
        before = snapshot(store)
        assert refusal(await alice.call_tool("add_card", CARD)) == M_AUDIT_NEARLY_FULL
        assert refusal(await alice.call_tool("grade_card", {"card_id": 1, "correct": False})) == M_AUDIT_NEARLY_FULL
        assert snapshot(store) == before
        for _ in range(2):
            payload(await alice.call_tool("set_member_role", {"team_id": team_id, "member_no": 1, "role": "owner"}))
        assert audit_counters(store, team_id) == (11, 10, 0)
        assert refusal(await alice.call_tool("add_card", CARD)) == M_AUDIT_FULL
        assert refusal(await alice.call_tool("grade_card", {"card_id": 2, "correct": True})) == M_AUDIT_FULL
        # Failures are only counted now: the real reason, not the audit log's.
        assert refusal(await alice.call_tool("grade_card", {"card_id": 99, "correct": True})) == M_NO_CARD.format(card_id=99)
        listed = payload(await alice.call_tool("list_cards", {}))
        assert listed["total"] == 2 and [c["review_count"] for c in listed["cards"]] == [5, 0]
        assert payload(await alice.call_tool("review", {}))["card_id"] == 2
    assert_audit_counts_agree(store)


async def test_invariant(store):
    # With the real limits: refusals alone can't fill a team's write allowance (each of
    # the team's members has at most MAX_REFUSALS_LOGGED_PER_MEMBER of them recorded) ...
    assert limits.MAX_MEMBERS_PER_TEAM * limits.MAX_REFUSALS_LOGGED_PER_MEMBER == 2_500
    assert 2_500 < limits.AUDIT_CAP_PER_TEAM - limits.AUDIT_OWNER_RESERVE
    # ... and every record took one number and one place: next_audit_seq - 1 =
    # audit_writes + audit_reads = the records, after a mix of everything.
    f = await team_fixture(store)
    dave, erin, frank = actor("dave"), actor("erin"), actor("frank")
    await store.add(frank, f.team, "q", "a", "t")  # denied
    await store.record_review(erin, f.team, 999, True)  # failed
    await store.read_audit_log(dave, f.team, 101, 0)
    await store.read_audit_log(erin, f.team, 101, 0)  # denied
    await store.leave_team(dave, f.team)  # failed: the last owner
    await store.add(frank, None, "q", "a", "t")  # frank's personal team
    assert_audit_counts_agree(store)


@pytest.fixture
def pg_store(pg_cluster):
    s = fresh_postgres_store(pg_cluster.admin_url, pg_cluster.app_url)
    yield s
    s.close()


@pytest.mark.postgres
async def test_writes_at_cap_wait_on_team_lock(pg_store, monkeypatch):
    # One place left before the reserve, and four adds held at the team's row until all
    # four wait there: exactly one gets the place. A store that checked the allowance
    # outside the lock would let them all through.
    f = await team_fixture(pg_store)
    _, used, _ = audit_counters(pg_store, f.team)
    monkeypatch.setattr(limits, "AUDIT_CAP_PER_TEAM", used + limits.AUDIT_OWNER_RESERVE + 1)
    dave = actor("dave")

    async def add(i):
        try:
            return (await pg_store.add(dave, f.team, f"q{i}", "a", "t")).kind
        except AuditFullError as e:
            return e.kind

    def hold(conn):
        conn.execute("SELECT 1 FROM teams WHERE team_id = %s FOR UPDATE", (f.team,))

    results = await queued_behind(pg_store, hold, [add(i) for i in range(4)], waiting=4)
    assert sorted(results) == ["nearly", "nearly", "nearly", "ok"]
    assert raw(pg_store, "SELECT COUNT(*) FROM cards WHERE team_id = ?", (f.team,)) == [(2,)]
    assert audit_counters(pg_store, f.team)[1] == used + 1
    assert_audit_counts_agree(pg_store)
