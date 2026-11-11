"""The storage layer on its own: every method is scoped to a team the caller is in."""

import threading
from datetime import datetime, timedelta, timezone

import anyio
import pytest
from helpers import actor, raw, rows, snapshot, team_fixture

from flashcards_teams import ids, limits
from flashcards_teams.store import Outcome

pytestmark = pytest.mark.anyio

ALICE = actor("alice")
BOB = actor("bob")


async def card(call) -> dict:
    outcome = await call
    assert outcome.kind == "ok", outcome
    return outcome.value


async def cards(store, who, team_id=None, topic="", limit=50, after_id=0) -> list[dict]:
    return (await card(store.list_page(who, team_id, topic, limit, after_id)))["cards"]


async def personal_team(store, who) -> str:
    [team] = [t for t in await card(store.list_teams(who)) if t["personal"]]
    return team["team_id"]


async def test_every_method_is_scoped_to_its_team(store):
    await card(store.add(ALICE, None, "q", "a", "t"))
    # Bob has no personal team yet: nothing to see, and nothing gets created for him.
    assert await store.list_page(BOB, None, "", 50, 0) == Outcome("ok", {"cards": [], "total": 0})
    assert await store.least_recently_reviewed(BOB, None, "") == Outcome("ok", None)
    assert (await store.record_review(BOB, None, 1, True)).reason == "no_card"
    assert (await store.delete(BOB, None, 1)).reason == "no_card"
    assert rows(store, "teams") == 1
    # Naming Alice's team doesn't help: Bob isn't in it.
    alices = await personal_team(store, ALICE)
    for call in (
        store.list_page(BOB, alices, "", 50, 0),
        store.least_recently_reviewed(BOB, alices, ""),
        store.record_review(BOB, alices, 1, True),
        store.delete(BOB, alices, 1),
        store.add(BOB, alices, "q", "a", "t"),
    ):
        assert await call == Outcome("not_member")
    [only] = await cards(store, ALICE)
    assert only["review_count"] == 0 and rows(store, "cards") == 1


async def test_numbers_are_per_team_and_never_reused(store):
    assert (await card(store.add(ALICE, None, "q1", "a", "t")))["id"] == 1
    assert (await card(store.add(ALICE, None, "q2", "a", "t")))["id"] == 2
    assert (await card(store.add(BOB, None, "q", "a", "t")))["id"] == 1
    assert (await store.delete(ALICE, None, 2)).kind == "ok"
    assert (await card(store.add(ALICE, None, "q3", "a", "t")))["id"] == 3


async def test_concurrent_adds_get_unique_numbers(store):
    ids_seen = []

    async def add(i):
        ids_seen.append((await card(store.add(ALICE, None, f"q{i}", "a", "t")))["id"])

    async with anyio.create_task_group() as tg:
        for i in range(20):
            tg.start_soon(add, i)
    assert sorted(ids_seen) == list(range(1, 21))
    # The first adds raced to create the personal team: there is still only one.
    assert rows(store, "teams") == 1 and rows(store, "members") == 1


async def test_no_team_or_owner_key_appears_in_card_data(store):
    added = await card(store.add(ALICE, None, "q", "a", "t"))
    assert not {"owner", "team_id", "principal"} & set(added)
    assert all(not {"owner", "team_id", "principal"} & set(c) for c in await cards(store, ALICE))


async def test_card_limit_is_per_team(store, monkeypatch):
    monkeypatch.setattr(limits, "MAX_CARDS_PER_TEAM", 2)
    await card(store.add(ALICE, None, "q1", "a", "t"))
    await card(store.add(ALICE, None, "q2", "a", "t"))
    full = await store.add(ALICE, None, "q3", "a", "t")
    assert (full.kind, full.reason) == ("failed", "deck_full")
    assert (await card(store.add(BOB, None, "q", "a", "t")))["id"] == 1


async def test_total_size_limit_is_per_team(store, monkeypatch):
    monkeypatch.setattr(limits, "MAX_CHARS_PER_TEAM", 10)
    await card(store.add(ALICE, None, "qqq", "aaa", "tt"))  # 8 characters
    assert (await store.add(ALICE, None, "q", "a", "t")).reason == "deck_full"  # 8 + 3 > 10
    await card(store.add(BOB, None, "qqq", "aaa", "tt"))


async def test_review_order_uses_review_time_not_card_number(store, monkeypatch):
    # A fixed clock: Windows' clock can give two quick calls the same timestamp.
    ticks = (datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=s) for s in range(1000))
    monkeypatch.setattr(store, "_clock", lambda: next(ticks))
    await card(store.add(ALICE, None, "q1", "a", "t"))
    await card(store.add(ALICE, None, "q2", "a", "t"))
    order = [(await card(store.least_recently_reviewed(ALICE, None, "")))["id"]]
    await card(store.record_review(ALICE, None, 2, True))  # card 2 reviewed first...
    order.append((await card(store.least_recently_reviewed(ALICE, None, "")))["id"])
    await card(store.record_review(ALICE, None, 1, True))  # ...then card 1, so 2 is now the older review
    order.append((await card(store.least_recently_reviewed(ALICE, None, "")))["id"])
    assert order == [1, 1, 2]


async def test_topics_match_case_insensitively_and_ignore_spaces(store):
    await card(store.add(ALICE, None, "q", "a", "Geo"))
    await card(store.add(ALICE, None, "q", "a", "History"))
    assert (await card(store.list_page(ALICE, None, " geo ", 50, 0)))["total"] == 1
    assert [c["topic"] for c in await cards(store, ALICE, topic="GEO")] == ["Geo"]
    assert (await card(store.least_recently_reviewed(ALICE, None, "history")))["id"] == 2
    assert await card(store.least_recently_reviewed(ALICE, None, "art")) is None


async def test_list_pages_by_card_number(store):
    for i in range(5):
        await card(store.add(ALICE, None, f"q{i}", "a", "t"))
    assert [c["id"] for c in await cards(store, ALICE, limit=2)] == [1, 2]
    assert [c["id"] for c in await cards(store, ALICE, limit=2, after_id=2)] == [3, 4]
    assert [c["id"] for c in await cards(store, ALICE, limit=2, after_id=4)] == [5]
    assert (await card(store.list_page(ALICE, None, "", 2, 4)))["total"] == 5


async def test_a_refused_add_does_not_use_up_a_number(store, monkeypatch):
    monkeypatch.setattr(limits, "MAX_CARDS_PER_TEAM", 2)
    await card(store.add(ALICE, None, "q1", "a", "t"))
    await card(store.add(ALICE, None, "q2", "a", "t"))
    assert (await store.add(ALICE, None, "q3", "a", "t")).reason == "deck_full"
    assert (await store.delete(ALICE, None, 2)).kind == "ok"
    assert (await card(store.add(ALICE, None, "q4", "a", "t")))["id"] == 3


async def test_store_calls_run_off_the_event_loop(store, monkeypatch):
    # A slow database must not freeze every other request on this single-process server.
    threads = []
    original = type(store).tx

    def recording(self, read_only):
        threads.append(threading.get_ident())
        return original(self, read_only)

    monkeypatch.setattr(type(store), "tx", recording)
    await store.list_page(ALICE, None, "", 50, 0)
    await store.add(ALICE, None, "q", "a", "t")
    assert len(threads) == 2 and threading.get_ident() not in threads


async def test_cards_look_the_same_in_both_databases(store, monkeypatch):
    monkeypatch.setattr(store, "_clock", lambda: datetime(2026, 1, 1, tzinfo=timezone.utc))
    expected = {
        "id": 1, "question": "q", "answer": "a", "topic": "t", "created_at": "2026-01-01T00:00:00+00:00",
        "last_reviewed": None, "review_count": 0, "correct_count": 0, "wrong_count": 0,
    }
    added = await card(store.add(ALICE, None, "q", "a", "t"))
    assert added == expected
    assert {k: type(v) for k, v in added.items()} == {k: type(v) for k, v in expected.items()}
    assert await cards(store, ALICE) == [expected]
    graded = await card(store.record_review(ALICE, None, 1, False))
    assert graded == {**expected, "last_reviewed": "2026-01-01T00:00:00+00:00", "review_count": 1, "wrong_count": 1}


async def test_the_largest_card_number_is_simply_not_found(store):
    await card(store.add(ALICE, None, "q", "a", "t"))
    assert (await store.record_review(ALICE, None, 2**53, True)).reason == "no_card"
    assert (await store.delete(ALICE, None, 2**53)).reason == "no_card"


# --- two teams ---------------------------------------------------------------------


async def test_a_shared_team_has_its_own_cards_and_numbers(store):
    f = await team_fixture(store)
    erin = actor("erin")
    await card(store.add(erin, None, "personal", "a", "t"))  # erin's own deck, card #1
    assert (await card(store.add(erin, f.team, "shared", "a", "t")))["id"] == 2  # the team's #1 is the fixture's
    assert [c["question"] for c in await cards(store, erin)] == ["personal"]
    assert [c["question"] for c in await cards(store, erin, f.team)] == ["Fixture question?", "shared"]
    # Card #1 of the team, not of erin's own deck.
    await card(store.record_review(erin, f.team, 1, True))
    [own] = await cards(store, erin)
    assert own["review_count"] == 0
    assert (await card(store.least_recently_reviewed(erin, f.team, "")))["id"] == 2


async def test_roles_decide_and_are_read_on_every_call(store):
    f = await team_fixture(store)
    dave, erin, frank, gina = actor("dave"), actor("erin"), actor("frank"), actor("gina")
    assert (await card(store.list_page(frank, f.team, "", 50, 0)))["total"] == 1
    assert await store.add(frank, f.team, "q", "a", "t") == Outcome("denied", "add_card", "role")
    assert await store.record_review(frank, f.team, 1, True) == Outcome("denied", "grade_card", "role")
    assert await store.read_audit_log(erin, f.team, 101, 0) == Outcome("denied", "read_audit_log", "role")
    # Permission comes before existence: a viewer can't learn which cards exist.
    assert (await store.delete(frank, f.team, 999)).kind == "denied"
    assert await store.list_page(gina, f.team, "", 50, 0) == Outcome("not_member")
    await card(store.set_member_role(dave, f.team, f.numbers["erin"], "viewer"))
    assert (await store.add(erin, f.team, "q", "a", "t")).kind == "denied"
    await card(store.set_member_role(dave, f.team, f.numbers["erin"], "editor"))
    await card(store.add(erin, f.team, "q", "a", "t"))
    # The owner reads every record of the team, in order, the last one erin's new card.
    [(recorded,)] = raw(store, "SELECT COUNT(*) FROM audit_events WHERE team_id = ?", (f.team,))
    events = (await card(store.read_audit_log(dave, f.team, 101, 0)))["events"]
    assert [e["seq"] for e in events] == list(range(1, recorded + 1))
    assert {k: events[-1][k] for k in ("member_no", "action", "result")} == {
        "member_no": f.numbers["erin"], "action": "card.add", "result": "ok",
    }


async def test_members_and_owners(store):
    f = await team_fixture(store)
    dave, erin, henry = actor("dave"), actor("erin"), actor("henry")
    before = snapshot(store)
    for call in (
        store.set_member_role(dave, f.team, f.numbers["dave"], "editor"),
        store.remove_member(dave, f.team, f.numbers["dave"]),
        store.leave_team(dave, f.team),
    ):
        assert (await call).reason == "last_owner"
    assert (await store.remove_member(dave, f.team, f.numbers["gina"])).reason == "no_member"
    assert (await store.set_member_role(dave, f.team, 999, "viewer")).reason == "no_member"
    assert {k: v for k, v in snapshot(store).items() if k != "audit"} == {k: v for k, v in before.items() if k != "audit"}
    # With a second owner, the first can step down.
    await card(store.set_member_role(dave, f.team, f.numbers["erin"], "owner"))
    await card(store.set_member_role(dave, f.team, f.numbers["dave"], "editor"))
    assert (await store.leave_team(erin, f.team)).reason == "last_owner"
    await card(store.leave_team(henry, f.team))
    assert await store.list_page(henry, f.team, "", 50, 0) == Outcome("not_member")
    owner_view = [t for t in await card(store.list_teams(erin)) if t["team_id"] == f.team][0]
    assert [m["member_no"] for m in owner_view["members"]] == [1, 2, 3]
    assert "principal" not in str(owner_view) and "erin" not in str(owner_view)
    # The personal team: no invites, no leaving.
    await card(store.add(erin, None, "q", "a", "t"))
    personal = await personal_team(store, erin)
    assert (await store.create_invite(erin, personal, "editor", ids.hash_invite("x"))).reason == "personal_team"
    assert (await store.leave_team(erin, personal)).reason == "personal_team"


async def test_invites_work_once_while_valid(store, monkeypatch):
    f = await team_fixture(store)
    bob, gina = actor("bob"), actor("gina")
    code_hash = ids.hash_invite(f.code)
    # Already a member: refused, and the invite is still there for someone else.
    assert await store.join_team(actor("erin"), code_hash) == Outcome("failed", f.numbers["erin"], "already_member")
    joined = await card(store.join_team(gina, code_hash))  # gina was removed, so she gets a new number
    assert joined == {"team_id": f.team, "name": "Team A", "role": "editor", "member_no": 6}
    assert (await store.join_team(bob, code_hash)).reason == "invite_invalid"
    assert (await store.join_team(bob, ids.hash_invite("fti_wrong"))).reason == "invite_invalid"
    # Expired: the clock moves past the 72 hours.
    code = ids.new_invite_code()
    await card(store.create_invite(actor("dave"), f.team, "viewer", ids.hash_invite(code)))
    later = datetime.now(timezone.utc) + timedelta(seconds=limits.INVITE_TTL_SECONDS + 1)
    monkeypatch.setattr(store, "_clock", lambda: later)
    assert (await store.join_team(bob, ids.hash_invite(code))).reason == "invite_invalid"
    assert raw(store, "SELECT COUNT(*) FROM invites WHERE code_hash = ?", (code_hash,)) == [(1,)]


async def test_team_writes_are_audited_and_refusals_quota(store, monkeypatch):
    f = await team_fixture(store)
    frank = actor("frank")
    [(writes, reads, next_seq)] = raw(store, "SELECT audit_writes, audit_reads, next_audit_seq FROM teams WHERE team_id = ?", (f.team,))
    assert (writes, reads) == (rows(store, "audit_events") - 1, 0)  # bob's team has its own team.create
    assert next_seq == writes + 1
    monkeypatch.setattr(limits, "MAX_REFUSALS_LOGGED_PER_MEMBER", 2)
    for _ in range(3):
        assert (await store.delete(frank, f.team, 1)).kind == "denied"
    denied = raw(store, "SELECT member_no, client_id, action, target, result, reason FROM audit_events WHERE result = 'denied'")
    assert denied == [(f.numbers["frank"], "client-frank", "card.delete", "card:1", "denied", "role")] * 2
    assert raw(store, "SELECT refused_count FROM members WHERE team_id = ? AND member_no = ?", (f.team, f.numbers["frank"])) == [(3,)]
    seqs = [s for (s,) in raw(store, "SELECT seq FROM audit_events WHERE team_id = ? ORDER BY seq", (f.team,))]
    assert seqs == list(range(1, len(seqs) + 1))
