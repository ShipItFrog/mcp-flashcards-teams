"""The personal team behind the tools' no-team_id calls: made by the first add_card and
by nothing else, one per person."""

from datetime import datetime, timezone

import pytest
from helpers import actor, fresh_postgres_store, mcp_client, payload, queued_behind, raw, refusal, rows, running_app

from flashcards_teams import ids, limits
from flashcards_teams.server import M_NO_CARD

pytestmark = pytest.mark.anyio

CARD = {"question": "Capital of Peru?", "answer": "Lima", "topic": "geo"}
ALICE = actor("alice")


async def test_reading_creates_nothing(store):
    assert rows(store, "teams") == 0
    async with running_app(store) as app, mcp_client(app, "alice-1", "auto") as alice:
        listed = payload(await alice.call_tool("list_cards", {}))
        assert (listed["total"], listed["cards"], listed["next_after_id"]) == (0, [], None)
        assert payload(await alice.call_tool("review", {}))["card_id"] is None
        assert payload(await alice.call_tool("list_teams", {}))["teams"] == []
    assert rows(store, "teams") == 0 and rows(store, "members") == 0


async def test_grading_or_deleting_without_a_personal_team_is_no_card(store):
    async with running_app(store) as app, mcp_client(app, "alice-1", "auto") as alice:
        assert refusal(await alice.call_tool("grade_card", {"card_id": 1, "correct": True})) == M_NO_CARD.format(card_id=1)
        assert refusal(await alice.call_tool("delete_card", {"card_id": 1})) == M_NO_CARD.format(card_id=1)
    assert rows(store, "teams") == 0 and rows(store, "audit_events") == 0


async def test_the_first_add_creates_one_personal_team_with_its_owner(store):
    async with running_app(store) as app, mcp_client(app, "alice-1", "auto") as alice:
        assert payload(await alice.call_tool("add_card", CARD))["message"] == "Added card #1"
        assert payload(await alice.call_tool("add_card", CARD))["message"] == "Added card #2"
        [team] = payload(await alice.call_tool("list_teams", {}))["teams"]
    assert raw(store, "SELECT name, personal_of FROM teams") == [("Personal", ALICE.principal)]
    assert raw(store, "SELECT member_no, principal, role, via_invite_no FROM members") == [(1, ALICE.principal, "owner", None)]
    assert raw(store, "SELECT seq, member_no, action, target, result, new_role FROM audit_events WHERE action = 'team.create'") == [
        (1, 1, "team.create", "team", "ok", "owner")
    ]
    assert {k: team[k] for k in ("team_id", "name", "personal", "role", "member_no")} == {
        "team_id": raw(store, "SELECT team_id FROM teams")[0][0], "name": "Personal", "personal": True,
        "role": "owner", "member_no": 1,
    }
    # The principal is the storage key only: never shown.
    assert ALICE.principal not in str(team) and "alice" not in str(team)


async def test_the_personal_team_is_listed_first(store):
    async with running_app(store) as app, mcp_client(app, "alice-1", "auto") as alice:
        shared = payload(await alice.call_tool("create_team", {"name": "Book club"}))["team_id"]
        payload(await alice.call_tool("add_card", CARD))  # the personal team comes after, by time
        teams = payload(await alice.call_tool("list_teams", {}))["teams"]
    assert [(t["personal"], t["name"]) for t in teams] == [(True, "Personal"), (False, "Book club")]
    assert teams[1]["team_id"] == shared


@pytest.fixture
def pg_store(pg_cluster):
    s = fresh_postgres_store(pg_cluster.admin_url, pg_cluster.app_url)
    yield s
    s.close()


@pytest.mark.postgres
async def test_first_adds_race_for_personal_team(pg_store):
    # Postgres only (SQLite runs one call at a time). Deterministic, not a race left to
    # chance: another connection holds an uncommitted personal team for alice, so the
    # first add waits on it in its INSERT (and the other three behind the server-wide
    # lock) until it is rolled back. A store that looked for the personal team only before
    # taking the server-wide lock, and then inserted without ON CONFLICT, would fail every
    # add but one.
    store = pg_store

    def hold(conn):
        conn.execute(
            "INSERT INTO teams (team_id, name, personal_of, created_at, next_member_no) VALUES (%s, 'x', %s, %s, 2)",
            (ids.new_team_id(), ALICE.principal, datetime.now(timezone.utc).isoformat()),
        )

    def roll_back(conn):
        conn.rollback()

    calls = [store.add(ALICE, None, f"q{i}", "a", "t") for i in range(4)]
    outcomes = await queued_behind(store, hold, calls, waiting=4, before_release=roll_back)
    assert [o.kind for o in outcomes] == ["ok"] * 4
    assert sorted(o.value["id"] for o in outcomes) == [1, 2, 3, 4]
    assert raw(store, "SELECT COUNT(*) FROM teams WHERE personal_of = ?", (ALICE.principal,)) == [(1,)]
    assert raw(store, "SELECT COUNT(*) FROM members WHERE role = 'owner'") == [(1,)]
    assert raw(store, "SELECT COUNT(*) FROM audit_events WHERE action = 'team.create'") == [(1,)]


@pytest.mark.postgres
async def test_first_adds_at_the_last_free_place_both_succeed(pg_store, monkeypatch):
    # Postgres only. Room for one more team on the server: two first adds by the same
    # person queue on the server-wide lock, and the one that goes second must find the
    # personal team the first one made, not count it as a team too many.
    store = pg_store
    monkeypatch.setattr(limits, "MAX_TEAMS_TOTAL", 1)

    def hold(conn):
        store.lock_site(lambda sql, params=(): conn.execute(sql.replace("?", "%s"), params))

    calls = [store.add(ALICE, None, f"q{i}", "a", "t") for i in range(2)]
    outcomes = await queued_behind(store, hold, calls, waiting=2)
    assert [(o.kind, o.reason) for o in outcomes] == [("ok", ""), ("ok", "")]
    assert sorted(o.value["id"] for o in outcomes) == [1, 2]
    assert raw(store, "SELECT personal_of FROM teams") == [(ALICE.principal,)]
