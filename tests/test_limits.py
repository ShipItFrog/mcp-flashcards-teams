"""The limits on teams and members, lowered with monkeypatch so they are quick to reach.
They are read from ``limits`` on every call, so lowering them here takes effect."""

import logging

import pytest
from helpers import mcp_client, payload, raw, refusal, rows, running_app, snapshot, team_fixture

from flashcards_teams import limits
from flashcards_teams.server import (
    M_AUDIT_FULL, M_AUDIT_NEARLY_FULL, M_DENIED, M_LAST_OWNER, M_SERVER_FULL, M_TEAM_FULL, M_TOO_MANY_TEAMS,
)

pytestmark = pytest.mark.anyio

CARD = {"question": "q?", "answer": "a", "topic": "t"}


async def test_shared_teams_per_person(store, monkeypatch):
    monkeypatch.setattr(limits, "MAX_SHARED_TEAMS_PER_PERSON", 2)
    f = await team_fixture(store)  # bob already owns team B
    async with running_app(store) as app:
        async with mcp_client(app, "bob-1", "auto") as bob:
            payload(await bob.call_tool("create_team", {"name": "Second"}))
            before = snapshot(store)
            assert refusal(await bob.call_tool("create_team", {"name": "Third"})) == M_TOO_MANY_TEAMS.format(n=2)
            assert refusal(await bob.call_tool("join_team", {"code": f.code})) == M_TOO_MANY_TEAMS.format(n=2)
            assert snapshot(store) == before  # nothing written, the invite not used, no audit record
            # A personal team doesn't count.
            payload(await bob.call_tool("add_card", CARD))
        async with mcp_client(app, "gina-1", "auto") as gina:
            payload(await gina.call_tool("join_team", {"code": f.code}))


async def test_members_per_team(store, monkeypatch):
    monkeypatch.setattr(limits, "MAX_MEMBERS_PER_TEAM", 5)
    f = await team_fixture(store)  # team A has 4 members
    async with running_app(store) as app:
        async with mcp_client(app, "bob-1", "auto") as bob:
            payload(await bob.call_tool("join_team", {"code": f.code}))
        async with mcp_client(app, "dave-1", "auto") as dave:
            code = payload(await dave.call_tool("create_invite", {"team_id": f.team, "role": "viewer"}))["code"]
        before = snapshot(store)
        async with mcp_client(app, "gina-1", "auto") as gina:
            assert refusal(await gina.call_tool("join_team", {"code": code})) == M_TEAM_FULL.format(n=5)
        assert snapshot(store) == before
        # Room again once someone leaves.
        async with mcp_client(app, "frank-1", "auto") as frank:
            payload(await frank.call_tool("leave_team", {"team_id": f.team}))
        async with mcp_client(app, "gina-1", "auto") as gina:
            assert payload(await gina.call_tool("join_team", {"code": code}))["role"] == "viewer"


async def test_teams_on_the_whole_server(store, monkeypatch, caplog):
    # Personal teams count too. The limit is checked only when a team would be added.
    monkeypatch.setattr(limits, "MAX_TEAMS_TOTAL", 2)
    async with running_app(store) as app:
        async with mcp_client(app, "alice-1", "auto") as alice:
            payload(await alice.call_tool("add_card", CARD))  # alice's personal team
            payload(await alice.call_tool("create_team", {"name": "Shared"}))
            before = snapshot(store)
            with caplog.at_level(logging.WARNING, logger="flashcards_teams.server"):
                assert refusal(await alice.call_tool("create_team", {"name": "One too many"})) == M_SERVER_FULL
                async with mcp_client(app, "bob-1", "auto") as bob:
                    # bob has no personal team yet, and there is no room for one.
                    assert refusal(await bob.call_tool("add_card", CARD)) == M_SERVER_FULL
                    assert payload(await bob.call_tool("list_cards", {}))["total"] == 0
            assert snapshot(store) == before
            # Teams that already exist are not affected.
            assert payload(await alice.call_tool("add_card", CARD))["card"]["id"] == 2
    assert rows(store, "teams") == 2
    warnings = [r.getMessage() for r in caplog.records if r.name == "flashcards_teams.server"]
    assert warnings == [
        "Refused create_team: the server's team limit is reached",
        "Refused add_card: the server's team limit is reached",
    ]


async def test_a_refusal_the_audit_log_has_no_room_for_still_gives_the_real_reason(store, monkeypatch, caplog):
    # Only the owners' reserve is left: a refusal can't be recorded any more (it would eat
    # into the reserve), but it is still a refusal. The caller is told the real reason, the
    # member's refusals are still counted, and a change that needs a record is not made.
    f = await team_fixture(store)
    [(used,)] = raw(store, "SELECT audit_writes FROM teams WHERE team_id = ?", (f.team,))
    monkeypatch.setattr(limits, "AUDIT_CAP_PER_TEAM", used + limits.AUDIT_OWNER_RESERVE)
    before = snapshot(store)
    async with running_app(store) as app:
        with caplog.at_level(logging.WARNING, logger="flashcards_teams.store"):
            async with mcp_client(app, "frank-1", "auto") as frank:  # a viewer
                assert refusal(await frank.call_tool("add_card", {**CARD, "team_id": f.team})) == M_DENIED.format(
                    tool="add_card", role="editor"
                )
            async with mcp_client(app, "dave-1", "auto") as dave:  # the only owner
                assert refusal(await dave.call_tool("leave_team", {"team_id": f.team})) == M_LAST_OWNER
                assert refusal(await dave.call_tool("add_card", {**CARD, "team_id": f.team})) == M_AUDIT_NEARLY_FULL
    assert snapshot(store) == before  # no card, no record, nobody gone
    counted = raw(
        store, "SELECT member_no, refused_count FROM members WHERE team_id = ? AND refused_count > 0 ORDER BY member_no",
        (f.team,),
    )
    assert counted == [(f.numbers["dave"], 1), (f.numbers["frank"], 1)]
    assert [r.getMessage() for r in caplog.records if r.name == "flashcards_teams.store"] == [
        f"Refused {tool} in team {f.team} for member #{f.numbers[name]}: the team's audit log can't take another record"
        for tool, name in (("add_card", "frank"), ("leave_team", "dave"))
    ]


async def test_the_last_part_of_the_audit_allowance_is_kept_for_member_changes(store, monkeypatch):
    # Only the reserve is left: the cards can still be read but not changed, and nobody
    # can be invited or join, yet owners can still change roles and remove members, and
    # members can still leave. Once the reserve is used up too, those are refused as well.
    f = await team_fixture(store)
    [(used,)] = raw(store, "SELECT audit_writes FROM teams WHERE team_id = ?", (f.team,))
    monkeypatch.setattr(limits, "AUDIT_OWNER_RESERVE", 3)
    monkeypatch.setattr(limits, "AUDIT_CAP_PER_TEAM", used + 3)
    team = {"team_id": f.team}
    async with running_app(store) as app:
        async with mcp_client(app, "dave-1", "auto") as dave, mcp_client(app, "frank-1", "auto") as frank:
            before = snapshot(store)
            for tool, args in (
                ("add_card", {**CARD, **team}), ("grade_card", {"card_id": f.card_no, "correct": True, **team}),
                ("delete_card", {"card_id": f.card_no, **team}), ("create_invite", {"role": "viewer", **team}),
            ):
                assert refusal(await dave.call_tool(tool, args)) == M_AUDIT_NEARLY_FULL, tool
            async with mcp_client(app, "gina-1", "auto") as gina:
                assert refusal(await gina.call_tool("join_team", {"code": f.code})) == M_AUDIT_NEARLY_FULL
            assert payload(await dave.call_tool("list_cards", team))["total"] == 1
            assert payload(await frank.call_tool("review", team))["card_id"] == f.card_no
            assert snapshot(store) == before  # nothing written, the invite not used
            # The reserve: three member changes, then none.
            payload(await dave.call_tool("set_member_role", {"member_no": f.numbers["erin"], "role": "viewer", **team}))
            payload(await dave.call_tool("remove_member", {"member_no": f.numbers["henry"], **team}))
            payload(await frank.call_tool("leave_team", team))
            assert raw(store, "SELECT audit_writes FROM teams WHERE team_id = ?", (f.team,)) == [(used + 3,)]
            full = snapshot(store)
            assert refusal(await dave.call_tool("remove_member", {"member_no": f.numbers["erin"], **team})) == M_AUDIT_FULL
            assert snapshot(store) == full
    roles = raw(store, "SELECT member_no, role FROM members WHERE team_id = ? ORDER BY member_no", (f.team,))
    assert roles == [(f.numbers["dave"], "owner"), (f.numbers["erin"], "viewer")]


def test_the_documented_limits():
    # The numbers the README gives. The tests above lower a limit to reach it quickly;
    # this keeps the README and the code in step.
    assert (limits.MAX_CARDS_PER_TEAM, limits.MAX_CHARS_PER_TEAM) == (1000, 200_000)
    assert (limits.MAX_MEMBERS_PER_TEAM, limits.MAX_SHARED_TEAMS_PER_PERSON) == (25, 10)
    assert limits.INVITE_TTL_SECONDS == 72 * 3600
    assert limits.MAX_REFUSALS_LOGGED_PER_MEMBER == 100
