"""Roles and members through the tools: a change counts from the very next call, a team
always keeps an owner, and a refusal never tells what exists.

In the fixture (helpers.team_fixture) dave is the only owner, erin and henry are
editors, frank is a viewer, and gina was removed.
"""

import pytest
from helpers import mcp_client, payload, refusal, running_app, snapshot, team_fixture, without_audit

from flashcards_teams.server import M_DENIED, M_LAST_OWNER, M_NO_MEMBER, M_NO_TEAM, M_PERSONAL_LEAVE

pytestmark = pytest.mark.anyio

CARD = {"question": "Largest planet?", "answer": "Jupiter", "topic": "space"}


def owners(store, team_id) -> int:
    return sum(1 for t, _, role in snapshot(store)["members"] if t == team_id and role == "owner")


async def test_a_demotion_counts_from_the_next_call(store):
    f = await team_fixture(store)
    async with running_app(store) as app:
        async with mcp_client(app, "erin-1", "auto") as erin, mcp_client(app, "dave-1", "auto") as dave:
            payload(await erin.call_tool("add_card", {**CARD, "team_id": f.team}))
            payload(await dave.call_tool("set_member_role", {"team_id": f.team, "member_no": f.numbers["erin"], "role": "viewer"}))
            # The same session as before: nothing about the old role was kept.
            assert refusal(await erin.call_tool("add_card", {**CARD, "team_id": f.team})) == M_DENIED.format(
                tool="add_card", role="editor"
            )
            assert payload(await erin.call_tool("list_cards", {"team_id": f.team}))["total"] == 2


async def test_a_removal_counts_from_the_next_call(store):
    f = await team_fixture(store)
    async with running_app(store) as app:
        async with mcp_client(app, "erin-1", "auto") as erin, mcp_client(app, "dave-1", "auto") as dave:
            assert payload(await erin.call_tool("list_cards", {"team_id": f.team}))["total"] == 1
            assert payload(await dave.call_tool("remove_member", {"team_id": f.team, "member_no": f.numbers["erin"]}))[
                "message"
            ] == f"Removed member #{f.numbers['erin']}"
            assert refusal(await erin.call_tool("list_cards", {"team_id": f.team})) == M_NO_TEAM
            assert refusal(await erin.call_tool("add_card", {**CARD, "team_id": f.team})) == M_NO_TEAM


async def test_the_only_owner_cant_step_down_or_remove_themselves(store):
    f = await team_fixture(store)
    me = f.numbers["dave"]
    before = without_audit(snapshot(store))
    async with running_app(store) as app, mcp_client(app, "dave-1", "auto") as dave:
        for role in ("editor", "viewer"):
            assert refusal(await dave.call_tool("set_member_role", {"team_id": f.team, "member_no": me, "role": role})) == M_LAST_OWNER
        assert refusal(await dave.call_tool("remove_member", {"team_id": f.team, "member_no": me})) == M_LAST_OWNER
    assert without_audit(snapshot(store)) == before


async def test_with_two_owners_one_may_step_down(store):
    f = await team_fixture(store)
    async with running_app(store) as app, mcp_client(app, "dave-1", "auto") as dave:
        payload(await dave.call_tool("set_member_role", {"team_id": f.team, "member_no": f.numbers["erin"], "role": "owner"}))
        stepped = payload(await dave.call_tool("set_member_role", {"team_id": f.team, "member_no": f.numbers["dave"], "role": "editor"}))
        assert stepped == {"ok": True, "member_no": f.numbers["dave"], "role": "editor", "message": "Member #1 is now editor"}
        # Now erin is the only owner, and dave can't manage members any more.
        assert refusal(await dave.call_tool("remove_member", {"team_id": f.team, "member_no": f.numbers["erin"]})) == M_DENIED.format(
            tool="remove_member", role="owner"
        )
    assert owners(store, f.team) == 1


async def test_an_owner_may_remove_another_owner_but_not_the_last(store):
    f = await team_fixture(store)
    async with running_app(store) as app:
        async with mcp_client(app, "dave-1", "auto") as dave, mcp_client(app, "erin-1", "auto") as erin:
            payload(await dave.call_tool("set_member_role", {"team_id": f.team, "member_no": f.numbers["erin"], "role": "owner"}))
            payload(await erin.call_tool("remove_member", {"team_id": f.team, "member_no": f.numbers["dave"]}))
            assert refusal(await erin.call_tool("remove_member", {"team_id": f.team, "member_no": f.numbers["erin"]})) == M_LAST_OWNER
    assert owners(store, f.team) == 1


async def test_setting_the_same_role_is_ok(store):
    f = await team_fixture(store)
    before = without_audit(snapshot(store))
    async with running_app(store) as app, mcp_client(app, "dave-1", "auto") as dave:
        same = payload(await dave.call_tool("set_member_role", {"team_id": f.team, "member_no": f.numbers["erin"], "role": "editor"}))
        assert same["message"] == f"Member #{f.numbers['erin']} is now editor"
        # The only owner keeping the owner role isn't stepping down.
        payload(await dave.call_tool("set_member_role", {"team_id": f.team, "member_no": f.numbers["dave"], "role": "owner"}))
    assert without_audit(snapshot(store)) == before


async def test_a_missing_and_a_removed_member_look_the_same(store):
    f = await team_fixture(store)
    gina = f.numbers["gina"]
    before = without_audit(snapshot(store))
    async with running_app(store) as app, mcp_client(app, "dave-1", "auto") as dave:
        for member_no in (gina, 999):
            expected = M_NO_MEMBER.format(member_no=member_no)
            change = {"team_id": f.team, "member_no": member_no}
            assert refusal(await dave.call_tool("set_member_role", {**change, "role": "viewer"})) == expected
            assert refusal(await dave.call_tool("remove_member", change)) == expected
    assert without_audit(snapshot(store)) == before


async def test_permission_before_existence(store):
    # Refused for the role before anything is looked up, so a refusal can't reveal
    # whether a card or a member exists.
    f = await team_fixture(store)
    async with running_app(store) as app:
        async with mcp_client(app, "frank-1", "auto") as frank, mcp_client(app, "erin-1", "auto") as erin:
            for card_id in (999, f.card_no):
                assert refusal(await frank.call_tool("delete_card", {"team_id": f.team, "card_id": card_id})) == M_DENIED.format(
                    tool="delete_card", role="editor"
                )
                assert refusal(await frank.call_tool("grade_card", {"team_id": f.team, "card_id": card_id, "correct": True})) == (
                    M_DENIED.format(tool="grade_card", role="editor")
                )
            for member_no in (999, f.numbers["gina"], f.numbers["henry"]):
                for call in (
                    ("set_member_role", {"team_id": f.team, "member_no": member_no, "role": "viewer"}),
                    ("remove_member", {"team_id": f.team, "member_no": member_no}),
                ):
                    assert refusal(await erin.call_tool(*call)) == M_DENIED.format(tool=call[0], role="owner")


# --- leave_team ----------------------------------------------------------------------


async def test_after_leaving_the_team_is_gone_until_a_new_invite(store):
    f = await team_fixture(store)
    async with running_app(store) as app:
        async with mcp_client(app, "erin-1", "auto") as erin, mcp_client(app, "dave-1", "auto") as dave:
            assert payload(await erin.call_tool("leave_team", {"team_id": f.team})) == {"ok": True, "message": "You left the team."}
            # The same session: the next call already finds no team.
            assert refusal(await erin.call_tool("list_cards", {"team_id": f.team})) == M_NO_TEAM
            assert refusal(await erin.call_tool("leave_team", {"team_id": f.team})) == M_NO_TEAM
            code = payload(await dave.call_tool("create_invite", {"team_id": f.team, "role": "viewer"}))["code"]
            again = payload(await erin.call_tool("join_team", {"code": code}))
            # A new member number: the old one is never given out again.
            assert (again["member_no"], again["role"]) == (6, "viewer")
            assert again["member_no"] not in f.numbers.values()
            assert payload(await erin.call_tool("list_cards", {"team_id": f.team}))["total"] == 1


async def test_the_only_owner_cant_leave(store):
    f = await team_fixture(store)
    before = without_audit(snapshot(store))
    async with running_app(store) as app, mcp_client(app, "dave-1", "auto") as dave:
        assert refusal(await dave.call_tool("leave_team", {"team_id": f.team})) == M_LAST_OWNER
    assert without_audit(snapshot(store)) == before


async def test_with_two_owners_one_may_leave(store):
    f = await team_fixture(store)
    async with running_app(store) as app:
        async with mcp_client(app, "dave-1", "auto") as dave, mcp_client(app, "erin-1", "auto") as erin:
            payload(await dave.call_tool("set_member_role", {"team_id": f.team, "member_no": f.numbers["erin"], "role": "owner"}))
            payload(await dave.call_tool("leave_team", {"team_id": f.team}))
            assert refusal(await erin.call_tool("leave_team", {"team_id": f.team})) == M_LAST_OWNER
    assert owners(store, f.team) == 1
    assert [m for m in snapshot(store)["members"] if m[0] == f.team and m[1] == f.numbers["dave"]] == []


async def test_nobody_can_leave_their_personal_team(store):
    async with running_app(store) as app, mcp_client(app, "erin-1", "auto") as erin:
        payload(await erin.call_tool("add_card", CARD))
        [personal] = payload(await erin.call_tool("list_teams", {}))["teams"]
        before = without_audit(snapshot(store))
        assert refusal(await erin.call_tool("leave_team", {"team_id": personal["team_id"]})) == M_PERSONAL_LEAVE
        assert payload(await erin.call_tool("list_cards", {}))["total"] == 1
    assert without_audit(snapshot(store)) == before
