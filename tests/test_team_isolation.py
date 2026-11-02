"""Team isolation, end to end over every transport: a team's id is useless to anyone who
isn't in it, and one team's card numbers never reach another team's cards.

In the fixture (helpers.team_fixture), team A has dave (owner), erin (editor) and frank
(viewer); bob owns team B and is a stranger to team A.
"""

import logging

import pytest
from helpers import (
    ISSUER, TRANSPORTS, actor, mcp_client, payload, refusal, running_app, snapshot, team_fixture, team_part,
)

from flashcards_teams import ids
from flashcards_teams.server import M_DENIED, M_NO_TEAM
from flashcards_teams.store import Actor, Outcome

pytestmark = pytest.mark.anyio


def team_calls(team_id: str, card_no: int = 1, member_no: int = 1) -> list[tuple[str, dict]]:
    """All ten team tools, aimed at one team."""
    return [
        ("list_cards", {"team_id": team_id}),
        ("review", {"team_id": team_id}),
        ("add_card", {"team_id": team_id, "question": "q?", "answer": "a", "topic": "t"}),
        ("grade_card", {"team_id": team_id, "card_id": card_no, "correct": True}),
        ("delete_card", {"team_id": team_id, "card_id": card_no}),
        ("create_invite", {"team_id": team_id, "role": "editor"}),
        ("set_member_role", {"team_id": team_id, "member_no": member_no, "role": "viewer"}),
        ("remove_member", {"team_id": team_id, "member_no": member_no}),
        ("read_audit_log", {"team_id": team_id}),
        ("leave_team", {"team_id": team_id}),
    ]


async def invite(store, owner: str, team_id: str, role: str) -> str:
    """A fresh invite code, made through the store."""
    code = ids.new_invite_code()
    outcome = await store.create_invite(actor(owner), team_id, role, ids.hash_invite(code))
    assert outcome.kind == "ok", outcome
    return code


@pytest.mark.parametrize("transport", TRANSPORTS)
async def test_another_teams_member_gets_no_team_for_every_tool(store, transport, caplog):
    mode, stateless = transport
    f = await team_fixture(store)
    before = snapshot(store)
    with caplog.at_level(logging.INFO, logger="flashcards_teams.server"):
        async with running_app(store, stateless=stateless) as app, mcp_client(app, "bob-1", mode) as bob:
            for tool, args in team_calls(f.team, f.card_no, f.numbers["dave"]):
                assert refusal(await bob.call_tool(tool, args)) == M_NO_TEAM, tool
    # Nothing changed anywhere, audit records included: a stranger leaves no trace in team A.
    assert snapshot(store) == before
    refusals = [r.getMessage() for r in caplog.records if r.getMessage().startswith("Refused")]
    assert len(refusals) == 10
    for message in refusals:
        assert message.endswith(": caller is not a member of the requested team")
        for secret in (f.team, "bob", "client-", ISSUER):
            assert secret not in message


@pytest.mark.parametrize("transport", TRANSPORTS)
async def test_a_real_a_made_up_and_a_malformed_team_id_look_the_same(store, transport):
    mode, stateless = transport
    f = await team_fixture(store)
    made_up = ids.new_team_id()
    before = snapshot(store)
    async with running_app(store, stateless=stateless) as app, mcp_client(app, "bob-1", mode) as bob:
        for team_id in (f.team, made_up, "not-a-team", "t_' OR 1=1--"):
            for tool, args in team_calls(team_id):
                assert refusal(await bob.call_tool(tool, args)) == M_NO_TEAM, (team_id, tool)
    assert snapshot(store) == before


@pytest.mark.parametrize("transport", TRANSPORTS)
async def test_card_numbers_are_per_team_and_never_cross(store, transport):
    mode, stateless = transport
    f = await team_fixture(store)
    # erin is an editor in both teams.
    erins_code = await invite(store, "bob", f.other_team, "editor")
    async with running_app(store, stateless=stateless) as app:
        async with mcp_client(app, "bob-1", mode) as bob:
            added = payload(await bob.call_tool("add_card", {"team_id": f.other_team, "question": "B?", "answer": "b", "topic": "t"}))
            assert added["card"]["id"] == 1  # team A has a card #1 of its own
            assert payload(await bob.call_tool("add_card", {"team_id": f.other_team, "question": "B2?", "answer": "b", "topic": "t"}))["card"]["id"] == 2
        team_a = team_part(snapshot(store), f.team)
        async with mcp_client(app, "erin-1", mode) as erin:
            assert payload(await erin.call_tool("join_team", {"code": erins_code}))["team_id"] == f.other_team
            graded = payload(await erin.call_tool("grade_card", {"team_id": f.other_team, "card_id": 1, "correct": True}))
            assert graded["card"]["question"] == "B?"
            payload(await erin.call_tool("delete_card", {"team_id": f.other_team, "card_id": 1}))
            assert [c["question"] for c in payload(await erin.call_tool("list_cards", {"team_id": f.other_team}))["cards"]] == ["B2?"]
            [a_card] = payload(await erin.call_tool("list_cards", {"team_id": f.team}))["cards"]
    # Team A's card #1 was neither graded nor deleted, and nothing else of team A moved.
    assert a_card["review_count"] == 0
    after = snapshot(store)
    assert {k: v for k, v in team_part(after, f.team).items() if k != "audit"} == {
        k: v for k, v in team_a.items() if k != "audit"
    }
    assert team_part(after, f.team)["audit"] == team_a["audit"]


@pytest.mark.parametrize("transport", TRANSPORTS)
async def test_a_role_counts_only_in_its_own_team(store, transport):
    mode, stateless = transport
    f = await team_fixture(store)
    # dave owns team A and is only a viewer in team B.
    daves_code = await invite(store, "bob", f.other_team, "viewer")
    async with running_app(store, stateless=stateless) as app, mcp_client(app, "dave-1", mode) as dave:
        assert payload(await dave.call_tool("join_team", {"code": daves_code}))["role"] == "viewer"
        assert payload(await dave.call_tool("read_audit_log", {"team_id": f.team}))["ok"] is True
        assert refusal(await dave.call_tool("read_audit_log", {"team_id": f.other_team})) == M_DENIED.format(
            tool="read_audit_log", role="owner"
        )
        assert refusal(await dave.call_tool("add_card", {"team_id": f.other_team, "question": "q?", "answer": "a", "topic": "t"})) == (
            M_DENIED.format(tool="add_card", role="editor")
        )


@pytest.mark.parametrize("transport", TRANSPORTS)
async def test_the_same_subject_from_another_issuer_is_not_a_member(store, transport):
    mode, stateless = transport
    f = await team_fixture(store)
    alices_code = await invite(store, "dave", f.team, "editor")
    async with running_app(store, stateless=stateless) as app:
        async with mcp_client(app, "alice-1", mode) as alice:
            payload(await alice.call_tool("join_team", {"code": alices_code}))
            assert payload(await alice.call_tool("list_cards", {"team_id": f.team}))["total"] == 1
        async with mcp_client(app, "other-issuer", mode) as impostor:
            for tool, args in team_calls(f.team):
                assert refusal(await impostor.call_tool(tool, args)) == "Not signed in.", tool
    # Even if a token from the other issuer got past the server, the store sees someone else.
    other = Actor("https://other-idp.example.test|alice", "test-client")
    assert await store.list_page(other, f.team, "", 51, 0) == Outcome("not_member")
    assert await store.add(other, f.team, "q", "a", "t") == Outcome("not_member")
