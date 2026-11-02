"""Every team tool, called by every kind of person, over every transport, on both
databases: the reply and exactly what changed in the data.

The expected results are written out here rather than taken from the server, so a
change to the rules must change this table too. In the fixture (helpers.team_fixture)
dave is the only owner, erin an editor, frank a viewer, bob owns another team and is a
stranger here, and gina was a member and has been removed.
"""

import pytest
from helpers import (
    ISSUER, TRANSPORTS, mcp_client, payload, refusal, running_app, snapshot, team_fixture, without_audit,
)

from flashcards_teams.server import M_ALREADY, M_DENIED, M_LAST_OWNER, M_NO_TEAM

pytestmark = pytest.mark.anyio

IDENTITIES = {"owner": "dave", "editor": "erin", "viewer": "frank", "outsider": "bob", "removed": "gina"}

_TABLE = {
    #                                                    owner         editor    viewer    outsider   removed
    ("list_cards", "review"):                           ("ok",         "ok",     "ok",     "no_team", "no_team"),
    ("add_card", "grade_card", "delete_card"):          ("ok",         "ok",     "denied", "no_team", "no_team"),
    ("create_invite", "set_member_role",
     "remove_member", "read_audit_log"):                ("ok",         "denied", "denied", "no_team", "no_team"),
    # dave is the fixture's only owner, so he can't leave.
    ("leave_team",):                                    ("last_owner", "ok",     "ok",     "no_team", "no_team"),
}
EXPECTED = {tool: dict(zip(IDENTITIES, cells)) for tools, cells in _TABLE.items() for tool in tools}
# The role each tool's "Permission denied" message names.
NEEDS = {
    "list_cards": "viewer", "review": "viewer", "leave_team": "viewer",
    "add_card": "editor", "grade_card": "editor", "delete_card": "editor",
    "create_invite": "owner", "set_member_role": "owner", "remove_member": "owner", "read_audit_log": "owner",
}


def arguments(tool: str, f) -> dict:
    """What each tool is called with: always the fixture's team, and henry as the member
    to change or remove."""
    return {
        "team_id": f.team,
        **{
            "add_card": {"question": "Matrix question?", "answer": "Matrix answer", "topic": "matrix"},
            "grade_card": {"card_id": f.card_no, "correct": True},
            "delete_card": {"card_id": f.card_no},
            "create_invite": {"role": "viewer"},
            "set_member_role": {"member_no": f.numbers["henry"], "role": "viewer"},
            "remove_member": {"member_no": f.numbers["henry"]},
        }.get(tool, {}),
    }


def after_success(tool: str, before: dict, f, caller: str) -> dict:
    """The snapshot (without audit counts) a successful call must leave behind."""
    after = without_audit(before)
    team = f.team
    [counters] = [t for t in after["teams"] if t[0] == team]

    def replace(key, old, new=None):
        assert old in after[key], (key, old)
        after[key] = sorted([r for r in after[key] if r != old] + ([new] if new is not None else []))

    if tool == "add_card":
        after["cards"] = sorted(after["cards"] + [(team, counters[1], 0)])
        replace("teams", counters, (team, counters[1] + 1, counters[2], counters[3]))
    elif tool == "grade_card":
        replace("cards", (team, f.card_no, 0), (team, f.card_no, 1))
    elif tool == "delete_card":
        replace("cards", (team, f.card_no, 0))
    elif tool == "create_invite":
        after["invites"] = sorted(after["invites"] + [(team, counters[3], True)])
        replace("teams", counters, (team, counters[1], counters[2], counters[3] + 1))
    elif tool == "set_member_role":
        replace("members", (team, f.numbers["henry"], "editor"), (team, f.numbers["henry"], "viewer"))
    elif tool == "remove_member":
        replace("members", (team, f.numbers["henry"], "editor"))
    elif tool == "leave_team":
        [mine] = [m for m in after["members"] if m[:2] == (team, f.numbers[caller])]
        replace("members", mine)
    # list_cards, review and read_audit_log change nothing (read_audit_log's own
    # record is in the audit counts, left out here).
    return after


@pytest.mark.parametrize("transport", TRANSPORTS)
@pytest.mark.parametrize("identity", list(IDENTITIES))
@pytest.mark.parametrize("tool", list(EXPECTED))
async def test_matrix(store, tool, identity, transport):
    mode, stateless = transport
    name = IDENTITIES[identity]
    f = await team_fixture(store)
    before = snapshot(store)
    async with running_app(store, stateless=stateless) as app, mcp_client(app, f"{name}-1", mode) as client:
        result = await client.call_tool(tool, arguments(tool, f))
    expected = EXPECTED[tool][identity]
    if expected == "ok":
        assert payload(result)["ok"] is True
        change = after_success(tool, before, f, name)
    else:
        message = {
            "denied": M_DENIED.format(tool=tool, role=NEEDS[tool]),
            "no_team": M_NO_TEAM,
            "last_owner": M_LAST_OWNER,
        }[expected]
        assert refusal(result) == message
        change = without_audit(before)
    assert without_audit(snapshot(store)) == change


@pytest.mark.parametrize("identity", list(IDENTITIES))
async def test_team_free_tools(store, identity):
    # create_team, list_teams and join_team belong to no team: anyone signed in may call them.
    name = IDENTITIES[identity]
    f = await team_fixture(store)
    async with running_app(store) as app, mcp_client(app, f"{name}-1", "auto") as client:
        mine = payload(await client.call_tool("create_team", {"name": f"{name}'s team"}))
        assert {k: mine[k] for k in ("ok", "name", "role", "member_no")} == {
            "ok": True, "name": f"{name}'s team", "role": "owner", "member_no": 1,
        }
        joined = await client.call_tool("join_team", {"code": f.code})
        if identity in ("outsider", "removed"):
            assert payload(joined)["team_id"] == f.team and payload(joined)["role"] == "editor"
        else:
            assert refusal(joined) == M_ALREADY.format(member_no=f.numbers[name])
        teams = payload(await client.call_tool("list_teams", {}))["teams"]
    if identity not in ("outsider", "removed"):
        # Refusing a member didn't use the invite up: it still works for someone new.
        async with running_app(store) as app, mcp_client(app, "alice-1", "auto") as alice:
            assert payload(await alice.call_tool("join_team", {"code": f.code}))["team_id"] == f.team
    # Only the caller's own teams; nothing created for them (no personal team).
    expected = {mine["team_id"], f.team} | ({f.other_team} if name == "bob" else set())
    assert {t["team_id"] for t in teams} == expected
    assert not any(t["personal"] for t in teams)
    assert "principal" not in str(teams) and ISSUER not in str(teams)


def test_the_table_covers_every_team_tool_and_person():
    assert len(EXPECTED) == 10 and set(EXPECTED) == set(NEEDS)
    assert all(set(cells) == set(IDENTITIES) for cells in EXPECTED.values())
