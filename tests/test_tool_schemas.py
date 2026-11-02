"""What clients see in tools/list: exactly these parameters, nothing a caller could use
to claim an identity or a role, and the same list for everyone."""

import pytest
from helpers import mcp_client, running_app, team_fixture

from flashcards_teams import limits

pytestmark = pytest.mark.anyio

# Written out here, not taken from the server.
PARAMETERS = {
    "add_card": {"question", "answer", "topic", "team_id"},
    "list_cards": {"topic", "limit", "after_id", "team_id"},
    "review": {"topic", "team_id"},
    "grade_card": {"card_id", "correct", "team_id"},
    "delete_card": {"card_id", "team_id"},
    "create_team": {"name"},
    "list_teams": set(),
    "create_invite": {"team_id", "role"},
    "join_team": {"code"},
    "set_member_role": {"team_id", "member_no", "role"},
    "remove_member": {"team_id", "member_no"},
    "read_audit_log": {"team_id", "limit", "after_seq"},
    "leave_team": {"team_id"},
}
# Who the caller is comes from the token alone.
IDENTITY_NAMES = {"owner", "user", "sub", "principal", "actor", "as_role"}


async def schemas(app, token: str) -> dict[str, dict]:
    async with mcp_client(app, token, "auto") as client:
        return {tool.name: tool.input_schema for tool in (await client.list_tools()).tools}


async def test_every_tool_has_exactly_its_parameters(store):
    async with running_app(store) as app:
        tools = await schemas(app, "alice-1")
    assert {name: set(schema.get("properties", {})) for name, schema in tools.items()} == PARAMETERS
    for name, schema in tools.items():
        assert not IDENTITY_NAMES & set(schema.get("properties", {})), name


async def test_parameter_details(store):
    async with running_app(store) as app:
        tools = await schemas(app, "alice-1")
    # An invite can't make anyone an owner.
    assert tools["create_invite"]["properties"]["role"]["enum"] == ["editor", "viewer"]
    assert set(tools["create_invite"]["required"]) == {"team_id", "role"}
    assert tools["set_member_role"]["properties"]["role"]["enum"] == ["owner", "editor", "viewer"]
    assert tools["leave_team"]["required"] == ["team_id"]
    assert tools["join_team"]["required"] == ["code"]
    # Written out in server.py (a type is fixed when the module loads): it must be the limit.
    assert tools["join_team"]["properties"]["code"]["maxLength"] == limits.MAX_INVITE_CODE
    limit = tools["read_audit_log"]["properties"]["limit"]
    assert (limit["default"], limit["maximum"], limit["minimum"]) == (100, 500, 1)
    # The five card tools work without a team (the personal deck).
    for name in ("add_card", "list_cards", "review", "grade_card", "delete_card"):
        assert "team_id" not in tools[name].get("required", []), name


async def test_everyone_sees_the_same_tools(store):
    await team_fixture(store)  # frank is a viewer there; bob is in another team only
    async with running_app(store) as app:
        viewer = await schemas(app, "frank-1")
        outsider = await schemas(app, "bob-1")
        nobody_yet = await schemas(app, "alice-1")
    assert len(viewer) == 13
    assert viewer == outsider == nobody_yet
