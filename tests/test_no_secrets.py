"""Nothing secret or identifying reaches the audit log, its readers, or the app's log:
not the cards' text, the team's name, tokens, who people are (issuer and sub), invite
codes, or the database's own error text. The client_id the log does keep is cleaned.

Every value below that must not leak carries "SENTINEL", so a leak is easy to find.
"""

import json
import logging

import pytest
from helpers import mcp_client, payload, raw, refusal, running_app
from mcp.server.auth.provider import AccessToken, TokenVerifier

from flashcards_teams import limits
from flashcards_teams.identity import clean_client_id
from flashcards_teams.server import M_DENIED, M_INVITE, M_NO_CARD, M_NO_TEAM

pytestmark = pytest.mark.anyio

ISSUER = "https://issuer-SENTINEL-ISS.example.test"
RESOURCE = "http://127.0.0.1:8000/mcp"
PEOPLE = ("owner", "editor", "viewer", "leaver", "removed", "stranger")
TOKENS = {
    f"tok-SENTINEL-{who}": AccessToken(
        token=f"tok-SENTINEL-{who}", client_id="client-ns", scopes=["flashcards"], resource=RESOURCE,
        subject=f"sub-SENTINEL-{who}", claims={"iss": ISSUER, "sub": f"sub-SENTINEL-{who}"},
    )
    for who in PEOPLE
}
QUESTION, ANSWER, TOPIC = "QUESTION-SENTINEL-1", "ANSWER-SENTINEL-2", "TOPIC-SENTINEL-3"
TEAM_NAME = "TEAM-SENTINEL-4"
BAD_CODE = "fti_SENTINEL-made-up-code"


class Verifier(TokenVerifier):
    async def verify_token(self, token: str) -> AccessToken | None:
        return TOKENS.get(token)


def everything_stored(store) -> str:
    """Every audit record, every column as text."""
    return "\n".join("|".join(str(value) for value in row) for row in raw(store, "SELECT * FROM audit_events"))


async def test_no_secret_in_the_audit_log_its_readers_or_the_app_log(store, caplog):
    secrets = [QUESTION, ANSWER, TOPIC, TEAM_NAME, BAD_CODE, ISSUER, *TOKENS]
    secrets += [f"sub-SENTINEL-{who}" for who in PEOPLE]
    read_outputs = []
    with caplog.at_level(logging.DEBUG):
        async with running_app(store, token_verifier=Verifier(), issuer=ISSUER) as app:
            async with mcp_client(app, "tok-SENTINEL-owner", "auto") as owner:
                team_id = payload(await owner.call_tool("create_team", {"name": TEAM_NAME}))["team_id"]
                team = {"team_id": team_id}
                numbers = {"owner": 1}
                for who, role in (("editor", "editor"), ("viewer", "viewer"), ("leaver", "editor"), ("removed", "viewer")):
                    code = payload(await owner.call_tool("create_invite", {"role": role, **team}))["code"]
                    secrets.append(code)
                    async with mcp_client(app, f"tok-SENTINEL-{who}", "auto") as person:
                        numbers[who] = payload(await person.call_tool("join_team", {"code": code}))["member_no"]
                        # The code is used now: trying it again is refused.
                        assert refusal(await person.call_tool("join_team", {"code": code})) == M_INVITE
                async with mcp_client(app, "tok-SENTINEL-editor", "auto") as editor:
                    card = {"question": QUESTION, "answer": ANSWER, "topic": TOPIC, **team}
                    first = payload(await editor.call_tool("add_card", card))["card"]["id"]
                    second = payload(await editor.call_tool("add_card", card))["card"]["id"]
                    payload(await editor.call_tool("grade_card", {"card_id": first, "correct": True, **team}))
                    payload(await editor.call_tool("delete_card", {"card_id": second, **team}))
                    assert refusal(await editor.call_tool("grade_card", {"card_id": 999, "correct": True, **team})) == (
                        M_NO_CARD.format(card_id=999)
                    )
                    assert refusal(await editor.call_tool("join_team", {"code": BAD_CODE})) == M_INVITE
                    payload(await editor.call_tool("add_card", {"question": QUESTION, "answer": ANSWER, "topic": TOPIC}))
                payload(await owner.call_tool("set_member_role", {"member_no": numbers["viewer"], "role": "editor", **team}))
                payload(await owner.call_tool("set_member_role", {"member_no": numbers["viewer"], "role": "viewer", **team}))
                payload(await owner.call_tool("remove_member", {"member_no": numbers["removed"], **team}))
                async with mcp_client(app, "tok-SENTINEL-leaver", "auto") as leaver:
                    payload(await leaver.call_tool("leave_team", team))
                async with mcp_client(app, "tok-SENTINEL-viewer", "auto") as viewer:
                    assert refusal(await viewer.call_tool("add_card", {**card})) == M_DENIED.format(tool="add_card", role="editor")
                    assert refusal(await viewer.call_tool("read_audit_log", team)) == M_DENIED.format(
                        tool="read_audit_log", role="owner"
                    )
                for who in ("stranger", "removed"):
                    async with mcp_client(app, f"tok-SENTINEL-{who}", "auto") as outsider:
                        assert refusal(await outsider.call_tool("add_card", card)) == M_NO_TEAM
                        assert refusal(await outsider.call_tool("read_audit_log", team)) == M_NO_TEAM
                after = 0
                while after is not None:
                    page = payload(await owner.call_tool("read_audit_log", {"limit": 5, "after_seq": after, **team}))
                    read_outputs.append(page)
                    after = page["next_after_seq"]
                listed = payload(await owner.call_tool("list_teams", {}))
    stored = everything_stored(store)
    outputs = json.dumps(read_outputs)
    # Everything logged on the server's side. The test's own MCP client logs each message it
    # sends (arguments included) at DEBUG: that is the caller's log, not the server's.
    server_log = "\n".join(caplog.handler.format(r) for r in caplog.records if not r.name.startswith("mcp.client"))
    assert "Refused add_card: caller is not a member of the requested team" in server_log
    # The scenario recorded what it should: every action, refusals and failures included.
    actions = {e["action"] for page in read_outputs for e in page["events"]}
    assert actions == {
        "team.create", "invite.create", "member.join", "card.add", "card.grade", "card.delete",
        "member.role", "member.remove", "member.leave", "audit.read",
    }
    assert {e["result"] for page in read_outputs for e in page["events"]} == {"ok", "denied", "failed"}
    for secret in secrets:
        assert secret not in stored, secret
        assert secret not in outputs, secret
        assert secret not in server_log, secret
    # The rest of the team's own answers say nothing about who anyone is either.
    assert ISSUER not in json.dumps(listed) and "sub-SENTINEL" not in json.dumps(listed)


async def test_client_id_sanitized(store):
    # The client_id is the app's own claim: printable ASCII only, at most MAX_CLIENT_ID
    # characters, "" when there is none.
    async with running_app(store) as app:
        for token in ("weird-client-1", "long-client-1", "no-client-1"):
            async with mcp_client(app, token, "auto") as client:
                payload(await client.call_tool("add_card", {"question": "q?", "answer": "a", "topic": "t"}))
    stored = {}  # each person's personal team: the client_ids its records hold
    for team_id, principal in raw(store, "SELECT team_id, personal_of FROM teams"):
        found = raw(store, "SELECT DISTINCT client_id FROM audit_events WHERE team_id = ?", (team_id,))
        stored[principal.rsplit("|", 1)[1]] = [client_id for (client_id,) in found]
    alphabet = "".join(chr(ord("a") + i % 26) for i in range(100))
    assert stored == {
        "weird": ["bad?client?" + "x" * 53],
        "long": [alphabet[:64]],
        "noclient": [""],
    }
    assert limits.MAX_CLIENT_ID == 64
    assert all(len(c) <= limits.MAX_CLIENT_ID and c.isprintable() for ids in stored.values() for c in ids)
    assert clean_client_id(None) == ""


async def test_list_teams_has_no_identity(store):
    async with running_app(store, token_verifier=Verifier(), issuer=ISSUER) as app:
        async with mcp_client(app, "tok-SENTINEL-owner", "auto") as owner:
            team = payload(await owner.call_tool("create_team", {"name": "Team"}))["team_id"]
            code = payload(await owner.call_tool("create_invite", {"team_id": team, "role": "editor"}))["code"]
            payload(await owner.call_tool("add_card", {"question": "q?", "answer": "a", "topic": "t"}))  # personal team
            async with mcp_client(app, "tok-SENTINEL-editor", "auto") as editor:
                payload(await editor.call_tool("join_team", {"code": code}))
                as_member = json.dumps(payload(await editor.call_tool("list_teams", {})))
            as_owner = json.dumps(payload(await owner.call_tool("list_teams", {})))
    assert '"members"' in as_owner  # the owner's view lists the members, by number only
    for text in (as_owner, as_member):
        assert ISSUER not in text and "sub-SENTINEL" not in text and "principal" not in text and "personal_of" not in text
