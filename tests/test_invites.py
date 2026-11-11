"""Invite codes: made by owners only, for one person, for 72 hours, while the person who
made them is still an owner. Every way of being invalid looks the same, and none of
them leaves a record in any team.

In the fixture (helpers.team_fixture) dave is the only owner of team A and ``f.code``
is an unused editor invite; bob owns team B and gina was removed from team A.
"""

import hashlib
import logging
from datetime import datetime, timedelta, timezone

import pytest
from helpers import (
    actor, audit_rows, fresh_postgres_store, mcp_client, payload, queued_behind, raw, refusal, rows, running_app,
    snapshot, team_fixture, without_audit,
)

from flashcards_teams import ids, limits
from flashcards_teams.server import (
    M_ALREADY, M_INVITE, M_INVITES_USED_UP, M_PERSONAL, M_TEAM_FULL, M_TOO_MANY_TEAMS,
)

pytestmark = pytest.mark.anyio


def unused(store, team_id, invite_no) -> bool:
    [(free,)] = raw(store, "SELECT used_at IS NULL FROM invites WHERE team_id = ? AND invite_no = ?", (team_id, invite_no))
    return bool(free)


async def test_an_invite_works_once(store):
    f = await team_fixture(store)
    async with running_app(store) as app:
        async with mcp_client(app, "bob-1", "auto") as bob:
            joined = payload(await bob.call_tool("join_team", {"code": f.code}))
        async with mcp_client(app, "gina-1", "auto") as gina:
            assert refusal(await gina.call_tool("join_team", {"code": f.code})) == M_INVITE
    assert joined == {"ok": True, "team_id": f.team, "name": "Team A", "role": "editor", "member_no": 6}
    assert raw(store, "SELECT used_by FROM invites WHERE team_id = ? AND invite_no = ?", (f.team, f.invite_no)) == [(6,)]


async def test_an_invite_expires(store, monkeypatch):
    f = await team_fixture(store)
    async with running_app(store) as app:
        async with mcp_client(app, "dave-1", "auto") as dave:
            before = datetime.now(timezone.utc)
            created = payload(await dave.call_tool("create_invite", {"team_id": f.team, "role": "viewer"}))
            after = datetime.now(timezone.utc)
        expires = datetime.fromisoformat(created["expires_at"])
        # 72 hours from when it was made, which was between before and after (the expiry is
        # kept in whole seconds, so it may be up to a second earlier).
        made = expires - timedelta(seconds=limits.INVITE_TTL_SECONDS)
        assert before - timedelta(seconds=1) <= made <= after
        assert created["message"] == (
            f"Give this code to one person, privately. It works once and expires at {created['expires_at']}. "
            "It won't be shown again."
        )
        # Just after its expiry time it works for nobody (the fixture's code, made before it,
        # neither); just before, it still works. Timed from the reply, not from this test's
        # clock, so a slow machine can't move the boundary.
        monkeypatch.setattr(store, "_clock", lambda: expires + timedelta(seconds=1))
        async with mcp_client(app, "bob-1", "auto") as bob:
            assert refusal(await bob.call_tool("join_team", {"code": created["code"]})) == M_INVITE
            assert refusal(await bob.call_tool("join_team", {"code": f.code})) == M_INVITE
        monkeypatch.setattr(store, "_clock", lambda: expires - timedelta(seconds=60))
        async with mcp_client(app, "bob-1", "auto") as bob:
            assert payload(await bob.call_tool("join_team", {"code": created["code"]}))["role"] == "viewer"


async def test_every_invalid_invite_looks_the_same_and_leaves_no_record(store, monkeypatch, caplog):
    f = await team_fixture(store)
    async with running_app(store) as app:
        async with mcp_client(app, "dave-1", "auto") as dave, mcp_client(app, "erin-1", "auto") as erin:
            payload(await dave.call_tool("set_member_role", {"team_id": f.team, "member_no": f.numbers["erin"], "role": "owner"}))
            by_erin = payload(await erin.call_tool("create_invite", {"team_id": f.team, "role": "viewer"}))["code"]
            payload(await dave.call_tool("set_member_role", {"team_id": f.team, "member_no": f.numbers["erin"], "role": "editor"}))
            to_expire = payload(await dave.call_tool("create_invite", {"team_id": f.team, "role": "viewer"}))["code"]
        async with mcp_client(app, "gina-1", "auto") as gina:
            payload(await gina.call_tool("join_team", {"code": f.code}))  # f.code is used now
        before = snapshot(store)
        replies = []
        with caplog.at_level(logging.INFO, logger="flashcards_teams.server"):
            async with mcp_client(app, "bob-1", "auto") as bob:
                replies.append(await bob.call_tool("join_team", {"code": "fti_" + "x" * 32}))  # wrong
                replies.append(await bob.call_tool("join_team", {"code": f.code}))  # used
                replies.append(await bob.call_tool("join_team", {"code": by_erin}))  # its maker is no longer an owner
                later = datetime.now(timezone.utc) + timedelta(seconds=limits.INVITE_TTL_SECONDS + 1)
                monkeypatch.setattr(store, "_clock", lambda: later)
                replies.append(await bob.call_tool("join_team", {"code": to_expire}))  # expired
    assert [refusal(r) for r in replies] == [M_INVITE] * 4
    # Nothing recorded in any team, and nothing else changed.
    assert snapshot(store) == before
    # The app log has one line for each, the same line, saying nothing about who or which team.
    assert [r.getMessage() for r in caplog.records if r.name == "flashcards_teams.server"] == [
        "Refused join_team: invite code not valid"
    ] * 4


async def test_an_invite_works_again_once_its_maker_is_an_owner_again(store):
    f = await team_fixture(store)
    async with running_app(store) as app:
        async with mcp_client(app, "dave-1", "auto") as dave, mcp_client(app, "erin-1", "auto") as erin:
            payload(await dave.call_tool("set_member_role", {"team_id": f.team, "member_no": f.numbers["erin"], "role": "owner"}))
            code = payload(await erin.call_tool("create_invite", {"team_id": f.team, "role": "viewer"}))["code"]
            payload(await dave.call_tool("set_member_role", {"team_id": f.team, "member_no": f.numbers["erin"], "role": "editor"}))
            async with mcp_client(app, "bob-1", "auto") as bob:
                assert refusal(await bob.call_tool("join_team", {"code": code})) == M_INVITE
                payload(await dave.call_tool("set_member_role", {"team_id": f.team, "member_no": f.numbers["erin"], "role": "owner"}))
                # Not used and not expired: it works again.
                joined = payload(await bob.call_tool("join_team", {"code": code}))
    assert (joined["team_id"], joined["role"]) == (f.team, "viewer")


async def test_the_role_comes_from_the_invite(store):
    f = await team_fixture(store)
    async with running_app(store) as app:
        async with mcp_client(app, "dave-1", "auto") as dave:
            code = payload(await dave.call_tool("create_invite", {"team_id": f.team, "role": "viewer"}))["code"]
        async with mcp_client(app, "bob-1", "auto") as bob:
            assert payload(await bob.call_tool("join_team", {"code": code}))["role"] == "viewer"
        async with mcp_client(app, "gina-1", "auto") as gina:
            assert payload(await gina.call_tool("join_team", {"code": f.code}))["role"] == "editor"
    joined = raw(store, "SELECT member_no, role, via_invite_no FROM members WHERE team_id = ? AND member_no >= 6 ORDER BY member_no", (f.team,))
    assert joined == [(6, "viewer", f.invite_no + 1), (7, "editor", f.invite_no)]


async def test_a_member_is_refused_and_the_invite_stays_usable(store):
    f = await team_fixture(store)
    async with running_app(store) as app:
        async with mcp_client(app, "frank-1", "auto") as frank:
            assert refusal(await frank.call_tool("join_team", {"code": f.code})) == M_ALREADY.format(member_no=f.numbers["frank"])
        assert unused(store, f.team, f.invite_no)
        async with mcp_client(app, "bob-1", "auto") as bob:
            payload(await bob.call_tool("join_team", {"code": f.code}))
    assert not unused(store, f.team, f.invite_no)


async def test_a_full_team_or_too_many_teams_leaves_the_invite_unused(store, monkeypatch):
    f = await team_fixture(store)
    members = sum(1 for t, *_ in snapshot(store)["members"] if t == f.team)
    async with running_app(store) as app, mcp_client(app, "bob-1", "auto") as bob:
        monkeypatch.setattr(limits, "MAX_MEMBERS_PER_TEAM", members)
        assert refusal(await bob.call_tool("join_team", {"code": f.code})) == M_TEAM_FULL.format(n=members)
        assert unused(store, f.team, f.invite_no)
        monkeypatch.setattr(limits, "MAX_MEMBERS_PER_TEAM", members + 1)
        monkeypatch.setattr(limits, "MAX_SHARED_TEAMS_PER_PERSON", 1)  # bob is in team B already
        assert refusal(await bob.call_tool("join_team", {"code": f.code})) == M_TOO_MANY_TEAMS.format(n=1)
        assert unused(store, f.team, f.invite_no)
        monkeypatch.setattr(limits, "MAX_SHARED_TEAMS_PER_PERSON", 2)
        assert payload(await bob.call_tool("join_team", {"code": f.code}))["team_id"] == f.team


async def test_only_the_codes_hash_is_stored(store):
    f = await team_fixture(store)
    async with running_app(store) as app, mcp_client(app, "dave-1", "auto") as dave:
        created = payload(await dave.call_tool("create_invite", {"team_id": f.team, "role": "editor"}))
    code = created["code"]
    assert code.startswith("fti_") and len(code) == 36
    [(code_hash,)] = raw(store, "SELECT code_hash FROM invites WHERE team_id = ? AND invite_no = ?", (f.team, created["invite_no"]))
    assert code_hash == hashlib.sha256(code.encode("utf-8")).hexdigest()
    # The code itself is nowhere in the database.
    for table in ("invites", "audit_events", "teams", "members"):
        assert code not in str(raw(store, f"SELECT * FROM {table}")), table


async def test_a_personal_team_cant_have_invites(store):
    async with running_app(store) as app, mcp_client(app, "erin-1", "auto") as erin:
        payload(await erin.call_tool("add_card", {"question": "q?", "answer": "a", "topic": "t"}))
        [personal] = payload(await erin.call_tool("list_teams", {}))["teams"]
        for role in ("editor", "viewer"):
            assert refusal(await erin.call_tool("create_invite", {"team_id": personal["team_id"], "role": role})) == M_PERSONAL
    assert rows(store, "invites") == 0


async def test_a_team_can_create_only_so_many_invites(store, monkeypatch):
    # For its whole life, so the invites table, never emptied, stays small.
    monkeypatch.setattr(limits, "MAX_INVITES_PER_TEAM", 3)
    async with running_app(store) as app, mcp_client(app, "dave-1", "auto") as dave:
        team = payload(await dave.call_tool("create_team", {"name": "Few invites"}))["team_id"]
        for n in (1, 2, 3):  # the third is still allowed
            assert payload(await dave.call_tool("create_invite", {"team_id": team, "role": "viewer"}))["invite_no"] == n
        before, records = snapshot(store), audit_rows(store, team)
        assert refusal(await dave.call_tool("create_invite", {"team_id": team, "role": "editor"})) == (
            M_INVITES_USED_UP.format(n=3)
        )
        # No invite, but the failure is recorded.
        assert without_audit(snapshot(store)) == without_audit(before)
        added = audit_rows(store, team)[len(records):]
        assert [(r["action"], r["target"], r["result"], r["reason"]) for r in added] == [
            ("invite.create", "team", "failed", "invites_used_up")
        ]
        # A personal team is refused for being one, whatever its count.
        monkeypatch.setattr(limits, "MAX_INVITES_PER_TEAM", 0)
        payload(await dave.call_tool("add_card", {"question": "q?", "answer": "a", "topic": "t"}))
        [personal] = [t for t in payload(await dave.call_tool("list_teams", {}))["teams"] if t["personal"]]
        assert refusal(await dave.call_tool("create_invite", {"team_id": personal["team_id"], "role": "viewer"})) == M_PERSONAL
    assert rows(store, "invites") == 3


@pytest.fixture
def pg_store(pg_cluster):
    s = fresh_postgres_store(pg_cluster.admin_url, pg_cluster.app_url)
    yield s
    s.close()


@pytest.mark.postgres
async def test_two_people_using_one_code_at_once(pg_store):
    # Postgres only. Both joins are held at the team's row until both are waiting there:
    # whichever goes second must find the code used.
    f = await team_fixture(pg_store)
    code_hash = ids.hash_invite(f.code)

    def hold(conn):
        conn.execute("SELECT 1 FROM teams WHERE team_id = %s FOR UPDATE", (f.team,))

    outcomes = await queued_behind(
        pg_store, hold, [pg_store.join_team(actor("bob"), code_hash), pg_store.join_team(actor("gina"), code_hash)], waiting=2
    )
    assert sorted((o.kind, o.reason) for o in outcomes) == [("failed", "invite_invalid"), ("ok", "")]
    assert raw(pg_store, "SELECT COUNT(*) FROM members WHERE team_id = ? AND via_invite_no = ?", (f.team, f.invite_no)) == [(1,)]
