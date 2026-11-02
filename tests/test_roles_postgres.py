"""Postgres only: role changes racing each other, with real concurrent connections.
Every write locks its team's row and reads the caller's role again under that lock, so
a change that commits while a call waits is the one that counts."""

import pytest
from helpers import actor, fresh_postgres_store, queued_behind, raw, team_fixture

pytestmark = [pytest.mark.anyio, pytest.mark.postgres]


@pytest.fixture
def pg_store(pg_cluster):
    s = fresh_postgres_store(pg_cluster.admin_url, pg_cluster.app_url)
    yield s
    s.close()


def lock_row(team_id):
    def hold(conn):
        conn.execute("SELECT 1 FROM teams WHERE team_id = %s FOR UPDATE", (team_id,))

    return hold


async def test_mutual_demotion_waits_on_team_lock(pg_store):
    # Two owners demote each other at the same moment. Whichever goes second is no
    # longer an owner when it reads its role under the lock: refused, not a team
    # without owners (and not "last owner" either).
    f = await team_fixture(pg_store)
    dave, erin = actor("dave"), actor("erin")
    assert (await pg_store.set_member_role(dave, f.team, f.numbers["erin"], "owner")).kind == "ok"
    outcomes = await queued_behind(
        pg_store,
        lock_row(f.team),
        [
            pg_store.set_member_role(dave, f.team, f.numbers["erin"], "editor"),
            pg_store.set_member_role(erin, f.team, f.numbers["dave"], "editor"),
        ],
        waiting=2,
    )
    assert sorted(o.kind for o in outcomes) == ["denied", "ok"]
    assert [o.value for o in outcomes if o.kind == "denied"] == ["set_member_role"]
    assert raw(pg_store, "SELECT COUNT(*) FROM members WHERE team_id = ? AND role = 'owner'", (f.team,)) == [(1,)]


async def test_write_rechecks_role_after_lock(pg_store):
    # erin is an editor when her add starts and a viewer by the time it gets the lock.
    f = await team_fixture(pg_store)

    def demote_erin(conn):
        conn.execute(
            "UPDATE members SET role = 'viewer' WHERE team_id = %s AND member_no = %s", (f.team, f.numbers["erin"])
        )

    [outcome] = await queued_behind(
        pg_store,
        lock_row(f.team),
        [pg_store.add(actor("erin"), f.team, "q", "a", "t")],
        waiting=1,
        before_release=demote_erin,
    )
    assert (outcome.kind, outcome.value) == ("denied", "add_card")
    assert raw(pg_store, "SELECT COUNT(*) FROM cards WHERE team_id = ?", (f.team,)) == [(1,)]
    assert raw(pg_store, "SELECT next_card_no FROM teams WHERE team_id = ?", (f.team,)) == [(2,)]
