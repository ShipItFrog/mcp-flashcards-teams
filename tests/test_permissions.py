"""The permission table on its own: exactly the agreed rules, and deny by default."""

from flashcards_teams import permissions

# Written out here, not imported: a change to the table must change this file too.
EXPECTED_REQUIRED = {
    "list_cards": "viewer",
    "review": "viewer",
    "add_card": "editor",
    "grade_card": "editor",
    "delete_card": "editor",
    "create_invite": "owner",
    "set_member_role": "owner",
    "remove_member": "owner",
    "read_audit_log": "owner",
    "leave_team": "viewer",
}


def test_required_table_exact():
    assert permissions.REQUIRED == EXPECTED_REQUIRED


def test_deny_by_default():
    # Tools that belong to no team, a made-up tool, and the empty name.
    for tool in ("create_team", "list_teams", "join_team", "drop_everything", ""):
        for role in ("owner", "editor", "viewer"):
            assert permissions.allowed(role, tool) is False, (role, tool)
    # Roles that don't exist, or none at all.
    for tool in EXPECTED_REQUIRED:
        for role in (None, "", "admin", "Owner", "superuser"):
            assert permissions.allowed(role, tool) is False, (role, tool)


def test_role_rank():
    assert permissions.ROLES == ("owner", "editor", "viewer")
    assert permissions.ROLE_RANK == {"viewer": 1, "editor": 2, "owner": 3}
    for tool, need in EXPECTED_REQUIRED.items():
        for role in permissions.ROLES:
            expected = permissions.ROLE_RANK[role] >= permissions.ROLE_RANK[need]
            assert permissions.allowed(role, tool) is expected, (role, tool)
    # A higher role may do everything a lower one may.
    assert permissions.allowed("viewer", "grade_card") is False
    assert permissions.allowed("editor", "remove_member") is False
    assert permissions.allowed("owner", "list_cards") is True
