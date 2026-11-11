"""Who may do what in a team: the only source of the permission rules.

Roles live in this server's database and are read again on every call; nothing here
comes from the token. A tool or role not listed is refused (deny by default).
"""

from __future__ import annotations

ROLES = ("owner", "editor", "viewer")
ROLE_RANK = {"viewer": 1, "editor": 2, "owner": 3}
# Team tools and the lowest role that may use them. create_team, list_teams and
# join_team belong to no team: being signed in is enough.
REQUIRED = {
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


def allowed(role: str | None, tool: str) -> bool:
    need = REQUIRED.get(tool)
    if need is None or role not in ROLE_RANK:
        return False  # deny by default
    return ROLE_RANK[role] >= ROLE_RANK[need]


# The action each tool records in the audit log.
AUDIT_ACTION = {
    "add_card": "card.add",
    "grade_card": "card.grade",
    "delete_card": "card.delete",
    "create_team": "team.create",
    "create_invite": "invite.create",
    "join_team": "member.join",
    "set_member_role": "member.role",
    "remove_member": "member.remove",
    "read_audit_log": "audit.read",
    "leave_team": "member.leave",
}
# Tools whose successful calls may use the last part of a team's audit allowance
# (limits.AUDIT_OWNER_RESERVE). read_audit_log has an allowance of its own.
RESERVE_TOOLS = frozenset({"set_member_role", "remove_member", "leave_team"})
# Tools whose successful calls count toward limits.MAX_WRITES_PER_MEMBER_PER_DAY.
DAILY_CAPPED_TOOLS = frozenset({"add_card", "grade_card", "delete_card", "create_invite"})
