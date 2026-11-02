"""Every limit in one place.

Read them as ``limits.NAME`` at the moment they are used (never copy one into another
name at import time), so a test can lower a limit with monkeypatch.
"""

from __future__ import annotations

# Per team, personal teams included. Bounds the database size on a free-tier database.
MAX_CARDS_PER_TEAM = 1000
# Total characters (question + answer + topic) one team may store.
MAX_CHARS_PER_TEAM = 200_000
MAX_TEAM_NAME = 50
# Shared teams one person may belong to; their personal team doesn't count.
MAX_SHARED_TEAMS_PER_PERSON = 10
MAX_MEMBERS_PER_TEAM = 25
INVITE_TTL_SECONDS = 72 * 3600
# Longest invite code join_team accepts.
MAX_INVITE_CODE = 100
# Longest client_id stored in an audit record; longer ones are cut.
MAX_CLIENT_ID = 200
PERSONAL_TEAM_NAME = "Personal"

# Audit records each team may write: every one except a successful audit.read. Set for
# normal use (one person, 50 card changes a day) for at least five years. Tentative
# until the per-row size is measured.
AUDIT_CAP_PER_TEAM = 100_000
# The last part of the write allowance, kept for the owners' member changes and for
# members leaving (permissions.RESERVE_TOOLS), so a full log can still be acted on.
AUDIT_OWNER_RESERVE = 200
# Successful audit.read records each team may write. Tentative, like AUDIT_CAP_PER_TEAM.
AUDIT_READS_CAP_PER_TEAM = 2_000
# Teams on the whole server, personal teams included. Tentative placeholder.
MAX_TEAMS_TOTAL = 20
# Refusals and failures recorded one by one for each member of each team, for life;
# later ones are only counted.
MAX_REFUSALS_LOGGED_PER_MEMBER = 100
SCHEMA_VERSION = 1
