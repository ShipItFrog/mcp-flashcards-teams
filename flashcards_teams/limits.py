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
# Shared teams one person may belong to; their personal team doesn't count. Two, so one
# account takes at most three of the server's MAX_TEAMS_TOTAL places.
MAX_SHARED_TEAMS_PER_PERSON = 2
MAX_MEMBERS_PER_TEAM = 25
INVITE_TTL_SECONDS = 72 * 3600
# Longest invite code join_team accepts.
MAX_INVITE_CODE = 100
# Longest client_id stored in an audit record; longer ones are cut. A hint at the app,
# not identity, so 64 characters are enough and keep every audit row small.
MAX_CLIENT_ID = 64
PERSONAL_TEAM_NAME = "Personal"
# Invite codes each team may ever create. Bounds the invites table, which is never
# emptied, well below the team's audit allowance.
MAX_INVITES_PER_TEAM = 1_000
# Changes (permissions.DAILY_CAPPED_TOOLS) one member may make in one team in one UTC
# day: ten times normal use, so a runaway client can't use up a team's lifetime
# allowance in an afternoon.
MAX_WRITES_PER_MEMBER_PER_DAY = 500

# Audit records each team may write: every one except a successful audit.read. Set for
# normal use (one person, 50 card changes a day) for at least five years.
AUDIT_CAP_PER_TEAM = 100_000
# The last part of the write allowance, kept for the owners' member changes and for
# members leaving (permissions.RESERVE_TOOLS), so a full log can still be acted on.
AUDIT_OWNER_RESERVE = 200
# Successful audit.read records each team may write: one read a day for five years,
# with room to spare. Each one is a row, so reads can't grow the log without bound.
AUDIT_READS_CAP_PER_TEAM = 2_000
# Teams on the whole server, personal teams included (both kinds take about as much
# room at worst): every team filled to its limits fits in half of a 1 GB database.
MAX_TEAMS_TOTAL = 12
# Refusals and failures recorded one by one for each member of each team, for life;
# later ones are only counted.
MAX_REFUSALS_LOGGED_PER_MEMBER = 100
SCHEMA_VERSION = 1
