"""Team ids and invite codes.

Both are random, so they can't be guessed or counted through. An invite code is shown
once and only its hash is stored; it is high-entropy, so a plain sha256 is enough.
"""

from __future__ import annotations

import hashlib
import re
import secrets

TEAM_ID_RE = re.compile(r"^t_[A-Za-z0-9_-]{16}$")


def new_team_id() -> str:
    return "t_" + secrets.token_urlsafe(12)  # 18 characters, 96 random bits


def new_invite_code() -> str:
    return "fti_" + secrets.token_urlsafe(24)  # 36 characters, 192 random bits


def hash_invite(code: str) -> str:
    return hashlib.sha256(code.strip().encode("utf-8")).hexdigest()
