"""Deliberately broken variants of the server, used only to prove the tests catch
real mistakes. Each one is applied with monkeypatch at test time (see conftest.py);
the source files are never modified.

Run all of them with:  python tests/run_mutations.py
Every mutation must make at least one test fail.
"""

from __future__ import annotations

import time
from contextlib import contextmanager

import anyio
import jwt
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken
from mcp.server.auth.settings import AuthSettings

from flashcards_teams import app as app_module
from flashcards_teams import server
from flashcards_teams import store as store_module
from flashcards_teams import verifier as verifier_module

A = app_module
S = store_module
V = verifier_module


def _shared_deck(issuer: str) -> str:
    """Forgot the per-user key: everyone shares one deck."""
    return "everyone"


def _key_by_client_id(issuer: str) -> str:
    """Keys data by the OAuth client (the app) instead of the user."""
    return f"{issuer}|{get_access_token().client_id}"


def _no_subject_check(issuer: str) -> str:
    """Drops the 'token must have a subject' defence."""
    token = get_access_token()
    if (token.claims or {}).get("iss") != issuer:
        raise server.ToolError("Not signed in.")
    return f"{issuer}|{token.subject}"


def _no_issuer_check(issuer: str) -> str:
    """Trusts any issuer: the same `sub` from two identity providers becomes one person."""
    token = get_access_token()
    if token is None or not token.subject:
        raise server.ToolError("Not signed in.")
    return f"{issuer}|{token.subject}"


def _record_review_unscoped(self, owner, card_no, correct):
    """One query that forgot its owner filter."""
    with self._lock, self._conn:
        cur = self._conn.execute(
            "UPDATE cards SET last_reviewed = ?, review_count = review_count + 1,"
            " correct_count = correct_count + ?, wrong_count = wrong_count + ? WHERE card_no = ?",
            (S._now(), 1 if correct else 0, 0 if correct else 1, card_no),
        )
        if cur.rowcount == 0:
            return None
        row = self._conn.execute(f"SELECT {S._CARD_COLUMNS} FROM cards WHERE card_no = ?", (card_no,)).fetchone()
    return S._row_to_card(row)


def _least_recent_ignores_time(self, owner, topic):
    """Review order that only looks at 'reviewed or not', not when."""
    clause, params = S._topic_clause(topic)
    with self._lock:
        row = self._conn.execute(
            f"SELECT {S._CARD_COLUMNS} FROM cards WHERE owner = ?{clause}"
            " ORDER BY last_reviewed IS NOT NULL, card_no LIMIT 1",
            [owner, *params],
        ).fetchone()
    return S._row_to_card(row) if row else None


def _list_unpaginated(self, owner, topic, limit, after_id):
    """Listing that ignores the page size and cursor."""
    clause, params = S._topic_clause(topic)
    with self._lock:
        rows = self._conn.execute(
            f"SELECT {S._CARD_COLUMNS} FROM cards WHERE owner = ?{clause} ORDER BY card_no", [owner, *params]
        ).fetchall()
    return [S._row_to_card(r) for r in rows]


def _auth_without_audience_check(**kwargs):
    """Accepts tokens issued for any server."""
    kwargs["validate_token_resource"] = False
    return AuthSettings(**kwargs)


# --- the real JWT verifier ---


def _decode_without_signature(self, token):
    """Reads the token without checking its signature (every claim is still checked)."""
    return jwt.decode(
        token,
        issuer=self.issuer,
        audience=self.audience,
        leeway=V.LEEWAY_SECONDS,
        options={
            "verify_signature": False,
            **dict.fromkeys(["verify_exp", "verify_nbf", "verify_iat", "verify_iss", "verify_aud", "verify_sub"], True),
            "require": V.REQUIRED_CLAIMS,
        },
    )


def _decode_any_audience(self, token):
    """Forgot the audience check: accepts tokens the provider issued for other servers."""
    key = self._keys.get_signing_key_from_jwt(token)
    return jwt.decode(
        token, key, algorithms=V.ALGORITHMS, issuer=self.issuer, leeway=V.LEEWAY_SECONDS,
        options={"verify_aud": False, "require": ["iss", "sub", "exp"]},
    )


def _decode_any_issuer(self, token):
    """Forgot the issuer check."""
    key = self._keys.get_signing_key_from_jwt(token)
    return jwt.decode(
        token, key, algorithms=V.ALGORITHMS, audience=self.audience, leeway=V.LEEWAY_SECONDS,
        options={"require": V.REQUIRED_CLAIMS},
    )


def _decode_ignoring_expiry(self, token):
    """Forgot the expiry check."""
    key = self._keys.get_signing_key_from_jwt(token)
    return jwt.decode(
        token, key, algorithms=V.ALGORITHMS, issuer=self.issuer, audience=self.audience, leeway=V.LEEWAY_SECONDS,
        options={"verify_exp": False, "require": ["iss", "sub", "aud"]},
    )


async def _verify_subject_optional(self, token):
    """Accepts a token that doesn't name a user."""

    def decode():
        key = self._keys.get_signing_key_from_jwt(token)
        return jwt.decode(
            token, key, algorithms=V.ALGORITHMS, issuer=self.issuer, audience=self.audience,
            leeway=V.LEEWAY_SECONDS, options={"require": ["iss", "aud", "exp"]},
        )

    try:
        claims = await anyio.to_thread.run_sync(decode)
    except Exception:
        return None
    return AccessToken(
        token=token, client_id="", scopes=V._scopes(claims), expires_at=int(claims["exp"]),
        resource=self.audience, subject=claims.get("sub"), claims={"iss": claims["iss"], "sub": claims.get("sub")},
    )


def _rs256_only(mp):
    """Hard-codes RS256, as Descope's metadata suggests, though a project run by Descope itself signs with ES384."""
    mp.setattr(V, "ALGORITHMS", ["RS256"])


def _unverified(token):
    return jwt.decode(token, options={"verify_signature": False})


def _rewrap_verify_token(mp, change):
    """Run the real verify_token, then apply `change(result, claims)` to what it accepted."""
    original = V.JwtTokenVerifier.verify_token

    async def patched(self, token):
        result = await original(self, token)
        return change(result, _unverified(token)) if result is not None else None

    mp.setattr(V.JwtTokenVerifier, "verify_token", patched)


def _resource_from_first_aud(mp):
    """Takes the resource from the token's aud (its first entry) instead of the configured URL."""
    _rewrap_verify_token(
        mp, lambda r, c: r.model_copy(update={"resource": c["aud"] if isinstance(c["aud"], str) else c["aud"][0]})
    )


def _client_id_without_azp(mp):
    """Reads the client ID only from client_id, which Descope's tokens don't have."""
    _rewrap_verify_token(mp, lambda r, c: r.model_copy(update={"client_id": str(c.get("client_id") or "")}))


def _scope_not_split(claims):
    """Treats the space-separated scope string as one scope."""
    scope = claims.get("scope")
    return [scope] if isinstance(scope, str) else (scope or [])


def _token_logged_on_mismatch(mp):
    """Logs the token itself when explaining an issuer or audience mismatch."""
    original = V._claimed

    def patched(token):
        V.logger.info("mismatched token: %s", token)
        return original(token)

    mp.setattr(V, "_claimed", patched)


class _InlineAnyio:
    """anyio stand-in whose to_thread.run_sync runs the function on the event loop."""

    class to_thread:
        @staticmethod
        async def run_sync(fn, *args):
            return fn(*args)


def _dsub_ignored(mp):
    """Ignores dsub, so a customized sub is trusted as the user's ID."""
    original = V.JwtTokenVerifier._decode

    def patched(self, token):
        claims = original(self, token)
        claims.pop("dsub", None)
        return claims

    mp.setattr(V.JwtTokenVerifier, "_decode", patched)


def _token_type_ignored(mp):
    """Accepts the same provider's refresh and ID tokens as access tokens."""
    original = V._kind_problem
    mp.setattr(V, "_kind_problem", lambda claims: original({k: v for k, v in claims.items() if k != "token_type"}))


def _lifetime_capped_only_with_iat(mp):
    """Checks the lifetime only when the token says when it was issued."""
    original = V._kind_problem
    mp.setattr(V, "_kind_problem", lambda claims: original(claims) if "iat" in claims else "")


def _lifetime_counted_from_now(mp):
    """Counts the lifetime from now, so a long-lived token close to expiry passes."""
    original = V._kind_problem
    mp.setattr(V, "_kind_problem", lambda claims: original({k: v for k, v in claims.items() if k != "iat"}))


def _empty_token_type_allowed(mp):
    """Treats a null or empty token_type as no token_type at all."""
    original = V._kind_problem
    mp.setattr(
        V, "_kind_problem",
        lambda claims: original({k: v for k, v in claims.items() if k != "token_type" or v}),
    )


# --- the provider's signing keys (SigningKeys) ---


def _after_init(mp, change):
    """Run the real SigningKeys.__init__, then `change(self)`."""
    original = V.SigningKeys.__init__

    def patched(self, *args, **kwargs):
        original(self, *args, **kwargs)
        change(self)

    mp.setattr(V.SigningKeys, "__init__", patched)


def _after_failure(mp, change):
    """Run the real SigningKeys._failed, then `change(self)`."""
    original = V.SigningKeys._failed

    def patched(self, e):
        original(self, e)
        change(self)

    mp.setattr(V.SigningKeys, "_failed", patched)


def _default_user_agent(store):
    """Fetches keys with Python's default User-Agent, which Descope's endpoint refuses."""
    store._client.headers = {}


def _token_in_key_warning(mp):
    """Logs a warning naming the token when no keys are young enough to check it."""
    original = V.SigningKeys.get_signing_key_from_jwt

    def patched(self, token):
        try:
            return original(self, token)
        except V.SigningKeysUnavailable:
            V.logger.warning("No signing keys to check the token %s", token)
            raise

    mp.setattr(V.SigningKeys, "get_signing_key_from_jwt", patched)


def _staleness_from_last_attempt(store):
    """Dates the kept keys from the failed attempt, so they never grow too old."""
    if store._snapshot is not None:
        store._snapshot = (store._snapshot[0], store._clock())


def _failed_fetch_drops_keys(store):
    """Throws the last good keys away when a fetch fails."""
    store._snapshot = None


def _empty_set_replaces_keys(mp):
    """Takes a response with no usable keys as an empty key set that replaces the good one."""
    original = V.SigningKeys._download

    def patched(self):
        try:
            return original(self)
        except jwt.PyJWKSetError:  # no usable keys at all, or none for the allowed algorithms
            return {}
        except jwt.PyJWKClientError as e:
            if "did not contain any signing keys" in str(e):  # only encryption keys
                return {}
            raise  # unreachable, not an object: still a failed fetch

    mp.setattr(V.SigningKeys, "_download", patched)


def _key_age_from_fetch_end(mp):
    """Dates the keys from the end of their fetch, so a slow fetch makes them last longer."""
    original = V.SigningKeys._succeeded
    mp.setattr(V.SigningKeys, "_succeeded", lambda self, keys, started: original(self, keys, self._clock()))


def _download_any_algorithm(self):
    """Keeps keys for algorithms the verifier doesn't allow."""
    keys = {}
    for key in self._client.get_signing_keys():
        keys.setdefault(key.key_id, key)
    if not keys:
        raise jwt.PyJWKSetError("The key endpoint published no signing keys")
    return keys


def _removed_keys_kept(mp):
    """Merges a new key set into the old one, so a key the provider dropped keeps working."""
    original = V.SigningKeys._succeeded

    def patched(self, keys, started):
        old = self._snapshot[0] if self._snapshot is not None else {}
        original(self, {**old, **keys}, started)

    mp.setattr(V.SigningKeys, "_succeeded", patched)


def _fetch_catching_only_jwt_errors(self):
    """Treats only PyJWT's errors as a failed fetch; anything else escapes."""
    started = self._clock()
    self._last_attempt = started
    try:
        keys = self._download()
    except jwt.PyJWTError as e:
        self._failed(e)
        return
    self._succeeded(keys, started)


def _back_off_not_reset(mp):
    """Keeps counting failures after a success, so the next outage starts with long waits."""
    original = V.SigningKeys._succeeded

    def patched(self, keys, started):
        failures, failing_since = self._failures, self._failing_since
        original(self, keys, started)
        self._failures, self._failing_since = failures, failing_since

    mp.setattr(V.SigningKeys, "_succeeded", patched)


def _back_off_from_attempt_start(store):
    """Counts the wait from the start of the failed attempt, so a slow timeout eats it."""
    store._retry_at -= store._clock() - store._last_attempt


def _gate_counts_only_successes(store):
    """Counts the unknown-key-id gap from the last successful fetch only (PyJWT's cooldown)."""
    store._last_attempt = store._snapshot[1] if store._snapshot is not None else None


def _wants_fetch_ignoring_back_off_for_unknown_kids(self, kid):
    """Lets a token with an unknown key id fetch during back-off."""
    now = self._clock()
    in_back_off = self._retry_at is not None and now < self._retry_at
    snap = self._snapshot
    if snap is None or now - snap[1] >= V.KEYS_CACHE_SECONDS:
        return not in_back_off
    if kid in snap[0]:
        return False
    return self._last_attempt is None or now - self._last_attempt >= V.KEYS_UNKNOWN_KID_GAP_SECONDS


def _get_key(*, no_kid_shortcut=True, wait_with_keys=False, wait_without_keys=True):
    """A SigningKeys.get_key with one mistake about tokens without a kid or about waiting."""

    def get_key(self, kid):
        if no_kid_shortcut and (not isinstance(kid, str) or not kid):
            raise V.UnknownKeyId("The token names no key id")
        if self._wants_fetch(kid):
            wait = wait_without_keys if self._usable() is None else wait_with_keys
            if wait:
                acquired = self._fetch_lock.acquire(timeout=V.KEYS_WAIT_SECONDS)
            else:
                acquired = self._fetch_lock.acquire(blocking=False)
            if acquired:
                try:
                    if self._wants_fetch(kid):
                        self._fetch()
                finally:
                    self._fetch_lock.release()
        keys = self._usable()
        if keys is None:
            raise V.SigningKeysUnavailable("No signing keys young enough to trust")
        key = keys.get(kid)
        if key is None:
            raise V.UnknownKeyId("No published key matches the token's key id")
        return key

    return get_key


class _NoLock:
    """A lock that never stops anyone, so every request runs its own fetch."""

    def acquire(self, blocking=True, timeout=-1):
        return True

    def release(self):
        pass


def _outage_warning_per_request(mp):
    """Logs a warning on every request refused for want of keys."""
    original = V.SigningKeys.get_key

    def patched(self, kid):
        try:
            return original(self, kid)
        except V.SigningKeysUnavailable:
            V.logger.warning("Could not check an access token: no signing keys")
            raise

    mp.setattr(V.SigningKeys, "get_key", patched)


def _recovery_not_logged(mp):
    """Forgets the failure count just before a success, so the recovery isn't logged."""
    original = V.SigningKeys._succeeded

    def patched(self, keys, started):
        self._failures = 0
        original(self, keys, started)

    mp.setattr(V.SigningKeys, "_succeeded", patched)


def _max_age_crossing_not_logged(mp):
    """Doesn't log the moment an outage outlasts the kept keys."""
    original = V.SigningKeys._failed

    def patched(self, e):
        self._said_refusing = True
        original(self, e)

    mp.setattr(V.SigningKeys, "_failed", patched)


def _key_outage_logged_as_info(mp):
    """Logs a key outage at INFO, where it hides among token rejections."""
    original = V.SigningKeys._failed

    def patched(self, e):
        V.logger.warning = V.logger.info  # for this call only: other warnings stay warnings
        try:
            original(self, e)
        finally:
            del V.logger.warning

    mp.setattr(V.SigningKeys, "_failed", patched)


def _unknown_key_id_silent(mp):
    """Reports a key id the provider doesn't publish as a provider outage, so nothing is logged."""
    original = V.SigningKeys.get_key
    unavailable = V.SigningKeysUnavailable

    def patched(self, kid):
        try:
            return original(self, kid)
        except V.UnknownKeyId:
            raise unavailable("No signing keys young enough to trust") from None

    mp.setattr(V.SigningKeys, "get_key", patched)


def _lenient_url(env, name, errors):
    """The first version's URL check: present, http(s), https unless local. No standard form."""
    value = env.get(name, "").strip()
    if not value:
        errors.append(f"{name} is missing")
        return value
    parts = A.urlsplit(value)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        errors.append(f"{name} must be a full URL")
    elif parts.scheme == "http" and parts.hostname not in A.LOCAL_HOSTS:
        errors.append(f"{name} must use https")
    return value


async def _guard_allows_any_method(self, scope, receive, send):
    """The guard still names the scope in challenges, but lets GET through again."""
    if scope["type"] == "http" and scope["path"] == self.path and scope["method"] != "POST":
        await self.app(scope, receive, send)
        return
    await _ORIGINAL_GUARD_CALL(self, scope, receive, send)


_ORIGINAL_GUARD_CALL = A.McpEndpointGuard.__call__


def _challenge_without_scope(mp):
    """401 and 403 challenges no longer name the required scope."""
    original = A.McpEndpointGuard.__init__

    def patched(self, app, *, path, scopes):
        original(self, app, path=path, scopes=scopes)
        self.scope_param = b""

    mp.setattr(A.McpEndpointGuard, "__init__", patched)


_PG_NUMBER = (
    "INSERT INTO owners (owner, next_no) VALUES (%s, 2)"
    " ON CONFLICT (owner) DO UPDATE SET next_no = owners.next_no + 1 RETURNING next_no - 1 AS card_no"
)


def _pg_add(*, max_numbering=False, limit_before_lock=False, number_in_own_transaction=False):
    """A Postgres add with one ordering or transaction mistake."""

    def check_limits(conn, owner, question, answer, topic):
        usage = conn.execute(
            "SELECT COUNT(*) AS cards, COALESCE(SUM(length(question) + length(answer) + length(topic)), 0) AS chars"
            " FROM cards WHERE owner = %s",
            (owner,),
        ).fetchone()
        if usage["cards"] >= S.MAX_CARDS_PER_OWNER or usage["chars"] + len(question) + len(answer) + len(topic) > S.MAX_CHARS_PER_OWNER:
            raise S.CardLimitError

    def _add(self, owner, question, answer, topic):
        if number_in_own_transaction:
            with self._connection() as conn:  # committed at once, whatever happens next
                card_no = conn.execute(_PG_NUMBER, (owner,)).fetchone()["card_no"]
        with self._connection() as conn:
            if limit_before_lock:
                check_limits(conn, owner, question, answer, topic)
            if not number_in_own_transaction:
                card_no = conn.execute(_PG_NUMBER, (owner,)).fetchone()["card_no"]
            if max_numbering:
                card_no = conn.execute(
                    "SELECT COALESCE(MAX(card_no), 0) + 1 AS n FROM cards WHERE owner = %s", (owner,)
                ).fetchone()["n"]
            if not limit_before_lock:
                check_limits(conn, owner, question, answer, topic)
            row = conn.execute(
                "INSERT INTO cards (owner, card_no, question, answer, topic, topic_key, created_at)"
                f" VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING {S._CARD_COLUMNS}",
                (owner, card_no, question, answer, topic, S.topic_key(topic), S._now()),
            ).fetchone()
        return S._row_to_card(row)

    return _add


def _pg_review_nulls_last(self, owner, topic):
    """Orders by review time alone: Postgres puts never-reviewed cards (NULL) last."""
    clause, params = S._topic_clause(topic, "%s")
    with self._connection() as conn:
        row = conn.execute(
            f"SELECT {S._CARD_COLUMNS} FROM cards WHERE owner = %s{clause} ORDER BY last_reviewed, card_no LIMIT 1",
            [owner, *params],
        ).fetchone()
    return S._row_to_card(row) if row else None


def _pg_record_review_unscoped(self, owner, card_no, correct):
    """One Postgres query that forgot its owner filter."""
    with self._connection() as conn:
        row = conn.execute(
            "UPDATE cards SET last_reviewed = %s, review_count = review_count + 1,"
            " correct_count = correct_count + %s, wrong_count = wrong_count + %s"
            f" WHERE card_no = %s RETURNING {S._CARD_COLUMNS}",
            (S._now(), 1 if correct else 0, 0 if correct else 1, card_no),
        ).fetchone()
    return S._row_to_card(row) if row else None


def _pg_request_errors_unmapped(mp):
    """Requests hand the driver's own error on instead of StoreUnavailableError
    (startup still maps its errors)."""

    @contextmanager
    def connection(self):
        with self._pool.connection() as conn:
            yield conn

    mp.setattr(S.PostgresCardStore, "_connection", connection)


def _pg_prepared_statements(mp):
    """Leaves psycopg's server-side prepared statements on, which Neon's pooler may break."""
    original = S.PostgresCardStore.__init__

    def init(self, url):
        original(self, url)
        self._pool.kwargs.pop("prepare_threshold", None)

    mp.setattr(S.PostgresCardStore, "__init__", init)


def _pg_full_as_unavailable(mp):
    """Reports a full database as a passing outage ("try again in a minute")."""
    original = S.PostgresCardStore._mapped_errors

    @contextmanager
    def mapped(self):
        try:
            with original(self):
                yield
        except S.StoreFullError:
            raise S.StoreUnavailableError from None

    mp.setattr(S.PostgresCardStore, "_mapped_errors", mapped)


def _pg_no_connection_check(mp):
    """The pool hands out connections without checking them, so one the server dropped
    (Neon pausing) fails the next request."""
    import psycopg_pool

    mp.setattr(psycopg_pool.ConnectionPool, "check_connection", staticmethod(lambda conn: None))


def _database_url_echoed(value, errors):
    """Puts the database URL, password and all, into the error message."""
    if not value.startswith(("postgresql://", "postgres://")) or "sslmode=require" not in value:
        errors.append(f"FLASHCARDS_DATABASE_URL is not usable: {value!r}")


def _database_url_lenient(value, errors):
    """Only checks the scheme: no host, port or TLS checks."""
    if not value.startswith(("postgresql://", "postgres://")):
        errors.append("FLASHCARDS_DATABASE_URL must be a postgresql:// URL (value not shown)")


def _sqlite_allowed_on_render(mp):
    """Lets the server start on Render with a SQLite file that every restart wipes."""
    original = A._database
    mp.setattr(A, "_database", lambda env, on_render, errors: original(env, False, errors))


def _characters_unchecked(value, field):
    """Only rejects text that isn't valid UTF-8; NUL passes and Postgres then fails."""
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise server.ToolError(f"{field} contains invalid characters") from None


async def _outage_unexplained(call):
    """A database outage reaches the user as the SDK's generic error."""
    return await call


class _ServerWithListen(server.MCPServer):
    """Leaves subscriptions/listen on (the SDK default)."""

    def __init__(self, *args, **kwargs):
        kwargs.pop("subscriptions", None)
        super().__init__(*args, **kwargs)


class _StatefulServer(server.MCPServer):
    """Runs the app with per-connection sessions, which have a global cap."""

    def streamable_http_app(self, **kwargs):
        return super().streamable_http_app(**{**kwargs, "stateless_http": False})


MUTATIONS = {
    "shared-deck": lambda mp: mp.setattr(server, "current_owner", _shared_deck),
    "key-by-client-id": lambda mp: mp.setattr(server, "current_owner", _key_by_client_id),
    "no-subject-check": lambda mp: mp.setattr(server, "current_owner", _no_subject_check),
    "no-issuer-check": lambda mp: mp.setattr(server, "current_owner", _no_issuer_check),
    "unscoped-grade": lambda mp: mp.setattr(S.SqliteCardStore, "_record_review", _record_review_unscoped),
    "no-audience-check": lambda mp: mp.setattr(server, "AuthSettings", _auth_without_audience_check),
    "review-ignores-time": lambda mp: mp.setattr(S.SqliteCardStore, "_least_recently_reviewed", _least_recent_ignores_time),
    "unpaginated-list": lambda mp: mp.setattr(S.SqliteCardStore, "_list", _list_unpaginated),
    "topic-not-normalized": lambda mp: mp.setattr(S, "topic_key", lambda topic: topic),
    "no-rate-limit": lambda mp: mp.setattr(server.RateLimiter, "check", lambda self, key: None),
    "jwt-signature-not-checked": lambda mp: mp.setattr(V.JwtTokenVerifier, "_decode", _decode_without_signature),
    "jwt-audience-not-checked": lambda mp: mp.setattr(V.JwtTokenVerifier, "_decode", _decode_any_audience),
    "jwt-issuer-not-checked": lambda mp: mp.setattr(V.JwtTokenVerifier, "_decode", _decode_any_issuer),
    "jwt-expiry-not-checked": lambda mp: mp.setattr(V.JwtTokenVerifier, "_decode", _decode_ignoring_expiry),
    "jwt-subject-optional": lambda mp: mp.setattr(V.JwtTokenVerifier, "verify_token", _verify_subject_optional),
    "jwt-keys-not-cached": lambda mp: mp.setattr(V, "KEYS_CACHE_SECONDS", 0),
    "jwt-default-user-agent": lambda mp: _after_init(mp, _default_user_agent),
    "jwt-rs256-only": _rs256_only,
    "jwt-resource-from-first-aud": _resource_from_first_aud,
    "jwt-scope-not-split": lambda mp: mp.setattr(V, "_scopes", _scope_not_split),
    "jwt-client-id-without-azp": _client_id_without_azp,
    "jwt-token-logged-on-mismatch": _token_logged_on_mismatch,
    "jwt-token-in-key-warning": _token_in_key_warning,
    "jwt-decode-on-event-loop": lambda mp: mp.setattr(V, "anyio", _InlineAnyio),
    "jwt-dsub-ignored": _dsub_ignored,
    # A provider outage reported as a token problem.
    "jwt-key-errors-look-like-token-errors": lambda mp: mp.setattr(V, "SigningKeysUnavailable", V.UnknownKeyId),
    "jwt-token-type-ignored": _token_type_ignored,
    "jwt-lifetime-uncapped": lambda mp: mp.setattr(V, "MAX_LIFETIME_SECONDS", 10**12),
    "jwt-lifetime-capped-only-with-iat": _lifetime_capped_only_with_iat,
    "jwt-lifetime-counted-from-now": _lifetime_counted_from_now,
    "jwt-empty-token-type-allowed": _empty_token_type_allowed,
    # The provider's signing keys during an outage (SigningKeys).
    "jwt-no-stale-keys": lambda mp: mp.setattr(V, "KEYS_MAX_AGE_SECONDS", V.KEYS_CACHE_SECONDS),
    "jwt-stale-keys-forever": lambda mp: mp.setattr(V, "KEYS_MAX_AGE_SECONDS", 10**12),
    "jwt-staleness-from-last-attempt": lambda mp: _after_failure(mp, _staleness_from_last_attempt),
    "jwt-failed-fetch-drops-keys": lambda mp: _after_failure(mp, _failed_fetch_drops_keys),
    "jwt-empty-set-replaces-keys": _empty_set_replaces_keys,
    "jwt-disallowed-algorithm-keys-kept": lambda mp: mp.setattr(V.SigningKeys, "_download", _download_any_algorithm),
    "jwt-removed-keys-kept": _removed_keys_kept,
    "jwt-fetch-error-escapes": lambda mp: mp.setattr(V.SigningKeys, "_fetch", _fetch_catching_only_jwt_errors),
    "jwt-no-back-off": lambda mp: mp.setattr(V, "KEYS_RETRY_FIRST_SECONDS", 0),
    "jwt-back-off-uncapped": lambda mp: mp.setattr(V, "KEYS_RETRY_MAX_SECONDS", 10**9),
    "jwt-back-off-not-reset": _back_off_not_reset,
    "jwt-back-off-from-attempt-start": lambda mp: _after_failure(mp, _back_off_from_attempt_start),
    "jwt-unknown-kid-refresh-unlimited": lambda mp: mp.setattr(V, "KEYS_UNKNOWN_KID_GAP_SECONDS", 0),
    "jwt-unknown-kid-gate-counts-only-successes": lambda mp: _after_failure(mp, _gate_counts_only_successes),
    "jwt-unknown-kid-ignores-back-off": lambda mp: mp.setattr(
        V.SigningKeys, "_wants_fetch", _wants_fetch_ignoring_back_off_for_unknown_kids
    ),
    "jwt-no-kid-fetches": lambda mp: mp.setattr(V.SigningKeys, "get_key", _get_key(no_kid_shortcut=False)),
    "jwt-concurrent-fetches": lambda mp: _after_init(mp, lambda store: setattr(store, "_fetch_lock", _NoLock())),
    "jwt-refresh-waits-for-in-flight-fetch": lambda mp: mp.setattr(V.SigningKeys, "get_key", _get_key(wait_with_keys=True)),
    "jwt-waiters-never-wait": lambda mp: mp.setattr(V.SigningKeys, "get_key", _get_key(wait_without_keys=False)),
    "jwt-no-wait-limit": lambda mp: mp.setattr(V, "KEYS_WAIT_SECONDS", -1),
    "jwt-outage-warning-per-attempt": lambda mp: mp.setattr(V.logger, "debug", V.logger.warning),
    "jwt-outage-warning-per-request": _outage_warning_per_request,
    "jwt-recovery-not-logged": _recovery_not_logged,
    "jwt-max-age-crossing-not-logged": _max_age_crossing_not_logged,
    "jwt-key-outage-logged-as-info": _key_outage_logged_as_info,
    "jwt-key-age-from-fetch-end": _key_age_from_fetch_end,
    "jwt-fetch-timeout-unbounded": lambda mp: mp.setattr(V, "KEYS_FETCH_TIMEOUT_SECONDS", None),
    # A token problem reported as a provider outage.
    "jwt-unknown-key-id-silent": _unknown_key_id_silent,
    "jwt-keys-aged-by-wall-clock": lambda mp: _after_init(mp, lambda store: setattr(store, "_clock", time.time)),
    "app-urls-not-standard-form": lambda mp: mp.setattr(A, "_url", _lenient_url),
    "app-key-url-on-any-host": lambda mp: mp.setattr(A, "_same_host", lambda url, other: True),
    "app-get-allowed": lambda mp: mp.setattr(A.McpEndpointGuard, "__call__", _guard_allows_any_method),
    "app-challenge-without-scope": _challenge_without_scope,
    "app-listen-enabled": lambda mp: mp.setattr(server, "MCPServer", _ServerWithListen),
    "app-stateful": lambda mp: mp.setattr(server, "MCPServer", _StatefulServer),
    "app-default-keep-alive": lambda mp: mp.setattr(A, "KEEP_ALIVE_SECONDS", 5),
    "app-no-connection-limit": lambda mp: mp.setattr(A, "MAX_CONNECTIONS", None),
    "app-workers-from-environment": lambda mp: mp.setattr(A, "WORKERS", None),
    "app-sqlite-allowed-on-render": _sqlite_allowed_on_render,
    "app-database-url-echoed": lambda mp: mp.setattr(A, "_database_url", _database_url_echoed),
    "app-database-url-unchecked": lambda mp: mp.setattr(A, "_database_url", _database_url_lenient),
    "app-database-url-in-repr": lambda mp: mp.setattr(A.Settings, "__repr__", lambda self: f"Settings({self.database_url!r})"),
    "app-allowed-origins-ignored": lambda mp: mp.setattr(A, "_origins", lambda env, errors: []),
    "app-settings-not-stripped": lambda mp: mp.setattr(A, "_setting", lambda env, name: env.get(name)),
    "app-stray-url-characters-unexplained": lambda mp: mp.setattr(A, "NOT_IN_URLS", frozenset()),
    "store-on-event-loop": lambda mp: mp.setattr(S, "anyio", _InlineAnyio),
    "text-nul-allowed": lambda mp: mp.setattr(server, "_check_characters", _characters_unchecked),
    "outage-unexplained": lambda mp: mp.setattr(server, "_stored", _outage_unexplained),
    # Postgres only: run_mutations.py skips these when no local Postgres is available.
    "pg-number-from-max": lambda mp: mp.setattr(S.PostgresCardStore, "_add", _pg_add(max_numbering=True)),
    "pg-limit-checked-before-lock": lambda mp: mp.setattr(S.PostgresCardStore, "_add", _pg_add(limit_before_lock=True)),
    "pg-number-in-own-transaction": lambda mp: mp.setattr(S.PostgresCardStore, "_add", _pg_add(number_in_own_transaction=True)),
    "pg-review-nulls-last": lambda mp: mp.setattr(S.PostgresCardStore, "_least_recently_reviewed", _pg_review_nulls_last),
    "pg-unscoped-grade": lambda mp: mp.setattr(S.PostgresCardStore, "_record_review", _pg_record_review_unscoped),
    "pg-no-connection-check": _pg_no_connection_check,
    "pg-request-errors-unmapped": _pg_request_errors_unmapped,
    "pg-prepared-statements": _pg_prepared_statements,
    "pg-full-as-unavailable": _pg_full_as_unavailable,
    "app-origins-not-standardized": lambda mp: mp.setattr(A, "_standard_origin", lambda origin: origin),
}
