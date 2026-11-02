"""Real access-token checks: a JWT from the identity provider, verified locally.

The provider signs each access token. This server checks it on its own, using the
provider's published public keys (its JWKS), so a request needs no call to the
provider. A token is accepted only if:

- its signature is valid, made with one of the provider's keys. The allowed
  algorithms are fixed here and never taken from the token (RFC 8725);
- its issuer (`iss`) is exactly the configured one;
- its audience (`aud`) includes this server's URL, so a token the same provider
  issued for some other server is refused (RFC 8707);
- it has not expired (`exp` is required) and is not dated in the future;
- it names a user (`sub`), which identity.py uses as the user's identity, and has no
  `dsub` claim (Descope's sign that a token template replaced `sub`);
- if it names its kind (`token_type`), that is `access_token`, so a token that
  says it is a refresh or ID token can't stand in for one. Descope's access tokens
  carry the claim; tokens without it are judged by the other checks only;
- it is short-lived: valid for at most a day (Descope's last 10 minutes).

Anything else returns None, and the SDK answers 401. Tokens are never logged.
The server holds no secrets for this: the issuer, key URL and its own URL are public.

Keys: fetched when first needed and reused for 5 minutes; if the provider can't be
reached, the last keys are used for up to 30 minutes after that fetch, with retries
backing off from 5 seconds to a minute, one fetch at a time (see SigningKeys).
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from typing import Any

import anyio
import jwt
from mcp.server.auth.provider import AccessToken, TokenVerifier

from . import __version__

logger = logging.getLogger(__name__)

# Asymmetric algorithms only. Descope's metadata lists only RS256, but a project run
# by Descope itself publishes ES384 keys. PyJWT also requires the token's algorithm
# to be the one bound to the matching key, so a token can't pick a weaker one.
ALGORITHMS = ["RS256", "ES384"]
REQUIRED_CLAIMS = ["iss", "sub", "aud", "exp"]
# Tolerated clock difference between this server and the provider.
LEEWAY_SECONDS = 30
# The only token_type accepted when a token has the claim, even if it is null or empty
# (Descope's access tokens carry it).
ACCESS_TOKEN_TYPE = "access_token"
# Longest validity accepted: from iat to exp, or from now to exp when there is no
# iat. A token valid for longer is not a short-lived access token, and would stay
# usable that long if it leaked.
MAX_LIFETIME_SECONDS = 24 * 60 * 60
# The key settings below are read when used, never copied, so changing one changes
# the behaviour at once. Ages count from the start of the last successful fetch.
# Keys younger than this are used without asking the provider. While it is reachable,
# a key it revoked stays accepted for at most this long (Descope rotates daily).
KEYS_CACHE_SECONDS = 300
# Past this age every token is refused until a fetch succeeds. Descope's tokens last
# 10 minutes, so this rides out a short outage; while the endpoint is down, a revoked
# key stays accepted this long. Must exceed KEYS_CACHE_SECONDS + KEYS_RETRY_MAX_SECONDS.
KEYS_MAX_AGE_SECONDS = 1800
# After a failed fetch, wait this long before the next one, doubling after each failure.
KEYS_RETRY_FIRST_SECONDS = 5
# Longest wait between failed fetches: at most one a minute during a long outage, and
# back within a minute once the provider recovers.
KEYS_RETRY_MAX_SECONDS = 60
# A token naming a key id we don't have triggers a fetch only this long after the last
# attempt (failed ones count), so a rotated key is picked up within 10 seconds and
# made-up key ids can't make this server flood the provider.
KEYS_UNKNOWN_KID_GAP_SECONDS = 10
# A request with no usable keys waits this long for the fetch in progress (about twice
# the fetch timeout) before it is refused.
KEYS_WAIT_SECONDS = 10
KEYS_FETCH_TIMEOUT_SECONDS = 5
# Descope's key endpoint refuses urllib's default User-Agent with 403, so send our own.
USER_AGENT = f"mcp-flashcards-teams/{__version__}"


def _scopes(claims: dict[str, Any]) -> list[str]:
    """`scope` is a space-separated string (RFC 9068); a list is accepted too."""
    scope = claims.get("scope")
    if isinstance(scope, str):
        return scope.split()
    if isinstance(scope, list):
        return [s for s in scope if isinstance(s, str)]
    return []


def _kind_problem(claims: dict[str, Any]) -> str:
    """Why these claims don't describe a short-lived access token, or "" if they do."""
    if "token_type" in claims and claims["token_type"] != ACCESS_TOKEN_TYPE:
        return f"its token_type is {str(claims['token_type'])[:40]!r}, not {ACCESS_TOKEN_TYPE!r}"
    exp, iat = claims["exp"], claims.get("iat")
    if iat is not None:
        lifetime = exp - iat
    else:
        # Without iat, count from now, allowing for the provider's clock running ahead.
        lifetime = exp - time.time() - LEEWAY_SECONDS
    if lifetime > MAX_LIFETIME_SECONDS:
        return f"it is valid for {int(lifetime)} seconds, more than the {MAX_LIFETIME_SECONDS} allowed"
    return ""


def _claimed(token: str) -> dict[str, Any]:
    """The token's claims without any checks - only for explaining a rejection."""
    try:
        return jwt.decode(token, options={"verify_signature": False})
    except jwt.PyJWTError:
        return {}


class UnknownKeyId(jwt.PyJWKClientError):
    """The token names no key id, or one the provider doesn't publish: a token problem."""


class SigningKeysUnavailable(jwt.PyJWKClientError):
    """There are no keys young enough to trust: a provider problem, logged by SigningKeys."""


def _reason(e: Exception) -> str:
    return f"{type(e).__name__}: {str(e)[:200]!r}"


class SigningKeys:
    """The provider's signing keys: cached, refreshed with back-off, one fetch at a time.
    PyJWT only fetches, parses and filters (its cache is off); every rule about when
    to fetch and which keys to trust lives here. Times come from self._clock."""

    def __init__(self, jwks_url: str, *, clock: Callable[[], float] = time.monotonic) -> None:
        self._client = jwt.PyJWKClient(
            jwks_url, cache_jwk_set=False, timeout=KEYS_FETCH_TIMEOUT_SECONDS, headers={"User-Agent": USER_AGENT}
        )
        self._clock = clock
        # Held for the whole of a fetch, so "locked" means "a fetch is in progress".
        self._fetch_lock = threading.Lock()
        self._snapshot: tuple[dict[str, jwt.PyJWK], float] | None = None  # (keys, fetch start), replaced whole
        self._failures = 0
        self._failing_since: float | None = None
        self._retry_at: float | None = None
        self._last_attempt: float | None = None
        self._said_refusing = False

    def get_signing_key_from_jwt(self, token: str) -> jwt.PyJWK:  # same name as PyJWKClient's
        return self.get_key(jwt.get_unverified_header(token).get("kid"))

    def get_key(self, kid: object) -> jwt.PyJWK:
        if not isinstance(kid, str) or not kid:
            raise UnknownKeyId("The token names no key id")
        if self._wants_fetch(kid):
            if self._usable() is None:
                # Nothing to fall back on: wait, for a while, for the fetch in progress.
                acquired = self._fetch_lock.acquire(timeout=KEYS_WAIT_SECONDS)
            else:
                # The current keys will do: never wait for someone else's fetch.
                acquired = self._fetch_lock.acquire(blocking=False)
            if acquired:
                try:
                    if self._wants_fetch(kid):  # re-check: another request may just have fetched or failed
                        self._fetch()
                finally:
                    self._fetch_lock.release()
        keys = self._usable()
        if keys is None:
            raise SigningKeysUnavailable("No signing keys young enough to trust")
        key = keys.get(kid)
        if key is None:
            raise UnknownKeyId("No published key matches the token's key id")
        return key

    def _usable(self) -> dict[str, jwt.PyJWK] | None:
        snap = self._snapshot
        if snap is None or self._clock() - snap[1] >= KEYS_MAX_AGE_SECONDS:
            return None
        return snap[0]

    def _wants_fetch(self, kid: str) -> bool:  # read without the lock: a hint, re-checked under it
        now = self._clock()
        if self._retry_at is not None and now < self._retry_at:
            return False
        snap = self._snapshot
        if snap is None or now - snap[1] >= KEYS_CACHE_SECONDS:
            return True
        if kid in snap[0]:
            return False
        return self._last_attempt is None or now - self._last_attempt >= KEYS_UNKNOWN_KID_GAP_SECONDS

    def _fetch(self) -> None:  # caller holds _fetch_lock
        started = self._clock()
        self._last_attempt = started
        try:
            keys = self._download()
        except Exception as e:  # fail closed: any failure keeps the last good set
            self._failed(e)
            return
        self._succeeded(keys, started)

    def _download(self) -> dict[str, jwt.PyJWK]:
        keys: dict[str, jwt.PyJWK] = {}
        for key in self._client.get_signing_keys():
            # A key for another algorithm can't verify any token (PyJWT requires the
            # token's alg to be the key's), so a set of only such keys is a failure.
            if key.algorithm_name in ALGORITHMS:
                keys.setdefault(key.key_id, key)  # the first of a repeated kid, like PyJWT
        if not keys:
            raise jwt.PyJWKSetError("The key endpoint published no signing keys for the allowed algorithms")
        return keys

    def _succeeded(self, keys: dict[str, jwt.PyJWK], started: float) -> None:  # caller holds _fetch_lock
        if self._failures:
            logger.info(
                "Fetched the identity provider's signing keys again, after %d failed attempts over %d seconds",
                self._failures, int(self._clock() - self._failing_since),
            )
        # The new set replaces the old one: a key the provider dropped stops working now.
        self._snapshot = (keys, started)
        self._failures = 0
        self._failing_since = None
        self._retry_at = None
        self._said_refusing = False

    def _failed(self, e: Exception) -> None:  # caller holds _fetch_lock; the keys stay as they are
        now = self._clock()
        self._failures += 1
        if self._failures == 1:
            self._failing_since = self._last_attempt
        # Counted from the end of the attempt, so a slow timeout doesn't eat the wait.
        delay = min(KEYS_RETRY_FIRST_SECONDS * 2 ** min(self._failures - 1, 16), KEYS_RETRY_MAX_SECONDS)
        self._retry_at = now + delay
        snap = self._snapshot
        refusing = snap is None or now - snap[1] >= KEYS_MAX_AGE_SECONDS
        # Log changes of state only: never per request, never the token or its kid. A
        # warning when an outage starts, one more if it outlasts the keys, else debug.
        if self._failures == 1 or (refusing and not self._said_refusing):
            if snap is None:
                logger.warning(
                    "Could not fetch the identity provider's signing keys (%s). There are no keys yet, so every "
                    "access token is refused until a fetch succeeds; retrying with back-off",
                    _reason(e),
                )
            elif refusing:
                logger.warning(
                    "Could not fetch the identity provider's signing keys (%s). The last keys fetched are %d "
                    "seconds old, past the %d-second limit, so every access token is refused until a fetch "
                    "succeeds; retrying with back-off",
                    _reason(e), int(now - snap[1]), KEYS_MAX_AGE_SECONDS,
                )
            else:
                logger.warning(
                    "Could not fetch the identity provider's signing keys (%s). Still accepting tokens signed "
                    "with the keys fetched %d seconds ago, for at most %d more seconds; retrying with back-off",
                    _reason(e), int(now - snap[1]), int(KEYS_MAX_AGE_SECONDS - (now - snap[1])),
                )
        else:
            logger.debug(
                "Still cannot fetch the identity provider's signing keys (%s); %d failed attempts, next in %d seconds",
                _reason(e), self._failures, delay,
            )
        self._said_refusing = self._said_refusing or refusing


class JwtTokenVerifier(TokenVerifier):
    def __init__(self, *, issuer: str, audience: str, jwks_url: str) -> None:
        self.issuer = issuer
        self.audience = audience
        self._keys = SigningKeys(jwks_url)

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            # Fetching keys is blocking network I/O, so it runs in a worker thread.
            claims = await anyio.to_thread.run_sync(self._decode, token)
        except UnknownKeyId:
            logger.info("Rejected an access token: no published key matches its key id")
            return None
        except SigningKeysUnavailable:
            # A provider problem, already logged by SigningKeys when it started.
            return None
        except (jwt.InvalidIssuerError, jwt.InvalidAudienceError) as e:
            # The signature was valid, so this is a real token from the provider,
            # issued for something else: usually a configuration mismatch. Say what
            # it claimed (never the token itself) so the mismatch is easy to spot.
            claimed = _claimed(token)
            logger.info(
                "Rejected an access token: %s. It claims iss=%.200r aud=%.200r; this server expects iss=%r aud=%r",
                type(e).__name__, claimed.get("iss"), claimed.get("aud"), self.issuer, self.audience,
            )
            return None
        except jwt.PyJWTError as e:
            logger.info("Rejected an access token: %s: %.200r", type(e).__name__, str(e))
            return None
        except Exception as e:
            # Fail closed: an unexpected error is a rejected token, not a crash. One
            # line, no traceback: it could repeat on every request.
            logger.warning("Could not check an access token: %s: %.200r", type(e).__name__, str(e))
            return None
        if "dsub" in claims:
            # Descope moves the user ID to `dsub` when a token template overrides `sub`;
            # `sub` may then no longer identify the user, and it is the user's identity here.
            logger.warning(
                "Rejected an access token with a 'dsub' claim: its 'sub' may not be the user's ID. "
                "Turn off 'override subject claim' in the token template this server's tokens use."
            )
            return None
        if not claims["sub"]:
            return None
        try:
            problem = _kind_problem(claims)
        except (TypeError, ValueError, OverflowError):
            # PyJWT accepts an exp or iat that int() can read, such as a numeric string,
            # or a number too large for a float. Fail closed instead of answering 500.
            problem = "its exp or iat is not a plain number"
        if problem:
            logger.info("Rejected an access token: %s", problem)
            return None
        return AccessToken(
            token=token,
            client_id=str(claims.get("client_id") or claims.get("azp") or ""),
            scopes=_scopes(claims),
            expires_at=int(claims["exp"]),
            # The audience check passed, so this token was issued for this server.
            resource=self.audience,
            subject=claims["sub"],
            claims={"iss": claims["iss"], "sub": claims["sub"]},
        )

    def _decode(self, token: str) -> dict[str, Any]:
        key = self._keys.get_signing_key_from_jwt(token)
        return jwt.decode(
            token,
            key,
            algorithms=ALGORITHMS,
            issuer=self.issuer,
            audience=self.audience,
            leeway=LEEWAY_SECONDS,
            options={"require": REQUIRED_CLAIMS},
        )
