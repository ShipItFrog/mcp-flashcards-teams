"""Real signed JWTs for tests: an RSA key pair standing in for the identity
provider's, a way to mint tokens with any claims (good or deliberately bad), and a
stand-in for the provider's key endpoint.

Only the network fetch of the keys is replaced. Key parsing and every token check are
the real PyJWT code; caching, key lookup, back-off and the refresh rules are the real
SigningKeys code, timed by a fake clock.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import http.server
import json
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from helpers import ISSUER, RESOURCE, SCOPE

from flashcards_teams.verifier import JwtTokenVerifier, SigningKeys

KID = "provider-key-1"
PROVIDER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
# A project run by Descope itself signs with an EC P-384 key (ES384), so the provider has one too.
EC_KID = "provider-key-2"
PROVIDER_EC_KEY = ec.generate_private_key(ec.SECP384R1())
ATTACKER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
# A key the provider starts publishing later, as when it rotates its keys.
ROTATED_KID = "provider-key-3"
ROTATED_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
JWKS_URL = "https://auth.example.test/.well-known/jwks.json"
# A Descope project ID and an OAuth client ID, as they appear inside real tokens.
PROJECT_ID = "P123"
CLIENT_ID = "TPA3exampleclient"

# Marks a claim to leave out of the token entirely.
DROP = object()


def _public_jwk(private_key: Any, kid: str) -> dict[str, Any]:
    if isinstance(private_key, rsa.RSAPrivateKey):
        jwk, alg = jwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key(), as_dict=True), "RS256"
    else:
        jwk, alg = jwt.algorithms.ECAlgorithm.to_jwk(private_key.public_key(), as_dict=True), "ES384"
    return {**jwk, "kid": kid, "use": "sig", "alg": alg}


JWKS = {"keys": [_public_jwk(PROVIDER_KEY, KID), _public_jwk(PROVIDER_EC_KEY, EC_KID)]}


def jwk(key: Any, kid: str | None, **fields: Any) -> dict[str, Any]:
    """One published key: the public half of a private key, or for bytes an HS256
    secret (kty oct). kid=None leaves the kid out; `fields` override the rest, for
    example use="enc" or alg="RS384"."""
    if isinstance(key, bytes):
        entry = {**jwt.algorithms.HMACAlgorithm.to_jwk(key, as_dict=True), "kid": kid, "use": "sig", "alg": "HS256"}
    else:
        entry = _public_jwk(key, kid)
    entry.update(fields)
    return {k: v for k, v in entry.items() if not (k == "kid" and v is None)}


def jwks_of(*entries: dict[str, Any]) -> dict[str, Any]:
    """A key set publishing these keys, in this order (repeated kids allowed)."""
    return {"keys": list(entries)}


def claims(**overrides: Any) -> dict[str, Any]:
    now = int(time.time())
    base = {
        "iss": ISSUER,
        "sub": "alice",
        "aud": RESOURCE,
        "exp": now + 600,
        "iat": now,
        "scope": SCOPE,
        "client_id": "test-client",
    }
    base.update(overrides)
    return {k: v for k, v in base.items() if v is not DROP}


def sign(*, key: Any = PROVIDER_KEY, kid: str | None = KID, alg: str = "RS256", **overrides: Any) -> str:
    headers = {"kid": kid} if kid else {}
    return jwt.encode(claims(**overrides), key, algorithm=alg, headers=headers)


def descope_token(**overrides: Any) -> str:
    """Shaped like a Descope MCP access token: `aud` is a list with this server's URL
    not first, `scope` holds several space-separated scopes, the client ID is in
    `azp` (no `client_id`), `token_type` is "access_token", and it lasts 10 minutes."""
    now = int(time.time())
    shape = {
        "sub": "U2alice",
        "aud": [CLIENT_ID, PROJECT_ID, RESOURCE],
        "scope": f"{SCOPE} offline_access",
        "azp": CLIENT_ID,
        "client_id": DROP,
        "token_type": "access_token",
        "amr": ["oauth"],
        "iat": now,
        "exp": now + 600,
    }
    return sign(**{**shape, **overrides})


def unsigned() -> str:
    """alg "none": no signature at all."""
    return jwt.encode(claims(), None, algorithm="none", headers={"kid": KID})


def hmac_signed_with_public_key() -> str:
    """The classic algorithm-confusion attack: an HS256 token whose HMAC secret is
    the provider's *public* key, which anyone can download. Built by hand because
    PyJWT refuses to create it."""
    public_pem = PROVIDER_KEY.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )

    def b64(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    header = b64(json.dumps({"alg": "HS256", "typ": "JWT", "kid": KID}).encode())
    body = b64(json.dumps(claims()).encode())
    signature = hmac.new(public_pem, f"{header}.{body}".encode(), hashlib.sha256).digest()
    return f"{header}.{body}.{b64(signature)}"


class FakeClock:
    """A clock that moves only when told to. It starts at 0.0 on purpose, so a check
    like `if self._last_attempt:` (true or false instead of `is None`) shows up."""

    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds

    def set(self, t: float) -> None:
        self.now = t


class KeyEndpoint:
    """Stands in for the provider's JWKS endpoint, counts how often it is hit and
    records which threads fetched. With `error`, every fetch raises it instead;
    `jwks` and `error` can be changed during a test. With `outcomes` (key sets or
    exceptions), fetches take them in turn, the last one repeating. With `clock`, the
    time of each fetch is recorded in `times`; `during_fetch` runs inside each fetch
    (for example to let time pass)."""

    def __init__(
        self,
        jwks: Any = JWKS,
        *,
        error: Exception | None = None,
        outcomes: list[Any] | None = None,
        clock: FakeClock | None = None,
        during_fetch: Callable[[], None] | None = None,
    ) -> None:
        self.jwks = jwks
        self.error = error
        self.outcomes = outcomes
        self.clock = clock
        self.during_fetch = during_fetch
        self.fetches = 0
        self.threads: list[int] = []
        self.times: list[float] = []
        self._lock = threading.Lock()

    def __call__(self) -> Any:
        with self._lock:
            self.fetches += 1
            number = self.fetches
            self.threads.append(threading.get_ident())
            if self.clock is not None:
                self.times.append(self.clock())
        if self.during_fetch is not None:
            self.during_fetch()
        return self._answer(number)

    def _answer(self, number: int) -> Any:
        if self.outcomes is not None:
            outcome = self.outcomes[min(number, len(self.outcomes)) - 1]
            if isinstance(outcome, BaseException):
                raise outcome
            return outcome
        if self.error is not None:
            raise self.error
        return self.jwks


class HeldEndpoint(KeyEndpoint):
    """A KeyEndpoint whose `hold`-th fetch (the first by default) sets `started` and
    then waits for `release`. The 5-second limit only keeps a broken test from hanging;
    correct code never reaches it. Other fetches answer at once. Tests always set
    `release` in a finally block."""

    def __init__(self, jwks: Any = JWKS, *, hold: int = 1, **kwargs: Any) -> None:
        super().__init__(jwks, **kwargs)
        self.hold = hold
        self.started = threading.Event()
        self.release = threading.Event()

    def _answer(self, number: int) -> Any:
        if number == self.hold:
            self.started.set()
            self.release.wait(5)
        return super()._answer(number)


class ObservedLock:
    """Wraps the lock a SigningKeys already has (so a lock a variant swapped in is
    observed too) and records each acquire's (blocking, timeout) before passing it on."""

    def __init__(self, inner: Any) -> None:
        self.inner = inner
        self.calls: list[tuple[bool, float]] = []
        self.attempts = 0
        self._changed = threading.Condition()

    def acquire(self, blocking: bool = True, timeout: float = -1) -> bool:
        with self._changed:
            self.calls.append((blocking, timeout))
            self.attempts += 1
            self._changed.notify_all()
        return self.inner.acquire(blocking, timeout)

    def release(self) -> None:
        self.inner.release()

    def wait_for_attempts(self, n: int, timeout: float = 5) -> bool:
        with self._changed:
            return self._changed.wait_for(lambda: self.attempts >= n, timeout)


class JsonServer:
    """A real local HTTP server that serves JSON documents by path (404 otherwise) and,
    like Descope's endpoints, answers 403 to Python's default User-Agent. Records the
    paths and User-Agents it saw."""

    def __init__(self, documents: dict[str, Any]) -> None:
        self.documents = documents
        self.paths: list[str] = []
        self.agents: list[str] = []
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                agent = self.headers.get("User-Agent", "")
                outer.paths.append(self.path)
                outer.agents.append(agent)
                if agent.startswith("Python-urllib"):
                    self.send_response(403)
                    self.end_headers()
                    return
                if self.path not in outer.documents:
                    self.send_response(404)
                    self.end_headers()
                    return
                body = json.dumps(outer.documents[self.path]).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args: Any) -> None:  # keep test output quiet
                pass

        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base = f"http://127.0.0.1:{self._server.server_address[1]}"

    def __enter__(self) -> "JsonServer":
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self._server.shutdown()
        self._server.server_close()


@contextmanager
def key_server() -> Iterator[tuple[str, list[str]]]:
    """A local JWKS endpoint. Yields its URL and the User-Agents it saw."""
    with JsonServer({"/.well-known/jwks.json": JWKS}) as server:
        yield f"{server.base}/.well-known/jwks.json", server.agents


def make_keys(endpoint: KeyEndpoint | None = None, clock: FakeClock | None = None) -> SigningKeys:
    store = SigningKeys(JWKS_URL, clock=clock or FakeClock())
    store._client.fetch_data = endpoint or KeyEndpoint()  # replace only the network call
    return store


def make_verifier(endpoint: KeyEndpoint | None = None, clock: FakeClock | None = None) -> JwtTokenVerifier:
    verifier = JwtTokenVerifier(issuer=ISSUER, audience=RESOURCE, jwks_url=JWKS_URL)
    verifier._keys._client.fetch_data = endpoint or KeyEndpoint()  # replace only the network call
    verifier._keys._clock = clock or FakeClock()
    return verifier
