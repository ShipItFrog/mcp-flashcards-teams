"""The real token verifier, called directly with real signed JWTs. Every rule it
promises (signature, algorithm, issuer, audience, expiry, subject, token type,
lifetime) has a token that breaks exactly that rule and nothing else."""

import logging
import threading
import time
import urllib.error
import urllib.request

import anyio
import jwt
import pytest
from helpers import ISSUER, RESOURCE, SCOPE
from jwt_helpers import (
    ATTACKER_KEY,
    CLIENT_ID,
    DROP,
    EC_KID,
    JWKS,
    KID,
    PROJECT_ID,
    PROVIDER_EC_KEY,
    ROTATED_KEY,
    ROTATED_KID,
    FakeClock,
    JsonServer,
    KeyEndpoint,
    descope_token,
    hmac_signed_with_public_key,
    jwk,
    jwks_of,
    key_server,
    make_verifier,
    sign,
    unsigned,
)

from flashcards_teams.verifier import JwtTokenVerifier

pytestmark = pytest.mark.anyio
# The documented limit (README: "valid for at most a day"), written out here rather
# than read from the verifier, so changing the code's limit fails these tests.
DAY = 24 * 60 * 60


async def test_a_valid_token_names_the_user():
    exp = int(time.time()) + 600
    token = await make_verifier().verify_token(sign(exp=exp))
    assert token is not None
    assert token.subject == "alice"
    assert token.claims == {"iss": ISSUER, "sub": "alice"}
    assert token.resource == RESOURCE
    assert token.scopes == [SCOPE]
    assert token.client_id == "test-client"
    assert token.expires_at == exp


async def test_a_token_shaped_like_descopes_is_read_correctly():
    # aud is a list with this server's URL not first, scope holds several scopes and
    # the client ID is in azp: getting any of these wrong would lock out every real
    # user (401 from the SDK's resource check, or 403 for a missing scope).
    token = await make_verifier().verify_token(descope_token())
    assert token is not None
    assert token.subject == "U2alice"
    assert token.resource == RESOURCE
    assert token.scopes == [SCOPE, "offline_access"]
    assert token.client_id == CLIENT_ID


# Built when the test runs, so times are fresh.
REJECTED = {
    "signed-by-another-key": lambda: sign(key=ATTACKER_KEY),
    "no-signature-alg-none": unsigned,
    "hmac-signed-with-the-public-key": hmac_signed_with_public_key,
    "right-key-other-algorithm": lambda: sign(alg="RS512"),
    "algorithm-not-the-one-bound-to-the-key": lambda: sign(key=PROVIDER_EC_KEY, kid=KID, alg="ES384"),
    "unknown-key-id": lambda: sign(kid="some-other-key"),
    "no-key-id": lambda: sign(kid=None),
    "wrong-issuer": lambda: sign(iss="https://evil.example.test"),
    "issuer-with-extra-slash": lambda: sign(iss=ISSUER + "/"),
    "no-issuer": lambda: sign(iss=DROP),
    "issued-for-another-server": lambda: sign(aud="https://other.example.test/mcp"),
    "audience-list-without-this-server": lambda: sign(aud=["https://a.example.test/mcp", "https://b.example.test/mcp"]),
    "audience-is-a-path-under-this-server": lambda: sign(aud=RESOURCE + "/admin"),
    # An ordinary sign-in token from the same project: same keys, aud = project ID.
    "session-token-for-the-project": lambda: sign(aud=PROJECT_ID),
    "no-audience": lambda: sign(aud=DROP),
    "expired": lambda: sign(exp=int(time.time()) - 120),
    "no-expiry": lambda: sign(exp=DROP),
    "not-valid-yet": lambda: sign(nbf=int(time.time()) + 300),
    "issued-in-the-future": lambda: sign(iat=int(time.time()) + 300),
    "no-subject": lambda: sign(sub=DROP),
    "empty-subject": lambda: sign(sub=""),
    "subject-not-a-string": lambda: sign(sub=12345),
    # Descope's sign that a token template replaced sub with something else.
    "subject-overridden-dsub-present": lambda: sign(dsub="U2alice"),
    "custom-subject-shared-by-a-team": lambda: sign(sub="acme", dsub="U2victim"),
    # Other kinds of token from the same provider, with everything else valid.
    "refresh-token": lambda: sign(token_type="refresh_token"),
    "id-token": lambda: sign(token_type="id_token"),
    "token-type-empty": lambda: sign(token_type=""),
    "token-type-null": lambda: sign(token_type=None),
    "valid-for-more-than-a-day": lambda: sign(exp=int(time.time()) + DAY + 60),
    "valid-for-more-than-a-day-no-iat": lambda: sign(iat=DROP, exp=int(time.time()) + DAY + 3600),
    # Long-lived, but close to expiry: the declared lifetime counts, not the time left.
    "issued-over-a-day-ago-still-valid": lambda: (lambda now: sign(iat=now - DAY, exp=now + 600))(int(time.time())),
    # PyJWT accepts an exp that int() can read; the lifetime check must reject it, not crash.
    "expiry-as-a-string": lambda: sign(exp=str(int(time.time()) + 600)),
    "not-a-jwt": lambda: "not-a-jwt",
}


@pytest.mark.parametrize("make_token", REJECTED.values(), ids=REJECTED.keys())
async def test_a_token_breaking_any_rule_is_rejected(make_token):
    assert await make_verifier().verify_token(make_token()) is None


ACCEPTED = {
    "es384-key-like-descopes-own-project": lambda: sign(key=PROVIDER_EC_KEY, kid=EC_KID, alg="ES384"),
    "audience-list-including-this-server": lambda: sign(aud=["https://other.example.test/mcp", RESOURCE]),
    "provider-clock-slightly-ahead": lambda: sign(iat=int(time.time()) + 10),
    "scope-as-a-list": lambda: sign(scope=[SCOPE, "openid"]),
    "token-type-access-token": lambda: sign(token_type="access_token"),
    "valid-for-exactly-a-day": lambda: (lambda now: sign(iat=now, exp=now + DAY))(int(time.time())),
    "no-iat": lambda: sign(iat=DROP),
}


@pytest.mark.parametrize("make_token", ACCEPTED.values(), ids=ACCEPTED.keys())
async def test_legitimate_variations_are_accepted(make_token):
    token = await make_verifier().verify_token(make_token())
    assert token is not None and token.subject == "alice"
    assert SCOPE in token.scopes


async def test_missing_scope_means_no_scopes():
    # Accepted here; the SDK then answers 403 if the server requires a scope.
    token = await make_verifier().verify_token(sign(scope=DROP))
    assert token is not None and token.scopes == []


async def test_keys_are_cached_and_made_up_key_ids_cannot_flood_the_provider():
    endpoint = KeyEndpoint()
    clock = FakeClock()
    verifier = make_verifier(endpoint, clock)
    for _ in range(20):
        assert await verifier.verify_token(sign()) is not None
    assert endpoint.fetches == 1
    for i in range(50):
        assert await verifier.verify_token(sign(kid=f"made-up-{i}")) is None
    # No re-fetch within 10 seconds of the last one; then one for all the made-up ids.
    assert endpoint.fetches == 1
    clock.advance(10)
    for i in range(50, 100):
        assert await verifier.verify_token(sign(kid=f"made-up-{i}")) is None
    assert endpoint.fetches == 2


async def test_keys_are_fetched_off_the_event_loop():
    # A slow key endpoint must not freeze every other request on this single-process server.
    endpoint = KeyEndpoint()
    assert await make_verifier(endpoint).verify_token(sign()) is not None
    assert endpoint.threads and threading.get_ident() not in endpoint.threads


@pytest.mark.parametrize(
    "endpoint",
    [
        KeyEndpoint(error=jwt.PyJWKClientConnectionError("connection refused")),
        KeyEndpoint(error=ValueError("the key endpoint sent something that isn't JSON")),
        KeyEndpoint(jwks={"keys": []}),
        KeyEndpoint(jwks=["not", "an", "object"]),
        KeyEndpoint(jwks=jwks_of(jwk(ROTATED_KEY, KID, use="enc"))),
        KeyEndpoint(jwks=jwks_of(jwk(b"a shared secret, not a public key", KID))),
    ],
    ids=["unreachable", "not-json", "no-keys", "not-an-object", "no-signing-keys", "only-disallowed-algorithms"],
)
async def test_a_broken_key_endpoint_rejects_the_token_with_one_warning(caplog, endpoint):
    # A WARNING (visible to monitoring, unlike a token rejection) when the outage
    # starts, of one line, without a traceback; the retries that follow add none.
    clock = FakeClock()
    verifier = make_verifier(endpoint, clock)
    with caplog.at_level(logging.INFO, logger="flashcards_teams.verifier"):
        assert await verifier.verify_token(sign()) is None
        clock.advance(6)
        assert await verifier.verify_token(sign()) is None
        clock.advance(11)
        assert await verifier.verify_token(sign()) is None
    assert endpoint.fetches == 3
    [record] = caplog.records
    assert record.levelno == logging.WARNING
    assert record.exc_info is None and "\n" not in record.getMessage()


async def test_an_unknown_key_id_is_a_token_problem_not_a_provider_problem(caplog):
    with caplog.at_level(logging.INFO, logger="flashcards_teams.verifier"):
        assert await make_verifier().verify_token(sign(kid="made-up")) is None
    assert {r.levelno for r in caplog.records} == {logging.INFO}


async def test_keys_are_fetched_over_real_http_without_pythons_default_user_agent(no_proxy):
    with key_server() as (url, seen):
        # The stand-in really does refuse the default, like Descope's endpoint...
        with pytest.raises(urllib.error.HTTPError) as refused:
            urllib.request.urlopen(url, timeout=5)
        assert refused.value.code == 403
        # ...and the verifier's own fetch still gets the keys.
        verifier = JwtTokenVerifier(issuer=ISSUER, audience=RESOURCE, jwks_url=url)
        token = await verifier.verify_token(sign())
    assert token is not None and token.subject == "alice"
    assert not seen[-1].startswith("Python-urllib")


@pytest.mark.parametrize(
    "make_token, claimed",
    [
        (lambda: sign(iss="https://other-idp.example.test/P123"), "https://other-idp.example.test/P123"),
        (lambda: sign(aud="https://other.example.test/mcp"), "https://other.example.test/mcp"),
    ],
    ids=["issuer", "audience"],
)
async def test_a_mismatch_logs_what_the_token_claimed_and_what_was_expected(caplog, make_token, claimed):
    # A validly signed token for the wrong issuer or audience is almost always a
    # configuration mistake, so the log must make the difference visible.
    with caplog.at_level(logging.INFO, logger="flashcards_teams.verifier"):
        assert await make_verifier().verify_token(make_token()) is None
    assert claimed in caplog.text
    assert f"expects iss={ISSUER!r} aud={RESOURCE!r}" in caplog.text


async def test_tokens_never_appear_in_the_logs(caplog):
    # Every rejection path, including the ones that see genuine, unexpired tokens
    # (an issuer or audience mismatch, the key endpoint failing).
    tokens = [make() for make in REJECTED.values()] + [sign(), descope_token()]
    with caplog.at_level(logging.DEBUG):
        for token in tokens:
            await make_verifier().verify_token(token)
        for endpoint in (
            KeyEndpoint(error=jwt.PyJWKClientConnectionError("connection refused")),
            KeyEndpoint(error=ValueError("garbage")),
            KeyEndpoint(jwks={"keys": []}),
        ):
            await make_verifier(endpoint).verify_token(tokens[-1])
        # An outage while the last keys are still used, past their age limit, and the recovery.
        endpoint, clock = KeyEndpoint(), FakeClock()
        verifier = make_verifier(endpoint, clock)
        await verifier.verify_token(tokens[-1])
        endpoint.error = jwt.PyJWKClientConnectionError("connection refused")
        for seconds in (600, 1800):
            clock.advance(seconds)
            for token in tokens[-2:]:
                await verifier.verify_token(token)
        endpoint.error = None
        clock.advance(60)
        for token in tokens[-2:]:
            assert await verifier.verify_token(token) is not None
    assert caplog.records
    for token in tokens:
        if token.count(".") == 2:
            assert token not in caplog.text
            signature = token.rsplit(".", 1)[-1]
            assert not signature or signature not in caplog.text  # not even the signature part


# --- the provider's keys during an outage ---

OUTAGE = jwt.PyJWKClientConnectionError("connection refused")
LOGGER = "flashcards_teams.verifier"


async def outage_after_first_fetch(endpoint=None, clock=None):
    """A verifier that fetched the keys at 0; the endpoint has failed ever since."""
    endpoint, clock = endpoint or KeyEndpoint(), clock or FakeClock()
    verifier = make_verifier(endpoint, clock)
    assert await verifier.verify_token(sign()) is not None
    endpoint.error = OUTAGE
    return verifier, endpoint, clock


def warnings(caplog):
    return [r for r in caplog.records if r.levelno >= logging.WARNING]


async def test_users_stay_signed_in_during_a_short_provider_outage(caplog):
    with caplog.at_level(logging.INFO, logger=LOGGER):
        verifier, _, clock = await outage_after_first_fetch()
        clock.advance(600)
        assert await verifier.verify_token(sign()) is not None
        assert await verifier.verify_token(descope_token()) is not None
    assert len(warnings(caplog)) == 1


async def test_everyone_is_refused_once_keys_are_too_old(caplog):
    with caplog.at_level(logging.INFO, logger=LOGGER):
        verifier, _, clock = await outage_after_first_fetch()
        clock.advance(600)
        assert await verifier.verify_token(sign()) is not None
        clock.advance(1200)
        assert await verifier.verify_token(sign()) is None
        assert await verifier.verify_token(sign(key=PROVIDER_EC_KEY, kid=EC_KID, alg="ES384")) is None
        logged = len(caplog.records)
        for _ in range(10):
            assert await verifier.verify_token(sign()) is None
        assert len(caplog.records) == logged
    assert len(warnings(caplog)) <= 2


async def test_a_revoked_key_stops_working_at_the_next_successful_fetch():
    endpoint, clock = KeyEndpoint(), FakeClock()
    verifier = make_verifier(endpoint, clock)
    assert await verifier.verify_token(sign()) is not None
    endpoint.jwks = jwks_of(JWKS["keys"][1])  # EC_KID only
    clock.advance(300)
    assert await verifier.verify_token(sign()) is None
    assert await verifier.verify_token(sign(key=PROVIDER_EC_KEY, kid=EC_KID, alg="ES384")) is not None


async def test_a_rotated_key_works_on_its_first_token():
    endpoint, clock = KeyEndpoint(), FakeClock()
    verifier = make_verifier(endpoint, clock)
    assert await verifier.verify_token(sign()) is not None
    endpoint.jwks = jwks_of(*JWKS["keys"], jwk(ROTATED_KEY, ROTATED_KID))
    clock.advance(10)
    assert await verifier.verify_token(sign(key=ROTATED_KEY, kid=ROTATED_KID)) is not None
    assert endpoint.fetches == 2


async def test_simultaneous_requests_during_an_outage_fetch_once(caplog):
    with caplog.at_level(logging.INFO, logger=LOGGER):
        verifier, endpoint, clock = await outage_after_first_fetch()
        clock.advance(300)  # stale, but still usable
        results = []

        async def request():
            results.append(await verifier.verify_token(sign()))

        async with anyio.create_task_group() as tg:
            for _ in range(30):
                tg.start_soon(request)
    assert len(results) == 30 and all(r is not None for r in results)
    assert endpoint.fetches == 2
    assert len(warnings(caplog)) == 1


async def test_an_outage_is_not_reported_as_unknown_key_ids(caplog):
    verifier = make_verifier(KeyEndpoint(error=OUTAGE))
    with caplog.at_level(logging.INFO, logger=LOGGER):
        for _ in range(10):
            assert await verifier.verify_token(sign()) is None
    [record] = caplog.records
    assert record.levelno == logging.WARNING
    assert "no published key" not in caplog.text


@pytest.mark.parametrize(
    "make_token, accepted",
    [(make, False) for make in REJECTED.values()] + [(make, True) for make in ACCEPTED.values()],
    ids=[f"rejected-{name}" for name in REJECTED] + [f"accepted-{name}" for name in ACCEPTED],
)
async def test_stale_keys_check_tokens_exactly_like_fresh_ones(make_token, accepted):
    verifier, _, clock = await outage_after_first_fetch()
    clock.advance(1000)
    token = await verifier.verify_token(make_token())
    assert (token is not None) == accepted
    if accepted:
        assert token.subject == "alice"


async def test_a_real_http_outage_falls_back_to_the_last_good_keys(caplog, no_proxy):
    path = "/.well-known/jwks.json"
    with JsonServer({path: JWKS}) as server, caplog.at_level(logging.INFO, logger=LOGGER):
        verifier = JwtTokenVerifier(issuer=ISSUER, audience=RESOURCE, jwks_url=server.base + path)
        clock = FakeClock()
        verifier._keys._clock = clock
        assert await verifier.verify_token(sign()) is not None
        del server.documents[path]  # from now on the endpoint answers 404
        clock.advance(300)
        assert await verifier.verify_token(sign()) is not None
        assert len(server.paths) == 2
        clock.advance(4.9)
        assert await verifier.verify_token(sign()) is not None
        assert len(server.paths) == 2
        clock.advance(0.1)
        assert await verifier.verify_token(sign()) is not None
        assert len(server.paths) == 3
        server.documents[path] = JWKS
        clock.advance(10)
        assert await verifier.verify_token(sign()) is not None
        assert len(server.paths) == 4
    assert [r.levelno for r in caplog.records] == [logging.WARNING, logging.INFO]
    assert "again, after 2 failed attempts" in caplog.records[-1].getMessage()
    assert not any(agent.startswith("Python-urllib") for agent in server.agents)
