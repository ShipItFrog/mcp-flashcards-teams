"""The provider's signing keys while it is up, down, slow or rotating its keys:
SigningKeys called directly, timed by a fake clock, against a stand-in key endpoint
that records when it was hit. The times are written out (300, 1800, 10, 5, 60)
rather than read from the code, so changing a setting fails these tests."""

import logging
import threading
import time

import jwt
import pytest
from jwt_helpers import (
    ATTACKER_KEY,
    EC_KID,
    JWKS,
    JWKS_URL,
    KID,
    PROVIDER_EC_KEY,
    PROVIDER_KEY,
    ROTATED_KEY,
    ROTATED_KID,
    FakeClock,
    HeldEndpoint,
    KeyEndpoint,
    ObservedLock,
    jwk,
    jwks_of,
    make_keys,
    sign,
)

from flashcards_teams import verifier as V
from flashcards_teams.verifier import SigningKeys, SigningKeysUnavailable, UnknownKeyId

OUTAGE = jwt.PyJWKClientConnectionError("connection refused")
WITH_ROTATED = jwks_of(*JWKS["keys"], jwk(ROTATED_KEY, ROTATED_KID))
LOGGER = "flashcards_teams.verifier"


def keys_at(clock, endpoint=None):
    endpoint = endpoint or KeyEndpoint(clock=clock)
    return make_keys(endpoint, clock), endpoint


# --- cache, stale keys and the age limit ---


def test_fresh_keys_are_served_without_fetching():
    clock = FakeClock()
    store, endpoint = keys_at(clock)
    for t in (0, 150, 299.9):
        clock.set(t)
        for _ in range(20):
            assert store.get_key(KID).key_id == KID
    assert endpoint.times == [0]


def test_keys_are_refetched_once_due():
    clock = FakeClock()
    store, endpoint = keys_at(clock)
    store.get_key(KID)
    clock.set(300)
    store.get_key(KID)
    store.get_key(KID)
    assert endpoint.times == [0, 300]


def test_a_failed_refresh_keeps_the_last_good_keys():
    clock = FakeClock()
    store, endpoint = keys_at(clock)
    first = store.get_key(KID)
    endpoint.error = OUTAGE
    clock.set(300)
    assert store.get_key(KID) is first
    assert endpoint.times == [0, 300]


def stale_store(clock):
    """Keys fetched at 0, and the endpoint failing ever since."""
    store, endpoint = keys_at(clock)
    store.get_key(KID)
    endpoint.error = OUTAGE
    return store, endpoint


def test_stale_keys_are_refused_from_the_max_age():
    clock = FakeClock()
    store, _ = stale_store(clock)
    clock.set(1799.9)
    assert store.get_key(KID).key_id == KID
    assert store.get_key(EC_KID).key_id == EC_KID
    clock.set(1800)
    for kid in (KID, EC_KID):
        with pytest.raises(SigningKeysUnavailable):
            store.get_key(kid)


def test_keys_come_back_when_the_provider_recovers():
    clock = FakeClock()
    store, endpoint = stale_store(clock)
    clock.set(1800)
    with pytest.raises(SigningKeysUnavailable):
        store.get_key(KID)
    endpoint.error = None
    clock.set(store._retry_at)
    assert store.get_key(KID).key_id == KID
    fetches = endpoint.fetches
    clock.advance(299)
    assert store.get_key(KID).key_id == KID
    assert endpoint.fetches == fetches


# --- back-off ---


def test_failed_fetches_back_off_doubling_to_a_minute():
    clock = FakeClock()
    store, endpoint = keys_at(clock, KeyEndpoint(error=OUTAGE, clock=clock))
    for t in range(201):
        clock.set(t)
        with pytest.raises(SigningKeysUnavailable):
            store.get_key(KID)
    assert endpoint.times == [0, 5, 15, 35, 75, 135, 195]


def test_back_off_also_limits_refreshes_of_stale_keys():
    clock = FakeClock()
    store, endpoint = keys_at(clock)
    store.get_key(KID)
    endpoint.error = OUTAGE
    for i in range(600, 1001):
        clock.set(i / 2)
        assert store.get_key(KID).key_id == KID
    assert endpoint.times == [0, 300, 305, 315, 335, 375, 435, 495]


def test_success_resets_the_back_off():
    clock = FakeClock()
    endpoint = KeyEndpoint(outcomes=[JWKS, OUTAGE, OUTAGE, JWKS, OUTAGE], clock=clock)
    store, _ = keys_at(clock, endpoint)
    for i in range(1251):
        clock.set(i / 2)
        assert store.get_key(KID).key_id == KID
    assert endpoint.times == [0, 300, 305, 315, 615, 620]


def test_back_off_counts_from_the_end_of_a_slow_attempt():
    clock = FakeClock()
    endpoint = KeyEndpoint(error=OUTAGE, clock=clock, during_fetch=lambda: clock.advance(5))
    store, _ = keys_at(clock, endpoint)
    with pytest.raises(SigningKeysUnavailable):
        store.get_key(KID)  # fails at 5, after a 5-second attempt
    clock.set(9.9)
    with pytest.raises(SigningKeysUnavailable):
        store.get_key(KID)
    assert endpoint.times == [0]
    clock.set(10)
    with pytest.raises(SigningKeysUnavailable):
        store.get_key(KID)
    assert endpoint.times[:2] == [0, 10]


def test_key_ages_count_from_the_start_of_a_slow_fetch():
    # The safe end: a fetch that takes 5 seconds doesn't make its keys last 5 seconds longer.
    clock = FakeClock()
    endpoint = KeyEndpoint(clock=clock, during_fetch=lambda: clock.advance(5))
    store, _ = keys_at(clock, endpoint)
    store.get_key(KID)  # fetched from 0 to 5
    endpoint.during_fetch = None
    endpoint.error = OUTAGE
    clock.set(299.9)
    store.get_key(KID)
    assert endpoint.times == [0]
    clock.set(300)
    store.get_key(KID)  # due at 300, not 305
    assert endpoint.times == [0, 300]
    clock.set(1799.9)
    assert store.get_key(KID).key_id == KID
    clock.set(1800)
    with pytest.raises(SigningKeysUnavailable):
        store.get_key(KID)  # too old at 1800, not 1805


def test_requests_during_back_off_do_not_fetch():
    clock = FakeClock()
    store, endpoint = keys_at(clock, KeyEndpoint(error=OUTAGE, clock=clock))
    for _ in range(1000):
        with pytest.raises(SigningKeysUnavailable):
            store.get_key(KID)
    assert endpoint.fetches == 1


# --- what counts as a good response ---

UNUSABLE = {
    "unreachable": jwt.PyJWKClientConnectionError("Fail to fetch data from the url, err: connection refused"),
    "http-500": jwt.PyJWKClientConnectionError("Fail to fetch data from the url, err: HTTP Error 500"),
    "not-json": ValueError("Expecting value: line 1 column 1 (char 0)"),
    "not-an-object": ["x"],
    "no-keys": {"keys": []},
    "keys-not-a-list": {"keys": "x"},
    "junk-key": {"keys": [{"kty": "junk", "kid": ROTATED_KID}]},
    "only-encryption-keys": jwks_of(jwk(ROTATED_KEY, ROTATED_KID, use="enc")),
    "keys-without-kid": jwks_of(jwk(ROTATED_KEY, None), jwk(PROVIDER_EC_KEY, None)),
    "only-disallowed-algorithms": jwks_of(jwk(b"a shared secret, not a public key", ROTATED_KID)),
    "unexpected-error": RuntimeError("something unexpected"),
    "connection-reset": ConnectionResetError(10054, "An existing connection was forcibly closed"),
}


@pytest.mark.parametrize("bad", UNUSABLE.values(), ids=UNUSABLE.keys())
def test_an_unusable_response_is_a_failed_fetch(bad):
    clock = FakeClock()
    store, endpoint = keys_at(clock, KeyEndpoint(outcomes=[JWKS, bad], clock=clock))
    store.get_key(KID)
    clock.set(300)
    assert store.get_key(KID).key_id == KID
    with pytest.raises(UnknownKeyId):
        store.get_key(ROTATED_KID)  # a failed fetch adds no keys
    assert endpoint.times[-1] == 300
    clock.set(304.9)
    store.get_key(KID)
    assert endpoint.times == [0, 300]
    clock.set(305)
    store.get_key(KID)
    assert endpoint.times == [0, 300, 305]


class Stop(BaseException):
    """Like KeyboardInterrupt or SystemExit: not a failed fetch."""


def test_an_interrupted_fetch_is_not_taken_for_a_failed_one():
    clock = FakeClock()
    store, _ = keys_at(clock, KeyEndpoint(outcomes=[JWKS, Stop()], clock=clock))
    store.get_key(KID)
    clock.set(300)
    with pytest.raises(Stop):
        store.get_key(KID)
    assert not store._fetch_lock.locked()
    assert store._failures == 0 and store._retry_at is None


def test_only_usable_signing_keys_are_kept():
    published = jwks_of(
        jwk(PROVIDER_KEY, KID),
        jwk(ROTATED_KEY, "enc-1", use="enc"),
        jwk(ROTATED_KEY, None),
        jwk(b"a shared secret, not a public key", "hs-1"),
        jwk(ROTATED_KEY, "rs384-1", alg="RS384"),
        jwk(ATTACKER_KEY, KID),  # the same kid again, other key material: the first one wins
    )
    store = make_keys(KeyEndpoint(published))
    key = store.get_key(KID)
    assert key.key.public_numbers() == PROVIDER_KEY.public_key().public_numbers()
    for kid in ("enc-1", "hs-1", "rs384-1"):
        with pytest.raises(UnknownKeyId):
            store.get_key(kid)


# --- rotation and unknown key ids ---


def test_a_key_missing_from_a_new_set_is_dropped_at_once():
    clock = FakeClock()
    store, endpoint = keys_at(clock)
    store.get_key(KID)
    endpoint.jwks = jwks_of(JWKS["keys"][1])  # EC_KID only
    clock.set(300)
    with pytest.raises(UnknownKeyId):
        store.get_key(KID)
    assert store.get_key(EC_KID).key_id == EC_KID
    endpoint.error = OUTAGE
    clock.set(600)
    with pytest.raises(UnknownKeyId):
        store.get_key(KID)  # no falling back to an older set
    assert endpoint.times[-1] == 600


def test_a_rotated_key_is_picked_up_by_its_first_token():
    clock = FakeClock()
    store, endpoint = keys_at(clock)
    store.get_key(KID)
    endpoint.jwks = WITH_ROTATED
    clock.set(10)
    assert store.get_key(ROTATED_KID).key_id == ROTATED_KID
    assert endpoint.times == [0, 10]
    assert store.get_key(KID).key_id == KID


def test_a_new_key_id_waits_out_the_gap():
    clock = FakeClock()
    store, endpoint = keys_at(clock)
    store.get_key(KID)
    endpoint.jwks = WITH_ROTATED
    clock.set(9.9)
    with pytest.raises(UnknownKeyId):
        store.get_key(ROTATED_KID)
    assert endpoint.times == [0]
    clock.set(10)
    assert store.get_key(ROTATED_KID).key_id == ROTATED_KID


def test_made_up_key_ids_fetch_at_most_once_per_gap():
    clock = FakeClock()
    store, endpoint = keys_at(clock)
    for i in range(6000):
        clock.set(i / 100)
        with pytest.raises(UnknownKeyId):
            store.get_key(f"made-up-{i}")
    assert endpoint.times == [0, 10, 20, 30, 40, 50]


def test_made_up_key_ids_cannot_flood_a_failing_provider():
    clock = FakeClock()
    store, endpoint = keys_at(clock, KeyEndpoint(outcomes=[JWKS, OUTAGE], clock=clock))
    for i in range(1201):
        clock.set(i / 10)
        with pytest.raises(UnknownKeyId):
            store.get_key(f"made-up-{i}")
        assert store.get_key(KID).key_id == KID
    assert endpoint.times == [0, 10, 20, 30, 50, 90]


def test_tokens_without_a_key_id_never_cause_a_fetch():
    store, endpoint = keys_at(FakeClock())
    for kid in (None, "", 123, ["x"]):
        with pytest.raises(UnknownKeyId):
            store.get_key(kid)
    with pytest.raises(UnknownKeyId):
        store.get_signing_key_from_jwt(sign(kid=None))
    assert endpoint.fetches == 0


def test_each_lookup_fetches_at_most_once():
    clock = FakeClock()
    store, endpoint = keys_at(clock)
    store.get_key(KID)
    clock.set(300)
    with pytest.raises(UnknownKeyId):
        store.get_key("made-up")
    assert endpoint.fetches == 2


# --- one fetch at a time ---


def run(target, *args):
    """Run target in a thread; the outcome lands in the returned list."""
    outcome = []

    def body():
        try:
            outcome.append(target(*args))
        except Exception as e:
            outcome.append(e)

    thread = threading.Thread(target=body, daemon=True)
    thread.start()
    return thread, outcome


def held_store(endpoint, clock=None):
    store = make_keys(endpoint, clock)
    store._fetch_lock = ObservedLock(store._fetch_lock)
    return store


@pytest.mark.parametrize("succeeds", [True, False], ids=["succeeds", "fails"])
def test_requests_without_keys_share_one_fetch(succeeds):
    endpoint = HeldEndpoint(error=None if succeeds else OUTAGE)
    store = held_store(endpoint)
    threads = []
    try:
        threads.append(run(store.get_key, KID))
        assert endpoint.started.wait(5)
        threads += [run(store.get_key, KID) for _ in range(5)]
        assert store._fetch_lock.wait_for_attempts(6)
    finally:
        endpoint.release.set()
    for thread, _ in threads:
        thread.join(timeout=5)
    assert not any(thread.is_alive() for thread, _ in threads)
    assert endpoint.fetches == 1
    outcomes = [outcome[0] for _, outcome in threads]
    if succeeds:
        assert all(isinstance(o, jwt.PyJWK) and o.key_id == KID for o in outcomes)
    else:
        assert all(isinstance(o, SigningKeysUnavailable) for o in outcomes)


def test_requests_with_usable_keys_do_not_wait_for_a_refresh():
    clock = FakeClock()
    endpoint = HeldEndpoint(hold=2)
    store = held_store(endpoint, clock)
    old = store.get_key(KID)
    clock.advance(300)
    try:
        refresher, _ = run(store.get_key, KID)
        assert endpoint.started.wait(5)
        others = [run(store.get_key, KID) for _ in range(5)]
        for thread, _ in others:
            thread.join(timeout=2)
        assert not any(thread.is_alive() for thread, _ in others)
        assert all(outcome == [old] for _, outcome in others)
        assert refresher.is_alive()
    finally:
        endpoint.release.set()
    refresher.join(timeout=5)
    assert endpoint.fetches == 2


def test_unknown_key_ids_do_not_wait_for_a_fetch_in_flight():
    clock = FakeClock()
    endpoint = HeldEndpoint(hold=2)
    store = held_store(endpoint, clock)
    store.get_key(KID)
    clock.advance(10)
    try:
        first, _ = run(store.get_key, "made-up-0")
        assert endpoint.started.wait(5)
        clock.advance(10)  # the gap has passed again, so the second lookup wants a fetch too
        second, outcome = run(store.get_key, "made-up-1")
        second.join(timeout=2)
        assert not second.is_alive()
        assert isinstance(outcome[0], UnknownKeyId)
        assert store._fetch_lock.calls[-1] == (False, -1)  # it tried the lock, without waiting
        assert first.is_alive()
    finally:
        endpoint.release.set()
    first.join(timeout=5)
    assert endpoint.fetches == 2


def test_waiting_for_a_fetch_is_capped_at_ten_seconds():
    endpoint = HeldEndpoint()
    store = held_store(endpoint)
    try:
        first, _ = run(store.get_key, KID)
        assert endpoint.started.wait(5)
        second, outcome = run(store.get_key, KID)
        assert store._fetch_lock.wait_for_attempts(2)
        assert store._fetch_lock.calls[1] == (True, 10)
    finally:
        endpoint.release.set()
    for thread in (first, second):
        thread.join(timeout=5)
    assert outcome[0].key_id == KID


def test_a_waiter_that_times_out_is_refused(monkeypatch):
    monkeypatch.setattr(V, "KEYS_WAIT_SECONDS", 0)
    endpoint = HeldEndpoint()
    store = held_store(endpoint)
    try:
        first, _ = run(store.get_key, KID)
        assert endpoint.started.wait(5)
        with pytest.raises(SigningKeysUnavailable):
            store.get_key(KID)
    finally:
        endpoint.release.set()
    first.join(timeout=5)
    assert endpoint.fetches == 1


# --- logging ---


def records(caplog, level=logging.INFO):
    return [r for r in caplog.records if r.name == LOGGER and r.levelno >= level]


def test_an_outage_logs_one_warning_and_one_recovery_line(caplog):
    clock = FakeClock()
    with caplog.at_level(logging.INFO, logger=LOGGER):
        store, endpoint = stale_store(clock)
        for t in range(300, 1701):
            clock.set(t)
            store.get_key(KID)
        endpoint.error = None
        for t in range(1701, 1761):
            clock.set(t)
            store.get_key(KID)
    assert endpoint.times[-1] == 1755
    warning, recovered = records(caplog)
    assert warning.levelno == logging.WARNING and "Still accepting" in warning.getMessage()
    assert "fetched 300 seconds ago, for at most 1500 more seconds" in warning.getMessage()
    assert recovered.levelno == logging.INFO and "again, after" in recovered.getMessage()
    assert f"after {endpoint.fetches - 2} failed attempts over 1455 seconds" in recovered.getMessage()


def test_an_outage_past_the_max_age_logs_once_more(caplog):
    clock = FakeClock()
    with caplog.at_level(logging.INFO, logger=LOGGER):
        store, endpoint = stale_store(clock)
        for t in range(300, 2421):
            if t == 2400:
                endpoint.error = None
            clock.set(t)
            try:
                store.get_key(KID)
            except SigningKeysUnavailable:
                pass
    assert [r.levelno for r in records(caplog)] == [logging.WARNING, logging.WARNING, logging.INFO]
    assert "past the 1800-second limit" in records(caplog)[1].getMessage()


def test_a_second_outage_past_the_max_age_is_logged_again(caplog):
    clock = FakeClock()
    with caplog.at_level(logging.INFO, logger=LOGGER):
        store, endpoint = stale_store(clock)
        for t in range(300, 4241):
            if t == 2400:
                endpoint.error = None  # back at the retry at 2415
            if t == 2416:
                endpoint.error = OUTAGE  # down again: first failure at 2715, past the limit at 4230
            clock.set(t)
            try:
                store.get_key(KID)
            except SigningKeysUnavailable:
                pass
    logged = records(caplog)
    warning, info = logging.WARNING, logging.INFO
    assert [r.levelno for r in logged] == [warning, warning, info, warning, warning]
    assert "past the 1800-second limit" in logged[-1].getMessage()


def test_a_cold_start_outage_says_every_token_is_refused(caplog):
    clock = FakeClock()
    with caplog.at_level(logging.INFO, logger=LOGGER):
        store, endpoint = keys_at(clock, KeyEndpoint(error=OUTAGE, clock=clock))
        with pytest.raises(SigningKeysUnavailable):
            store.get_key(KID)
        [warning] = records(caplog)
        assert warning.levelno == logging.WARNING and "no keys yet" in warning.getMessage()
        for _ in range(100):
            with pytest.raises(SigningKeysUnavailable):
                store.get_key(KID)
        assert endpoint.fetches == 1 and len(records(caplog)) == 1
        endpoint.error = None
        clock.set(store._retry_at)
        assert store.get_key(KID).key_id == KID
    [_, recovered] = records(caplog)
    assert recovered.levelno == logging.INFO and "again, after 1 failed attempts" in recovered.getMessage()


def test_log_lines_are_single_lines_without_tracebacks(caplog):
    clock = FakeClock()
    with caplog.at_level(logging.DEBUG, logger=LOGGER):
        store, endpoint = stale_store(clock)
        endpoint.error = RuntimeError("a\nb")
        for t in range(300, 2421):
            if t == 2400:
                endpoint.error = None
            clock.set(t)
            try:
                store.get_key(KID)
            except SigningKeysUnavailable:
                pass
    logged = records(caplog, logging.DEBUG)
    assert {r.levelno for r in logged} == {logging.DEBUG, logging.INFO, logging.WARNING}
    for record in logged:
        assert record.exc_info is None and "\n" not in record.getMessage()


def test_later_failures_are_logged_at_debug_only(caplog):
    clock = FakeClock()
    with caplog.at_level(logging.DEBUG, logger=LOGGER):
        store, endpoint = stale_store(clock)
        for t in range(300, 1000):
            clock.set(t)
            store.get_key(KID)
    logged = records(caplog, logging.DEBUG)
    assert len(logged) == endpoint.fetches - 1  # one line per failed attempt
    assert logged[0].levelno == logging.WARNING
    assert all(r.levelno == logging.DEBUG for r in logged[1:])
    assert "2 failed attempts, next in 10 seconds" in logged[1].getMessage()


def test_the_default_clock_is_monotonic():
    assert SigningKeys(JWKS_URL)._clock is time.monotonic


def test_key_fetches_time_out_after_five_seconds():
    # Without a timeout, a provider that accepts the connection and then says nothing
    # would hold the one fetch, and every request waiting for keys, forever.
    assert SigningKeys(JWKS_URL)._client.timeout == 5
