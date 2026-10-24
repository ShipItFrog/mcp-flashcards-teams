"""The storage layer on its own: every method is scoped to its owner."""

import threading

import anyio
import pytest

from flashcards_teams import store as store_module
from flashcards_teams.store import CardLimitError

pytestmark = pytest.mark.anyio

ALICE = "https://auth.example.test|alice"
BOB = "https://auth.example.test|bob"


async def test_every_method_is_scoped_to_its_owner(store):
    await store.add(ALICE, "q", "a", "t")
    assert await store.list(BOB) == []
    assert await store.count(BOB) == 0
    assert await store.least_recently_reviewed(BOB) is None
    assert await store.record_review(BOB, 1, True) is None
    assert await store.delete(BOB, 1) is False
    [card] = await store.list(ALICE)
    assert card["review_count"] == 0


async def test_numbers_are_per_owner_and_never_reused(store):
    assert (await store.add(ALICE, "q1", "a", "t"))["id"] == 1
    assert (await store.add(ALICE, "q2", "a", "t"))["id"] == 2
    assert (await store.add(BOB, "q", "a", "t"))["id"] == 1
    assert await store.delete(ALICE, 2)
    assert (await store.add(ALICE, "q3", "a", "t"))["id"] == 3


async def test_concurrent_adds_get_unique_numbers(store):
    ids = []

    async def add(i):
        ids.append((await store.add(ALICE, f"q{i}", "a", "t"))["id"])

    async with anyio.create_task_group() as tg:
        for i in range(20):
            tg.start_soon(add, i)
    assert sorted(ids) == list(range(1, 21))


async def test_owner_key_never_appears_in_card_data(store):
    card = await store.add(ALICE, "q", "a", "t")
    assert "owner" not in card
    assert all("owner" not in c for c in await store.list(ALICE))


async def test_card_limit_is_per_owner(store, monkeypatch):
    monkeypatch.setattr(store_module, "MAX_CARDS_PER_OWNER", 2)
    await store.add(ALICE, "q1", "a", "t")
    await store.add(ALICE, "q2", "a", "t")
    with pytest.raises(CardLimitError):
        await store.add(ALICE, "q3", "a", "t")
    assert (await store.add(BOB, "q", "a", "t"))["id"] == 1


async def test_total_size_limit_is_per_owner(store, monkeypatch):
    monkeypatch.setattr(store_module, "MAX_CHARS_PER_OWNER", 10)
    await store.add(ALICE, "qqq", "aaa", "tt")  # 8 characters
    with pytest.raises(CardLimitError):
        await store.add(ALICE, "q", "a", "t")  # 8 + 3 > 10
    await store.add(BOB, "qqq", "aaa", "tt")


async def test_review_order_uses_review_time_not_card_number(store, monkeypatch):
    # A fixed clock: Windows' clock can give two quick calls the same timestamp.
    ticks = iter(f"2026-01-01T00:00:{s:02d}+00:00" for s in range(60))
    monkeypatch.setattr(store_module, "_now", lambda: next(ticks))
    await store.add(ALICE, "q1", "a", "t")
    await store.add(ALICE, "q2", "a", "t")
    order = [(await store.least_recently_reviewed(ALICE))["id"]]
    await store.record_review(ALICE, 2, True)  # card 2 reviewed first...
    order.append((await store.least_recently_reviewed(ALICE))["id"])
    await store.record_review(ALICE, 1, True)  # ...then card 1, so 2 is now the older review
    order.append((await store.least_recently_reviewed(ALICE))["id"])
    assert order == [1, 1, 2]


async def test_topics_match_case_insensitively_and_ignore_spaces(store):
    await store.add(ALICE, "q", "a", "Geo")
    await store.add(ALICE, "q", "a", "History")
    assert await store.count(ALICE, " geo ") == 1
    assert [c["topic"] for c in await store.list(ALICE, "GEO")] == ["Geo"]
    assert (await store.least_recently_reviewed(ALICE, "history"))["id"] == 2
    assert await store.least_recently_reviewed(ALICE, "art") is None


async def test_list_pages_by_card_number(store):
    for i in range(5):
        await store.add(ALICE, f"q{i}", "a", "t")
    assert [c["id"] for c in await store.list(ALICE, limit=2)] == [1, 2]
    assert [c["id"] for c in await store.list(ALICE, limit=2, after_id=2)] == [3, 4]
    assert [c["id"] for c in await store.list(ALICE, limit=2, after_id=4)] == [5]


async def test_a_refused_add_does_not_use_up_a_number(store, monkeypatch):
    monkeypatch.setattr(store_module, "MAX_CARDS_PER_OWNER", 2)
    await store.add(ALICE, "q1", "a", "t")
    await store.add(ALICE, "q2", "a", "t")
    with pytest.raises(CardLimitError):
        await store.add(ALICE, "q3", "a", "t")
    assert await store.delete(ALICE, 2)
    assert (await store.add(ALICE, "q4", "a", "t"))["id"] == 3


async def test_store_calls_run_off_the_event_loop(store, monkeypatch):
    # A slow database must not freeze every other request on this single-process server.
    threads = []
    original = type(store)._count

    def counting(self, owner, topic):
        threads.append(threading.get_ident())
        return original(self, owner, topic)

    monkeypatch.setattr(type(store), "_count", counting)
    await store.count(ALICE)
    assert threads and threading.get_ident() not in threads


async def test_cards_look_the_same_in_both_databases(store, monkeypatch):
    monkeypatch.setattr(store_module, "_now", lambda: "2026-01-01T00:00:00+00:00")
    expected = {
        "id": 1, "question": "q", "answer": "a", "topic": "t", "created_at": "2026-01-01T00:00:00+00:00",
        "last_reviewed": None, "review_count": 0, "correct_count": 0, "wrong_count": 0,
    }
    card = await store.add(ALICE, "q", "a", "t")
    assert card == expected
    assert {k: type(v) for k, v in card.items()} == {k: type(v) for k, v in expected.items()}
    assert await store.list(ALICE) == [expected]
    graded = await store.record_review(ALICE, 1, False)
    assert graded == {**expected, "last_reviewed": "2026-01-01T00:00:00+00:00", "review_count": 1, "wrong_count": 1}


async def test_the_largest_card_number_is_simply_not_found(store):
    await store.add(ALICE, "q", "a", "t")
    assert await store.record_review(ALICE, 2**53, True) is None
    assert await store.delete(ALICE, 2**53) is False
