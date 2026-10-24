"""Tool behaviour for a single user, including the abuse limits."""

import pytest
from helpers import error_text, mcp_client, payload, running_app
from mcp.server.mcpserver.exceptions import ToolError

from flashcards_teams.server import _text, _topic_filter
from flashcards_teams.store import StoreFullError, StoreUnavailableError

pytestmark = pytest.mark.anyio

CARD = {"question": "Capital of France?", "answer": "Paris", "topic": "geo"}


async def test_review_returns_the_question_but_never_the_answer(store):
    async with running_app(store) as app, mcp_client(app, "alice-1", "auto") as alice:
        await alice.call_tool("add_card", CARD)
        result = await alice.call_tool("review", {})
    drawn = payload(result)
    assert drawn["question"] == "Capital of France?"
    assert "Paris" not in str(drawn)
    assert all("Paris" not in getattr(block, "text", "") for block in result.content)


async def test_grading_updates_the_card(store):
    async with running_app(store) as app, mcp_client(app, "alice-1", "auto") as alice:
        await alice.call_tool("add_card", CARD)
        card = payload(await alice.call_tool("grade_card", {"card_id": 1, "correct": False}))["card"]
    assert card["review_count"] == 1 and card["wrong_count"] == 1 and card["last_reviewed"]


async def test_delete_removes_the_card(store):
    async with running_app(store) as app, mcp_client(app, "alice-1", "auto") as alice:
        await alice.call_tool("add_card", CARD)
        payload(await alice.call_tool("delete_card", {"card_id": 1}))
        assert payload(await alice.call_tool("list_cards", {}))["total"] == 0
        assert error_text(await alice.call_tool("delete_card", {"card_id": 1})).endswith("No card with id 1")


async def test_list_is_paginated(store):
    async with running_app(store) as app, mcp_client(app, "alice-1", "auto") as alice:
        for i in range(5):
            await alice.call_tool("add_card", {**CARD, "question": f"Q{i}"})
        page1 = payload(await alice.call_tool("list_cards", {"limit": 2}))
        page2 = payload(await alice.call_tool("list_cards", {"limit": 2, "after_id": page1["next_after_id"]}))
        page3 = payload(await alice.call_tool("list_cards", {"limit": 2, "after_id": page2["next_after_id"]}))
    assert [c["id"] for c in page1["cards"]] == [1, 2] and page1["total"] == 5
    assert [c["id"] for c in page2["cards"]] == [3, 4]
    assert [c["id"] for c in page3["cards"]] == [5] and page3["next_after_id"] is None


async def test_exactly_one_full_page_has_no_next_page(store):
    async with running_app(store) as app, mcp_client(app, "alice-1", "auto") as alice:
        for _ in range(2):
            await alice.call_tool("add_card", CARD)
        assert payload(await alice.call_tool("list_cards", {"limit": 2}))["next_after_id"] is None


@pytest.mark.parametrize("limit", [0, 101, True])
async def test_page_size_is_bounded(store, limit):
    async with running_app(store) as app, mcp_client(app, "alice-1", "auto") as alice:
        assert (await alice.call_tool("list_cards", {"limit": limit})).is_error


async def test_topic_filter_matches_however_the_topic_is_typed(store):
    async with running_app(store) as app, mcp_client(app, "alice-1", "auto") as alice:
        await alice.call_tool("add_card", {**CARD, "topic": "Geo"})
        await alice.call_tool("add_card", {**CARD, "topic": "null"})  # a literal topic named "null"
        assert payload(await alice.call_tool("list_cards", {"topic": " geo "}))["total"] == 1
        assert payload(await alice.call_tool("review", {"topic": "GEO"}))["card_id"] == 1
        # The string "null" is a topic like any other, not "no filter".
        assert payload(await alice.call_tool("list_cards", {"topic": "null"}))["total"] == 1
        assert payload(await alice.call_tool("list_cards", {}))["total"] == 2


@pytest.mark.parametrize(
    ("field", "limit"),
    [("question", 500), ("answer", 1000), ("topic", 50)],
)
async def test_text_length_limits_are_exact(store, field, limit):
    async with running_app(store) as app, mcp_client(app, "alice-1", "auto") as alice:
        assert not (await alice.call_tool("add_card", {**CARD, field: "x" * limit})).is_error
        assert f"{field} is too long" in error_text(await alice.call_tool("add_card", {**CARD, field: "x" * (limit + 1)}))


@pytest.mark.parametrize(
    ("change", "expected"),
    [({"question": "   "}, "question must not be empty"), ({"answer": ""}, "answer must not be empty")],
)
async def test_empty_text_is_rejected(store, change, expected):
    async with running_app(store) as app, mcp_client(app, "alice-1", "auto") as alice:
        assert expected in error_text(await alice.call_tool("add_card", {**CARD, **change}))
        assert payload(await alice.call_tool("list_cards", {}))["total"] == 0


@pytest.mark.parametrize("card_id", [0, -1, 2**53 + 1, True])
async def test_card_ids_out_of_range_or_not_integers_are_rejected(store, card_id):
    async with running_app(store) as app, mcp_client(app, "alice-1", "auto") as alice:
        await alice.call_tool("add_card", CARD)
        assert (await alice.call_tool("grade_card", {"card_id": card_id, "correct": True})).is_error
        [card] = payload(await alice.call_tool("list_cards", {}))["cards"]
        assert card["review_count"] == 0


def test_text_with_invalid_unicode_is_rejected():
    with pytest.raises(ToolError, match="invalid characters"):
        _text("bad \ud800 surrogate", "question", 500)


async def test_rate_limit_is_per_user(store):
    async with running_app(store, rate_limit=(3, 60.0)) as app:
        async with mcp_client(app, "alice-1", "auto") as alice:
            for _ in range(3):
                assert not (await alice.call_tool("list_cards", {})).is_error
            assert "Too many requests" in error_text(await alice.call_tool("list_cards", {}))
        async with mcp_client(app, "bob-1", "auto") as bob:
            assert not (await bob.call_tool("list_cards", {})).is_error


@pytest.mark.parametrize("field", ["question", "answer", "topic"])
async def test_text_with_a_nul_character_is_rejected(store, field):
    # Postgres text can't hold NUL, so both databases refuse it the same way.
    async with running_app(store) as app, mcp_client(app, "alice-1", "auto") as alice:
        assert f"{field} contains invalid characters" in error_text(await alice.call_tool("add_card", {**CARD, field: "a\x00b"}))
        assert payload(await alice.call_tool("list_cards", {}))["total"] == 0


async def test_a_topic_filter_with_a_nul_character_is_rejected(store):
    async with running_app(store) as app, mcp_client(app, "alice-1", "auto") as alice:
        for tool in ("list_cards", "review"):
            assert "topic contains invalid characters" in error_text(await alice.call_tool(tool, {"topic": "a\x00b"}))


def test_a_topic_filter_with_invalid_unicode_is_rejected():
    with pytest.raises(ToolError, match="invalid characters"):
        _topic_filter("bad \ud800 surrogate")


class UnavailableStore:
    """A store whose database can't be reached."""

    async def _unavailable(self, *args, **kwargs):
        raise StoreUnavailableError

    add = list = count = least_recently_reviewed = record_review = delete = _unavailable

    def close(self):
        pass


async def test_a_database_outage_gets_a_message_the_user_can_act_on():
    calls = [
        ("add_card", CARD),
        ("list_cards", {}),
        ("review", {}),
        ("grade_card", {"card_id": 1, "correct": True}),
        ("delete_card", {"card_id": 1}),
    ]
    async with running_app(UnavailableStore()) as app, mcp_client(app, "alice-1", "auto") as alice:
        for tool, args in calls:
            assert "temporarily unavailable" in error_text(await alice.call_tool(tool, args))


class FullStore(UnavailableStore):
    """A store whose database is out of space."""

    async def _full(self, *args, **kwargs):
        raise StoreFullError

    add = list = count = least_recently_reviewed = record_review = delete = _full


async def test_a_full_database_is_not_reported_as_try_again_later():
    async with running_app(FullStore()) as app, mcp_client(app, "alice-1", "auto") as alice:
        message = error_text(await alice.call_tool("add_card", CARD))
    assert "out of space" in message and "try again" not in message
