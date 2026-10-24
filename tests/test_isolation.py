"""Per-user isolation, end to end: real ASGI app, real auth middleware, real MCP
client, fake tokens. Every test runs over every transport the server supports
(see helpers.TRANSPORTS)."""

import pytest
from helpers import TRANSPORTS, error_text, mcp_client, payload, running_app, total_cards

pytestmark = pytest.mark.anyio

CARD = {"question": "What does the mitochondria do?", "answer": "Makes ATP", "topic": "bio"}


@pytest.mark.parametrize("transport", TRANSPORTS)
async def test_other_user_sees_none_of_your_cards(store, transport):
    mode, stateless = transport
    async with running_app(store, stateless=stateless) as app:
        async with mcp_client(app, "alice-1", mode) as alice:
            assert payload(await alice.call_tool("add_card", CARD))["card"]["id"] == 1
            await alice.call_tool("add_card", {**CARD, "question": "Second question"})

        async with mcp_client(app, "bob-1", mode) as bob:
            listed = payload(await bob.call_tool("list_cards", {}))
            assert listed["total"] == 0 and listed["cards"] == []
            assert payload(await bob.call_tool("review", {}))["card_id"] is None

        async with mcp_client(app, "alice-1", mode) as alice:
            assert payload(await alice.call_tool("list_cards", {}))["total"] == 2


@pytest.mark.parametrize("transport", TRANSPORTS)
async def test_other_user_cannot_grade_or_delete_your_card_by_number(store, transport):
    mode, stateless = transport
    async with running_app(store, stateless=stateless) as app:
        async with mcp_client(app, "alice-1", mode) as alice:
            await alice.call_tool("add_card", CARD)

        async with mcp_client(app, "bob-1", mode) as bob:
            assert error_text(await bob.call_tool("grade_card", {"card_id": 1, "correct": True})).endswith(
                "No card with id 1"
            )
            assert error_text(await bob.call_tool("delete_card", {"card_id": 1})).endswith("No card with id 1")

        async with mcp_client(app, "alice-1", mode) as alice:
            [card] = payload(await alice.call_tool("list_cards", {}))["cards"]
            assert card["review_count"] == 0 and card["last_reviewed"] is None


@pytest.mark.parametrize("transport", TRANSPORTS)
async def test_someone_elses_card_looks_exactly_like_a_missing_one(store, transport):
    mode, stateless = transport
    async with running_app(store, stateless=stateless) as app:
        async with mcp_client(app, "alice-1", mode) as alice:
            await alice.call_tool("add_card", CARD)  # alice's card #1

        async with mcp_client(app, "bob-1", mode) as bob:
            foreign = error_text(await bob.call_tool("grade_card", {"card_id": 1, "correct": True}))
            missing = error_text(await bob.call_tool("grade_card", {"card_id": 999, "correct": True}))
    assert foreign.removesuffix("1") == missing.removesuffix("999")


@pytest.mark.parametrize("transport", TRANSPORTS)
async def test_same_person_with_a_new_token_keeps_their_deck(store, transport):
    mode, stateless = transport
    async with running_app(store, stateless=stateless) as app:
        async with mcp_client(app, "alice-1", mode) as alice:
            await alice.call_tool("add_card", CARD)
        async with mcp_client(app, "alice-2", mode) as alice_again:
            assert payload(await alice_again.call_tool("list_cards", {}))["total"] == 1


@pytest.mark.parametrize("transport", TRANSPORTS)
async def test_card_numbers_are_per_user(store, transport):
    mode, stateless = transport
    async with running_app(store, stateless=stateless) as app:
        async with mcp_client(app, "alice-1", mode) as alice:
            await alice.call_tool("add_card", CARD)
            assert payload(await alice.call_tool("add_card", CARD))["card"]["id"] == 2
        async with mcp_client(app, "bob-1", mode) as bob:
            assert payload(await bob.call_tool("add_card", CARD))["card"]["id"] == 1


@pytest.mark.parametrize("transport", TRANSPORTS)
async def test_token_without_a_subject_is_refused(store, transport):
    mode, stateless = transport
    async with running_app(store, stateless=stateless) as app:
        async with mcp_client(app, "no-subject", mode) as nobody:
            assert "Not signed in" in error_text(await nobody.call_tool("add_card", CARD))
            assert "Not signed in" in error_text(await nobody.call_tool("list_cards", {}))
    assert total_cards(store) == 0


@pytest.mark.parametrize("transport", TRANSPORTS)
async def test_same_subject_from_another_issuer_is_a_different_person(store, transport):
    mode, stateless = transport
    async with running_app(store, stateless=stateless) as app:
        async with mcp_client(app, "alice-1", mode) as alice:
            await alice.call_tool("add_card", CARD)
        async with mcp_client(app, "other-issuer", mode) as impostor:
            assert "Not signed in" in error_text(await impostor.call_tool("list_cards", {}))
            assert "Not signed in" in error_text(await impostor.call_tool("delete_card", {"card_id": 1}))
        async with mcp_client(app, "alice-1", mode) as alice:
            assert payload(await alice.call_tool("list_cards", {}))["total"] == 1
