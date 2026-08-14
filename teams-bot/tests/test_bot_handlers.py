from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from bot_handlers import (
    UNAUTHORIZED_REPLY,
    is_azure_webchat,
    is_direct_bot_chat,
    is_personal_chat,
    is_sender_authorized,
    register_handlers,
    resolve_sender_identity,
    should_handle_message,
    strip_bot_mention,
)
from investigation_runner import sanitize_thread_id
from state import active_investigations


def test_strip_bot_mention():
    assert (
        strip_bot_mention("Hello <at>OpenSRE</at> check pods", "OpenSRE")
        == "Hello  check pods"
    )


def test_channel_requires_mention():
    assert (
        should_handle_message(text="hi", mentioned=False, conversation_type="channel")
        is False
    )
    assert (
        should_handle_message(text="hi", mentioned=True, conversation_type="channel")
        is True
    )


def test_personal_always_handles():
    assert (
        should_handle_message(
            text="help", mentioned=False, conversation_type="personal"
        )
        is True
    )


def test_is_personal_chat():
    assert is_personal_chat("personal") is True
    assert is_personal_chat("channel") is False


def test_azure_webchat_handles_without_mention():
    assert is_azure_webchat("webchat") is True
    assert is_direct_bot_chat(None, "webchat") is True
    assert (
        should_handle_message(
            text="help",
            mentioned=False,
            conversation_type=None,
            channel_id="webchat",
        )
        is True
    )


@pytest.mark.asyncio
async def test_on_message_active_thread_queues_instead_of_investigation():
    on_message_handler = None

    class FakeApp:
        def on_message(self, fn):
            nonlocal on_message_handler
            on_message_handler = fn
            return fn

        def on_card_action_execute(self, _verb):
            def decorator(fn):
                return fn

            return decorator

    register_handlers(FakeApp())
    assert on_message_handler is not None

    conversation_id = "19:abc@thread.tacv2"
    thread_id = sanitize_thread_id(conversation_id)
    active_investigations.add(thread_id)

    ctx = MagicMock()
    ctx.send = AsyncMock(return_value=MagicMock(id="act-1"))
    ctx.stream = MagicMock()
    ctx.stream.update = MagicMock()
    ctx.stream.close = MagicMock()

    activity = MagicMock()
    activity.text = "also check redis"
    activity.entities = []
    activity.conversation = MagicMock(
        id=conversation_id, conversation_type="personal", conversationType=None
    )
    activity.channel_id = None
    activity.channelId = None
    ctx.activity = activity

    try:
        with patch("bot_handlers.queue_message", new_callable=AsyncMock) as mock_queue:
            with patch(
                "bot_handlers.run_investigation", new_callable=AsyncMock
            ) as mock_run:
                await on_message_handler(ctx)

        mock_queue.assert_awaited_once_with(
            thread_id=thread_id, text="also check redis"
        )
        mock_run.assert_not_awaited()
        ctx.send.assert_awaited_once()
        sent_input = ctx.send.await_args.args[0]
        assert sent_input.text == "Message queued — I'll use it after the current step."
    finally:
        active_investigations.discard(thread_id)


@pytest.mark.asyncio
async def test_on_message_queue_409_starts_follow_up_investigation():
    """409 from queue-message means investigation just finished.
    The message must start a follow-up run (same thread_id keeps agent context);
    no error text should be sent to the user."""
    on_message_handler = None

    class FakeApp:
        def on_message(self, fn):
            nonlocal on_message_handler
            on_message_handler = fn
            return fn

        def on_card_action_execute(self, _verb):
            def decorator(fn):
                return fn

            return decorator

    register_handlers(FakeApp())
    assert on_message_handler is not None

    conversation_id = "19:409@thread.tacv2"
    thread_id = sanitize_thread_id(conversation_id)
    active_investigations.add(thread_id)

    ctx = MagicMock()
    ctx.send = AsyncMock(return_value=MagicMock(id="act-409"))
    ctx.stream = MagicMock()
    ctx.activity = MagicMock(
        text="follow up",
        entities=[],
        conversation=MagicMock(
            id=conversation_id, conversation_type="personal", conversationType=None
        ),
        channel_id=None,
        channelId=None,
    )

    import aiohttp

    try:
        with patch("bot_handlers.queue_message", new_callable=AsyncMock) as mock_queue:
            mock_queue.side_effect = aiohttp.ClientResponseError(
                request_info=MagicMock(),
                history=(),
                status=409,
                message="Conflict",
            )
            with patch(
                "bot_handlers.run_investigation", new_callable=AsyncMock
            ) as mock_run:
                await on_message_handler(ctx)

        # Must start a follow-up investigation — not drop the message.
        mock_run.assert_awaited_once()
        # No error text sent to user.
        ctx.send.assert_not_awaited()
    finally:
        active_investigations.discard(thread_id)


def _register_on_message_handler():
    on_message_handler = None
    on_submit_handler = None

    class FakeApp:
        def on_message(self, fn):
            nonlocal on_message_handler
            on_message_handler = fn
            return fn

        def on_card_action_execute(self, _verb):
            def decorator(fn):
                nonlocal on_submit_handler
                on_submit_handler = fn
                return fn

            return decorator

    register_handlers(FakeApp())
    return on_message_handler, on_submit_handler


def _personal_activity(*, text: str, user_id: str = "user-allowed", upn: str = ""):
    activity = MagicMock()
    activity.text = text
    activity.entities = []
    activity.conversation = MagicMock(
        id="19:auth@thread.tacv2",
        conversation_type="personal",
        conversationType=None,
    )
    activity.channel_id = None
    activity.channelId = None
    activity.from_ = MagicMock(
        id=user_id,
        aadObjectId=user_id,
        userPrincipalName=upn or None,
        properties={},
    )
    return activity


@pytest.mark.asyncio
async def test_on_message_denied_when_not_on_allowlist(monkeypatch):
    monkeypatch.setenv("TEAMS_AUTHZ_MODE", "allowlist")
    monkeypatch.setenv("TEAMS_ALLOWED_USER_IDS", "other-user")

    on_message_handler, _ = _register_on_message_handler()
    ctx = MagicMock()
    ctx.send = AsyncMock()
    ctx.activity = _personal_activity(text="check pods", user_id="blocked-user")

    with patch("bot_handlers.run_investigation", new_callable=AsyncMock) as mock_run:
        await on_message_handler(ctx)

    mock_run.assert_not_awaited()
    ctx.send.assert_awaited_once()
    assert ctx.send.await_args.args[0].text == UNAUTHORIZED_REPLY


@pytest.mark.asyncio
async def test_on_message_allowed_when_user_id_on_allowlist(monkeypatch):
    monkeypatch.setenv("TEAMS_AUTHZ_MODE", "allowlist")
    monkeypatch.setenv("TEAMS_ALLOWED_USER_IDS", "allowed-user")

    on_message_handler, _ = _register_on_message_handler()
    ctx = MagicMock()
    ctx.send = AsyncMock(return_value=MagicMock(id="act-1"))
    ctx.stream = MagicMock()
    ctx.stream.update = MagicMock()
    ctx.stream.close = MagicMock()
    ctx.activity = _personal_activity(text="check pods", user_id="allowed-user")

    with patch("bot_handlers.run_investigation", new_callable=AsyncMock) as mock_run:
        await on_message_handler(ctx)

    mock_run.assert_awaited_once()


@pytest.mark.asyncio
async def test_on_submit_denied_when_not_on_allowlist(monkeypatch):
    monkeypatch.setenv("TEAMS_AUTHZ_MODE", "allowlist")
    monkeypatch.setenv("TEAMS_ALLOWED_UPNS", "allowed@example.com")

    _, on_submit_handler = _register_on_message_handler()
    ctx = MagicMock()
    ctx.activity = _personal_activity(text="", user_id="user-1", upn="blocked@example.com")
    ctx.activity.value = MagicMock(action=MagicMock(data={"answer_thread_id": "teams-x"}))

    with patch("bot_handlers.submit_answers", new_callable=AsyncMock) as mock_submit:
        response = await on_submit_handler(ctx)

    mock_submit.assert_not_awaited()
    assert response.value == UNAUTHORIZED_REPLY


@pytest.mark.asyncio
async def test_on_submit_allowed_when_upn_on_allowlist(monkeypatch):
    monkeypatch.setenv("TEAMS_AUTHZ_MODE", "allowlist")
    monkeypatch.setenv("TEAMS_ALLOWED_UPNS", "allowed@example.com")

    _, on_submit_handler = _register_on_message_handler()
    ctx = MagicMock()
    ctx.activity = _personal_activity(
        text="", user_id="user-1", upn="allowed@example.com"
    )
    ctx.activity.value = MagicMock(action=MagicMock(data={"answer_thread_id": "teams-x"}))

    with patch("bot_handlers.submit_answers", new_callable=AsyncMock) as mock_submit:
        response = await on_submit_handler(ctx)

    mock_submit.assert_awaited_once_with(thread_id="teams-x", answers={})
    assert response.value == "Answer submitted"


def test_resolve_sender_identity_prefers_aad_object_id():
    activity = MagicMock()
    activity.from_ = MagicMock(
        id="teams-id",
        aadObjectId="aad-object-id",
        userPrincipalName="alice@example.com",
        properties={},
    )
    assert resolve_sender_identity(activity) == ("aad-object-id", "alice@example.com")


def test_is_sender_authorized_open_mode(monkeypatch):
    monkeypatch.setenv("TEAMS_AUTHZ_MODE", "open")
    activity = _personal_activity(text="hi", user_id="anyone")
    assert is_sender_authorized(activity) is True
