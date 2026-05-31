from __future__ import annotations

import pytest
from unittest.mock import MagicMock

from pcs import (
    MsgType, FrameBuffer,
    encode_frame, decode_frame, derive_hmac_key,
    make_msg_broadcast, make_error,
)
from pcs.exceptions import ErrorCode, PCSError

from client.auth import login, AuthError, RateLimitError
from client.session import PCSSession

HMAC_KEY = derive_hmac_key(b"test-secret")


class FakeConnection:
    def __init__(self, responses: list[bytes]) -> None:
        self._responses = responses
        self._sent = []
        self._hmac_key = HMAC_KEY

    def send_frame(self, msg_type, payload, msg_id):
        self._sent.append((msg_type, payload, msg_id))

    def receive_raw_frames(self, timeout=None):
        if self._responses:
            return [self._responses.pop(0)]
        return []

    @property
    def hmac_key(self):
        return self._hmac_key

    @property
    def is_connected(self):
        return True


def make_frame(msg_type, payload, msg_id=1):
    return encode_frame(msg_type, payload, msg_id, HMAC_KEY)


class TestLogin:
    def test_success_returns_token(self):
        raw = make_frame(MsgType.AUTH_OK, {"session_token": "abc123"})
        conn = FakeConnection([raw])
        token = login(conn, "alice", "password")
        assert token == "abc123"

    def test_wrong_password_raises_auth_error(self):
        raw = make_frame(MsgType.ERROR, {"error_code": int(ErrorCode.ERR_AUTH)})
        conn = FakeConnection([raw])
        with pytest.raises(AuthError):
            login(conn, "alice", "wrong")

    def test_rate_limit_raises_rate_limit_error(self):
        raw = make_frame(MsgType.ERROR, {"error_code": int(ErrorCode.ERR_RATE_LIMIT)})
        conn = FakeConnection([raw])
        with pytest.raises(RateLimitError):
            login(conn, "alice", "password")

    def test_no_response_raises_auth_error(self):
        conn = FakeConnection([])
        with pytest.raises(AuthError):
            login(conn, "alice", "password")

    def test_sends_correct_username(self):
        raw = make_frame(MsgType.AUTH_OK, {"session_token": "tok"})
        conn = FakeConnection([raw])
        login(conn, "wiktoria", "haslo")
        assert conn._sent[0][1]["username"] == "wiktoria"

    def test_sends_password_hash_field(self):
        raw = make_frame(MsgType.AUTH_OK, {"session_token": "tok"})
        conn = FakeConnection([raw])
        login(conn, "alice", "password")
        assert "password_hash" in conn._sent[0][1]
        assert conn._sent[0][1]["password_hash"].startswith("$2")

    def test_uses_msg_id_1(self):
        raw = make_frame(MsgType.AUTH_OK, {"session_token": "tok"})
        conn = FakeConnection([raw])
        login(conn, "alice", "password")
        assert conn._sent[0][2] == 1


class TestPCSSession:
    def _make_session(self):
        conn = MagicMock()
        conn.receive_raw_frames.return_value = []
        return PCSSession(conn, "alice", "token123"), conn

    def test_msg_id_increments_on_each_send(self):
        session, conn = self._make_session()
        session.send_message("cześć")
        session.send_message("hej")
        calls = conn.send_frame.call_args_list
        assert calls[0][0][2] == 2
        assert calls[1][0][2] == 3

    def test_msg_id_increments_for_ping(self):
        session, conn = self._make_session()
        session.send_message("test")
        session.send_ping()
        calls = conn.send_frame.call_args_list
        assert calls[0][0][2] == 2
        assert calls[1][0][2] == 3

    def test_send_message_includes_session_token(self):
        session, conn = self._make_session()
        session.send_message("hej")
        payload = conn.send_frame.call_args[0][1]
        assert payload["session_token"] == "token123"

    def test_send_message_includes_text(self):
        session, conn = self._make_session()
        session.send_message("testowa wiadomosc")
        payload = conn.send_frame.call_args[0][1]
        assert payload["message"] == "testowa wiadomosc"

    def test_handle_broadcast_calls_on_message(self):
        session, conn = self._make_session()
        raw = encode_frame(
            MsgType.MSG_BROADCAST,
            make_msg_broadcast("bob", "hej", "2026-01-01T12:00:00+00:00"),
            1, HMAC_KEY,
        )
        frame = decode_frame(raw, HMAC_KEY)

        received = []
        session.handle_frame(
            frame,
            lambda s, t, ts: received.append((s, t)),
            lambda c: None,
            lambda: None,
        )
        assert received == [("bob", "hej")]

    def test_handle_pong_calls_on_pong(self):
        session, conn = self._make_session()
        raw = encode_frame(MsgType.PONG, {}, 1, HMAC_KEY)
        frame = decode_frame(raw, HMAC_KEY)

        pong_called = []
        session.handle_frame(frame, lambda s, t, ts: None, lambda c: None, lambda: pong_called.append(True))
        assert pong_called == [True]

    def test_handle_error_calls_on_error(self):
        session, conn = self._make_session()
        raw = encode_frame(MsgType.ERROR, make_error(ErrorCode.ERR_HMAC), 1, HMAC_KEY)
        frame = decode_frame(raw, HMAC_KEY)

        errors = []
        with pytest.raises(PCSError):
            session.handle_frame(frame, lambda s, t, ts: None, lambda c: errors.append(c), lambda: None)
        assert errors[0] == int(ErrorCode.ERR_HMAC)


class TestFrameBufferIntegration:
    def test_split_frame_reassembled(self):
        raw = encode_frame(MsgType.PING, {}, 1, HMAC_KEY)
        buf = FrameBuffer()
        half = len(raw) // 2
        buf.feed(raw[:half])
        assert buf.drain() == []
        buf.feed(raw[half:])
        frames = buf.drain()
        assert len(frames) == 1
        assert decode_frame(frames[0], HMAC_KEY).msg_type == MsgType.PING

    def test_multiple_frames_in_one_chunk(self):
        r1 = encode_frame(MsgType.PING, {}, 1, HMAC_KEY)
        r2 = encode_frame(MsgType.PONG, {}, 2, HMAC_KEY)
        buf = FrameBuffer()
        buf.feed(r1 + r2)
        frames = buf.drain()
        assert len(frames) == 2