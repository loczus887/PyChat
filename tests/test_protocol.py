import struct
import pytest

from pcs import (
    HEADER_SIZE, HMAC_SIZE, MAGIC, MAX_PAYLOAD_SIZE,
    MsgType, SessionState, ErrorCode,
    PCSFrame, FrameBuffer,
    encode_frame, decode_frame,
    make_auth_req, make_auth_ok, make_msg_send, make_msg_broadcast, make_error,
)
from pcs.exceptions import (
    PCSFrameError, PCSHMACError, PCSPayloadTooLargeError, PCSUnknownTypeError,
)

TEST_KEY = b"test-hmac-key-32-bytes-padded!!!"


def _raw_frame(msg_type=MsgType.PING, payload=None, msg_id=1, key=TEST_KEY):
    return encode_frame(msg_type, payload or {}, msg_id, key)


class TestConstants:
    def test_magic_value(self):
        assert MAGIC == bytes([0x50, 0x43])

    def test_header_size(self):
        assert HEADER_SIZE == 11

    def test_hmac_size(self):
        assert HMAC_SIZE == 32

    def test_max_payload(self):
        assert MAX_PAYLOAD_SIZE == 65_536


class TestEncodeFrame:
    def test_total_length_ping(self):
        raw = _raw_frame(MsgType.PING, {}, 1)
        assert len(raw) == HEADER_SIZE + 2 + HMAC_SIZE

    def test_magic_in_output(self):
        raw = _raw_frame()
        assert raw[:2] == MAGIC

    def test_type_byte(self):
        raw = _raw_frame(MsgType.AUTH_REQ)
        assert raw[2] == 0x01

    def test_msg_id_big_endian(self):
        raw = _raw_frame(msg_id=0x00_01_02_03)
        assert raw[7:11] == bytes([0x00, 0x01, 0x02, 0x03])

    def test_length_field_big_endian(self):
        payload = {"username": "alice", "password_hash": "abc"}
        raw = _raw_frame(MsgType.AUTH_REQ, payload, 1)
        length = struct.unpack(">I", raw[3:7])[0]
        import json
        expected = len(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode())
        assert length == expected

    def test_raises_on_oversized_payload(self):
        huge = {"data": "x" * (MAX_PAYLOAD_SIZE + 1)}
        with pytest.raises(PCSPayloadTooLargeError):
            encode_frame(MsgType.MSG_SEND, huge, 1, TEST_KEY)

    def test_raises_on_invalid_msg_id(self):
        with pytest.raises(ValueError):
            encode_frame(MsgType.PING, {}, -1, TEST_KEY)
        with pytest.raises(ValueError):
            encode_frame(MsgType.PING, {}, 0x1_0000_0000, TEST_KEY)


class TestDecodeFrameHappyPath:
    def test_roundtrip_ping(self):
        raw = encode_frame(MsgType.PING, {}, 42, TEST_KEY)
        frame = decode_frame(raw, TEST_KEY)
        assert frame.msg_type == MsgType.PING
        assert frame.msg_id == 42
        assert frame.payload == {}

    def test_roundtrip_auth_req(self):
        payload = make_auth_req("alice", "$2b$12$hash")
        raw = encode_frame(MsgType.AUTH_REQ, payload, 1, TEST_KEY)
        frame = decode_frame(raw, TEST_KEY)
        assert frame.msg_type == MsgType.AUTH_REQ
        assert frame.payload["username"] == "alice"

    def test_roundtrip_msg_broadcast(self):
        payload = make_msg_broadcast("bob", "cześć!", "2024-01-01T12:00:00Z")
        raw = encode_frame(MsgType.MSG_BROADCAST, payload, 99, TEST_KEY)
        frame = decode_frame(raw, TEST_KEY)
        assert frame.payload["from"] == "bob"
        assert frame.payload["message"] == "cześć!"

    def test_roundtrip_error(self):
        payload = make_error(ErrorCode.ERR_AUTH, "bad password")
        raw = encode_frame(MsgType.ERROR, payload, 5, TEST_KEY)
        frame = decode_frame(raw, TEST_KEY)
        assert frame.payload["error_code"] == int(ErrorCode.ERR_AUTH)

    def test_all_message_types_encode_decode(self):
        for msg_type in MsgType:
            raw = encode_frame(msg_type, {}, 1, TEST_KEY)
            frame = decode_frame(raw, TEST_KEY)
            assert frame.msg_type == msg_type

    def test_unicode_payload(self):
        payload = {"message": "Zażółć gęślą jaźń 日本語 🎉"}
        raw = encode_frame(MsgType.MSG_SEND, payload, 1, TEST_KEY)
        frame = decode_frame(raw, TEST_KEY)
        assert frame.payload["message"] == payload["message"]


class TestDecodeFrameErrors:
    def test_invalid_magic_raises_format_error(self):
        raw = bytearray(_raw_frame())
        raw[0] = 0xFF
        with pytest.raises(PCSFrameError) as exc_info:
            decode_frame(bytes(raw), TEST_KEY)
        assert exc_info.value.error_code == ErrorCode.ERR_FORMAT

    def test_invalid_hmac_raises_hmac_error(self):
        raw = bytearray(_raw_frame())
        raw[-1] ^= 0xFF
        with pytest.raises(PCSHMACError):
            decode_frame(bytes(raw), TEST_KEY)

    def test_wrong_key_raises_hmac_error(self):
        raw = _raw_frame(key=TEST_KEY)
        with pytest.raises(PCSHMACError):
            decode_frame(raw, b"wrong-key-32-bytes-padded!!!!!!")

    def test_frame_too_short_raises_format_error(self):
        with pytest.raises(PCSFrameError) as exc_info:
            decode_frame(b"\x50\x43\x01" + b"\x00" * 5, TEST_KEY)
        assert exc_info.value.error_code == ErrorCode.ERR_FORMAT

    def test_unknown_type_raises_unknown_type_error(self):
        payload_bytes = b"{}"
        header = struct.pack(">2sBII", MAGIC, 0xFF, len(payload_bytes), 1)
        import hmac as hmac_mod, hashlib
        mac = hmac_mod.new(TEST_KEY, header + payload_bytes, hashlib.sha256).digest()
        raw = header + payload_bytes + mac
        with pytest.raises(PCSUnknownTypeError):
            decode_frame(raw, TEST_KEY)

    def test_payload_too_large_in_header_raises(self):
        header = struct.pack(">2sBII", MAGIC, int(MsgType.MSG_SEND), MAX_PAYLOAD_SIZE + 1, 1)
        fake_rest = bytes(MAX_PAYLOAD_SIZE + 1 + HMAC_SIZE)
        with pytest.raises(PCSPayloadTooLargeError):
            decode_frame(header + fake_rest, TEST_KEY)

    def test_hmac_error_is_critical(self):
        raw = bytearray(_raw_frame())
        raw[-1] ^= 0x01
        with pytest.raises(PCSHMACError) as exc_info:
            decode_frame(bytes(raw), TEST_KEY)
        assert exc_info.value.is_critical is True

    def test_unknown_type_is_noncritical(self):
        payload_bytes = b"{}"
        header = struct.pack(">2sBII", MAGIC, 0xFE, len(payload_bytes), 1)
        import hmac as hmac_mod, hashlib
        mac = hmac_mod.new(TEST_KEY, header + payload_bytes, hashlib.sha256).digest()
        with pytest.raises(PCSUnknownTypeError) as exc_info:
            decode_frame(header + payload_bytes + mac, TEST_KEY)
        assert exc_info.value.is_critical is False


class TestFrameBuffer:
    def test_single_complete_frame(self):
        buf = FrameBuffer()
        raw = _raw_frame(MsgType.PONG, {}, 1)
        buf.feed(raw)
        frames = buf.drain()
        assert len(frames) == 1
        assert frames[0] == raw

    def test_partial_read_accumulates(self):
        buf = FrameBuffer()
        raw = _raw_frame(MsgType.PONG, {}, 1)
        half = len(raw) // 2
        buf.feed(raw[:half])
        assert buf.drain() == []
        buf.feed(raw[half:])
        frames = buf.drain()
        assert len(frames) == 1

    def test_multiple_frames_in_one_feed(self):
        buf = FrameBuffer()
        raw1 = _raw_frame(MsgType.PING, {}, 1)
        raw2 = _raw_frame(MsgType.PONG, {}, 2)
        buf.feed(raw1 + raw2)
        frames = buf.drain()
        assert len(frames) == 2

    def test_frame_split_across_many_reads(self):
        buf = FrameBuffer()
        raw = _raw_frame(MsgType.AUTH_REQ, make_auth_req("u", "h"), 1)
        for byte in raw:
            buf.feed(bytes([byte]))
        frames = buf.drain()
        assert len(frames) == 1
        assert frames[0] == raw

    def test_drain_clears_consumed_data(self):
        buf = FrameBuffer()
        raw = _raw_frame()
        buf.feed(raw)
        buf.drain()
        assert buf.buffered_bytes == 0

    def test_leftover_bytes_remain(self):
        buf = FrameBuffer()
        raw = _raw_frame()
        buf.feed(raw + b"\xDE\xAD")
        buf.drain()
        assert buf.buffered_bytes == 2

    def test_invalid_magic_raises(self):
        buf = FrameBuffer()
        bad = bytearray(_raw_frame())
        bad[0] = 0xFF
        buf.feed(bytes(bad))
        with pytest.raises(PCSFrameError):
            buf.drain()

    def test_clear_resets_buffer(self):
        buf = FrameBuffer()
        buf.feed(b"\xDE\xAD\xBE\xEF")
        buf.clear()
        assert buf.buffered_bytes == 0

    def test_decode_after_drain(self):
        buf = FrameBuffer()
        payload = make_msg_broadcast("alice", "hello", "2024-01-01T00:00:00Z")
        raw = encode_frame(MsgType.MSG_BROADCAST, payload, 7, TEST_KEY)
        buf.feed(raw)
        [raw_frame] = buf.drain()
        frame = decode_frame(raw_frame, TEST_KEY)
        assert frame.msg_type == MsgType.MSG_BROADCAST
        assert frame.msg_id == 7
        assert frame.payload["from"] == "alice"


class TestPayloadHelpers:
    def test_make_auth_req(self):
        d = make_auth_req("user1", "hash123")
        assert d == {"username": "user1", "password_hash": "hash123"}

    def test_make_auth_ok(self):
        d = make_auth_ok("token-abc")
        assert d == {"session_token": "token-abc"}

    def test_make_msg_send(self):
        d = make_msg_send("alice", "hi", "token-xyz")
        assert d["username"] == "alice"
        assert d["session_token"] == "token-xyz"

    def test_make_msg_broadcast(self):
        d = make_msg_broadcast("bob", "yo", "ts")
        assert d["from"] == "bob"

    def test_make_error(self):
        d = make_error(ErrorCode.ERR_HMAC, "bad mac")
        assert d["error_code"] == 0x03
        assert d["message"] == "bad mac"


class TestSessionState:
    def test_state_ordering(self):
        assert SessionState.DISCONNECTED < SessionState.CONNECTED
        assert SessionState.CONNECTED < SessionState.AUTHENTICATED
        assert SessionState.AUTHENTICATED < SessionState.READY
        assert SessionState.READY < SessionState.CLOSED
