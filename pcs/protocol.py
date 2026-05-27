from __future__ import annotations

import hashlib
import hmac as hmac_module
import json
import struct
from dataclasses import dataclass
from enum import IntEnum

from .exceptions import (
    ErrorCode,
    PCSFrameError,
    PCSHMACError,
    PCSPayloadTooLargeError,
    PCSUnknownTypeError,
)

MAGIC: bytes = bytes([0x50, 0x43])
HEADER_FORMAT: str = ">2sBII"
HEADER_SIZE: int = struct.calcsize(HEADER_FORMAT)
HMAC_SIZE: int = 32
MAX_PAYLOAD_SIZE: int = 65_536

assert HEADER_SIZE == 11


class MsgType(IntEnum):
    AUTH_REQ       = 0x01
    AUTH_OK        = 0x02
    MSG_SEND       = 0x03
    MSG_BROADCAST  = 0x04
    PING           = 0x05
    PONG           = 0x06
    ERROR          = 0x07
    BYE            = 0x08


class SessionState(IntEnum):
    DISCONNECTED   = 0
    CONNECTED      = 1
    AUTHENTICATED  = 2
    READY          = 3
    CLOSED         = 4


_KNOWN_TYPES: frozenset[int] = frozenset(t.value for t in MsgType)


@dataclass(slots=True)
class PCSFrame:
    msg_type: MsgType
    msg_id:   int
    payload:  dict


def encode_frame(
    msg_type:  MsgType,
    payload:   dict,
    msg_id:    int,
    hmac_key:  bytes,
) -> bytes:
    if not (0 <= msg_id <= 0xFFFF_FFFF):
        raise ValueError(f"msg_id {msg_id} poza zakresem uint32")

    payload_bytes = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    if len(payload_bytes) > MAX_PAYLOAD_SIZE:
        raise PCSPayloadTooLargeError(len(payload_bytes))

    header = struct.pack(HEADER_FORMAT, MAGIC, int(msg_type), len(payload_bytes), msg_id)
    mac = _compute_hmac(hmac_key, header + payload_bytes)
    return header + payload_bytes + mac


def decode_frame(raw: bytes, hmac_key: bytes) -> PCSFrame:
    if len(raw) < HEADER_SIZE + HMAC_SIZE:
        raise PCSFrameError(ErrorCode.ERR_FORMAT, "Frame too short")

    header = raw[:HEADER_SIZE]
    magic, type_byte, length, msg_id = struct.unpack(HEADER_FORMAT, header)

    if magic != MAGIC:
        raise PCSFrameError(
            ErrorCode.ERR_FORMAT,
            f"Invalid magic: expected {MAGIC!r}, got {magic!r}",
        )

    if length > MAX_PAYLOAD_SIZE:
        raise PCSPayloadTooLargeError(length)

    expected_total = HEADER_SIZE + length + HMAC_SIZE
    if len(raw) != expected_total:
        raise PCSFrameError(
            ErrorCode.ERR_FORMAT,
            f"Frame size mismatch: expected {expected_total}B, got {len(raw)}B",
        )

    payload_bytes = raw[HEADER_SIZE : HEADER_SIZE + length]
    received_mac  = raw[HEADER_SIZE + length :]

    expected_mac = _compute_hmac(hmac_key, header + payload_bytes)
    if not hmac_module.compare_digest(expected_mac, received_mac):
        raise PCSHMACError()

    if type_byte not in _KNOWN_TYPES:
        raise PCSUnknownTypeError(type_byte)

    try:
        payload = json.loads(payload_bytes.decode("utf-8")) if payload_bytes else {}
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise PCSFrameError(ErrorCode.ERR_FORMAT, f"Invalid JSON payload: {exc}") from exc

    if not isinstance(payload, dict):
        raise PCSFrameError(ErrorCode.ERR_FORMAT, "Payload must be a JSON object")

    return PCSFrame(msg_type=MsgType(type_byte), msg_id=msg_id, payload=payload)


class FrameBuffer:
    def __init__(self) -> None:
        self._buf: bytearray = bytearray()

    def feed(self, data: bytes | bytearray) -> None:
        self._buf.extend(data)

    def drain(self) -> list[bytes]:
        frames: list[bytes] = []
        while True:
            frame = self._try_extract_one()
            if frame is None:
                break
            frames.append(frame)
        return frames

    def _try_extract_one(self) -> bytes | None:
        if len(self._buf) < HEADER_SIZE:
            return None

        magic, _type, length, _msg_id = struct.unpack(
            HEADER_FORMAT, bytes(self._buf[:HEADER_SIZE])
        )

        if magic != MAGIC:
            raise PCSFrameError(
                ErrorCode.ERR_FORMAT,
                f"Invalid magic in buffer: {bytes(self._buf[:2])!r}",
            )

        if length > MAX_PAYLOAD_SIZE:
            raise PCSPayloadTooLargeError(length)

        total_needed = HEADER_SIZE + length + HMAC_SIZE
        if len(self._buf) < total_needed:
            return None

        frame_bytes = bytes(self._buf[:total_needed])
        del self._buf[:total_needed]
        return frame_bytes

    def clear(self) -> None:
        self._buf.clear()

    @property
    def buffered_bytes(self) -> int:
        return len(self._buf)


def make_auth_req(username: str, password_hash: str) -> dict:
    return {"username": username, "password_hash": password_hash}


def make_auth_ok(session_token: str) -> dict:
    return {"session_token": session_token}


def make_msg_send(username: str, message: str, session_token: str) -> dict:
    return {"username": username, "message": message, "session_token": session_token}


def make_msg_broadcast(from_user: str, message: str, timestamp: str) -> dict:
    return {"from": from_user, "message": message, "timestamp": timestamp}


def make_error(error_code: ErrorCode, message: str = "") -> dict:
    return {"error_code": int(error_code), "message": message}


def _compute_hmac(key: bytes, data: bytes) -> bytes:
    return hmac_module.new(key, data, hashlib.sha256).digest()
