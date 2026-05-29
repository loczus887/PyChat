from __future__ import annotations

import hashlib
import hmac
import os
import ssl
from dataclasses import dataclass, field

from .exceptions import PCSReplayAttackError

try:
    import bcrypt
except ImportError:
    bcrypt = None


def hkdf_extract(salt: bytes, input_key_material: bytes, digestmod=hashlib.sha256) -> bytes:
    return hmac.new(salt, input_key_material, digestmod).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int, digestmod=hashlib.sha256) -> bytes:
    hash_len = digestmod().digest_size
    if length <= 0 or length > 255 * hash_len:
        raise ValueError("Invalid HKDF output length")

    output = b""
    previous_block = b""
    counter = 1
    while len(output) < length:
        previous_block = hmac.new(
            prk, previous_block + info + bytes([counter]), digestmod
        ).digest()
        output += previous_block
        counter += 1
    return output[:length]


def derive_hmac_key(
    input_key_material: bytes,
    salt: bytes | None = None,
    info: bytes = b"pcs-hmac-sha256",
    length: int = 32,
) -> bytes:
    if not input_key_material:
        raise ValueError("input_key_material must not be empty")
    effective_salt = salt if salt is not None else b"\x00" * hashlib.sha256().digest_size
    prk = hkdf_extract(effective_salt, input_key_material)
    return hkdf_expand(prk, info, length)


def _require_bcrypt() -> None:
    if bcrypt is None:
        raise RuntimeError("bcrypt dependency is not available")


def hash_password(password: str, rounds: int = 12) -> str:
    _require_bcrypt()
    password_bytes = password.encode("utf-8")
    hashed = bcrypt.hashpw(password_bytes, bcrypt.gensalt(rounds=rounds))
    return hashed.decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    _require_bcrypt()
    return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))


def generate_session_token(size: int = 16) -> str:
    if size <= 0:
        raise ValueError("size must be positive")
    return os.urandom(size).hex()


def create_server_tls_context(
    certfile: str,
    keyfile: str,
    cafile: str | None = None,
    require_client_cert: bool = False,
) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    context.check_hostname = False
    if cafile:
        context.load_verify_locations(cafile=cafile)
    context.verify_mode = ssl.CERT_REQUIRED if require_client_cert else ssl.CERT_NONE
    return context


def create_client_tls_context(cafile: str | None = None) -> ssl.SSLContext:
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=cafile)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return context


@dataclass(slots=True)
class ReplayProtector:
    _last_msg_id_by_session: dict[str, int] = field(default_factory=dict)

    def validate(self, session_id: str, msg_id: int) -> None:
        if not (0 <= msg_id <= 0xFFFF_FFFF):
            raise ValueError("msg_id must be uint32")
        last_msg_id = self._last_msg_id_by_session.get(session_id)
        if last_msg_id is not None and msg_id <= last_msg_id:
            raise PCSReplayAttackError(
                f"Replay detected for session {session_id}: msg_id={msg_id}, last={last_msg_id}"
            )
        self._last_msg_id_by_session[session_id] = msg_id

    def reset_session(self, session_id: str) -> None:
        self._last_msg_id_by_session.pop(session_id, None)

    def clear(self) -> None:
        self._last_msg_id_by_session.clear()
