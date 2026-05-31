from __future__ import annotations

import hashlib
import hmac
import os
import ssl
from dataclasses import dataclass, field
from pathlib import Path

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


PCS_HKDF_INFO = b"pcs-hmac-sha256"
PCS_TLS_LABEL = b"pcs-hmac-sha256"


def hash_password(password: str, rounds: int = 12) -> str:
    _require_bcrypt()
    password_bytes = password.encode("utf-8")
    hashed = bcrypt.hashpw(password_bytes, bcrypt.gensalt(rounds=rounds))
    return hashed.decode("utf-8")


_BCRYPT_ALPHABET = b"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"


def _encode_bcrypt_base64(data: bytes) -> str:
    result: list[str] = []
    buffer = 0
    bits = 0
    for byte in data:
        buffer = (buffer << 8) | byte
        bits += 8
        while bits >= 6:
            bits -= 6
            idx = (buffer >> bits) & 0x3F
            result.append(chr(_BCRYPT_ALPHABET[idx]))
    if bits:
        idx = (buffer << (6 - bits)) & 0x3F
        result.append(chr(_BCRYPT_ALPHABET[idx]))
    return "".join(result)


def hash_password_for_user(password: str, username: str, rounds: int = 12) -> str:
    _require_bcrypt()
    seed = hashlib.sha256(username.encode("utf-8")).digest()[:16]
    b64_salt = _encode_bcrypt_base64(seed)[:22]
    salt = f"$2b${rounds:02d}${b64_salt}".encode("ascii")
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    _require_bcrypt()
    return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))


def derive_hmac_key_from_ssl(
    ssl_object,
    fallback_key: bytes | None = None,
    *,
    prefer_tls_export: bool = False,
) -> bytes:
    if fallback_key is not None and not prefer_tls_export:
        return fallback_key

    if ssl_object is not None:
        try:
            ikm = ssl_object.export_keying_material(PCS_TLS_LABEL, None, 32)
            return derive_hmac_key(ikm, info=PCS_HKDF_INFO)
        except (AttributeError, ssl.SSLError, ValueError, NotImplementedError):
            pass

    if fallback_key is not None:
        return fallback_key
    raise ValueError("Brak klucza HMAC - podaj --hmac-secret lub wlacz TLS export.")


def generate_session_token(size: int = 16) -> str:
    if size <= 0:
        raise ValueError("size must be positive")
    return os.urandom(size).hex()


def _cert_key_pair_valid(cert_path: Path, key_path: Path) -> bool:
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization

        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        return (
            cert.public_key().public_numbers()
            == key.public_key().public_numbers()
        )
    except Exception:
        return False


def generate_self_signed_cert(
    certfile: str | Path,
    keyfile: str | Path,
    cn: str = "localhost",
) -> tuple[Path, Path]:
    from datetime import datetime, timedelta, timezone
    import ipaddress

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    cert_path = Path(certfile)
    key_path = Path(keyfile)
    cert_path.parent.mkdir(parents=True, exist_ok=True)

    if cert_path.exists() and key_path.exists() and _cert_key_pair_valid(cert_path, key_path):
        return cert_path, key_path

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.now(timezone.utc)

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.DNSName(cn),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert_path, key_path


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
