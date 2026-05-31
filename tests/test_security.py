import hashlib
import hmac as hmac_module
import ssl

import pytest

from pcs import (
    ReplayProtector,
    create_client_tls_context,
    derive_hmac_key,
    generate_session_token,
    hash_password,
    hkdf_expand,
    hkdf_extract,
    verify_password,
)
from pcs.exceptions import PCSReplayAttackError

bcrypt = pytest.importorskip("bcrypt")


class TestHKDF:
    def test_extract_matches_hmac(self):
        salt = b"salt"
        ikm = b"input-key-material"
        prk = hkdf_extract(salt, ikm)
        expected = hmac_module.new(salt, ikm, hashlib.sha256).digest()
        assert prk == expected

    def test_expand_length(self):
        prk = b"\x01" * 32
        okm = hkdf_expand(prk, b"pcs", 42)
        assert len(okm) == 42

    def test_derive_hmac_key_deterministic(self):
        ikm = b"shared-secret"
        salt = b"session-salt"
        k1 = derive_hmac_key(ikm, salt=salt, info=b"pcs-hmac", length=32)
        k2 = derive_hmac_key(ikm, salt=salt, info=b"pcs-hmac", length=32)
        assert k1 == k2
        assert len(k1) == 32

    def test_derive_hmac_key_rejects_empty_ikm(self):
        with pytest.raises(ValueError):
            derive_hmac_key(b"")


class TestBcrypt:
    def test_hash_and_verify(self):
        password = "S3curePassword!"
        password_hash = hash_password(password)
        assert password_hash.startswith("$2")
        assert verify_password(password, password_hash) is True
        assert verify_password("wrong-password", password_hash) is False

    def test_hash_for_user_deterministic(self):
        from pcs import hash_password_for_user
        h1 = hash_password_for_user("secret", "alice")
        h2 = hash_password_for_user("secret", "alice")
        assert h1 == h2
        assert h1.startswith("$2")
        assert hash_password_for_user("secret", "bob") != h1


class TestReplayProtection:
    def test_accepts_strictly_increasing_msg_id(self):
        rp = ReplayProtector()
        rp.validate("sess-1", 1)
        rp.validate("sess-1", 2)
        rp.validate("sess-1", 3)

    def test_rejects_same_or_lower_msg_id(self):
        rp = ReplayProtector()
        rp.validate("sess-1", 10)
        with pytest.raises(PCSReplayAttackError):
            rp.validate("sess-1", 10)
        with pytest.raises(PCSReplayAttackError):
            rp.validate("sess-1", 9)

    def test_reset_session_clears_counter(self):
        rp = ReplayProtector()
        rp.validate("sess-1", 50)
        rp.reset_session("sess-1")
        rp.validate("sess-1", 1)


class TestSessionToken:
    def test_token_length(self):
        token = generate_session_token(16)
        assert isinstance(token, str)
        assert len(token) == 32

    def test_token_invalid_size(self):
        with pytest.raises(ValueError):
            generate_session_token(0)


class TestTLS:
    def test_client_context_is_tls13_or_higher(self):
        context = create_client_tls_context()
        assert isinstance(context, ssl.SSLContext)
        assert context.minimum_version == ssl.TLSVersion.TLSv1_3
        assert context.verify_mode == ssl.CERT_REQUIRED
