from __future__ import annotations

import logging

from pcs import MsgType, decode_frame, make_auth_req, hash_password_for_user
from pcs.exceptions import ErrorCode, PCSHMACError

from client.connection import PCSConnection

logger = logging.getLogger(__name__)

AUTH_TIMEOUT = 10.0


class AuthError(Exception):
    pass


class RateLimitError(AuthError):
    pass


def login(
    conn: PCSConnection,
    username: str,
    password: str,
    msg_id: int = 1,
) -> str:
    password_hash = hash_password_for_user(password, username)
    conn.send_frame(
        MsgType.AUTH_REQ,
        make_auth_req(username, password_hash),
        msg_id,
    )
    logger.debug("Wysłano AUTH_REQ dla użytkownika '%s'", username)

    raw_frames = conn.receive_raw_frames(timeout=AUTH_TIMEOUT)

    if not raw_frames:
        raise AuthError("Brak odpowiedzi serwera w ciągu %gs." % AUTH_TIMEOUT)

    try:
        frame = decode_frame(raw_frames[0], conn.hmac_key)
    except PCSHMACError as exc:
        raise AuthError(
            "Błąd HMAC - klucz nie zgadza się z serwerem. "
            "Upewnij się, że --hmac-secret jest identyczny po obu stronach "
            "(Docker domyślnie: pychat-default-secret)."
        ) from exc

    if frame.msg_type is MsgType.AUTH_OK:
        token = frame.payload.get("session_token", "")
        logger.info("Zalogowano jako '%s'", username)
        return token

    if frame.msg_type is MsgType.ERROR:
        code = frame.payload.get("error_code")
        if code == int(ErrorCode.ERR_RATE_LIMIT):
            raise RateLimitError("Za dużo prób logowania. Odczekaj chwilę i spróbuj ponownie.")
        raise AuthError("Nieprawidłowy login lub hasło.")

    raise AuthError(f"Nieoczekiwana odpowiedź serwera: {frame.msg_type.name}")