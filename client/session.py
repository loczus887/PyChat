from __future__ import annotations

import logging

from pcs import MsgType, decode_frame, make_msg_send, make_error
from pcs.exceptions import ErrorCode, PCSError, CRITICAL_ERRORS

from client.connection import PCSConnection

logger = logging.getLogger(__name__)


class PCSSession:
    def __init__(
        self,
        conn: PCSConnection,
        username: str,
        session_token: str,
        hmac_key: bytes,
    ) -> None:
        self.conn = conn
        self.username = username
        self.session_token = session_token
        self.hmac_key = hmac_key
        self._msg_id = 1

    def _next_id(self) -> int:
        self._msg_id += 1
        return self._msg_id

    def send_message(self, text: str) -> None:
        payload = make_msg_send(self.username, text, self.session_token)
        self.conn.send_frame(MsgType.MSG_SEND, payload, self._next_id(), self.hmac_key)
        logger.debug("MSG_SEND msg_id=%d", self._msg_id)

    def send_ping(self) -> None:
        self.conn.send_frame(MsgType.PING, {}, self._next_id(), self.hmac_key)
        logger.debug("PING wysłany msg_id=%d", self._msg_id)

    def send_bye(self) -> None:
        self.conn.send_frame(MsgType.BYE, {}, self._next_id(), self.hmac_key)
        logger.debug("BYE wysłany")

    def receive_frames(self) -> list:
        raw_frames = self.conn.receive_raw_frames()
        result = []
        for raw in raw_frames:
            try:
                frame = decode_frame(raw, self.hmac_key)
                result.append(frame)
            except PCSError as exc:
                logger.error("Błąd dekodowania ramki: %s", exc)
        return result

    def handle_frame(self, frame, on_message, on_error, on_pong) -> None:
        match frame.msg_type:
            case MsgType.MSG_BROADCAST:
                sender = frame.payload.get("from", "?")
                text = frame.payload.get("message", "")
                timestamp = frame.payload.get("timestamp", "")
                on_message(sender, text, timestamp)
            case MsgType.PONG:
                on_pong()
            case MsgType.ERROR:
                code = frame.payload.get("error_code")
                on_error(code)
            case _:
                logger.warning("Nieoczekiwana ramka: %s", frame.msg_type)