from __future__ import annotations

import logging
import socket
import ssl
import time

from pcs import (
    FrameBuffer,
    MsgType,
    create_client_tls_context,
    derive_hmac_key_from_ssl,
    encode_frame,
)
from server.session import RECONNECT_TIMEOUT

logger = logging.getLogger(__name__)

RECV_SIZE = 4096


class PCSConnection:
    def __init__(
        self,
        host: str,
        port: int,
        cafile: str | None = None,
        verify_cert: bool = True,
        hmac_fallback: bytes | None = None,
        hmac_from_tls: bool = False,
    ) -> None:
        self.host = host
        self.port = port
        self.cafile = cafile
        self.verify_cert = verify_cert
        self._hmac_fallback = hmac_fallback
        self._hmac_from_tls = hmac_from_tls

        self._sock: ssl.SSLSocket | None = None
        self._buffer = FrameBuffer()
        self._hmac_key: bytes | None = None
        self._connected = False

    def connect(self) -> None:
        if self._connected:
            return

        raw_sock = socket.create_connection((self.host, self.port), timeout=10)

        if self.verify_cert:
            tls_ctx = create_client_tls_context(cafile=self.cafile)
        else:
            tls_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            tls_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            tls_ctx.check_hostname = False
            tls_ctx.verify_mode = ssl.CERT_NONE

        self._sock = tls_ctx.wrap_socket(raw_sock, server_hostname=self.host)
        self._hmac_key = derive_hmac_key_from_ssl(
            self._sock, self._hmac_fallback, prefer_tls_export=self._hmac_from_tls,
        )
        self._buffer.clear()
        self._connected = True
        logger.info("Połączono z %s:%d (TLS %s)", self.host, self.port, self._sock.version())

    @property
    def hmac_key(self) -> bytes:
        if self._hmac_key is None:
            raise RuntimeError("Brak klucza HMAC - najpierw connect().")
        return self._hmac_key

    def close(self) -> None:
        self._connected = False
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        self._hmac_key = None
        self._buffer.clear()
        logger.info("Połączenie zamknięte.")

    def send_frame(
        self,
        msg_type: MsgType,
        payload: dict,
        msg_id: int,
    ) -> None:
        if not self._connected or self._sock is None:
            raise ConnectionError("Brak połączenia z serwerem.")

        raw = encode_frame(msg_type, payload, msg_id, self.hmac_key)
        self._sock.sendall(raw)
        logger.debug("Wysłano ramkę: type=%s msg_id=%d rozmiar=%dB", msg_type.name, msg_id, len(raw))

    def receive_raw_frames(self, timeout: float | None = None) -> list[bytes]:
        if not self._connected or self._sock is None:
            raise ConnectionError("Brak połączenia z serwerem.")

        self._sock.settimeout(timeout)
        try:
            data = self._sock.recv(RECV_SIZE)
        except socket.timeout:
            return []
        finally:
            self._sock.settimeout(None)

        if not data:
            raise ConnectionError("Serwer zamknął połączenie.")

        self._buffer.feed(data)
        return self._buffer.drain()

    @property
    def is_connected(self) -> bool:
        return self._connected
    

    def reconnect(
        self,
        username: str,
        password: str,
        timeout: float = RECONNECT_TIMEOUT,
    ) -> str:
        from client.auth import login, AuthError

        deadline = time.monotonic() + timeout
        attempt = 0
        while time.monotonic() < deadline:
            attempt += 1
            try:
                self.close()
                self.connect()
                token = login(self, username, password)
                logger.info("Reconnect udany (próba %d)", attempt)
                return token
            except (ConnectionError, OSError, AuthError) as exc:
                logger.warning("Reconnect próba %d nieudana: %s", attempt, exc)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                time.sleep(min(0.5, remaining))

        raise ConnectionError(f"Nie udało się ponownie połączyć w ciągu {timeout}s.")