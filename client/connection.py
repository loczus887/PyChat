from __future__ import annotations

import logging
import socket
import ssl

from pcs import (
    FrameBuffer,
    MsgType,
    create_client_tls_context,
    encode_frame,
)

logger = logging.getLogger(__name__)

RECV_SIZE = 4096


class PCSConnection:
    """Zarządza połączeniem TCP/TLS z serwerem PCS."""

    def __init__(
        self,
        host: str,
        port: int,
        cafile: str | None = None,
        verify_cert: bool = True,
    ) -> None:
        self.host = host
        self.port = port
        self.cafile = cafile
        self.verify_cert = verify_cert

        self._sock: ssl.SSLSocket | None = None
        self._buffer = FrameBuffer()
        self._connected = False

    def connect(self) -> None:
        """Nawiązuje połączenie TCP i wykonuje handshake TLS 1.3."""
        if self._connected:
            return

        raw_sock = socket.create_connection((self.host, self.port), timeout=10)

        if self.verify_cert:
            tls_ctx = create_client_tls_context(cafile=self.cafile)
        else:
            # tryb testowy — bez weryfikacji certyfikatu serwera
            tls_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            tls_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            tls_ctx.check_hostname = False
            tls_ctx.verify_mode = ssl.CERT_NONE

        self._sock = tls_ctx.wrap_socket(raw_sock, server_hostname=self.host)
        self._buffer.clear()
        self._connected = True
        logger.info("Połączono z %s:%d (TLS %s)", self.host, self.port, self._sock.version())

    def close(self) -> None:
        """Zamyka połączenie."""
        self._connected = False
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        self._buffer.clear()
        logger.info("Połączenie zamknięte.")

    def send_frame(
        self,
        msg_type: MsgType,
        payload: dict,
        msg_id: int,
        hmac_key: bytes,
    ) -> None:
        """Koduje i wysyła pojedynczą ramkę PCS."""
        if not self._connected or self._sock is None:
            raise ConnectionError("Brak połączenia z serwerem.")

        raw = encode_frame(msg_type, payload, msg_id, hmac_key)
        self._sock.sendall(raw)
        logger.debug(
            "Wysłano ramkę: type=%s msg_id=%d rozmiar=%dB",
            msg_type.name, msg_id, len(raw),
        )

    def receive_raw_frames(self) -> list[bytes]:
        """
        Czyta dostępne dane z socketu i zwraca listę kompletnych surowych ramek.
        Używa FrameBuffer do obsługi partial read TCP.
        Blokuje dopóki nie przyjdą dane.
        """
        if not self._connected or self._sock is None:
            raise ConnectionError("Brak połączenia z serwerem.")

        data = self._sock.recv(RECV_SIZE)
        if not data:
            raise ConnectionError("Serwer zamknął połączenie.")

        self._buffer.feed(data)
        return self._buffer.drain()

    @property
    def is_connected(self) -> bool:
        return self._connected