from __future__ import annotations

import logging
import threading
from datetime import datetime

from pcs.exceptions import PCSError
from client.auth import AuthError
from client.connection import PCSConnection
from client.keepalive import KeepAlive
from client.session import PCSSession
from client.auth import login

logger = logging.getLogger(__name__)


def _format_time(iso_timestamp: str) -> str:
    try:
        return datetime.fromisoformat(iso_timestamp).astimezone().strftime("%H:%M")
    except (ValueError, TypeError):
        return "??:??"


class ChatCLI:
    def __init__(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        hmac_fallback: bytes | None = None,
        cafile: str | None = None,
        verify_cert: bool = True,
        keepalive: bool = True,
        hmac_from_tls: bool = False,
    ) -> None:
        self._host = host
        self._port = port
        self._username = username
        self._password = password
        self._hmac_fallback = hmac_fallback
        self._cafile = cafile
        self._verify_cert = verify_cert
        self._keepalive_enabled = keepalive
        self._hmac_from_tls = hmac_from_tls

        self._conn: PCSConnection | None = None
        self._session: PCSSession | None = None
        self._keepalive: KeepAlive | None = None
        self._running = False

    def _connect_and_login(self) -> None:
        self._conn = PCSConnection(
            self._host, self._port,
            cafile=self._cafile,
            verify_cert=self._verify_cert,
            hmac_fallback=self._hmac_fallback,
            hmac_from_tls=self._hmac_from_tls,
        )
        self._conn.connect()
        token = login(self._conn, self._username, self._password)
        self._session = PCSSession(self._conn, self._username, token)

    def _on_message(self, sender: str, text: str, timestamp: str) -> None:
        t = _format_time(timestamp)
        print(f"\r[{t}] {sender}: {text}")
        print("> ", end="", flush=True)

    def _on_error(self, code) -> None:
        print(f"\r[błąd serwera] kod={code}")
        self._running = False

    def _on_pong(self) -> None:
        if self._keepalive:
            self._keepalive.pong_received()

    def _receive_loop(self) -> None:
        while self._running:
            try:
                if self._keepalive and self._keepalive.connection_lost:
                    print("\r[utracono połączenie, próba reconnect...]")
                    try:
                        self._keepalive.stop()
                        token = self._conn.reconnect(
                            self._username, self._password,
                        )
                        self._session = PCSSession(
                            self._conn, self._username, token,
                        )
                        self._keepalive = KeepAlive(self._session)
                        self._keepalive.start()
                        print("\r[ponownie połączono]")
                    except ConnectionError:
                        print("\r[nie udało się reconnect - rozłączono]")
                        self._running = False
                        return

                frames = self._session.receive_frames()
                for frame in frames:
                    self._session.handle_frame(
                        frame, self._on_message, self._on_error, self._on_pong
                    )

            except ConnectionError:
                if self._running:
                    print("\r[połączenie zerwane]")
                    self._running = False
                return
            except PCSError:
                self._running = False
                return

    def run(self) -> None:
        self._connect_and_login()
        if self._keepalive_enabled:
            self._keepalive = KeepAlive(self._session)
            self._keepalive.start()
        self._running = True

        recv_thread = threading.Thread(target=self._receive_loop, daemon=True)
        recv_thread.start()

        ka_info = "" if self._keepalive_enabled else " [keep-alive wyłączony]"
        print(f"[połączono jako {self._username}{ka_info}] Wpisz wiadomość lub Ctrl+C aby wyjść.")

        try:
            while self._running:
                try:
                    text = input("> ")
                    if text.strip():
                        self._session.send_message(text)
                        now = datetime.now().strftime("%H:%M")
                        print(f"\r[{now}] {self._username}: {text}")
                        print("> ", end="", flush=True)
                except EOFError:
                    break
        except KeyboardInterrupt:
            pass
        finally:
            self._running = False
            if self._keepalive:
                self._keepalive.stop()
            if self._session:
                try:
                    self._session.send_bye()
                except Exception:
                    pass
            if self._conn:
                self._conn.close()
            print("\n[rozłączono]")