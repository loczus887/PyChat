from __future__ import annotations

import logging
import threading

logger = logging.getLogger(__name__)

PING_INTERVAL = 30.0
PONG_TIMEOUT  = 10.0


class KeepAlive:
    def __init__(self, session) -> None:
        self._session = session
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._pong_event = threading.Event()
        self.connection_lost = False

    def start(self) -> None:
        self._stop_event.clear()
        self.connection_lost = False
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        logger.debug("KeepAlive uruchomiony.")

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=2.0)
        logger.debug("KeepAlive zatrzymany.")

    def pong_received(self) -> None:
        self._pong_event.set()

    def _run(self) -> None:
        while not self._stop_event.wait(PING_INTERVAL):
            try:
                self._pong_event.clear()
                self._session.send_ping()
                logger.debug("PING wysłany, czekam na PONG...")

                if not self._pong_event.wait(timeout=PONG_TIMEOUT):
                    logger.warning("Brak PONG — połączenie zerwane.")
                    self.connection_lost = True
                    return
            except ConnectionError as exc:
                logger.warning("KeepAlive: błąd połączenia: %s", exc)
                self.connection_lost = True
                return