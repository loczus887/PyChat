from __future__ import annotations

import secrets
import time
from collections import deque

from pcs import SessionState
from pcs.exceptions import (
    ErrorCode,
    PCSFrameError,
    PCSRateLimitError,
    PCSReplayAttackError,
)

PING_INTERVAL     = 30
PONG_TIMEOUT      = 10
SESSION_TIMEOUT   = 60
RECONNECT_TIMEOUT = 5
MAX_AUTH_ATTEMPTS = 5
AUTH_WINDOW       = 60
MAX_REQUESTS_PER_SEC = 10

_VALID_TRANSITIONS: dict[SessionState, set[SessionState]] = {
    SessionState.DISCONNECTED: {SessionState.CONNECTED},
    SessionState.CONNECTED:    {SessionState.AUTHENTICATED, SessionState.CLOSED},
    SessionState.AUTHENTICATED:{SessionState.READY, SessionState.CLOSED},
    SessionState.READY:        {SessionState.CLOSED},
    SessionState.CLOSED:       set(),
}


class Session:
    def __init__(self, peer_address: tuple[str, int] | None = None) -> None:
        self.id             = secrets.token_hex(16)
        self.state          = SessionState.DISCONNECTED
        self.username:      str | None = None
        self.session_token: str | None = None
        self.peer_address   = peer_address
        self.hmac_key:       bytes | None = None
        self._last_msg_id   = 0
        self._last_activity = time.monotonic()
        self._created_at    = time.monotonic()
        self._auth_attempts: list[float] = []
        self._request_times: deque[float] = deque()

    def transition(self, new_state: SessionState) -> None:
        allowed = _VALID_TRANSITIONS[self.state]
        if new_state not in allowed:
            raise ValueError(
                f"Niedozwolone przejście stanu: {self.state.name} -> {new_state.name}"
            )
        self.state = new_state
        if new_state is not SessionState.CLOSED:
            self._last_activity = time.monotonic()

    def authenticate(self, username: str, session_token: str) -> None:
        self.transition(SessionState.AUTHENTICATED)
        self.username = username
        self.session_token = session_token
        self.transition(SessionState.READY)

    def validate_msg_id(self, msg_id: int) -> None:
        if msg_id <= self._last_msg_id:
            raise PCSReplayAttackError(
                f"Replay attack: msg_id={msg_id} <= last={self._last_msg_id}"
            )
        self._last_msg_id = msg_id
        self.record_activity()

    def record_activity(self) -> None:
        self._last_activity = time.monotonic()

    def is_timed_out(self) -> bool:
        return time.monotonic() - self._last_activity > SESSION_TIMEOUT

    def check_auth_rate_limit(self) -> bool:
        now = time.monotonic()
        self._auth_attempts = [t for t in self._auth_attempts if now - t < AUTH_WINDOW]
        if len(self._auth_attempts) >= MAX_AUTH_ATTEMPTS:
            return False
        self._auth_attempts.append(now)
        return True

    def check_rate_limit(self) -> bool:
        now = time.monotonic()
        while self._request_times and now - self._request_times[0] > 1.0:
            self._request_times.popleft()
        if len(self._request_times) >= MAX_REQUESTS_PER_SEC:
            return False
        self._request_times.append(now)
        return True

    def close(self) -> None:
        self.state = SessionState.CLOSED


class SessionManager:
    def __init__(self) -> None:
        self._sessions:  dict[str, Session] = {}
        self._by_token:  dict[str, Session] = {}

    def create(self, peer_address: tuple[str, int] | None = None) -> Session:
        session = Session(peer_address)
        session.transition(SessionState.CONNECTED)
        self._sessions[session.id] = session
        return session

    def get(self, session_id: str) -> Session | None:
        return self._sessions.get(session_id)

    def get_by_token(self, token: str) -> Session | None:
        return self._by_token.get(token)

    def register_token(self, session: Session) -> None:
        if session.session_token:
            self._by_token[session.session_token] = session

    def remove(self, session_id: str) -> Session | None:
        session = self._sessions.pop(session_id, None)
        if session and session.session_token:
            self._by_token.pop(session.session_token, None)
        return session

    def ready_sessions(self) -> list[Session]:
        return [s for s in self._sessions.values() if s.state is SessionState.READY]

    def cleanup_expired(self) -> list[Session]:
        expired = [s for s in self._sessions.values() if s.is_timed_out()]
        for s in expired:
            self.remove(s.id)
        return expired

    @property
    def count(self) -> int:
        return len(self._sessions)
