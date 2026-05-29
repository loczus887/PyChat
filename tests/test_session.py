from unittest.mock import patch
import pytest

from pcs import SessionState
from pcs.exceptions import PCSReplayAttackError
from server.session import (
    Session, SessionManager,
    PING_INTERVAL, PONG_TIMEOUT, SESSION_TIMEOUT,
    MAX_AUTH_ATTEMPTS, AUTH_WINDOW, MAX_REQUESTS_PER_SEC,
)


class TestSessionInit:
    def test_initial_state_is_disconnected(self):
        s = Session()
        assert s.state is SessionState.DISCONNECTED

    def test_id_is_unique(self):
        ids = {Session().id for _ in range(100)}
        assert len(ids) == 100

    def test_username_and_token_none(self):
        s = Session()
        assert s.username is None
        assert s.session_token is None

    def test_peer_address_stored(self):
        s = Session(("127.0.0.1", 9000))
        assert s.peer_address == ("127.0.0.1", 9000)


class TestStateTransitions:
    def test_disconnected_to_connected(self):
        s = Session()
        s.transition(SessionState.CONNECTED)
        assert s.state is SessionState.CONNECTED

    def test_connected_to_authenticated(self):
        s = Session()
        s.transition(SessionState.CONNECTED)
        s.transition(SessionState.AUTHENTICATED)
        assert s.state is SessionState.AUTHENTICATED

    def test_authenticated_to_ready(self):
        s = Session()
        s.transition(SessionState.CONNECTED)
        s.transition(SessionState.AUTHENTICATED)
        s.transition(SessionState.READY)
        assert s.state is SessionState.READY

    def test_ready_to_closed(self):
        s = Session()
        s.transition(SessionState.CONNECTED)
        s.transition(SessionState.AUTHENTICATED)
        s.transition(SessionState.READY)
        s.transition(SessionState.CLOSED)
        assert s.state is SessionState.CLOSED

    def test_connected_to_closed_on_error(self):
        s = Session()
        s.transition(SessionState.CONNECTED)
        s.transition(SessionState.CLOSED)
        assert s.state is SessionState.CLOSED

    def test_authenticated_to_closed_on_error(self):
        s = Session()
        s.transition(SessionState.CONNECTED)
        s.transition(SessionState.AUTHENTICATED)
        s.transition(SessionState.CLOSED)
        assert s.state is SessionState.CLOSED

    def test_invalid_disconnected_to_ready(self):
        s = Session()
        with pytest.raises(ValueError):
            s.transition(SessionState.READY)

    def test_invalid_connected_to_ready(self):
        s = Session()
        s.transition(SessionState.CONNECTED)
        with pytest.raises(ValueError):
            s.transition(SessionState.READY)

    def test_invalid_ready_to_connected(self):
        s = Session()
        s.transition(SessionState.CONNECTED)
        s.transition(SessionState.AUTHENTICATED)
        s.transition(SessionState.READY)
        with pytest.raises(ValueError):
            s.transition(SessionState.CONNECTED)

    def test_invalid_closed_to_any(self):
        s = Session()
        s.transition(SessionState.CONNECTED)
        s.transition(SessionState.CLOSED)
        for target in SessionState:
            with pytest.raises(ValueError):
                s.transition(target)

    def test_invalid_skip_authenticated(self):
        s = Session()
        s.transition(SessionState.CONNECTED)
        with pytest.raises(ValueError):
            s.transition(SessionState.DISCONNECTED)


class TestAuthenticate:
    def test_authenticate_transitions_to_ready(self):
        s = Session()
        s.transition(SessionState.CONNECTED)
        s.authenticate("alice", "token-abc")
        assert s.state is SessionState.READY
        assert s.username == "alice"
        assert s.session_token == "token-abc"

    def test_authenticate_from_wrong_state_raises(self):
        s = Session()
        with pytest.raises(ValueError):
            s.authenticate("alice", "token-abc")

    def test_authenticate_twice_raises(self):
        s = Session()
        s.transition(SessionState.CONNECTED)
        s.authenticate("alice", "token-abc")
        with pytest.raises(ValueError):
            s.authenticate("alice", "token-abc")


class TestMsgIdValidation:
    def _ready_session(self):
        s = Session()
        s.transition(SessionState.CONNECTED)
        s.authenticate("u", "t")
        return s

    def test_first_msg_id_accepted(self):
        s = self._ready_session()
        s.validate_msg_id(1)
        assert s._last_msg_id == 1

    def test_increasing_ids_accepted(self):
        s = self._ready_session()
        for i in range(1, 11):
            s.validate_msg_id(i)
        assert s._last_msg_id == 10

    def test_duplicate_msg_id_raises(self):
        s = self._ready_session()
        s.validate_msg_id(5)
        with pytest.raises(PCSReplayAttackError):
            s.validate_msg_id(5)

    def test_lower_msg_id_raises(self):
        s = self._ready_session()
        s.validate_msg_id(10)
        with pytest.raises(PCSReplayAttackError):
            s.validate_msg_id(9)

    def test_msg_id_zero_raises(self):
        s = self._ready_session()
        with pytest.raises(PCSReplayAttackError):
            s.validate_msg_id(0)

    def test_large_msg_id_jump_accepted(self):
        s = self._ready_session()
        s.validate_msg_id(1)
        s.validate_msg_id(0xFFFF_FFFE)
        assert s._last_msg_id == 0xFFFF_FFFE

    def test_validate_updates_last_activity(self):
        s = self._ready_session()
        before = s._last_activity
        with patch("server.session.time") as mock_time:
            mock_time.monotonic.return_value = before + 5
            s.validate_msg_id(1)
        assert s._last_activity == before + 5


class TestTimeout:
    def test_not_timed_out_initially(self):
        s = Session()
        assert s.is_timed_out() is False

    def test_timed_out_after_session_timeout(self):
        s = Session()
        with patch("server.session.time") as mock_time:
            mock_time.monotonic.return_value = s._last_activity + SESSION_TIMEOUT + 1
            assert s.is_timed_out() is True

    def test_not_timed_out_just_before_limit(self):
        s = Session()
        with patch("server.session.time") as mock_time:
            mock_time.monotonic.return_value = s._last_activity + SESSION_TIMEOUT - 1
            assert s.is_timed_out() is False

    def test_record_activity_resets_timer(self):
        s = Session()
        base = s._last_activity
        with patch("server.session.time") as mock_time:
            mock_time.monotonic.return_value = base + SESSION_TIMEOUT + 1
            assert s.is_timed_out() is True
            s.record_activity()
            mock_time.monotonic.return_value = base + SESSION_TIMEOUT + 2
            assert s.is_timed_out() is False


class TestAuthRateLimit:
    def test_allows_up_to_max_attempts(self):
        s = Session()
        for _ in range(MAX_AUTH_ATTEMPTS):
            assert s.check_auth_rate_limit() is True

    def test_blocks_after_max_attempts(self):
        s = Session()
        for _ in range(MAX_AUTH_ATTEMPTS):
            s.check_auth_rate_limit()
        assert s.check_auth_rate_limit() is False

    def test_window_resets_after_timeout(self):
        s = Session()
        for _ in range(MAX_AUTH_ATTEMPTS):
            s.check_auth_rate_limit()
        with patch("server.session.time") as mock_time:
            mock_time.monotonic.return_value = s._auth_attempts[0] + AUTH_WINDOW + 1
            assert s.check_auth_rate_limit() is True

    def test_single_attempt_counted(self):
        s = Session()
        s.check_auth_rate_limit()
        assert len(s._auth_attempts) == 1


class TestRateLimit:
    def test_allows_up_to_max_per_second(self):
        s = Session()
        with patch("server.session.time") as mock_time:
            mock_time.monotonic.return_value = 1000.0
            for _ in range(MAX_REQUESTS_PER_SEC):
                assert s.check_rate_limit() is True

    def test_blocks_after_max_per_second(self):
        s = Session()
        with patch("server.session.time") as mock_time:
            mock_time.monotonic.return_value = 1000.0
            for _ in range(MAX_REQUESTS_PER_SEC):
                s.check_rate_limit()
            assert s.check_rate_limit() is False

    def test_allows_again_after_one_second(self):
        s = Session()
        with patch("server.session.time") as mock_time:
            mock_time.monotonic.return_value = 1000.0
            for _ in range(MAX_REQUESTS_PER_SEC):
                s.check_rate_limit()
            mock_time.monotonic.return_value = 1001.1
            assert s.check_rate_limit() is True


class TestClose:
    def test_close_from_ready(self):
        s = Session()
        s.transition(SessionState.CONNECTED)
        s.authenticate("u", "t")
        s.close()
        assert s.state is SessionState.CLOSED

    def test_close_from_connected(self):
        s = Session()
        s.transition(SessionState.CONNECTED)
        s.close()
        assert s.state is SessionState.CLOSED

    def test_close_idempotent(self):
        s = Session()
        s.close()
        s.close()
        assert s.state is SessionState.CLOSED


class TestSessionManager:
    def test_create_returns_connected_session(self):
        mgr = SessionManager()
        s = mgr.create(("127.0.0.1", 9000))
        assert s.state is SessionState.CONNECTED
        assert s.peer_address == ("127.0.0.1", 9000)

    def test_create_registers_session(self):
        mgr = SessionManager()
        s = mgr.create()
        assert mgr.get(s.id) is s

    def test_count(self):
        mgr = SessionManager()
        mgr.create()
        mgr.create()
        assert mgr.count == 2

    def test_get_unknown_returns_none(self):
        mgr = SessionManager()
        assert mgr.get("nonexistent") is None

    def test_remove_returns_session(self):
        mgr = SessionManager()
        s = mgr.create()
        removed = mgr.remove(s.id)
        assert removed is s
        assert mgr.count == 0

    def test_remove_unknown_returns_none(self):
        mgr = SessionManager()
        assert mgr.remove("nonexistent") is None

    def test_register_and_get_by_token(self):
        mgr = SessionManager()
        s = mgr.create()
        s.authenticate("alice", "token-xyz")
        mgr.register_token(s)
        assert mgr.get_by_token("token-xyz") is s

    def test_remove_cleans_token_index(self):
        mgr = SessionManager()
        s = mgr.create()
        s.authenticate("alice", "token-xyz")
        mgr.register_token(s)
        mgr.remove(s.id)
        assert mgr.get_by_token("token-xyz") is None

    def test_ready_sessions_filters_correctly(self):
        mgr = SessionManager()
        s1 = mgr.create()
        s2 = mgr.create()
        s3 = mgr.create()
        s1.authenticate("u1", "t1")
        s3.close()
        ready = mgr.ready_sessions()
        assert s1 in ready
        assert s2 not in ready
        assert s3 not in ready

    def test_cleanup_expired_removes_timed_out(self):
        mgr = SessionManager()
        s1 = mgr.create()
        s2 = mgr.create()
        with patch("server.session.time") as mock_time:
            mock_time.monotonic.return_value = s1._last_activity + SESSION_TIMEOUT + 1
            expired = mgr.cleanup_expired()
        assert s1 in expired
        assert s2 in expired
        assert mgr.count == 0

    def test_cleanup_keeps_active_sessions(self):
        mgr = SessionManager()
        s = mgr.create()
        with patch("server.session.time") as mock_time:
            mock_time.monotonic.return_value = s._last_activity + SESSION_TIMEOUT - 1
            expired = mgr.cleanup_expired()
        assert expired == []
        assert mgr.count == 1
