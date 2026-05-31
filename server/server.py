from __future__ import annotations

import asyncio
import datetime
import logging
import ssl
import time
from typing import Callable, Awaitable

from pcs import (
    MsgType, SessionState, FrameBuffer,
    encode_frame, decode_frame,
    make_auth_ok, make_msg_broadcast, make_error,
    derive_hmac_key_from_ssl, generate_session_token,
)
from pcs.exceptions import (
    ErrorCode,
    PCSFrameError,
    PCSHMACError,
    PCSPayloadTooLargeError,
    PCSReplayAttackError,
)
from server.session import SESSION_TIMEOUT, SessionManager

logger = logging.getLogger(__name__)

VerifyCredentials = Callable[[str, str], Awaitable[bool]]


class PCSServer:
    def __init__(
        self,
        host: str,
        port: int,
        hmac_key: bytes,
        verify_credentials: VerifyCredentials,
        ssl_context: ssl.SSLContext | None = None,
        hmac_from_tls: bool = False,
    ) -> None:
        self._host = host
        self._port = port
        self._hmac_key = hmac_key
        self._hmac_from_tls = hmac_from_tls
        self._verify_credentials = verify_credentials
        self._ssl_context = ssl_context
        self._session_manager = SessionManager()
        self._writers: dict[str, asyncio.StreamWriter] = {}
        self._out_counters: dict[str, int] = {}
        self._ip_auth_failures: dict[str, list[float]] = {}
        self._ip_blocked_until: dict[str, float] = {}
        self._server: asyncio.Server | None = None

    _AUTH_FAILURE_LIMIT = 5
    _AUTH_FAILURE_WINDOW = 60
    _IP_BLOCK_DURATION = 300

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle_client,
            self._host,
            self._port,
            ssl=self._ssl_context,
        )
        logger.info("PCS server listening on %s:%d", self._host, self.port)

    async def serve_forever(self) -> None:
        if self._server is None:
            await self.start()
        async with self._server:
            await self._server.serve_forever()

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    @property
    def port(self) -> int:
        if self._server is None:
            raise RuntimeError("Server not started")
        return self._server.sockets[0].getsockname()[1]

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        peer = writer.get_extra_info("peername")
        session = self._session_manager.create(peer)
        ssl_obj = writer.get_extra_info("ssl_object")
        session.hmac_key = derive_hmac_key_from_ssl(
            ssl_obj, self._hmac_key, prefer_tls_export=self._hmac_from_tls,
        )
        self._writers[session.id] = writer
        self._out_counters[session.id] = 0
        buf = FrameBuffer()

        logger.info("connect peer=%s session=%s active=%d", peer, session.id, self._session_manager.count)

        try:
            while True:
                try:
                    data = await asyncio.wait_for(reader.read(4096), timeout=SESSION_TIMEOUT)
                except asyncio.TimeoutError:
                    logger.warning("timeout session=%s idle=%ds", session.id, SESSION_TIMEOUT)
                    await self._send_error(session, ErrorCode.ERR_TIMEOUT)
                    break

                if not data:
                    break

                buf.feed(data)

                try:
                    raw_frames = buf.drain()
                except PCSFrameError as exc:
                    logger.warning("Buffer error session=%s error=%s", session.id, exc)
                    await self._send_error(session, exc.error_code)
                    if exc.is_critical:
                        break
                    continue

                for raw_frame in raw_frames:
                    should_close = await self._process_frame(raw_frame, session)
                    if should_close:
                        return

        except ConnectionError as exc:
            logger.warning("Connection error session=%s: %s", session.id, exc)
        finally:
            session.close()
            self._session_manager.remove(session.id)
            self._writers.pop(session.id, None)
            self._out_counters.pop(session.id, None)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            logger.info(
                "disconnect session=%s user=%s active=%d",
                session.id, session.username or "-", self._session_manager.count - 1,
            )

    async def _process_frame(self, raw_frame: bytes, session) -> bool:
        hmac_key = session.hmac_key or self._hmac_key
        try:
            frame = decode_frame(raw_frame, hmac_key)
        except PCSHMACError:
            logger.error("Invalid HMAC session=%s peer=%s", session.id, session.peer_address)
            await self._send_error(session, ErrorCode.ERR_HMAC)
            return True
        except PCSPayloadTooLargeError:
            await self._send_error(session, ErrorCode.ERR_PAYLOAD_TOO_BIG)
            return False
        except PCSFrameError as exc:
            await self._send_error(session, exc.error_code)
            return exc.is_critical

        if session.state not in (SessionState.DISCONNECTED, SessionState.CLOSED):
            try:
                session.validate_msg_id(frame.msg_id)
            except PCSReplayAttackError:
                logger.error("Replay attack session=%s msg_id=%d", session.id, frame.msg_id)
                return False

        if frame.msg_type not in (MsgType.BYE, MsgType.AUTH_REQ):
            if not session.check_rate_limit():
                await self._send_error(session, ErrorCode.ERR_RATE_LIMIT)
                return False

        match frame.msg_type:
            case MsgType.AUTH_REQ:
                return await self._handle_auth_req(frame, session)
            case MsgType.MSG_SEND:
                return await self._handle_msg_send(frame, session)
            case MsgType.PING:
                return await self._handle_ping(session)
            case MsgType.BYE:
                return await self._handle_bye(session)
            case _:
                logger.warning("Unexpected type=%s state=%s", frame.msg_type, session.state)
                await self._send_error(session, ErrorCode.ERR_UNKNOWN_TYPE)
                return False

    async def _handle_auth_req(self, frame, session) -> bool:
        if session.state is not SessionState.CONNECTED:
            await self._send_error(session, ErrorCode.ERR_FORMAT)
            return True

        ip = session.peer_address[0] if session.peer_address else ""
        if not self._check_ip_auth_limit(ip):
            logger.error("Brute-force blocked ip=%s", ip)
            await self._send_error(session, ErrorCode.ERR_RATE_LIMIT)
            return True

        username = frame.payload.get("username", "")
        password_hash = frame.payload.get("password_hash", "")

        try:
            ok = await self._verify_credentials(username, password_hash)
        except Exception as exc:
            logger.error("verify_credentials raised: %s", exc)
            await self._send_error(session, ErrorCode.ERR_AUTH)
            return True

        if not ok:
            self._record_ip_auth_failure(ip)
            logger.warning("Auth failed session=%s username=%s", session.id, username)
            await self._send_error(session, ErrorCode.ERR_AUTH)
            return True

        token = generate_session_token()
        session.authenticate(username, token)
        self._session_manager.register_token(session)

        await self._send(session, MsgType.AUTH_OK, make_auth_ok(token))
        logger.info(
            "auth_ok session=%s user=%s active=%d",
            session.id, username, self._session_manager.count,
        )
        return False

    async def _handle_msg_send(self, frame, session) -> bool:
        if session.state is not SessionState.READY:
            logger.warning("MSG_SEND ignored - state=%s session=%s", session.state, session.id)
            return False

        if frame.payload.get("session_token") != session.session_token:
            logger.warning("Invalid session token session=%s", session.id)
            await self._send_error(session, ErrorCode.ERR_AUTH)
            return True

        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        payload = make_msg_broadcast(
            session.username,
            frame.payload.get("message", ""),
            timestamp,
        )

        msg_len = len(frame.payload.get("message", ""))
        recipients = sum(
            1 for s in self._session_manager.ready_sessions() if s.id != session.id
        )
        logger.info(
            "msg_send user=%s bytes=%d recipients=%d session=%s",
            session.username, msg_len, recipients, session.id,
        )
        await self._broadcast(MsgType.MSG_BROADCAST, payload, exclude=session.id)
        return False

    async def _handle_ping(self, session) -> bool:
        if session.state is SessionState.READY:
            await self._send(session, MsgType.PONG, {})
        return False

    async def _handle_bye(self, session) -> bool:
        logger.info("BYE received session=%s username=%s", session.id, session.username)
        return True

    async def _broadcast(self, msg_type: MsgType, payload: dict, exclude: str | None) -> None:
        for s in self._session_manager.ready_sessions():
            if s.id == exclude:
                continue
            writer = self._writers.get(s.id)
            if writer:
                try:
                    writer.write(self._encode_for(s, msg_type, payload))
                    await writer.drain()
                except Exception as exc:
                    logger.warning("Broadcast failed session=%s: %s", s.id, exc)

    async def _send(self, session, msg_type: MsgType, payload: dict) -> None:
        writer = self._writers.get(session.id)
        if not writer:
            return
        try:
            writer.write(self._encode_for(session, msg_type, payload))
            await writer.drain()
        except Exception as exc:
            logger.warning("Send failed session=%s: %s", session.id, exc)

    async def _send_error(self, session, error_code: ErrorCode) -> None:
        await self._send(session, MsgType.ERROR, make_error(error_code))

    def _encode_for(self, session, msg_type: MsgType, payload: dict) -> bytes:
        self._out_counters[session.id] += 1
        hmac_key = session.hmac_key or self._hmac_key
        return encode_frame(msg_type, payload, self._out_counters[session.id], hmac_key)

    def _check_ip_auth_limit(self, ip: str) -> bool:
        now = time.monotonic()
        blocked_until = self._ip_blocked_until.get(ip)
        if blocked_until is not None:
            if now < blocked_until:
                return False
            self._ip_blocked_until.pop(ip, None)
            self._ip_auth_failures.pop(ip, None)
        failures = [t for t in self._ip_auth_failures.get(ip, []) if now - t < self._AUTH_FAILURE_WINDOW]
        self._ip_auth_failures[ip] = failures
        return len(failures) < self._AUTH_FAILURE_LIMIT

    def _record_ip_auth_failure(self, ip: str) -> None:
        now = time.monotonic()
        failures = [t for t in self._ip_auth_failures.get(ip, []) if now - t < self._AUTH_FAILURE_WINDOW]
        failures.append(now)
        self._ip_auth_failures[ip] = failures
        if len(failures) >= self._AUTH_FAILURE_LIMIT:
            self._ip_blocked_until[ip] = now + self._IP_BLOCK_DURATION
