import asyncio
import pytest

from pcs import (
    MsgType, FrameBuffer,
    encode_frame, decode_frame,
    make_auth_req, make_msg_send,
)
from pcs.exceptions import ErrorCode
from server.server import PCSServer

TEST_KEY = b"test-hmac-key-32-bytes-padded!!!"
VALID_USER = "alice"
VALID_HASH = "correct_hash"


async def fake_verify(username: str, password_hash: str) -> bool:
    return username == VALID_USER and password_hash == VALID_HASH


async def failing_verify(username: str, password_hash: str) -> bool:
    raise RuntimeError("DB down")


def make_server(**kwargs) -> PCSServer:
    defaults = dict(
        host="127.0.0.1",
        port=0,
        hmac_key=TEST_KEY,
        verify_credentials=fake_verify,
    )
    defaults.update(kwargs)
    return PCSServer(**defaults)


class ChatClient:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._reader = reader
        self._writer = writer
        self._buf = FrameBuffer()
        self._msg_id = 0

    async def send(self, msg_type: MsgType, payload: dict) -> None:
        self._msg_id += 1
        raw = encode_frame(msg_type, payload, self._msg_id, TEST_KEY)
        self._writer.write(raw)
        await self._writer.drain()

    async def recv(self, timeout: float = 2.0):
        while True:
            data = await asyncio.wait_for(self._reader.read(4096), timeout=timeout)
            if not data:
                raise EOFError("Connection closed by server")
            self._buf.feed(data)
            frames = self._buf.drain()
            if frames:
                return decode_frame(frames[0], TEST_KEY)

    async def close(self) -> None:
        self._writer.close()
        await self._writer.wait_closed()


async def connect(port: int) -> ChatClient:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    return ChatClient(reader, writer)


async def authenticated_client(port: int) -> tuple[ChatClient, str]:
    client = await connect(port)
    await client.send(MsgType.AUTH_REQ, make_auth_req(VALID_USER, VALID_HASH))
    frame = await client.recv()
    assert frame.msg_type == MsgType.AUTH_OK
    return client, frame.payload["session_token"]


def run(coro):
    return asyncio.run(coro)


class TestServerStartStop:
    def test_server_starts_and_stops(self):
        async def go():
            server = make_server()
            await server.start()
            assert server.port > 0
            await server.stop()
        run(go())

    def test_port_raises_before_start(self):
        server = make_server()
        with pytest.raises(RuntimeError):
            _ = server.port


class TestAuthFlow:
    def test_correct_credentials_returns_auth_ok(self):
        async def go():
            server = make_server()
            await server.start()
            try:
                client = await connect(server.port)
                await client.send(MsgType.AUTH_REQ, make_auth_req(VALID_USER, VALID_HASH))
                frame = await client.recv()
                assert frame.msg_type == MsgType.AUTH_OK
                assert "session_token" in frame.payload
                await client.close()
            finally:
                await server.stop()
        run(go())

    def test_wrong_password_returns_error(self):
        async def go():
            server = make_server()
            await server.start()
            try:
                client = await connect(server.port)
                await client.send(MsgType.AUTH_REQ, make_auth_req(VALID_USER, "wrong"))
                frame = await client.recv()
                assert frame.msg_type == MsgType.ERROR
                assert frame.payload["error_code"] == ErrorCode.ERR_AUTH
            finally:
                await server.stop()
        run(go())

    def test_wrong_credentials_closes_connection(self):
        async def go():
            server = make_server()
            await server.start()
            try:
                client = await connect(server.port)
                await client.send(MsgType.AUTH_REQ, make_auth_req(VALID_USER, "wrong"))
                await client.recv()
                with pytest.raises((asyncio.TimeoutError, ConnectionError, EOFError)):
                    await client.recv(timeout=1.0)
            finally:
                await server.stop()
        run(go())

    def test_verify_credentials_exception_returns_error(self):
        async def go():
            server = make_server(verify_credentials=failing_verify)
            await server.start()
            try:
                client = await connect(server.port)
                await client.send(MsgType.AUTH_REQ, make_auth_req(VALID_USER, VALID_HASH))
                frame = await client.recv()
                assert frame.msg_type == MsgType.ERROR
                assert frame.payload["error_code"] == ErrorCode.ERR_AUTH
            finally:
                await server.stop()
        run(go())

    def test_auth_req_in_ready_state_closes_session(self):
        async def go():
            server = make_server()
            await server.start()
            try:
                client, _ = await authenticated_client(server.port)
                await client.send(MsgType.AUTH_REQ, make_auth_req(VALID_USER, VALID_HASH))
                frame = await client.recv()
                assert frame.msg_type == MsgType.ERROR
            finally:
                await server.stop()
        run(go())


class TestMsgBroadcast:
    def test_msg_send_broadcast_to_other_clients(self):
        async def go():
            server = make_server()
            await server.start()
            try:
                sender, sender_token = await authenticated_client(server.port)
                receiver, _ = await authenticated_client(server.port)

                await sender.send(
                    MsgType.MSG_SEND,
                    make_msg_send(VALID_USER, "hello", sender_token),
                )
                frame = await receiver.recv()

                assert frame.msg_type == MsgType.MSG_BROADCAST
                assert frame.payload["from"] == VALID_USER
                assert frame.payload["message"] == "hello"
                assert "timestamp" in frame.payload

                await sender.close()
                await receiver.close()
            finally:
                await server.stop()
        run(go())

    def test_sender_does_not_receive_own_broadcast(self):
        async def go():
            server = make_server()
            await server.start()
            try:
                sender, sender_token = await authenticated_client(server.port)
                await sender.send(
                    MsgType.MSG_SEND,
                    make_msg_send(VALID_USER, "hello", sender_token),
                )
                with pytest.raises(asyncio.TimeoutError):
                    await sender.recv(timeout=0.5)
                await sender.close()
            finally:
                await server.stop()
        run(go())

    def test_msg_send_without_auth_is_ignored(self):
        async def go():
            server = make_server()
            await server.start()
            try:
                client = await connect(server.port)
                await client.send(
                    MsgType.MSG_SEND,
                    make_msg_send(VALID_USER, "hello", "fake_token"),
                )
                with pytest.raises(asyncio.TimeoutError):
                    await client.recv(timeout=0.5)
                await client.close()
            finally:
                await server.stop()
        run(go())

    def test_msg_send_invalid_session_token(self):
        async def go():
            server = make_server()
            await server.start()
            try:
                client, _ = await authenticated_client(server.port)
                await client.send(
                    MsgType.MSG_SEND,
                    make_msg_send(VALID_USER, "hello", "bad_token"),
                )
                frame = await client.recv()
                assert frame.msg_type == MsgType.ERROR
                assert frame.payload["error_code"] == ErrorCode.ERR_AUTH
            finally:
                await server.stop()
        run(go())


class TestPingPong:
    def test_ping_returns_pong(self):
        async def go():
            server = make_server()
            await server.start()
            try:
                client, _ = await authenticated_client(server.port)
                await client.send(MsgType.PING, {})
                frame = await client.recv()
                assert frame.msg_type == MsgType.PONG
                await client.close()
            finally:
                await server.stop()
        run(go())

    def test_ping_before_auth_no_pong(self):
        async def go():
            server = make_server()
            await server.start()
            try:
                client = await connect(server.port)
                await client.send(MsgType.PING, {})
                with pytest.raises(asyncio.TimeoutError):
                    await client.recv(timeout=0.5)
                await client.close()
            finally:
                await server.stop()
        run(go())


class TestBye:
    def test_bye_closes_connection(self):
        async def go():
            server = make_server()
            await server.start()
            try:
                client, _ = await authenticated_client(server.port)
                await client.send(MsgType.BYE, {})
                data = await asyncio.wait_for(client._reader.read(4096), timeout=1.0)
                assert data == b""
            finally:
                await server.stop()
        run(go())


class TestSecurity:
    def test_invalid_hmac_returns_error_and_closes(self):
        async def go():
            server = make_server()
            await server.start()
            try:
                wrong_key = b"wrong-key-32-bytes-padded!!!!!!"
                reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
                bad_client = ChatClient(reader, writer)
                bad_client._msg_id = 0

                raw = encode_frame(MsgType.AUTH_REQ, make_auth_req("u", "h"), 1, wrong_key)
                writer.write(raw)
                await writer.drain()

                data = await asyncio.wait_for(reader.read(4096), timeout=2.0)
                from pcs import FrameBuffer
                buf = FrameBuffer()
                buf.feed(data)
                frames = buf.drain()
                frame = decode_frame(frames[0], TEST_KEY)
                assert frame.msg_type == MsgType.ERROR
                assert frame.payload["error_code"] == ErrorCode.ERR_HMAC

                writer.close()
                await writer.wait_closed()
            finally:
                await server.stop()
        run(go())

    def test_replay_attack_dropped_silently(self):
        async def go():
            server = make_server()
            await server.start()
            try:
                sender, sender_token = await authenticated_client(server.port)
                receiver, _ = await authenticated_client(server.port)

                payload = make_msg_send(VALID_USER, "original", sender_token)
                await sender.send(MsgType.MSG_SEND, payload)

                frame = await receiver.recv()
                assert frame.payload["message"] == "original"

                raw = encode_frame(MsgType.MSG_SEND, payload, sender._msg_id, TEST_KEY)
                sender._writer.write(raw)
                await sender._writer.drain()

                with pytest.raises(asyncio.TimeoutError):
                    await receiver.recv(timeout=0.5)

                await sender.close()
                await receiver.close()
            finally:
                await server.stop()
        run(go())

    def test_auth_rate_limit_blocks_after_max_attempts(self):
        async def go():
            from server.session import MAX_AUTH_ATTEMPTS
            server = make_server()
            await server.start()
            try:
                errors = []
                for _ in range(MAX_AUTH_ATTEMPTS + 1):
                    client = await connect(server.port)
                    await client.send(MsgType.AUTH_REQ, make_auth_req(VALID_USER, "wrong"))
                    frame = await client.recv()
                    errors.append(frame.payload["error_code"])

                assert ErrorCode.ERR_RATE_LIMIT in errors
            finally:
                await server.stop()
        run(go())
