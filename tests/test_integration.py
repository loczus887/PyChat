import asyncio
import pytest

from pcs import MsgType, derive_hmac_key, hash_password_for_user
from pcs import encode_frame, decode_frame, FrameBuffer
from pcs.exceptions import ErrorCode
from db.users import UserDB
from server.server import PCSServer
from server.main import make_verify_credentials

HMAC_SECRET = b"integration-test-secret"
TEST_KEY = derive_hmac_key(HMAC_SECRET)
PASSWORD = "tajnehaslo123"


def make_server_with_db(db: UserDB) -> PCSServer:
    return PCSServer(
        host="127.0.0.1",
        port=0,
        hmac_key=TEST_KEY,
        verify_credentials=make_verify_credentials(db),
    )


def run(coro):
    return asyncio.run(coro)


class IntegrationClient:
    def __init__(self, reader, writer):
        self._reader = reader
        self._writer = writer
        self._buf = FrameBuffer()
        self._msg_id = 0

    async def send(self, msg_type, payload):
        self._msg_id += 1
        self._writer.write(encode_frame(msg_type, payload, self._msg_id, TEST_KEY))
        await self._writer.drain()

    async def recv(self, timeout=2.0):
        while True:
            data = await asyncio.wait_for(self._reader.read(4096), timeout=timeout)
            if not data:
                raise EOFError("Connection closed")
            self._buf.feed(data)
            frames = self._buf.drain()
            if frames:
                return decode_frame(frames[0], TEST_KEY)

    async def close(self):
        self._writer.close()
        await self._writer.wait_closed()


async def connect(port) -> IntegrationClient:
    r, w = await asyncio.open_connection("127.0.0.1", port)
    return IntegrationClient(r, w)


class TestFullAuthPipeline:
    def test_login_with_real_bcrypt_hash(self):
        async def go():
            db = UserDB(":memory:")
            db.init()
            db.create_user("alice", hash_password_for_user(PASSWORD, "alice"))

            server = make_server_with_db(db)
            await server.start()
            try:
                client = await connect(server.port)
                await client.send(MsgType.AUTH_REQ, {
                    "username": "alice",
                    "password_hash": hash_password_for_user(PASSWORD, "alice"),
                })
                frame = await client.recv()
                assert frame.msg_type == MsgType.AUTH_OK
                assert "session_token" in frame.payload
                await client.close()
            finally:
                await server.stop()
                db.close()
        run(go())

    def test_wrong_password_rejected(self):
        async def go():
            db = UserDB(":memory:")
            db.init()
            db.create_user("alice", hash_password_for_user(PASSWORD, "alice"))

            server = make_server_with_db(db)
            await server.start()
            try:
                client = await connect(server.port)
                await client.send(MsgType.AUTH_REQ, {
                    "username": "alice",
                    "password_hash": "zlehaslo",
                })
                frame = await client.recv()
                assert frame.msg_type == MsgType.ERROR
                assert frame.payload["error_code"] == ErrorCode.ERR_AUTH
            finally:
                await server.stop()
                db.close()
        run(go())

    def test_unknown_user_rejected(self):
        async def go():
            db = UserDB(":memory:")
            db.init()

            server = make_server_with_db(db)
            await server.start()
            try:
                client = await connect(server.port)
                await client.send(MsgType.AUTH_REQ, {
                    "username": "ghost",
                    "password_hash": hash_password_for_user(PASSWORD, "ghost"),
                })
                frame = await client.recv()
                assert frame.msg_type == MsgType.ERROR
                assert frame.payload["error_code"] == ErrorCode.ERR_AUTH
            finally:
                await server.stop()
                db.close()
        run(go())

    def test_full_chat_session(self):
        async def go():
            db = UserDB(":memory:")
            db.init()
            db.create_user("alice", hash_password_for_user(PASSWORD, "alice"))
            db.create_user("bob", hash_password_for_user(PASSWORD, "bob"))

            server = make_server_with_db(db)
            await server.start()
            try:
                alice = await connect(server.port)
                bob = await connect(server.port)

                await alice.send(MsgType.AUTH_REQ, {
                    "username": "alice",
                    "password_hash": hash_password_for_user(PASSWORD, "alice"),
                })
                alice_ok = await alice.recv()
                alice_token = alice_ok.payload["session_token"]

                await bob.send(MsgType.AUTH_REQ, {
                    "username": "bob",
                    "password_hash": hash_password_for_user(PASSWORD, "bob"),
                })
                await bob.recv()

                await alice.send(MsgType.MSG_SEND, {
                    "username": "alice",
                    "message": "hej bob!",
                    "session_token": alice_token,
                })

                frame = await bob.recv()
                assert frame.msg_type == MsgType.MSG_BROADCAST
                assert frame.payload["from"] == "alice"
                assert frame.payload["message"] == "hej bob!"

                await alice.close()
                await bob.close()
            finally:
                await server.stop()
                db.close()
        run(go())
