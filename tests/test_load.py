import asyncio
import time
import pytest

from pcs import MsgType, derive_hmac_key, encode_frame, decode_frame, FrameBuffer
from server.server import PCSServer

TEST_PASSWORD = "load_test_password"
TEST_KEY = derive_hmac_key(b"load-test-secret")

N_CLIENTS  = 50
N_MESSAGES = 20
LATENCY_LIMIT = 0.100


async def fast_verify(username: str, password_hash: str) -> bool:
    return password_hash == TEST_PASSWORD


def make_server() -> PCSServer:
    return PCSServer(
        host="127.0.0.1",
        port=0,
        hmac_key=TEST_KEY,
        verify_credentials=fast_verify,
    )


class LoadClient:
    def __init__(self, reader, writer, username: str) -> None:
        self._reader = reader
        self._writer = writer
        self._buf = FrameBuffer()
        self._queue: list = []
        self._msg_id = 0
        self.username = username
        self.token: str = ""

    async def send(self, msg_type: MsgType, payload: dict) -> None:
        self._msg_id += 1
        self._writer.write(encode_frame(msg_type, payload, self._msg_id, TEST_KEY))
        await self._writer.drain()

    async def recv(self):
        if self._queue:
            return self._queue.pop(0)
        while True:
            data = await self._reader.read(4096)
            if not data:
                raise EOFError("Connection closed")
            self._buf.feed(data)
            raw_frames = self._buf.drain()
            if raw_frames:
                decoded = [decode_frame(f, TEST_KEY) for f in raw_frames]
                self._queue.extend(decoded[1:])
                return decoded[0]

    async def close(self) -> None:
        self._writer.close()
        await self._writer.wait_closed()


async def connect_and_auth(port: int, username: str) -> LoadClient:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    client = LoadClient(reader, writer, username)
    await client.send(MsgType.AUTH_REQ, {
        "username": username,
        "password_hash": TEST_PASSWORD,
    })
    frame = await client.recv()
    assert frame.msg_type == MsgType.AUTH_OK
    client.token = frame.payload["session_token"]
    return client


async def collect(client: LoadClient, count: int) -> list:
    result = []
    for _ in range(count):
        frame = await client.recv()
        result.append(frame)
    return result


def run(coro):
    return asyncio.run(coro)


class TestConcurrentConnections:
    def test_50_clients_connect_and_auth(self):
        async def go():
            server = make_server()
            await server.start()
            try:
                clients = await asyncio.gather(*[
                    connect_and_auth(server.port, f"user{i}")
                    for i in range(N_CLIENTS)
                ])
                assert len(clients) == N_CLIENTS
                assert server._session_manager.count == N_CLIENTS
                await asyncio.gather(*[c.close() for c in clients])
            finally:
                await server.stop()
        run(go())

    def test_50_clients_session_state_ready(self):
        async def go():
            server = make_server()
            await server.start()
            try:
                clients = await asyncio.gather(*[
                    connect_and_auth(server.port, f"user{i}")
                    for i in range(N_CLIENTS)
                ])
                assert len(server._session_manager.ready_sessions()) == N_CLIENTS
                await asyncio.gather(*[c.close() for c in clients])
            finally:
                await server.stop()
        run(go())


class TestMessageDelivery:
    def test_no_message_loss_one_sender(self):
        async def go():
            server = make_server()
            await server.start()
            try:
                sender = await connect_and_auth(server.port, "sender")
                receivers = await asyncio.gather(*[
                    connect_and_auth(server.port, f"recv{i}")
                    for i in range(10)
                ])

                collectors = [
                    asyncio.create_task(collect(r, N_MESSAGES))
                    for r in receivers
                ]

                for i in range(N_MESSAGES):
                    await sender.send(MsgType.MSG_SEND, {
                        "username": "sender",
                        "message": f"msg{i}",
                        "session_token": sender.token,
                    })

                all_received = await asyncio.gather(*collectors)

                for i, received in enumerate(all_received):
                    assert len(received) == N_MESSAGES, \
                        f"receiver {i} got {len(received)}/{N_MESSAGES} messages"
                    texts = [f.payload["message"] for f in received]
                    for j in range(N_MESSAGES):
                        assert f"msg{j}" in texts, f"receiver {i} missing msg{j}"

                await sender.close()
                await asyncio.gather(*[r.close() for r in receivers])
            finally:
                await server.stop()
        run(go())

    def test_broadcast_correct_metadata(self):
        async def go():
            server = make_server()
            await server.start()
            try:
                sender   = await connect_and_auth(server.port, "alice")
                receiver = await connect_and_auth(server.port, "bob")

                await sender.send(MsgType.MSG_SEND, {
                    "username": "alice",
                    "message": "sprawdzam",
                    "session_token": sender.token,
                })
                frame = await receiver.recv()

                assert frame.msg_type == MsgType.MSG_BROADCAST
                assert frame.payload["from"] == "alice"
                assert frame.payload["message"] == "sprawdzam"
                assert "timestamp" in frame.payload

                await sender.close()
                await receiver.close()
            finally:
                await server.stop()
        run(go())

    def test_concurrent_senders_no_crash(self):
        async def go():
            server = make_server()
            await server.start()
            try:
                clients = await asyncio.gather(*[
                    connect_and_auth(server.port, f"user{i}")
                    for i in range(10)
                ])

                async def send_burst(client: LoadClient) -> None:
                    for i in range(5):
                        await client.send(MsgType.MSG_SEND, {
                            "username": client.username,
                            "message": f"{client.username}-{i}",
                            "session_token": client.token,
                        })

                await asyncio.gather(*[send_burst(c) for c in clients])
                await asyncio.sleep(0.2)

                assert server._session_manager.count == 10

                await asyncio.gather(*[c.close() for c in clients])
            finally:
                await server.stop()
        run(go())


class TestLatency:
    def test_single_message_latency_under_100ms(self):
        async def go():
            server = make_server()
            await server.start()
            try:
                sender   = await connect_and_auth(server.port, "sender")
                receiver = await connect_and_auth(server.port, "receiver")

                t0 = time.monotonic()
                await sender.send(MsgType.MSG_SEND, {
                    "username": "sender",
                    "message": "ping",
                    "session_token": sender.token,
                })
                await receiver.recv()
                latency = time.monotonic() - t0

                assert latency < LATENCY_LIMIT, \
                    f"Latencja {latency*1000:.1f} ms przekracza limit {LATENCY_LIMIT*1000:.0f} ms"

                await sender.close()
                await receiver.close()
            finally:
                await server.stop()
        run(go())

    def test_average_latency_20_messages(self):
        async def go():
            server = make_server()
            await server.start()
            try:
                sender   = await connect_and_auth(server.port, "sender")
                receiver = await connect_and_auth(server.port, "receiver")

                latencies = []
                for i in range(N_MESSAGES):
                    t0 = time.monotonic()
                    await sender.send(MsgType.MSG_SEND, {
                        "username": "sender",
                        "message": f"msg{i}",
                        "session_token": sender.token,
                    })
                    await receiver.recv()
                    latencies.append(time.monotonic() - t0)

                avg = sum(latencies) / len(latencies)
                worst = max(latencies)

                assert avg < LATENCY_LIMIT, \
                    f"Średnia latencja {avg*1000:.1f} ms > {LATENCY_LIMIT*1000:.0f} ms"
                assert worst < LATENCY_LIMIT * 3, \
                    f"Najgorsza latencja {worst*1000:.1f} ms > {LATENCY_LIMIT*3*1000:.0f} ms"

                await sender.close()
                await receiver.close()
            finally:
                await server.stop()
        run(go())

    def test_latency_with_50_connected_clients(self):
        async def go():
            server = make_server()
            await server.start()
            try:
                sender = await connect_and_auth(server.port, "sender")
                bystanders = await asyncio.gather(*[
                    connect_and_auth(server.port, f"user{i}")
                    for i in range(N_CLIENTS - 1)
                ])

                t0 = time.monotonic()
                await sender.send(MsgType.MSG_SEND, {
                    "username": "sender",
                    "message": "broadcast do 49",
                    "session_token": sender.token,
                })
                await asyncio.gather(*[b.recv() for b in bystanders])
                latency = time.monotonic() - t0

                assert latency < LATENCY_LIMIT, \
                    f"Broadcast do {N_CLIENTS-1} klientów: {latency*1000:.1f} ms > {LATENCY_LIMIT*1000:.0f} ms"

                await sender.close()
                await asyncio.gather(*[b.close() for b in bystanders])
            finally:
                await server.stop()
        run(go())
