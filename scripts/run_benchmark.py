from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from pcs import MsgType, derive_hmac_key, encode_frame, decode_frame, FrameBuffer
from server.server import PCSServer

TEST_KEY = derive_hmac_key(b"benchmark-secret")
TEST_PASSWORD = "bench_password"


async def _fast_verify(username: str, password_hash: str) -> bool:
    return password_hash == TEST_PASSWORD


class BenchClient:
    def __init__(self, reader, writer, username: str) -> None:
        self._reader = reader
        self._writer = writer
        self._buf = FrameBuffer()
        self._msg_id = 0
        self.username = username
        self.token = ""

    async def send(self, msg_type: MsgType, payload: dict) -> None:
        self._msg_id += 1
        self._writer.write(encode_frame(msg_type, payload, self._msg_id, TEST_KEY))
        await self._writer.drain()

    async def recv(self) -> object:
        while True:
            data = await self._reader.read(4096)
            if not data:
                raise EOFError("connection closed")
            self._buf.feed(data)
            frames = self._buf.drain()
            if frames:
                return decode_frame(frames[0], TEST_KEY)

    async def close(self) -> None:
        self._writer.close()
        await self._writer.wait_closed()


async def _connect(port: int, username: str) -> BenchClient:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    client = BenchClient(reader, writer, username)
    await client.send(MsgType.AUTH_REQ, {"username": username, "password_hash": TEST_PASSWORD})
    frame = await client.recv()
    if frame.msg_type != MsgType.AUTH_OK:
        raise RuntimeError(f"auth failed for {username}")
    client.token = frame.payload["session_token"]
    return client


async def bench_concurrent_connections(n_clients: int) -> dict:
    server = PCSServer("127.0.0.1", 0, TEST_KEY, _fast_verify)
    await server.start()
    t0 = time.perf_counter()
    try:
        clients = await asyncio.gather(*[
            _connect(server.port, f"user{i}") for i in range(n_clients)
        ])
        elapsed = time.perf_counter() - t0
        ready = len(server._session_manager.ready_sessions())
        await asyncio.gather(*[c.close() for c in clients])
        return {
            "scenario": "concurrent_connections",
            "clients": n_clients,
            "ready_sessions": ready,
            "elapsed_s": round(elapsed, 3),
            "success": ready == n_clients,
        }
    finally:
        await server.stop()


async def bench_message_latency(n_messages: int, latency_limit: float) -> dict:
    server = PCSServer("127.0.0.1", 0, TEST_KEY, _fast_verify)
    await server.start()
    try:
        sender = await _connect(server.port, "sender")
        receiver = await _connect(server.port, "receiver")
        latencies: list[float] = []

        for i in range(n_messages):
            t0 = time.perf_counter()
            await sender.send(MsgType.MSG_SEND, {
                "username": "sender",
                "message": f"msg{i}",
                "session_token": sender.token,
            })
            await receiver.recv()
            latencies.append(time.perf_counter() - t0)
            if (i + 1) % 10 == 0:
                await asyncio.sleep(1.05)

        avg_ms = statistics.mean(latencies) * 1000
        p95_ms = statistics.quantiles(latencies, n=20)[18] * 1000 if len(latencies) >= 20 else max(latencies) * 1000
        max_ms = max(latencies) * 1000

        await sender.close()
        await receiver.close()

        return {
            "scenario": "message_latency",
            "messages": n_messages,
            "avg_ms": round(avg_ms, 2),
            "p95_ms": round(p95_ms, 2),
            "max_ms": round(max_ms, 2),
            "limit_ms": latency_limit * 1000,
            "success": avg_ms < latency_limit * 1000,
        }
    finally:
        await server.stop()


async def bench_broadcast(n_receivers: int, latency_limit: float) -> dict:
    server = PCSServer("127.0.0.1", 0, TEST_KEY, _fast_verify)
    await server.start()
    try:
        sender = await _connect(server.port, "sender")
        receivers = await asyncio.gather(*[
            _connect(server.port, f"recv{i}") for i in range(n_receivers)
        ])

        t0 = time.perf_counter()
        await sender.send(MsgType.MSG_SEND, {
            "username": "sender",
            "message": "broadcast test",
            "session_token": sender.token,
        })
        await asyncio.gather(*[r.recv() for r in receivers])
        elapsed_ms = (time.perf_counter() - t0) * 1000

        await sender.close()
        await asyncio.gather(*[r.close() for r in receivers])

        return {
            "scenario": "broadcast_fanout",
            "receivers": n_receivers,
            "elapsed_ms": round(elapsed_ms, 2),
            "limit_ms": latency_limit * 1000,
            "success": elapsed_ms < latency_limit * 1000,
        }
    finally:
        await server.stop()


async def run_all(quick: bool) -> dict:
    n_clients = 10 if quick else 50
    n_messages = 10 if quick else 20
    limit = 0.100

    results = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "python": sys.version.split()[0],
        "quick_mode": quick,
        "benchmarks": [],
    }

    for coro in (
        bench_concurrent_connections(n_clients),
        bench_message_latency(n_messages, limit),
        bench_broadcast(min(n_clients - 1, 49), limit),
    ):
        results["benchmarks"].append(await coro)

    results["all_passed"] = all(b["success"] for b in results["benchmarks"])
    return results


def _print_report(results: dict) -> None:
    print("\n=== PyChat - raport wydajności ===\n")
    print(f"Czas:     {results['timestamp']}")
    print(f"Python:   {results['python']}")
    print(f"Tryb:     {'quick (CI)' if results['quick_mode'] else 'full'}\n")

    for b in results["benchmarks"]:
        status = "OK" if b["success"] else "FAIL"
        print(f"[{status}] {b['scenario']}")
        for key, val in b.items():
            if key not in ("scenario", "success"):
                print(f"       {key}: {val}")
        print()

    overall = "PASSED" if results["all_passed"] else "FAILED"
    print(f"Wynik ogólny: {overall}\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark wydajności PyChat")
    parser.add_argument("--quick", action="store_true", help="Krótszy przebieg (CI)")
    parser.add_argument("--output", type=Path, help="Zapisz wyniki JSON")
    args = parser.parse_args()

    results = asyncio.run(run_all(args.quick))
    _print_report(results)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(f"Zapisano: {args.output}")

    return 0 if results["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
