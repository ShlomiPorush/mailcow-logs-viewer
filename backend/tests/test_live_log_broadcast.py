"""Exercise slow-client isolation and subscription changes without network IO."""
import asyncio
import json
from app.routers import raw_logs


class Client:
    def __init__(self, blocked=False):
        self.blocked = blocked
        self.started = asyncio.Event()
        self.release = asyncio.Event()
        self.messages = []
        self.closed = False
        self.in_send = False

    async def accept(self):
        pass

    async def send_text(self, text):
        assert not self.in_send, "overlapping writes on one socket"
        self.in_send = True
        self.started.set()
        try:
            if self.blocked:
                await self.release.wait()
            self.messages.append(json.loads(text))
        finally:
            self.in_send = False

    async def close(self, **kwargs):
        self.closed = True


def test_slow_client_does_not_delay_healthy_delivery(monkeypatch):
    monkeypatch.setattr(raw_logs, "WS_SEND_TIMEOUT_SECONDS", 0.1, raising=False)
    async def run():
        manager = raw_logs.LogStreamManager()
        slow, fast = Client(True), Client()
        await manager.connect(slow, "postfix")
        await manager.connect(fast, "postfix")
        task = asyncio.create_task(manager.broadcast("postfix", [{"message": "test"}]))
        try:
            await asyncio.wait_for(fast.started.wait(), 0.05)
            await asyncio.wait_for(task, 0.5)
            assert slow.closed
            assert manager.get_connection_count() == {"postfix": 1}
            assert fast.messages[0]["entries"] == [{"message": "test"}]
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
    asyncio.run(run())


def test_global_broadcast_uses_snapshot_when_services_change():
    async def run():
        manager = raw_logs.LogStreamManager()
        first, second = Client(True), Client()
        await manager.connect(first, "postfix")
        await manager.connect(second, "dovecot")
        task = asyncio.create_task(manager.broadcast_to_all({"type": "status"}))
        await first.started.wait()
        await manager.switch_service(second, "dovecot", "nginx")
        first.release.set()
        await task
        assert second.messages == [{"type": "status"}]
    asyncio.run(run())


def test_overlapping_broadcasts_serialize_each_client():
    async def run():
        manager = raw_logs.LogStreamManager()
        client = Client(True)
        await manager.connect(client, "postfix")
        first = asyncio.create_task(manager.broadcast_to_all({"order": 1}))
        await client.started.wait()
        second = asyncio.create_task(manager.broadcast_to_all({"order": 2}))
        await asyncio.sleep(0)
        client.release.set()
        await asyncio.gather(first, second)
        assert client.messages == [{"order": 1}, {"order": 2}]
    asyncio.run(run())


def test_stalled_client_is_removed_after_switch_and_close_is_bounded(monkeypatch):
    monkeypatch.setattr(raw_logs, "WS_SEND_TIMEOUT_SECONDS", 0.02)
    monkeypatch.setattr(raw_logs, "WS_CLOSE_TIMEOUT_SECONDS", 0.02)
    class StalledClose(Client):
        async def close(self, **kwargs):
            self.closed = True
            await asyncio.Event().wait()
    async def run():
        manager = raw_logs.LogStreamManager()
        client = StalledClose(True)
        await manager.connect(client, "postfix")
        task = asyncio.create_task(manager.broadcast("postfix", []))
        await client.started.wait()
        await manager.switch_service(client, "postfix", "dovecot")
        await asyncio.wait_for(task, 1)
        assert client.closed
        assert manager.get_connection_count() == {}
        assert not manager._send_locks
        assert not await manager.switch_service(client, "dovecot", "postfix")
    asyncio.run(run())


def test_failed_socket_does_not_prevent_other_deliveries():
    class Broken(Client):
        async def send_text(self, text):
            raise RuntimeError("disconnected")
    async def run():
        manager = raw_logs.LogStreamManager()
        broken, healthy = Broken(), Client()
        await manager.connect(broken, "postfix")
        await manager.connect(healthy, "dovecot")
        await manager.broadcast_to_all({"type": "status"})
        assert broken.closed
        assert healthy.messages == [{"type": "status"}]
        assert manager.get_connection_count() == {"dovecot": 1}
    asyncio.run(run())


def test_websocket_control_messages_and_disconnect(monkeypatch):
    from fastapi.testclient import TestClient
    from app.main import app
    from app.config import settings
    manager = raw_logs.LogStreamManager()
    monkeypatch.setattr(raw_logs, "log_stream_manager", manager)
    for key in ("auth_enabled", "basic_auth_enabled", "oauth2_enabled"):
        monkeypatch.setattr(settings._inner, key, False)
    monkeypatch.setattr(settings._inner, "raw_logs_services", "postfix,dovecot")
    with TestClient(app).websocket_connect("/ws/raw-logs?service=postfix") as ws:
        assert ws.receive_json()["type"] == "connected"
        ws.send_json({"action": "subscribe", "service": "dovecot"})
        assert ws.receive_json()["service"] == "dovecot"
        ws.send_json({"action": "subscribe", "service": "invalid"})
        assert ws.receive_json()["type"] == "error"
    assert not manager.get_connection_count()
    assert not manager._send_locks
