"""Tests for streaming/broadcast.py in MAD-PS Explanation Service."""

import asyncio
import os
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

try:
    import pytest
except ImportError:
    class _MockPytest:
        class mark:
            @staticmethod
            def asyncio(fn):
                return fn
    pytest = _MockPytest()

from streaming.broadcast import WebSocketManager, EventBus, CouncilBroadcaster




class MockWebSocket:
    def __init__(self):
        self.accepted = False
        self.sent_messages = []
        self.should_fail = False

    async def accept(self):
        self.accepted = True

    async def send_json(self, payload):
        if self.should_fail:
            raise RuntimeError("Connection closed")
        self.sent_messages.append(payload)


@pytest.mark.asyncio
async def test_websocket_manager_connect_and_broadcast():
    manager = WebSocketManager()
    ws1 = MockWebSocket()
    ws2 = MockWebSocket()

    await manager.connect(ws1)
    await manager.connect(ws2)
    assert len(manager.connections) == 2
    assert ws1.accepted and ws2.accepted

    payload = {"event_type": "test_event", "text": "hello"}
    await manager.broadcast_json(payload)

    assert len(ws1.sent_messages) == 1
    assert ws1.sent_messages[0] == payload
    assert len(ws2.sent_messages) == 1
    assert ws2.sent_messages[0] == payload


@pytest.mark.asyncio
async def test_websocket_manager_handles_dead_connections():
    manager = WebSocketManager()
    ws_healthy = MockWebSocket()
    ws_dead = MockWebSocket()
    ws_dead.should_fail = True

    await manager.connect(ws_healthy)
    await manager.connect(ws_dead)
    assert len(manager.connections) == 2

    await manager.broadcast_json({"test": "data"})
    assert len(manager.connections) == 1
    assert ws_healthy in manager.connections
    assert ws_dead not in manager.connections


@pytest.mark.asyncio
async def test_event_bus_in_memory():
    bus = EventBus()
    await bus.connect()

    received_events = []

    async def on_stream(payload):
        received_events.append(payload)

    await bus.subscribe("council.stream", on_stream)
    await bus.publish("council.stream", {"msg": "stream event"})
    await asyncio.sleep(0.01)

    assert len(received_events) == 1
    assert received_events[0]["msg"] == "stream event"


@pytest.mark.asyncio
async def test_council_broadcaster_full_lifecycle():
    ws_mgr = WebSocketManager()
    bus = EventBus()
    broadcaster = CouncilBroadcaster(websocket_manager=ws_mgr, event_bus=bus)

    ws_client = MockWebSocket()
    await ws_mgr.connect(ws_client)

    bus_events = []

    async def capture_bus(payload):
        bus_events.append(payload)

    await bus.subscribe("council.stream", capture_bus)
    await bus.subscribe("council.phase", capture_bus)
    await bus.subscribe("council.verdict", capture_bus)
    await bus.subscribe("council.complete", capture_bus)

    # 1. Phase announce
    p1 = await broadcaster.phase_announce("🚀 Phase 1: Initial Prompt")
    assert p1["event_type"] == "phase_change"
    assert p1["source"] == "system"

    # 2. Agent stream token
    cb = broadcaster.create_stream_callback(phase="debate")
    await cb("gemini", "Thinking through threat models...")

    # 3. Direct broadcast
    await broadcaster.broadcast("agent_response", "claude", "Summary analysis", phase="debate")

    # 4. Verdict broadcast
    v = await broadcaster.broadcast_verdict("Final security explanation verdict")
    assert v["event_type"] == "council_verdict"

    # 5. Complete
    c = await broadcaster.broadcast_complete({"status": "success"})
    assert c["event_type"] == "council_complete"

    await asyncio.sleep(0.05)

    # Verify WebSocket received all messages
    assert len(ws_client.sent_messages) == 5
    event_types = [m["event_type"] for m in ws_client.sent_messages]
    assert event_types == [
        "phase_change",
        "agent_stream",
        "agent_response",
        "council_verdict",
        "council_complete",
    ]


if __name__ == "__main__":
    asyncio.run(test_websocket_manager_connect_and_broadcast())
    asyncio.run(test_websocket_manager_handles_dead_connections())
    asyncio.run(test_event_bus_in_memory())
    asyncio.run(test_council_broadcaster_full_lifecycle())
    print("All tests passed successfully!")
