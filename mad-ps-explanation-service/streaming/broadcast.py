"""
Broadcast and Event-Streaming Layer for MAD-PS Multi-Agent Debate Explanation Layer.
Clean extraction of the WebSocket broadcast, EventBus pub/sub, and phase-announcement patterns.
"""

from __future__ import annotations

import asyncio
import datetime
import inspect
import json
import logging
import os
from typing import Any, Callable, Dict, List, Optional, Set
from fastapi import WebSocket


logger = logging.getLogger("mad_ps_explanation.streaming")


class WebSocketManager:
    """Manages active client WebSocket connections and broadcasts JSON payloads."""

    def __init__(self) -> None:
        self.connections: Set[WebSocket] = set()

    async def connect(self, websocket: WebSocket) -> None:
        """Accept connection and register websocket client."""
        await websocket.accept()
        self.connections.add(websocket)
        logger.info("[WS] Client connected. Total active connections: %d", len(self.connections))

    def disconnect(self, websocket: WebSocket) -> None:
        """Unregister a disconnected websocket client."""
        if websocket in self.connections:
            self.connections.remove(websocket)
            logger.info("[WS] Client disconnected. Total active connections: %d", len(self.connections))

    async def broadcast_json(self, payload: Dict[str, Any]) -> None:
        """Broadcast a JSON serializable dict payload to all connected clients."""
        dead: List[WebSocket] = []
        for connection in list(self.connections):
            try:
                await connection.send_json(payload)
            except Exception as exc:
                logger.debug("[WS] Failed to send to client (%s), marking for removal", exc)
                dead.append(connection)

        for connection in dead:
            self.disconnect(connection)


class EventBus:
    """
    EventBus providing in-memory pub/sub with optional NATS JetStream integration.
    Falls back gracefully to in-memory dispatch if NATS is not reachable.
    """

    def __init__(self, nats_url: Optional[str] = None) -> None:
        self.subscribers: Dict[str, List[Callable]] = {}
        self._nc = None
        self._js = None
        self._use_nats = False
        self._nats_url = nats_url or os.environ.get("NATS_URL", "nats://council_nats:4222")

    async def connect(self) -> None:
        """Attempt connection to NATS, fallback to in-memory if unavailable."""
        try:
            import nats
            self._nc = await nats.connect(
                self._nats_url,
                connect_timeout=3,
                reconnect_time_wait=2,
                max_reconnect_attempts=3,
            )
            self._js = self._nc.jetstream()
            self._use_nats = True
            logger.info("[EventBus] NATS connected at %s", self._nats_url)
        except Exception as exc:
            self._use_nats = False
            logger.info("[EventBus] NATS unavailable (%s), using in-memory bus", exc)

    async def subscribe(self, subject: str, callback: Callable) -> None:
        """Subscribe an async or sync callback to a topic subject."""
        if subject not in self.subscribers:
            self.subscribers[subject] = []
        self.subscribers[subject].append(callback)

        if self._use_nats and self._nc:
            try:
                async def _nats_handler(msg):
                    try:
                        payload = json.loads(msg.data.decode())
                    except Exception:
                        payload = msg.data.decode()
                    if inspect.iscoroutinefunction(callback):
                        await callback(payload)
                    else:
                        callback(payload)

                await self._nc.subscribe(subject, cb=_nats_handler)
            except Exception as exc:
                logger.warning("[EventBus] NATS subscribe failed for %s: %s", subject, exc)

    async def publish(self, subject: str, payload: Any) -> None:
        """Publish an event to in-memory subscribers and NATS if connected."""
        # In-memory delivery
        if subject in self.subscribers:
            for cb in self.subscribers[subject]:
                try:
                    if inspect.iscoroutinefunction(cb):
                        asyncio.create_task(cb(payload))
                    else:
                        cb(payload)
                except Exception as exc:
                    logger.error("[EventBus] In-memory subscriber callback error on %s: %s", subject, exc)

        # NATS delivery
        if self._use_nats and self._nc:
            try:
                data = json.dumps(payload).encode() if isinstance(payload, (dict, list)) else str(payload).encode()
                await self._nc.publish(subject, data)
            except Exception as exc:
                logger.warning("[EventBus] NATS publish failed for %s: %s", subject, exc)

    async def close(self) -> None:
        """Close NATS connection if active."""
        if self._nc:
            try:
                await self._nc.close()
            except Exception:
                pass


class CouncilBroadcaster:
    """
    Central event broadcaster for Council multi-agent debate sessions.
    Handles structured event broadcasting over WebSockets, EventBus publishing,
    phase-change announcements, and live streaming token callbacks.
    """

    def __init__(
        self,
        websocket_manager: Optional[WebSocketManager] = None,
        event_bus: Optional[EventBus] = None,
    ) -> None:
        self.websocket_manager = websocket_manager or WebSocketManager()
        self.event_bus = event_bus or EventBus()

    async def broadcast(
        self,
        event_type: str,
        source: str,
        text: str,
        phase: str = "initial",
        stream_callback: Optional[Callable[[str, str], Any]] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Broadcast a structured event to WebSocket + event bus + optional stream callback."""
        payload: Dict[str, Any] = {
            "event_type": event_type,
            "source": source,
            "phase": phase,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "text": text,
        }
        if extra:
            payload.update(extra)

        await self.websocket_manager.broadcast_json(payload)
        await self.event_bus.publish("council.stream", payload)

        if stream_callback:
            if inspect.iscoroutinefunction(stream_callback):
                await stream_callback(source, text)
            else:
                stream_callback(source, text)

        return payload

    async def phase_announce(
        self,
        title: str,
        phase: str = "system",
        stream_callback: Optional[Callable[[str, str], Any]] = None,
    ) -> Dict[str, Any]:
        """
        Send a phase-change notification to the frontend and event bus.
        Notifies all connected agents and clients of stage transitions (Phase 1 -> Phase 2 -> ...).
        """
        payload: Dict[str, Any] = {
            "event_type": "phase_change",
            "source": "system",
            "phase": phase,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "text": title,
        }
        await self.websocket_manager.broadcast_json(payload)
        await self.event_bus.publish("council.stream", payload)
        await self.event_bus.publish("council.phase", payload)

        if stream_callback:
            if inspect.iscoroutinefunction(stream_callback):
                await stream_callback("system", title)
            else:
                stream_callback("system", title)

        return payload


    async def stream_chunk(
        self,
        provider: str,
        text: str,
        phase: str = "streaming",
    ) -> Dict[str, Any]:
        """Broadcast an individual token or text chunk streamed by an agent during debate."""
        payload: Dict[str, Any] = {
            "event_type": "agent_stream",
            "source": provider,
            "phase": phase,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "text": text,
        }
        await self.websocket_manager.broadcast_json(payload)
        await self.event_bus.publish("council.stream", payload)
        return payload

    def create_stream_callback(
        self,
        source: str = "agent",
        phase: str = "streaming",
    ) -> Callable[..., Any]:
        """
        Create a callable stream callback bound to a specific source and phase.
        Accepts either cb(chunk_text) or cb(source, chunk_text).
        """
        async def _callback(*args: Any) -> None:
            if len(args) == 1:
                chunk = str(args[0])
                provider = source
            elif len(args) >= 2:
                provider = str(args[0])
                chunk = str(args[1])
            else:
                return

            await self.stream_chunk(provider=provider, text=chunk, phase=phase)

        return _callback


    async def broadcast_verdict(
        self,
        verdict_text: str,
        source: str = "council",
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Broadcast final council verdict / explanation report to all listeners."""
        payload: Dict[str, Any] = {
            "event_type": "council_verdict",
            "source": source,
            "phase": "verdict",
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "text": verdict_text,
        }
        if extra:
            payload.update(extra)

        await self.websocket_manager.broadcast_json(payload)
        await self.event_bus.publish("council.verdict", payload)
        return payload

    async def broadcast_complete(self, summary: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Broadcast council debate completion signal."""
        payload: Dict[str, Any] = {
            "event_type": "council_complete",
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        if summary:
            payload["summary"] = summary

        await self.websocket_manager.broadcast_json(payload)
        await self.event_bus.publish("council.complete", payload)
        return payload
